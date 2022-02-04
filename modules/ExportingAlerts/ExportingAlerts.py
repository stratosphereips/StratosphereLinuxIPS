# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
import platform
# Your imports
from slack import WebClient
from slack.errors import SlackApiError
import os
import json
from stix2 import Indicator
from stix2 import Bundle
import ipaddress
from cabby import create_client
import time
import _thread
import sys
import validators
import datetime


class Module(Module, multiprocessing.Process):
    """
    Module to export alerts to slack and/or STX
    You need to have the token in your environment variables to use this module
    """
    name = 'ExportingAlerts'
    description = 'Export alerts to slack, STIX and json format'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.c1 = __database__.subscribe('evidence_added')
        # slack_bot_token_secret should contain your slack token only
        try:
            with open("modules/ExportingAlerts/slack_bot_token_secret", "r") as f:
                self.BOT_TOKEN = f.read()
        except FileNotFoundError:
            self.print("Please add slack bot token to modules/ExportingAlerts/slack_bot_token_secret. Stopping.")
            # Stop the module
            __database__.publish('export_alert','stop_process')
        # Get config vaeriables
        # Available options ['slack','stix']
        self.export_to = self.config.get('ExportingAlerts', 'export_to')
        # convert to list
        self.export_to = self.export_to.strip('][').replace(" ","").split(',')
        # Convert to lowercase
        self.export_to =  [option.lower() for option in self.export_to]
        self.slack_channel_name = self.config.get('ExportingAlerts', 'slack_channel_name')
        self.sensor_name = self.config.get('ExportingAlerts', 'sensor_name')
        self.TAXII_server = self.config.get('ExportingAlerts', 'TAXII_server')
        # taxii server port
        self.port = self.config.get('ExportingAlerts', 'port')
        self.use_https = self.config.get('ExportingAlerts', 'use_https')
        if self.use_https.lower() == 'true':
            self.use_https = True
        elif self.use_https.lower() == 'false':
            self.use_https = False
        self.discovery_path = self.config.get('ExportingAlerts', 'discovery_path')
        self.inbox_path = self.config.get('ExportingAlerts', 'inbox_path')
        # push delay exists -> create thread that waits
        # push delay doesnt exist -> running using file not interface -> only push to taxii server once before stopping
        try:
            self.push_delay = int(self.config.get('ExportingAlerts', 'push_delay'))
        except:
            # Here means that push_delay is None in slips.conf(default value).
            # we set it to export to the server every 1h by default
            self.push_delay = 60*60
        self.collection_name = self.config.get('ExportingAlerts', 'collection_name')
        self.taxii_username = self.config.get('ExportingAlerts', 'taxii_username')
        self.taxii_password = self.config.get('ExportingAlerts', 'taxii_password')
        self.jwt_auth_url = self.config.get('ExportingAlerts', 'jwt_auth_url')
        # This bundle should be created once and we should append all indicators to it
        self.is_bundle_created = False
        self.is_thread_created = False
        # To avoid duplicates in STIX_data.json
        self.added_ips = set()
        self.timeout = 0.0000001
        # flag to open json file only once
        self.is_json_file_opened = False
        self.json_file_handle = False

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    def get_ioc_type(self, ioc):
        """ Check the type of ioc, returns url, ip or domain"""
        try:
            # Is IPv4
            ip_address = ipaddress.IPv4Address(ioc)
            return 'ip'
        except ipaddress.AddressValueError:
            # Is it ipv6?
            try:
                ip_address = ipaddress.IPv6Address(ioc)
                return 'ip'
            except ipaddress.AddressValueError:
                # It does not look as IP address.
                if validators.domain(ioc):
                    return 'domain'
                elif validators.url(ioc):
                    return 'url'

    def ip_exists_in_stix_file(self, ip):
        """ Searches for ip in STIX_data.json to avoid exporting duplicates """
        return ip in self.added_ips

    def send_to_slack(self, msg_to_send: str) -> bool:
        # Msgs sent in this channel will be exported to slack
        # Token to login to your slack bot. it should be set in slack_bot_token_secret
        if self.BOT_TOKEN is '':
            # The file is empty
            self.print("Can't find SLACK_BOT_TOKEN in modules/ExportingAlerts/slack_bot_token_secret.", 0, 2)
            return False
        slack_client = WebClient(token=self.BOT_TOKEN)
        try:
            response = slack_client.chat_postMessage(
                # Channel name is set in slips.conf
                channel = self.slack_channel_name,
                # Sensor name is set in slips.conf
                text = self.sensor_name + ': ' + msg_to_send
            )
        except SlackApiError as e:
            # You will get a SlackApiError if "ok" is False
            assert e.response["error"] , "Problem while exporting to slack." # str like 'invalid_auth', 'channel_not_found'
        return True

    def push_to_TAXII_server(self):
        """
        Use Inbox Service (TAXII Service to Support Producer-initiated pushes of cyber threat information) to publish
        our STIX_data.json file
        """
        # Create a cabby client
        client = create_client(self.TAXII_server,
                                use_https = self.use_https,
                                port = self.port,
                                discovery_path=self.discovery_path)
        # jwt_auth_url is optional
        if self.jwt_auth_url is not '':
            client.set_auth(
                username=self.taxii_username,
                password=self.taxii_password,
                # URL used to obtain JWT token
                jwt_auth_url=self.jwt_auth_url
            )
        else:
            # User didn't provide jwt_auth_url in slips.conf
            client.set_auth(
                username=self.taxii_username,
                password=self.taxii_password,
            )
        # Check the available services to make sure inbox service is there
        services = client.discover_services()
        # Check if inbox is there
        for service in services :
            if 'inbox' in service.type.lower():
                break
        else:
            # Comes here if it cant find inbox in services
            self.print("Server doesn't have inbox available. Exporting STIX_data.json is cancelled.", 0, 2)
            return False
        # Get the data that we want to send
        with open("STIX_data.json") as stix_file:
            stix_data = stix_file.read()
        # Make sure we don't push empty files
        if len(stix_data) > 0:
            binding = 'urn:stix.mitre.org:json:2.1'
            # URI is the path to the inbox service we want to use in the taxii server
            client.push(stix_data, binding,
                        collection_names=[self.collection_name],
                        uri=self.inbox_path)
            self.print(f"Successfully exported to {self.TAXII_server}.", 1, 0)
            return True

    def export_to_STIX(self, msg_to_send: tuple) -> bool:
        """
        Function to export evidence to a STIX_data.json file in the cwd.
        msg_to_send is a tuple: (type_evidence, type_detection,detection_info, description)
            type_evidence: e.g PortScan, ThreatIntelligence etc
            type_detection: e.g dip sip dport sport
            detection_info: ip or port  OR ip:port:proto
            description: e.g 'New horizontal port scan detected to port 23. Not Estab TCP from IP: ip-address. Tot pkts sent all IPs: 9'
        """
        # self.print(f"Exporting STIX data to {self.TAXII_server} every {self.push_delay} seconds.")
        # ---------------- set name attribute ----------------
        type_evidence, type_detection, detection_info, description = msg_to_send[0], msg_to_send[1], msg_to_send[2], \
                                                                     msg_to_send[3]
        # In case of ssh connection, type_evidence is set to SSHSuccessful-by-ip (special case) , ip here is variable
        # So we change that to be able to access it in the below dict
        if 'SSHSuccessful' in type_evidence:
            type_evidence = 'SSHSuccessful'
        # This dict contains each type and the way we should describe it in STIX name attribute
        type_evidence_descriptions = {
            'PortScanType1': 'Vertical port scan',
            'PortScanType2': 'Horizontal port scan',
            'ThreatIntelligenceBlacklistIP' : 'Blacklisted IP',
            'SelfSignedCertificate' : 'Self-signed certificate',
            'LongConnection' : 'Long Connection',
            'SSHSuccessful' :'SSH connection from ip', #SSHSuccessful-by-ip
            'C&C channels detection' : 'C&C channels detection',
            'ThreatIntelligenceBlacklistDomain' : 'Threat Intelligence Blacklist Domain'
        }
        # Get the right description to use in stix
        try:
            name = type_evidence_descriptions[type_evidence]
        except KeyError:
            self.print("Can't find the description for type_evidence: {}".format(type_evidence), 0, 3)
            return False
        # ---------------- set pattern attribute ----------------
        if 'port' in type_detection:
            # detection_info is a port probably coming from a portscan we need the ip instead
            detection_info = description[description.index("IP: ") + 4:description.index(" Tot") - 1]
        elif 'tcp' in detection_info:
            #for example 127.0.0.1:443:tcp
            # Get the ip
            detection_info = detection_info.split(':')[0]
        ioc_type = self.get_ioc_type(detection_info)
        if ioc_type is 'ip':
            pattern = "[ip-addr:value = '{}']".format(detection_info)
        elif ioc_type is 'domain':
            pattern = "[domain-name:value = '{}']".format(detection_info)
        elif ioc_type is 'url':
            pattern = "[url:value = '{}']".format(detection_info)
        else:
            self.print("Can't set pattern for STIX. {}".format(detection_info), 0, 3)
            return False
        # Required Indicator Properties: type, spec_version, id, created, modified , all are set automatically
        # Valid_from, created and modified attribute will be set to the current time
        # ID will be generated randomly
        indicator = Indicator(name=name,
                              pattern=pattern,
                              pattern_type="stix")  # the pattern language that the indicator pattern is expressed in.
        # Create and Populate Bundle. All our indicators will be inside bundle['objects'].
        bundle = Bundle()
        if not self.is_bundle_created:
            bundle = Bundle(indicator)
            # Clear everything in the existing STIX_data.json if it's not empty
            open('STIX_data.json', 'w').close()
            # Write the bundle.
            with open('STIX_data.json', 'w') as stix_file:
                stix_file.write(str(bundle))
            self.is_bundle_created = True
        elif not self.ip_exists_in_stix_file(detection_info):
            # Bundle is already created just append to it
            # r+ to delete last 4 chars
            with open('STIX_data.json', 'r+') as stix_file:
                # delete the last 4 characters in the file ']\n}\n' so we can append to the objects array and add them back later
                stix_file.seek(0, os.SEEK_END)
                stix_file.seek(stix_file.tell() - 4, 0)
                stix_file.truncate()
            # Append mode to add the new indicator to the objects array
            with open('STIX_data.json', 'a') as stix_file:
                # Append the indicator in the objects array
                stix_file.write("," + str(indicator) + "]\n}\n")
        # Set of unique ips added to stix_data.json to avoid duplicates
        self.added_ips.add(detection_info)
        self.print("Indicator added to STIX_data.json", 2, 0)
        return True

    def send_to_server(self):
        """ Responsible for publishing STIX_data.json to the taxii server every n seconds """
        while True:
            time.sleep(self.push_delay)
            # Sometimes the time's up and we need to send to server again but there's no
            # new alerts in stix_data.json yet
            if os.path.exists("STIX_data.json"):
                self.push_to_TAXII_server()
                # Delete stix_data.json file so we don't send duplicates
                os.remove('STIX_data.json')
                self.is_bundle_created = False
            else:
                self.print(f"{self.push_delay} seconds passed, no new alerts in STIX_data.json.",2,0)

    def export_to_json(self, evidence):
        """ Export alerts and flows to exported_alerts.json, a suricata like json format. """

        if not self.is_json_file_opened:
            self.json_file_handle = open('exported_alerts.json','a')
            self.is_json_file_opened = True

        profileid= evidence['profileid']
        twid= evidence['twid']
        uid= evidence['uid']
        # get the original fllow that triggered this evidence
        flow = __database__.get_flow(profileid,twid,uid)[uid]
        # portscans aren't associated with 1 flow, so we don't have a uid or a flow for this alert, ignore #todo
        if flow:
            flow = json.loads(flow)
            # suricata ts format: Date+T+Time
            # toddo take the original timestamp or the current tiemstamp?
            timestamp =  str(datetime.datetime.now()).replace(' ','T')
            line = {'timestamp': timestamp,
                    'flow_id' : uid,
                    'src_ip': flow.get('saddr'),
                    'src_port': flow.get('sport'),
                    'dest_ip': flow.get('daddr'),
                    'dest_port': flow.get('dport'),
                    'proto': flow.get('proto'),
                    'event_type': 'alert',
                    'alert': evidence['data']['description'],
                    'state': flow.get('state'),
                    'bytes_toserver': flow.get('sbytes'),
                    'pkts_toserver': flow.get('spkts')
                    }
            if flow.get('label') != 'unknown':
                line.update({'label': flow.get('label') })
            line = str(line)
            self.json_file_handle.write(f'{line}\n')
            return True
        return False

    def run(self):
        # Main loop function
        while True:
            try:
                message_c1 = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message_c1['data'] == 'stop_process':
                    # We need to publish to taxii server before stopping
                    if 'stix' in self.export_to:
                        self.push_to_TAXII_server()

                    if self.json_file_handle:
                        self.json_file_handle.close()
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                if message_c1['channel'] == 'evidence_added':
                    if type(message_c1['data']) == str:
                        evidence = json.loads(message_c1['data'])
                        description = evidence['description']
                        if 'slack' in self.export_to:
                            sent_to_slack = self.send_to_slack(description)
                            if not sent_to_slack:
                                self.print("Problem in send_to_slack()", 0, 3)
                        if 'stix' in self.export_to:
                            msg_to_send = (evidence['type_evidence'],
                                           evidence['type_detection'],
                                           evidence['detection_info'],
                                           description)
                            # This thread is responsible for waiting n seconds before each push to the stix server
                            # it starts the timer when the first alert happens
                            # push_delay should be an int when slips is running using -i
                            if self.is_thread_created is False and '-i' in sys.argv:
                                # this thread is started only once
                                _thread.start_new_thread(self.send_to_server,())
                                self.is_thread_created = True
                            exported_to_stix = self.export_to_STIX(msg_to_send)
                            if not exported_to_stix:
                                self.print("Problem in export_to_STIX()", 0,3)
                        if 'json' in self.export_to:
                            self.export_to_json(evidence)
            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
