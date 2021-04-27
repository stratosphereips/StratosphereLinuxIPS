# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables
# 5. The file name of the python module (template.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to ignore the module
# 7. The name of the class MUST be 'Module', do not change it.

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
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
#todo add cabby to requirements.txt


class Module(Module, multiprocessing.Process):
    """
    Module to export alerts to slack and/or STX
    You need to have the token in your environment variables to use this module
    """
    name = 'ExportingAlerts'
    description = 'Module to export alerts to slack and STIX'
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
        self.c1 = __database__.subscribe('export_alert')
        # slack_bot_token_secret should contain your slack token only
        with open("modules/ExportingAlerts/slack_bot_token_secret", "r") as f:
            self.BOT_TOKEN = f.read()
        # Get config vaeriables
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
        self.collection_name = self.config.get('ExportingAlerts', 'collection_name')
        self.taxii_username = self.config.get('ExportingAlerts', 'taxii_username')
        self.taxii_password = self.config.get('ExportingAlerts', 'taxii_password')
        # This bundle should be created once and we should append all indicators to it
        self.is_bundle_created = False
        # To avoid duplicates in STIX_data.json
        self.added_ips = set()
        # Set the timeout based on the platform. This is because the
        # pyredis lib does not have officially recognized the
        # timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = None
        else:
            # Other systems)
            self.timeout = None
        # self.test()

    def test(self):
        """ to test this module, we'll remove it once we're done """
        data_to_send = {
            'export_to': 'slack',
            'msg': 'Test message with sensor name!!'
        }
        data_to_send = json.dumps(data_to_send)
        __database__.publish('export_alert', data_to_send)
        print("published")

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by
        taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to
         be printed
         debug: is the minimum debugging level required for this text to be
         printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the
        minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def is_ip(self, value):
        """ Checks if this value is a valid IP """
        try:
            # Is IPv4
            ip_address = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            # Is it ipv6?
            try:
                ip_address = ipaddress.IPv6Address(value)
            except ipaddress.AddressValueError:
                # It does not look as IP address.
                return False
        return True

    def ip_exists_in_stix_file(self, ip):
        """ Searches for ip in STIX_data.json to avoid exporting duplicates """
        return ip in self.added_ips

    def send_to_slack(self, msg_to_send: str) -> bool:
        # Msgs sent in this channel will be exported to slack
        # Token to login to your slack bot. it should be set in slack_bot_token_secret
        if self.BOT_TOKEN is '':
            # The file is empty
            self.print("Can't find SLACK_BOT_TOKEN in modules/ExportingAlerts/slack_bot_token_secret .", 0, 1)
            return False
        else:
            slack_client = WebClient(token=self.BOT_TOKEN)
            try:
                response = slack_client.chat_postMessage(
                    # Channel name is set in slips.conf
                    channel = self.slack_channel_name,
                    # Sensor name is set in slips.conf
                    text = self.sensor_name + ': ' + msg_to_send
                )
                self.print("Exported to slack")
            except SlackApiError as e:
                # You will get a SlackApiError if "ok" is False
                assert e.response["error"] , "Problem while exporting to slack." # str like 'invalid_auth', 'channel_not_found'
            return True

    def push_to_TAXII_server(self):
        """
        Use Inbox Service (TAXII Service to Support Producer-initiated pushes of cyber threat information) to publish
        our STIX_data.json file
        """
        # todo how often to call this function?
        # Create a cabby client
        client = create_client(self.TAXII_server,
                                use_https = bool(self.use_https),
                                port = self.port,
                                discovery_path=self.discovery_path)
        client.set_auth(
                username=self.taxii_username,
                password=self.taxii_password
            ) # todo fix authentication not working
        # Check the available services to make sure inbox service is there
        services = client.discover_services()
        # Check if inbox is there
        for service in services :
            if 'inbox' in service.type.lower():
                break
        else:
            # Comes here if it cant find inbox in services
            self.print("Server doesn't have inbox available. Exporting STIX_data.json is cancelled.",0,1)
            return False
        # Get the data that we want to send
        with open("STIX_data.json") as stix_file:
            stix_data = stix_file.read()
        binding = 'urn:stix.mitre.org:json:2.1'
        # URI is the path to the inbox service we want to use in the taxii server
        client.push(stix_data, binding,
                    collection_names=[self.collection_name],
                    uri=self.inbox_path)
        self.print(f"Successfully exported to {self.TAXII_server}.")
        return True

    def export_to_STIX(self, msg_to_send: tuple) -> bool:
        """
        Function to export evidence to a STIX_data.json file in the cwd.
        msg_to_send is a tuple: (type_evidence, type_detection,detection_info, description)
            type_evidence: e.g PortScan, ThreatIntelligence etc
            type_detection: e.g dip sip dport sport
            detection_info: ip or port
            description: e.g 'New horizontal port scan detected to port 23. Not Estab TCP from IP: ip-address. Tot pkts sent all IPs: 9'
        """
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
            'SelfSignedCertificate' : 'Self-signed certificate', # todo:  should we make it a stix indicator?
            'LongConnection' : 'Long Connection', # todo what should be the description for this? should we even make it a stix indicator?
            'SSHSuccessful' :'SSH connection from ip' #SSHSuccessful-by-ip
        }
        # Get the right description to use in stix
        try:
            name = type_evidence_descriptions[type_evidence]
        except KeyError:
            self.print("Can't find the description for type_evidence: {}".format(type_evidence), 0, 1)
            return False
        # ---------------- set pattern attribute ----------------

        if 'port' in type_detection:
            # detection_info is a port probably coming from a portscan we need the ip instead
            detection_info = description[description.index("IP: ") + 4:description.index(" Tot") - 1]
        if self.is_ip(detection_info):
            pattern = "[ip-addr:value = '{}']".format(detection_info)
        else:
            self.print("Can't set pattern for STIX. {}".format(detection_info), 0, 1)
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
        self.print("Indicator added to STIX_data.json")
        return True

    def run(self):
        # todo: should i add support for both stix and slack together?
        # todo: which one of them should be enabled by default?
        # Here's how this module works:
        # 1- the user specifies -a slack and adds SLACK_BOT_TOKEN to
        # 2- if you run slips using sudo use sudo -E instead to pass all env variables
        # 2- we send a msg to evidence_added(evidenceprocess) telling it to export all evidence sent to it to export_alert channel(this module)
        # 3- evidenceProcess sends a msg to export_alert channel with the evidence that should be sent and then this module exports it
        # Example of sending msgs to this module:
        # data_to_send = {
        #         'export_to' : 'slack',
        #         'msg' : 'temp msg'
        #     }
        # data_to_send = json.dumps(data_to_send)
        # __database__.publish('export_alert',data_to_send)
        try:
        # Main loop function
            while True:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message['data'] == 'stop_process':
                    return True
                if message['channel'] == 'export_alert':
                    if type(message['data']) == str:
                        # The data dict has two fields: export_to and msg
                        data = json.loads(message['data'])
                        msg_to_send = data.get("msg")
                        if 'slack' in data['export_to']:
                            sent_to_slack = self.send_to_slack(msg_to_send)
                            if not sent_to_slack:
                                self.print("Problem in send_to_slack()", 0, 1)
                        elif 'stix' in data['export_to']:
                            exported_to_stix = self.export_to_STIX(msg_to_send)
                            if not exported_to_stix:
                                self.print("Problem in export_to_STIX()", 0, 1)
                                return True
                            self.push_to_TAXII_server()
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
