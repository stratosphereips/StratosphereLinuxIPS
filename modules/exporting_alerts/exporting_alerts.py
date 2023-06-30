from slips_files.common.imports import *
from slack import WebClient
from slack.errors import SlackApiError
import os
import json
from stix2 import Indicator, Bundle
from cabby import create_client
import time
import threading
import sys
import datetime

class ExportingAlerts(Module, multiprocessing.Process):
    """
    Module to export alerts to slack and/or STIX
    You need to have the token in your environment variables to use this module
    """

    name = 'Exporting Alerts'
    description = 'Export alerts to slack or STIX format'
    authors = ['Alya Gomaa']

    def init(self):
        self.port = None
        self.c1 = self.db.subscribe('export_evidence')
        self.channels = {
            'export_evidence': self.c1
        }
        self.read_configuration()
        if 'slack' in self.export_to:
            self.get_slack_token()
        # This bundle should be created once and we should append all indicators to it
        self.is_bundle_created = False
        # To avoid duplicates in STIX_data.json
        self.added_ips = set()
        self.is_running_on_interface = '-i' in sys.argv or self.db.is_growing_zeek_dir()
        self.export_to_taxii_thread = threading.Thread(
            target=self.send_to_server, daemon=True
        )

    def read_configuration(self):
        """Read the configuration file for what we need"""
        conf = ConfigParser()
        # Available options ['slack','stix']
        self.export_to = conf.export_to()

        if 'slack' in self.export_to:
            self.slack_token_filepath = conf.slack_token_filepath()
            self.slack_channel_name = conf.slack_channel_name()
            self.sensor_name = conf.sensor_name()

        if 'stix' in self.export_to:
            self.TAXII_server = conf.taxii_server()
            self.port = conf.taxii_port()
            self.use_https = conf.use_https()
            self.discovery_path = conf.discovery_path()
            self.inbox_path = conf.inbox_path()
            # push_delay is only used when slips is running using -i
            self.push_delay = conf.push_delay()
            self.collection_name = conf.collection_name()
            self.taxii_username = conf.taxii_username()
            self.taxii_password = conf.taxii_password()
            self.jwt_auth_path = conf.jwt_auth_path()
            # push delay exists -> create thread that waits
            # push delay doesnt exist -> running using file not interface -> only push to taxii server once before
            # stopping

    def get_slack_token(self):
        if not hasattr(self, 'slack_token_filepath'):
            return False

        # slack_bot_token_secret should contain your slack token only
        try:
            with open(self.slack_token_filepath, 'r') as f:
                self.BOT_TOKEN = f.read()
                if len(self.BOT_TOKEN) < 5:
                    raise NameError
        except (FileNotFoundError, NameError):
            self.print(
                f'Please add slack bot token to '
                f'{self.slack_token_filepath}. Stopping.'
            )
            # Stop the module
            self.shutdown_gracefully()



    def ip_exists_in_stix_file(self, ip):
        """Searches for ip in STIX_data.json to avoid exporting duplicates"""
        return ip in self.added_ips

    def send_to_slack(self, msg_to_send: str) -> bool:
        # Msgs sent in this channel will be exported to slack
        # Token to login to your slack bot. it should be set in slack_bot_token_secret
        if self.BOT_TOKEN == '':
            # The file is empty
            self.print(
                f"Can't find SLACK_BOT_TOKEN in {self.slack_token_filepath}.",0,2,
            )
            return False

        slack_client = WebClient(token=self.BOT_TOKEN)
        try:
            slack_client.chat_postMessage(
                # Channel name is set in slips.conf
                channel=self.slack_channel_name,
                # Sensor name is set in slips.conf
                text=f'{self.sensor_name}: {msg_to_send}',
            )
            return True

        except SlackApiError as e:
            # You will get a SlackApiError if "ok" is False
            assert e.response[
                'error'
            ], 'Problem while exporting to slack.'   # str like 'invalid_auth', 'channel_not_found'
            return False

    def push_to_TAXII_server(self):
        """
        Use Inbox Service (TAXII Service to Support Producer-initiated pushes of cyber threat information) to publish
        our STIX_data.json file
        """
        # Create a cabby client
        client = create_client(
            self.TAXII_server,
            use_https=self.use_https,
            port=self.port,
            discovery_path=self.discovery_path,
        )
        # jwt_auth_url is optional
        if self.jwt_auth_path != '':
            client.set_auth(
                username=self.taxii_username,
                password=self.taxii_password,
                # URL used to obtain JWT token
                jwt_auth_url=self.jwt_auth_path,
            )
        else:
            # User didn't provide jwt_auth_path in slips.conf
            client.set_auth(
                username=self.taxii_username,
                password=self.taxii_password,
            )

        # Check the available services to make sure inbox service is there
        services = client.discover_services()
        # Check if inbox is there
        for service in services:
            if 'inbox' in service.type.lower():
                break
        else:
            # Comes here if it cant find inbox in services
            self.print(
                "Server doesn't have inbox available. "
                "Exporting STIX_data.json is cancelled.", 0, 2
            )
            return False

        # Get the data that we want to send
        with open('STIX_data.json') as stix_file:
            stix_data = stix_file.read()
        # Make sure we don't push empty files
        if len(stix_data) > 0:
            binding = 'urn:stix.mitre.org:json:2.1'
            # URI is the path to the inbox service we want to use in the taxii server
            client.push(
                stix_data,
                binding,
                collection_names=[self.collection_name],
                uri=self.inbox_path,
            )
            self.print(f'Successfully exported to TAXII server: {self.TAXII_server}.', 1, 0)
            return True

    def export_to_STIX(self, msg_to_send: tuple) -> bool:
        """
        Function to export evidence to a STIX_data.json file in the cwd.
        It keeps appending the given indicator to STIX_data.json until they're sent to the
        taxii server
        msg_to_send is a tuple: (evidence_type, attacker_direction,attacker, description)
            evidence_type: e.g PortScan, ThreatIntelligence etc
            attacker_direction: e.g dip sip dport sport
            attacker: ip or port  OR ip:port:proto
            description: e.g 'New horizontal port scan detected to port 23. Not Estab TCP from IP: ip-address. Tot pkts sent all IPs: 9'
        """
        # self.print(f"Exporting STIX data to {self.TAXII_server} every {self.push_delay} seconds.")
        # ---------------- set name attribute ----------------
        evidence_type, attacker_direction, attacker, description = (
            msg_to_send[0],
            msg_to_send[1],
            msg_to_send[2],
            msg_to_send[3],
        )
        # In case of ssh connection, evidence_type is set to SSHSuccessful-by-ip (special case) , ip here is variable
        # So we change that to be able to access it in the below dict
        if 'SSHSuccessful' in evidence_type:
            evidence_type = 'SSHSuccessful'
        # This dict contains each type and the way we should describe it in STIX name attribute

        # Get the right description to use in stix
        name = evidence_type

        # ---------------- set pattern attribute ----------------
        if 'port' in attacker_direction:
            # attacker is a port probably coming from a portscan we need the ip instead
            attacker = description[
                description.index('IP: ') + 4 : description.index(' Tot') - 1
            ]
        elif 'tcp' in attacker:
            # for example 127.0.0.1:443:tcp
            # Get the ip
            attacker = attacker.split(':')[0]
        ioc_type = utils.detect_data_type(attacker)
        if ioc_type == 'ip':
            pattern = f"[ip-addr:value = '{attacker}']"
        elif ioc_type == 'domain':
            pattern = f"[domain-name:value = '{attacker}']"
        elif ioc_type == 'url':
            pattern = f"[url:value = '{attacker}']"
        else:
            self.print(f"Can't set pattern for STIX. {attacker}", 0, 3)
            return False
        # Required Indicator Properties: type, spec_version, id, created, modified , all are set automatically
        # Valid_from, created and modified attribute will be set to the current time
        # ID will be generated randomly
        # ref https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_6khi84u7y58g
        indicator = Indicator(
            name=name, pattern=pattern, pattern_type='stix'
        )  # the pattern language that the indicator pattern is expressed in.
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
        elif not self.ip_exists_in_stix_file(attacker):
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
                stix_file.write(f',{str(indicator)}' + ']\n}\n')

        # Set of unique ips added to stix_data.json to avoid duplicates
        self.added_ips.add(attacker)
        self.print('Indicator added to STIX_data.json', 2, 0)
        return True

    def send_to_server(self):
        """
        Responsible for publishing STIX_data.json to the taxii server every
        self.push_delay seconds when running on an interface only
        """
        while True:
            # on an interface, we use the push delay from slips.conf
            # on files, we push once when slips is stopping
            time.sleep(self.push_delay)
            # Sometimes the time's up and we need to send to server again but there's no
            # new alerts in stix_data.json yet
            if os.path.exists('STIX_data.json'):
                self.push_to_TAXII_server()
                # Delete stix_data.json file so we don't send duplicates
                os.remove('STIX_data.json')
                self.is_bundle_created = False
            else:
                self.print(
                    f'{self.push_delay} seconds passed, no new alerts in STIX_data.json.', 2, 0
                )

    def shutdown_gracefully(self):
        # We need to publish to taxii server before stopping
        if 'stix' in self.export_to:
            self.push_to_TAXII_server()

        if hasattr(self, 'json_file_handle'):
            self.json_file_handle.close()

        if 'slack' in self.export_to and hasattr(self, 'BOT_TOKEN'):
            date_time = datetime.datetime.now()
            date_time = utils.convert_format(date_time, utils.alerts_format)
            self.send_to_slack(f'{date_time}: Slips finished on sensor: {self.sensor_name}.')

    def pre_main(self):
        utils.drop_root_privs()
        if (
            self.is_running_on_interface
            and 'stix' in self.export_to
        ):
            # This thread is responsible for waiting n seconds before
            # each push to the stix server
            # it starts the timer when the first alert happens
            self.export_to_taxii_thread.start()

        if 'slack' in self.export_to and hasattr(self, 'BOT_TOKEN'):
            date_time = datetime.datetime.now()
            date_time = utils.convert_format(date_time, utils.alerts_format)
            self.send_to_slack(f'{date_time}: Slips started on sensor: {self.sensor_name}.')

    def main(self):
        if msg:= self.get_msg('export_evidence'):
            evidence = json.loads(msg['data'])
            description = evidence['description']
            if 'slack' in self.export_to and hasattr(self, 'BOT_TOKEN'):
                srcip = evidence['profileid'].split("_")[-1]
                msg_to_send = f'Src IP {srcip} Detected {description}'
                self.send_to_slack(msg_to_send)

            if 'stix' in self.export_to:
                msg_to_send = (
                    evidence['evidence_type'],
                    evidence['attacker_direction'],
                    evidence['attacker'],
                    description,
                )
                exported_to_stix = self.export_to_STIX(msg_to_send)
                if not exported_to_stix:
                    self.print('Problem in export_to_STIX()', 0, 3)
