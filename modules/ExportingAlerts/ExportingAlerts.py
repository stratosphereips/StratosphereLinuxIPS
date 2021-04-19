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
import ipaddress
# pip install --ignore-installed six
#todo add this to requirements.txt


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
        self.BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
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
        #self.test()

    def test(self):
        """ to test this module, we'll remove it once we're done """
        data_to_send = {
            'export_to' : 'slack',
            'msg' : 'Test message!!'
        }
        data_to_send = json.dumps(data_to_send)
        __database__.publish('export_alert',data_to_send)
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

    def send_to_slack(self,msg_to_send):
        # Msgs sent in this channel will be exported either to slack or STIX
        # Token to login to our slack bot. This is a different kind of token.
        if self.BOT_TOKEN == None:
            self.print("Can't find SLACK_BOT_TOKEN in your environment variables.",0,1)
        else:
            slack_client = WebClient(token=self.BOT_TOKEN)
            try:
                response = slack_client.chat_postMessage(
                           channel="proj_slips_alerting_module",
                           text =  msg_to_send#"Hello Slack from exporting alerts module ! :tada:"
                            )
                self.print("Exported to slack")
            except SlackApiError as e:
                # You will get a SlackApiError if "ok" is False
                assert e.response["error"] , "Problem while exporting to slack." # str like 'invalid_auth', 'channel_not_found'

    def export_to_STIX(self,msg_to_send: tuple) -> bool:
        """
        Function to export a STIX json file.
        msg_to_send should be a tuple containing: (type_evidence, type_detection,detection_info, description)
            type_evidence: e.g PortScan, ThreatIntelligence etc
            type_detection: e.g dip sip dport sport
            detection_info: ip or port
            description: e.g port scans
        """
        # ['PortScanType2', 'dport', '23',
        # 'New horizontal port scan detected to port 23. Not Estab TCP from IP: 192.168.2.16. Tot pkts sent all IPs: 9']
        # ---------------- set name attribute ----------------
        type_evidence, type_detection, detection_info, description =  msg_to_send[0], msg_to_send[1], msg_to_send[2] , msg_to_send[3]

        # in case of ssh connection, type_evidence is set to SSHSuccessful-by-ip (special case) , ip here is variable
        # so we change that to be able to access it in the below dict
        if 'SSHSuccessful' in type_evidence:
            type_evidence = 'SSHSuccessful'

        # this dict contains each type and the way we should describe it in stix
        type_evidence_descriptions = {
            'PortScanType1': 'Vertical port scan',
            'PortScanType2': 'Horizontal port scan',
            'ThreatIntelligenceBlacklistIP' : 'Blacklisted IP',
            'SelfSignedCertificate' : 'Self-signed certificate', # todo:  should we make it a stix indicator?
            'LongConnection' : 'Long Connection', # todo what should be the description for this? should we even make it a stix indicator?
            'SSHSuccessful' :'SSH connection from ip' #SSHSuccessful-by-ip
        }

        # Port scans are not passed in type_evidence , they're passed in the description
        # Get the right description to use in stix
        try:
            name = type_evidence_descriptions[type_evidence]
        except KeyError:
            self.print("Can't find the description for type_evidence: {}".format(type_evidence),0,1)
            return False
        # ---------------- set pattern attribute ----------------
        if self.is_ip(type_detection):
            pattern = "[ip-addr:value = '{}']".format(type_detection)
        else:
            # It's a port probably coming from a portscan
            #todo: get the ip
            pass
        # Required Indicator Properties: type, spec_version, id, created, modified , all are set automatically
        # valid_from, created and modified attribute will be set to the current time
        # id will be generated randomly
        indicator = Indicator(name=name,
                              pattern=pattern,
                              pattern_type="stix") # characterize the pattern language that the indicator pattern is expressed in.
        return True

    def run(self):
        # todo: should i add support for both stix and slack together?
        # Here's how this module works:
        #1- the user specifies -a slack and adds SLACK_BOT_TOKEN to their environment variables
        #2- if you run slips using sudo use sudo -E instead to pass all env variables
        #2- we send a msg to evidence_added(evidenceprocess) telling it to export all evidence sent to it to export_alert channel(this module)
        #3- evidenceProcess sends a msg to export_alert channel with the evidence that should be sent and then this module exports it

        # Example of sending msgs to this module:
        # data_to_send = {
        #         'export_to' : 'slack',
        #         'msg' : 'this msg is sent using json dumps/loads'
        #     }
        # data_to_send = json.dumps(data_to_send)
        #__database__.publish('export_alert',data_to_send)
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
                            self.send_to_slack(msg_to_send)
                        elif 'stix' in data['export_to'].lower():
                            self.export_to_STIX(msg_to_send)
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
