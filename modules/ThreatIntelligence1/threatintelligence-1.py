# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import ipaddress
import os
import configparser
import json
import traceback


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'threatintelligence1'
    description = 'Check if the srcIP or dstIP are in a malicious list of IPs.'
    authors = ['Frantisek Strasak, Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Subscribe to the channel
        __database__.start(self.config)
        # Get a separator from the database
        self.separator = __database__.getFieldSeparator()
        self.c1 = __database__.subscribe('give_threat_intelligence')

        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            self.timeout = None
        else:
            self.timeout = None

    def __read_configuration(self, section: str, name: str) -> str:
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
            conf_variable = self.config.get(section, name)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option,
            # or no section or no configuration file specified
            conf_variable = None
        return conf_variable

    def set_evidence_ip(self, ip, ip_description='', profileid='', twid='', ip_state='ip'):
        '''
        Set an evidence for malicious IP met in the timewindow
        If profileid is None, do not set an Evidence
        Returns nothing
        '''
        type_evidence = 'ThreatIntelligenceBlacklistIP'
        key = ip_state + ':' + ip + ':' + type_evidence
        threat_level = 50
        confidence = 1
        description = 'TI ' + ip_description
        if not twid:
            twid = ''
        __database__.setEvidence(key, threat_level, confidence, description, profileid=profileid, twid=twid)

    def set_evidence_domain(self, domain, domain_description='', profileid='', twid=''):
        '''
        Set an evidence for malicious domain met in the timewindow
        If profileid is None, do not set an Evidence
        Returns nothing
        '''
        type_evidence = 'ThreatIntelligenceBlacklistDomain'
        key = 'dstdomain' + ':' + domain + ':' + type_evidence
        threat_level = 50
        confidence = 1
        description = 'TI ' + domain_description
        if not twid:
            twid = ''
        __database__.setEvidence(key, threat_level, confidence, description, profileid=profileid, twid=twid)

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time
                # (see at logsProcess.py), we will stop slips automatically.
                # The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    return True
                # Check that the message is for you.
                # The channel now can receive an IP address or a domain name
                elif message['channel'] == 'give_threat_intelligence' and type(message['data']) is not int:
                    data = message['data']
                    new_data = data[:data.find('-profile')]
                    data = data.split('-')
                    # Some data may contain '-', so this split by '-' is
                    # dangerous. To hack it now we access the data
                    # from the end first
                    profileid = data[-3]
                    twid = data[-2]
                    ip_state = data[-1]
                    # Check if the new data is an ip or a domain
                    try:
                        # Just try to see if it has the format of an ipv4 or ipv6
                        new_ip = ipaddress.ip_address(new_data)
                        # We need the string, not the ip object
                        new_ip = new_data
                        # Is an IP address (ipv4 or ipv6)
                        # Search for this IP in our database of IoC
                        ip_description = __database__.search_IP_in_IoC(new_ip)

                        if ip_description != False: # Dont change this condition. This is the only way it works
                            # If the IP is in the blacklist of IoC. Add it as Malicious
                            ip_description = json.loads(ip_description)
                            ip_info = ip_description['description']
                            ip_source = ip_description['source']
                            self.set_evidence_ip(new_ip, ip_source, profileid, twid, ip_state)
                    except ValueError:
                        # This is not an IP, then should be a domain
                        new_domain = new_data
                        # Search for this domain in our database of IoC
                        domain_description = __database__.search_Domain_in_IoC(new_domain)
                        print(f'Asked domain {new_domain}: desc {domain_description}')
                        if domain_description != False: # Dont change this condition. This is the only way it works
                            # If the domain is in the blacklist of IoC. Set an evidence
                            self.set_evidence_domain(new_domain, domain_description, profileid, twid)
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            self.print(traceback.format_exc())
            return True
