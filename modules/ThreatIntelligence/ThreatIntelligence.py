# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

# Your imports
import time
import ipaddress
import os
import configparser
from progress_bar import ProgressBar
from modules.ThreatIntelligence.update_ip_manager import UpdateIPManager

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'ThreatIntelligence'
    description = 'Check if the srcIP or dstIP are in a malicious list of IPs.'
    authors = ['Frantisek Strasak']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        self.separator = __database__.getFieldSeparator()
        # This default path is only used in case there is no path in the configuration file
        self.path_to_malicious_ip_folder = 'modules/ThreatIntelligence/malicious_ips_files/'
        # Subscribe to the new_ip channel
        self.c1 = __database__.subscribe('new_ip')
        # Create the update manager. This manager takes care of the re-downloading of the list of IoC when needed.
        self.update_manager = UpdateIPManager(self.outputqueue)
        # Update and load files containing malicious IPs.
        self.__update_remote_malicious_file()
        self.__load_malicious_ips()
        # This dictionary will hold each malicious ip to store in the db
        self. malicious_ips_dict = {}

    def __read_configuration(self, section: str, name: str) -> str:
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
             conf_variable = self.config.get(section, name)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            conf_variable = None
        return conf_variable

    def __update_remote_malicious_file(self) -> None:
        """ 
        Prepare to download a remote file with malicious ips. This file is remotely updated
        """
        # How often we should update malicious IP list.
        update_period = self.__read_configuration('modules', 'malicious_ips_update_period')
        # Run the update manager
        self.update_manager.update(update_period)

    def __load_malicious_ips(self) -> None:
        """ Load the malicious ips from all the files in a folder"""
        

        # First look if a variable "malicious_ip_file_path" in slips.conf is set. If not, we have the default ready
        self.path_to_malicious_ip_folder = self.__read_configuration('modules', 'malicious_ip_file_path')

        # Read all files in "modules/ThreatIntelligence/malicious_ips_files/" folder.
        self.print('Reading malicious IPs from files in foler {}.'.format(self.path_to_malicious_ip_folder), 0, 3)
        if len(os.listdir(self.path_to_malicious_ip_folder)) == 0:
            # No files to read.
            self.print('There are no files in {}.'.format(self.path_to_malicious_ip_folder), 1, 0)
        else:
            for ip_file in os.listdir(self.path_to_malicious_ip_folder):
                try:
                    self.__load_malicious_ips_file(self.path_to_malicious_ip_folder + '/' + ip_file)
                    self.print('\tLoading malicious IPs from file {}.', 5, 0)
                except FileNotFoundError as e:
                    self.print(e, 1, 0)

        # Add all loaded malicious ips to the database
        __database__.add_add_ips_to_ioc(self.malicious_ips_dict)

    def __load_malicious_ips_file(self, malicious_ips_path: str) -> None:
        """ 
        Read a file holding IP addresses and a description
        """
        with open(malicious_ips_path) as malicious_file:
            self.print('Reading the file {} for IoC'.format(malicious_ips_path), 3, 0)
            for line in malicious_file:
                if '#' in line:
                    # '#' is a comment line, ignore
                    continue
                ip = line.rstrip().split(',')[0]
                try:
                    ip_description = line.rstrip().split(',')[1]
                except IndexError:
                    ip_description = ''
                self.print('\tRead IP {}: {}'.format(ip, ip_description), 6, 0)

                # Check if ip is valid.
                try:
                    ip_address = ipaddress.IPv4Address(ip_address)
                    # Is ipv4?
                except ipaddress.AddressValueError:
                    # Is it ipv6?
                    try:
                        ip_address = ipaddress.IPv6Address(ip_address)
                    except ipaddress.AddressValueError:
                        # It does not look as IP address.
                        self.print('The IP address {} is not valid. It was found in {}.'.format(ip_address, malicious_ips_path), 1, 1)
                        continue

                self.malicious_ips_dict[str(ip_address)] = ip_description

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
                message = self.c1.get_message(timeout=None)
                # Check that the message is for you. Probably unnecessary...
                if message['channel'] == 'new_ip':
                    new_ip = message['data']
                    # Get what we know about this IP so far
                    description = __database__.search_IP_in_IoC(new_ip)
                    # Mark this IP as being malicious in the DB
                    ip_data = {}
                    ip_data['Malicious'] = 'True'
                    ip_data['description'] = ip_description
                    __database__.setInfoForIPs(ip, ipdata):
                    """
                    # Maybe store some evidence????
                    profile_id = 
                    # Type of evidence
                    type_evidence = 'MaliciousIP'
                    # Key
                    key = ???????? ':' + type_evidence
                    # Threat level
                    threat_level = 100
                    # Compute the confidence
                    confidence = 1
                    description = 'Malicious IP {} found: {}.'.format(ip, ip_description)
                    self.print(description, 3, 0)
                    # Store the evidence in the DB
                    __database__.setEvidenceForTW(profileid, twid, key, threat_level, confidence, description)
                    """

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
