# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder. 
#    cp modules/template/malicious_ips_files.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables

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


class MaliciousIPs(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'threat_inteligence'
    description = 'Check if the srcIP and dstIP are in malicious list of IPs.'
    authors = ['StratoTeam']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        self.separator = __database__.getFieldSeparator()

        self.c1 = __database__.subscribe('new_ip')
        self.path_to_malicious_ip_folder = 'modules/ThreatIntelligence/malicious_ips_files/'

        self.progress_bar = ProgressBar(bar_size=10, prefix="\t\t[ThreadIntelligence] Loading malicious IPs to DB: ")

        self.update_manager = UpdateIPManager(self.outputqueue)

        # Update and load files containing malicious IPs.
        self.__update_malicious_file()
        self.__load_malicious_ips()

    def __read_configuration(self, section: str, name: str) -> str:
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
             conf_variable = self.config.get(section, name)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            conf_variable = None
        return conf_variable

    def __update_malicious_file(self) -> None:
        # How often we should update malicious IP list.
        update_period = self.__read_configuration('modules', 'malicious_ips_update_period')
        self.update_manager.update(update_period)

    def __load_malicious_ips(self) -> None:
        self.progress_bar.start_progress_bar()
        malicious_ips_dict = {}

        # First look if a variable "malicious_ip_file_path" in slips.conf is set.
        malicious_ip_file_path = self.__read_configuration('modules', 'malicious_ip_file_path')
        if malicious_ip_file_path is not None:
            # The variable "malicious_ip_file_path" in slips.conf is set.
            self.outputqueue.put('03|logs|File {} containing malicious IPs was loaded.'.format(malicious_ip_file_path))
            try:
                self.__load_malicious_ips_file(malicious_ip_file_path, malicious_ips_dict)
            except FileNotFoundError as e:
                # The file does not exist.
                self.print(e, 1, 0)
                self.print('Error: The PATH to file for loading you malicious IPs '
                           'which you specify in slips.conf is NOT valid.', 1, 0)
        else:
            # The variable "malicious_ip_file_path" in slips.conf is NOT set.
            # Read all files in "modules/ThreatIntelligence/malicious_ips_files/" folder.
            self.outputqueue.put('03|logs|Reading malicious Ips from {}.'.format(self.path_to_malicious_ip_folder))
            if len(os.listdir(self.path_to_malicious_ip_folder)) == 0:
                # No file to read.
                self.print('In "{}" there are no files containing malicious IPs.'.format(self.path_to_malicious_ip_folder), 1, 0)
            else:
                for ip_file in os.listdir(self.path_to_malicious_ip_folder):
                    try:
                        self.__load_malicious_ips_file(self.path_to_malicious_ip_folder + '/' + ip_file, malicious_ips_dict)
                        self.print('\tMalicious IPs from {} file were loaded.', 5, 0)
                    except FileNotFoundError as e:
                        self.print(e, 1, 0)

        # Put all loaded malicious ips to database.
        __database__.add_all_loaded_malicous_ips(malicious_ips_dict)
        self.progress_bar.stop_progress_bar()

    def __load_malicious_ips_file(self, malicious_ips_path: str, malicious_ips_dict: dict) -> None:
        with open(malicious_ips_path) as f:
            for line in f:
                if '#' in line:
                    # '#' is comment line in malicious IP files.
                    continue
                line = line.rstrip()
                comma_index = line.find(',')
                ip_description = '-'
                if comma_index == -1:
                    # No description was found for the IP.
                    ip_address = line
                else:
                    try:
                        ip_description = line[comma_index + 1:]
                    except IndexError:
                        # There is the comma behind the ip, but no description.
                        pass
                    ip_address = line[:comma_index]

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
                        self.print('This ip: {} is not valid. It was found in {}.'.format(ip_address, malicious_ips_path), verbose=1, debug=1)
                        continue

                malicious_ips_dict[str(ip_address)] = ip_description

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
                message = self.c1.get_message(timeout=-1)
                # Check that the message is for you. Probably unnecessary...
                if message['channel'] == 'new_ip':
                    new_ip = message['data']
                    description = __database__.get_loaded_malicious_ip(new_ip)
                    if description is not None:
                        profile_id = 'profile' + self.separator + new_ip
                        __database__.set_profile_as_malicious(profile_id, description)

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
