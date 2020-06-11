# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import time
import ipaddress
import os
import configparser
import json
import ast
from modules.ThreatIntelligence1.update_ip_manager import UpdateIPManager

import traceback
# To open the file in slices
from itertools import islice


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'threatintelligence1'
    description = 'Check if the srcIP or dstIP are in a malicious list of IPs.'
    authors = ['Frantisek Strasak, Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        # This dictionary will hold each malicious ip to store in the db
        self.malicious_ips_dict = {}
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        self.separator = __database__.getFieldSeparator()
        # This default path is only used in case there is no path in the configuration file
        self.path_to_malicious_ip_folder = 'modules/ThreatIntelligence1/malicious_ips_files/'
        # Subscribe to the new_ip channel
        __database__.start(self.config)
        self.c1 = __database__.subscribe('give_threat_intelligence')

        # Create the update manager. This manager takes care of the re-downloading of the list of IoC when needed.
        self.update_manager = UpdateIPManager(self.outputqueue, config)

        # First step is to Update the remote file containing malicious IPs.
        self.__update_remote_malicious_file()

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
            # There is a conf, but there is no option, or no section or no configuration file specified
            conf_variable = None
        return conf_variable

    def __update_remote_malicious_file(self) -> None:
        """
        Prepare to download a remote file with malicious ips. This file is remotely updated
        """
        # Run the update manager
        self.update_manager.update()

    def __load_malicious_ips(self) -> None:
        """
        Load the names of malicious ips files in a folder and ask to read them into a dictionary.
        Then load the dictionary into our DB

        This is not going to the internet. Only from files to DB
        """
        # First look if a variable "malicious_ip_file_path" in slips.conf is set. If not, we have the default ready
        self.path_to_malicious_ip_folder = self.__read_configuration('threatintelligence', 'malicious_ip_file_path')

        # Read all files in "modules/ThreatIntelligence/malicious_ips_files/" folder.
        self.print('Loading malicious IPs from files in folder {}.'.format(self.path_to_malicious_ip_folder), 0, 3)
        if len(os.listdir(self.path_to_malicious_ip_folder)) == 0:
            # No files to read.
            self.print('There are no files in {}.'.format(self.path_to_malicious_ip_folder), 1, 0)
        else:
            # For each file in the folder with malicious files
            for ip_file in os.listdir(self.path_to_malicious_ip_folder):
                try:
                    # Only read the files with .txt or .csv
                    if '.txt' in ip_file[-4:] or '.csv' in ip_file[-4:]:
                        self.print('\tLoading malicious IPs from file {}.'.format(ip_file), 3, 0)
                        self.__load_malicious_ips_file(self.path_to_malicious_ip_folder + '/' + ip_file)
                        self.print('Finished loading the IPs from {}'.format(ip_file), 3, 0)
                except FileNotFoundError as e:
                    self.print(e, 1, 0)

        # Add all loaded malicious ips to the database
        __database__.add_ips_to_IoC(self.malicious_ips_dict)

    def __load_malicious_ips_file(self, malicious_ips_path: str) -> None:
        """
        Read all the files holding IP addresses and a description and put the
        info in a large dict.
        This also helps in having unique ioc accross files
        Returns nothing, but the dictionary should be filled
        """
        try:

            # Internal function to load the file in slices
            # The slices are needed because for some reason python 3.7.3 in macos gives error when we try to fill a dict that is too big.
            # def next_n_lines(file_opened, N):
            #   return [x.strip() for x in islice(file_opened, N)]

            # Max num of ips per batch 7000
            lines_read = 0
            with open(malicious_ips_path) as malicious_file:
                # lines = next_n_lines(malicious_file, 7000)

                self.print('Reading next lines in the file {} for IoC'.format(malicious_ips_path), 3, 0)
                for line in malicious_file:
                    if '#' in line:
                        # '#' is a comment line, ignore
                        continue
                    # Separate the lines like CSV
                    # In the new format the ip is in the second position. And surronded by "
                    ip_address = line.replace("\n","").replace("\"","").split(",")[1].strip()
                    try:
                        # In the new format the description is position 4
                        ip_description = line.replace("\n","").replace("\"","").split(",")[3].strip()
                    except IndexError:
                        ip_description = ''
                    self.print('\tRead IP {}: {}'.format(ip_address, ip_description), 6, 0)

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

                    # Store the ip in our local dict
                    self.malicious_ips_dict[str(ip_address)] = ip_description
                    lines_read += 1
        except Exception as inst:
            self.print('Problem on the __load_malicious_ips_file()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True

    def add_maliciousIP(self, ip = '', profileid = '', twid='' ):
        '''
        Add malicious IP to DB 'MaliciousIPs' with a profileid and twid where it was met
        Returns nothing
        '''

        ip_location = __database__.get_malicious_ip(ip)
        # if profileid or twid is None, do not put any value in a dictionary
        if profileid != 'None':
            try:
                profile_tws = ip_location[profileid]
                profile_tws = ast.literal_eval(profile_tws)
                profile_tws.add(twid)
                ip_location[profileid] = str(profile_tws)
            except KeyError:
                ip_location[profileid] = str({twid})
        elif not ip_location:
            ip_location = {}
        data = json.dumps(ip_location)
        __database__.add_malicious_ip(ip, data)

    def set_evidence(self, ip, ip_description = '', profileid = '', twid = '' ):
        '''
        Set an evidence for malicious IP met in the timewindow
        If profileid is None, do not set an Evidence
        Returns nothing
        '''
        type_evidence = 'ThreatIntelligenceBlacklist'
        key = 'dstip' + ':' + ip + ':' + type_evidence
        threat_level = 50
        confidence = 1
        description = 'Threat Intelligence. ' + ip_description
        if not twid:
            twid=''
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
            # First load the malicious ips from the file to the DB
            self.__load_malicious_ips()
            while True:
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    return True
                # Check that the message is for you.
                elif message['channel'] == 'give_threat_intelligence' and type(message['data']) is not int:
                    data = message['data']
                    data = data.split('-')
                    new_ip = data[0]
                    profileid = data[1]
                    twid = data[2]
                    # Search for this IP in our database of IoC
                    ip_description = __database__.search_IP_in_IoC(new_ip)

                    if ip_description != False:
                        # If the IP is in the blacklist of IoC. Add it as Malicious
                        ip_data = {}
                        # Maybe we should change the key to 'status' or something like that.
                        ip_data['Malicious'] = ip_description
                        __database__.setInfoForIPs(new_ip, ip_data)
                        self.add_maliciousIP(new_ip, profileid, twid)
                        self.set_evidence(new_ip, ip_description, profileid, twid)
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            self.print(traceback.format_exc())
            return True
