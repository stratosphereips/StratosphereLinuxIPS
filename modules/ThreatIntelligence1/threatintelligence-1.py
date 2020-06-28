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
import ast
from modules.ThreatIntelligence1.update_file_manager import UpdateFileManager
import traceback
import validators
import traceback


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
        # This dictionary will hold each malicious domain to store in the db
        self.malicious_domains_dict = {}
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        self.separator = __database__.getFieldSeparator()
        # This default path is only used in case there is no path in the configuration file
        self.path_to_malicious_data_folder = 'modules/ThreatIntelligence1/malicious_data_files/'
        # Subscribe to the channel
        __database__.start(self.config)
        self.c1 = __database__.subscribe('give_threat_intelligence')

        # Create the update manager. This manager takes care of the re-downloading of the list of IoC when needed.
        self.update_manager = UpdateFileManager(self.outputqueue, config)

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
            # There is a conf, but there is no option,
            # or no section or no configuration file specified
            conf_variable = None
        return conf_variable

    def __update_remote_malicious_file(self) -> None:
        """
        Prepare to download a remote file with malicious ips. This file is remotely updated
        """
        # Run the update manager
        self.update_manager.update()

    def __load_malicious_datafiles(self) -> None:
        """
        Load the content of malicious datafiles in a folder and ask to read
        them into a dictionary.
        Then load the dictionary into our DB

        This is not going to the internet. Only from files to DB
        """
        # First look if a variable "malicious_data_file_path" in slips.conf is set. If not, we have the default ready
        self.path_to_malicious_data_folder = self.__read_configuration('threatintelligence', 'malicious_data_file_path')

        # Read all files in "modules/ThreatIntelligence/malicious_data_files/" folder.
        self.print('Loading malicious data from files in folder {}.'.format(self.path_to_malicious_data_folder), 0, 3)
        if len(os.listdir(self.path_to_malicious_data_folder)) == 0:
            # No files to read.
            self.print('There are no files in {}.'.format(self.path_to_malicious_data_folder), 1, 0)
        else:
            # For each file in the folder with malicious files
            for data_file in os.listdir(self.path_to_malicious_data_folder):
                try:
                    # Only read the files with .txt or .csv
                    if '.txt' in data_file[-4:] or '.csv' in data_file[-4:]:
                        self.print('\tLoading malicious data from file {}.'.format(data_file), 3, 0)
                        self.__load_malicious_datafile(self.path_to_malicious_data_folder + '/' + data_file)
                        self.print('Finished loading the data from {}'.format(data_file), 3, 0)
                except FileNotFoundError as e:
                    self.print(e, 1, 0)

        # Add all loaded malicious ips to the database
        __database__.add_ips_to_IoC(self.malicious_ips_dict)
        # Add all loaded malicious domains to the database
        __database__.add_domains_to_IoC(self.malicious_domains_dict)

    def __load_malicious_datafile(self, malicious_data_path: str) -> None:
        """
        Read all the files holding IP addresses and a description and put the
        info in a large dict.
        This also helps in having unique ioc accross files
        Returns nothing, but the dictionary should be filled
        """
        try:
            lines_read = 0
            with open(malicious_data_path) as malicious_file:

                self.print('Reading next lines in the file {} for IoC'.format(malicious_data_path), 3, 0)

                # Remove comments
                while True:
                    line = malicious_file.readline()
                    # break while statement if it is not a comment line
                    # i.e. does not startwith #
                    if not line.startswith('#'):
                        break

                for line in malicious_file:
                    # The format of the file should be
                    # "0", "103.15.53.231","90", "Karel from our village. He is bad guy."
                    # So the second column will be used as important data with
                    # an IP or domain
                    # In the case of domains can be
                    # domain,www.netspy.net,NetSpy

                    # Separate the lines like CSV
                    # In the new format the ip is in the second position.
                    # And surronded by "
                    data = line.replace("\n","").replace("\"","").split(",")[1].strip()

                    try:
                        # In the new format the description is position 4
                        description = line.replace("\n","").replace("\"","").split(",")[3].strip()
                    except IndexError:
                        description = ''
                    self.print('\tRead Data {}: {}'.format(data, description), 6, 0)

                    # Check if ip is valid.
                    try:
                        ip_address = ipaddress.IPv4Address(data)
                        # Is IPv4!
                        # Store the ip in our local dict
                        self.malicious_ips_dict[str(ip_address)] = description
                    except ipaddress.AddressValueError:
                        # Is it ipv6?
                        try:
                            ip_address = ipaddress.IPv6Address(data)
                            # Is IPv6!
                            # Store the ip in our local dict
                            self.malicious_ips_dict[str(ip_address)] = description
                        except ipaddress.AddressValueError:
                            # It does not look as IP address.
                            # So it should be a domain
                            if validators.domain(data):
                                domain = data
                                # Store the ip in our local dict
                                self.malicious_domains_dict[str(domain)] = description
                            else:
                                self.print('The data {} is not valid. It was found in {}.'.format(data, malicious_data_path), 1, 1)
                                continue

                    lines_read += 1
        except Exception as inst:
            self.print('Problem on the __load_malicious_datafile()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            print(traceback.format_exc())
            return True

    def add_maliciousIP(self, ip='', profileid='', twid=''):
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

    def add_maliciousDomain(self, domain='', profileid='', twid=''):
        '''
        Add malicious domain to DB 'MaliciousDomainss' with a profileid and twid where domain was met
        Returns nothing
        '''
        domain_location = __database__.get_malicious_domain(domain)
        # if profileid or twid is None, do not put any value in a dictionary
        if profileid != 'None':
            try:
                profile_tws = domain_location[profileid]
                profile_tws = ast.literal_eval(profile_tws)
                profile_tws.add(twid)
                domain_location[profileid] = str(profile_tws)
            except KeyError:
                domain_location[profileid] = str({twid})
        elif not domain_location:
            domain_location = {}
        data = json.dumps(domain_location)
        __database__.add_malicious_domain(domain, data)

    def set_evidence_ip(self, ip, ip_description='', profileid='', twid=''):
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
            twid = ''
        __database__.setEvidence(key, threat_level, confidence, description, profileid=profileid, twid=twid)

    def set_evidence_domain(self, domain, domain_description='', profileid='', twid=''):
        '''
        Set an evidence for malicious domain met in the timewindow
        If profileid is None, do not set an Evidence
        Returns nothing
        '''
        type_evidence = 'ThreatIntelligenceBlacklist'
        key = 'dstdomain' + ':' + domain + ':' + type_evidence
        threat_level = 50
        confidence = 1
        description = 'Threat Intelligence. ' + domain_description
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
            # First load the malicious data from the files to the DB
            self.__load_malicious_datafiles()
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
                    data = data.split('-')
                    new_data = data[0]
                    profileid = data[1]
                    twid = data[2]
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
                            ip_data = {}
                            # Maybe we should change the key to 'status' or something like that.
                            ip_data['Malicious'] = ip_description
                            __database__.setInfoForIPs(new_ip, ip_data)
                            self.add_maliciousIP(new_ip, profileid, twid)
                            self.set_evidence_ip(new_ip, ip_description, profileid, twid)
                    except ValueError:
                        # This is not an IP, then should be a domain
                        new_domain = new_data
                        # Search for this domain in our database of IoC
                        domain_description = __database__.search_Domain_in_IoC(new_domain)
                        if domain_description != False: # Dont change this condition. This is the only way it works
                            # If the domain is in the blacklist of IoC. Add it as Malicious
                            domain_data = {}
                            # Maybe we should change the key to 'status' or something like that.
                            domain_data['Malicious'] = domain_description
                            __database__.setInfoForDomains(new_domain, domain_data)
                            self.add_maliciousDomain(new_domain, profileid, twid)
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
