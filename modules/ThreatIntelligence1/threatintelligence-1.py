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
import hashlib
import validators
import ast


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
        self.__read_configuration()

    def __read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
            # Read the path to where to store and read the malicious files
            self.path_to_local_threat_intelligence_data = self.config.get('threatintelligence', 'download_path_for_local_threat_intelligence')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.path_to_local_threat_intelligence_data = 'modules/ThreatIntelligence1/local_data_files/'

    def set_evidence_ip(self, ip, ip_description='', profileid='', twid='', ip_state='ip'):
        '''
        Set an evidence for malicious IP met in the timewindow
        '''

        type_detection = ip_state
        detection_info = ip
        type_evidence = 'ThreatIntelligenceBlacklistIP'
        threat_level = 80
        confidence = 1
        description = ip_description

        __database__.setEvidence(type_detection, detection_info, type_evidence,
                                 threat_level, confidence, description, profileid=profileid, twid=twid)

    def set_evidence_domain(self, domain, domain_description='', profileid='', twid=''):
        '''
        Set an evidence for malicious domain met in the timewindow
        '''

        type_detection = 'dstdomain'
        detection_info = domain
        type_evidence = 'ThreatIntelligenceBlacklistDomain'
        threat_level = 50
        confidence = 1
        description = domain_description

        __database__.setEvidence(type_detection,detection_info, type_evidence,
                                 threat_level, confidence, description, profileid=profileid, twid=twid)

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

    def __get_hash_from_file(self, filename):
        """
        Compute the hash of a local file
        """
        try:
            # The size of each read from the file
            BLOCK_SIZE = 65536

            # Create the hash object, can use something other
            # than `.sha256()` if you wish
            file_hash = hashlib.sha256()
            # Open the file to read it's bytes
            with open(filename, 'rb') as f:
                # Read from the file. Take in the amount declared above
                fb = f.read(BLOCK_SIZE)
                # While there is still data being read from the file
                while len(fb) > 0:
                    # Update the hash
                    file_hash.update(fb)
                    # Read the next block from the file
                    fb = f.read(BLOCK_SIZE)

            return file_hash.hexdigest()
        except Exception as inst:
            self.print('Problem on __get_hash_from_file()', 0, 0)
            self.print(str(type(inst)), 0, 0)
            self.print(str(inst.args), 0, 0)
            self.print(str(inst), 0, 0)

    def __load_malicious_datafile(self, malicious_data_path: str, data_file_name) -> None:
        """
        Read all the files holding IP addresses and a description and put the
        info in a large dict.
        This also helps in having unique ioc accross files
        Returns nothing, but the dictionary should be filled
        """
        try:
            malicious_ips_dict = {}
            malicious_domains_dict = {}
            with open(malicious_data_path) as malicious_file:

                self.print('Reading next lines in the file {} for IoC'.format(malicious_data_path), 4, 0)

                # Remove comments and find the description column if possible
                description_column = None
                while True:
                    line = malicious_file.readline()
                    # break while statement if it is not a comment line
                    # i.e. does not startwith #
                    if line.startswith('#"type"'):
                        # looks like the colums names, search where is the
                        # description column
                        for name_column in line.split(','):
                            if name_column.lower().startswith('desc'):
                                description_column = line.split(',').index(name_column)
                    if not line.startswith('#') and not line.startswith('"type"'):
                        break

                #
                # Find in which column is the imporant info in this
                # TI file (domain or ip)
                #

                # Store the current position of the TI file
                current_file_position = malicious_file.tell()

                # temp_line = malicious_file.readline()
                data = line.replace("\n","").replace("\"","").split(",")
                amount_of_columns = len(line.split(","))
                if description_column is None:
                    description_column = amount_of_columns - 1
                # Search the first column that is an IPv4, IPv6 or domain
                for column in range(amount_of_columns):
                    # Check if ip is valid.
                    try:
                        ip_address = ipaddress.IPv4Address(data[column].strip())
                        # Is IPv4! let go
                        data_column = column
                        self.print(f'The data is on column {column} and is ipv4: {ip_address}', 0, 6)
                        break
                    except ipaddress.AddressValueError:
                        # Is it ipv6?
                        try:
                            ip_address = ipaddress.IPv6Address(data[column].strip())
                            # Is IPv6! let go
                            data_column = column
                            self.print(f'The data is on column {column} and is ipv6: {ip_address}', 0, 6)
                            break
                        except ipaddress.AddressValueError:
                            # It does not look as IP address.
                            # So it should be a domain
                            if validators.domain(data[column].strip()):
                                data_column = column
                                self.print(f'The data is on column {column} and is domain: {data[column]}', 0, 6)
                                break
                            else:
                                # Some string that is not a domain
                                data_column = None
                                pass
                if data_column is None:
                    self.print(f'Error while reading the TI file {malicious_file}. Could not find a column with an IP or domain', 1, 1)
                    return False

                # Now that we read the first line, go back so we
                # can process it
                malicious_file.seek(current_file_position)

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
                    data = line.replace("\n","").replace("\"","").split(",")[data_column].strip()

                    description = line.replace("\n","").replace("\"","").split(",")[description_column].strip()
                    self.print('\tRead Data {}: {}'.format(data, description), 6, 0)

                    # Check if ip is valid.
                    try:
                        ip_address = ipaddress.IPv4Address(data)
                        # Is IPv4!
                        # Store the ip in our local dict
                        malicious_ips_dict[str(ip_address)] = json.dumps({'description': description, 'source':data_file_name})
                    except ipaddress.AddressValueError:
                        # Is it ipv6?
                        try:
                            ip_address = ipaddress.IPv6Address(data)
                            # Is IPv6!
                            # Store the ip in our local dict
                            malicious_ips_dict[str(ip_address)] = json.dumps({'description': description, 'source':data_file_name})
                        except ipaddress.AddressValueError:
                            # It does not look as IP address.
                            # So it should be a domain
                            if validators.domain(data):
                                domain = data
                                # Store the ip in our local dict
                                malicious_domains_dict[str(domain)] = json.dumps({'description': description, 'source':data_file_name})
                            else:
                                self.print('The data {} is not valid. It was found in {}.'.format(data, malicious_data_path), 1, 1)
                                continue
            # Add all loaded malicious ips to the database
            __database__.add_ips_to_IoC(malicious_ips_dict)
            # Add all loaded malicious domains to the database
            __database__.add_domains_to_IoC(malicious_domains_dict)
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the __load_malicious_datafile()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            print(traceback.format_exc())
            return True

    def __delete_old_source_IPs(self, file):
        """
        When file is updated, delete the old IPs in the cache
        """
        all_data = __database__.get_IPs_in_IoC()
        old_data = []
        for ip_data in all_data.items():
            ip = ip_data[0]
            data = json.loads(ip_data[1])
            if data["source"] == file:
                old_data.append(ip)
        if old_data:
            __database__.delete_ips_from_IoC_ips(old_data)

    def __delete_old_source_Domains(self, file):
        """
        When file is updated, delete the old Domains in the cache
        """
        all_data = __database__.get_Domains_in_IoC()
        old_data = []
        for domain_data in all_data.items():
            domain = domain_data[0]
            data = json.loads(domain_data[1])
            if data["source"] == file:
                old_data.append(domain)
        if old_data:
            __database__.delete_domains_from_IoC_domains(old_data)

    def __delete_old_source_data_from_database(self, data_file):
        '''
        Delete old IPs of the source from the database.
        :param data_file: the name of source to delete old IPs from.
        '''
        # Only read the files with .txt or .csv
        self.__delete_old_source_IPs(data_file)
        self.__delete_old_source_Domains(data_file)

    def load_malicious_local_files(self, path_to_files: str) -> bool:
        try:
            local_ti_files = os.listdir(path_to_files)
            for localfile in local_ti_files:
                self.print(f'Loading local TI file {localfile}', 3, 0)
                # Get what files are stored in cache db and their E-TAG to comapre with current files
                data = __database__.get_malicious_file_info(localfile)
                try:
                    old_hash = data['e-tag']
                except TypeError:
                    old_hash = ''
                # In the case of the local file, we dont store the e-tag but
                # the hash
                new_hash = self.__get_hash_from_file(path_to_files + '/' + localfile)
                if old_hash == new_hash:
                    # The 2 hashes are identical. File is up to date.
                    self.print(f'File {localfile} is up to date.', 3, 0)
                    return True
                elif new_hash and old_hash != new_hash:
                    # Our malicious file was changed. Load the new one
                    self.print(f'Updating the local TI file {localfile}', 3, 0)
                    if old_hash:
                        # File is updated and was in database.
                        # Delete previous data of this file.
                        self.__delete_old_source_data_from_database(localfile)
                    # Load updated data to the database
                    self.__load_malicious_datafile(path_to_files + '/' + localfile, localfile)

                    # Store the new etag and time of file in the database
                    malicious_file_info = {}
                    malicious_file_info['e-tag'] = new_hash
                    malicious_file_info['time'] = ''
                    __database__.set_malicious_file_info(localfile, malicious_file_info)
                    return True
                elif not new_hash:
                    # Something failed. Do not download
                    self.print(f'Some error ocurred on calculating file hash. Not loading  the file {localfile}', 0, 1)
                    return False


        except Exception as inst:
            self.print('Problem on __load_malicious_local_files()', 0, 0)
            self.print(str(type(inst)), 0, 0)
            self.print(str(inst.args), 0, 0)
            self.print(str(inst), 0, 0)

    def set_maliciousDomain_to_MaliciousDomains(self, domain, profileid, twid):
        '''
        Set malicious domain to DB 'MaliciousDomains' with a profileid and twid where domain was met
        '''
        # get all profiles and twis where this IP was met
        domain_profiled_twid = __database__.get_malicious_domain(domain)
        try:
            profile_tws = domain_profiled_twid[profileid]               # a dictionary {profile:set(tw1, tw2)}
            profile_tws = ast.literal_eval(profile_tws)                 # set(tw1, tw2)
            profile_tws.add(twid)
            domain_profiled_twid[profileid] = str(profile_tws)
        except KeyError:
            domain_profiled_twid[profileid] = str({twid})               # add key-pair to the dict if does not exist
        data = json.dumps(domain_profiled_twid)
        __database__.set_malicious_domain(domain, data)

    def set_maliciousDomain_to_DomainInfo(self, domain, domain_description):
        '''
        Set malicious domain in DomainsInfo.
        '''
        domain_data = {}
        # Maybe we should change the key to 'status' or something like that.
        domain_data['threatintelligence'] = domain_description
        __database__.setInfoForDomains(domain, domain_data)

    def set_maliciousIP_to_MaliousIPs(self, ip, profileid, twid):
        '''
        Set malicious IP in 'MaliciousIPs' key with a profileid and twid.
        '''

        # Retrieve all profiles and twis, where this malicios IP was met.
        ip_profileid_twid= __database__.get_malicious_ip(ip)
        try:
            profile_tws = ip_profileid_twid[profileid]             # a dictionary {profile:set(tw1, tw2)}
            profile_tws = ast.literal_eval(profile_tws)            # set(tw1, tw2)
            profile_tws.add(twid)
            ip_profileid_twid[profileid] = str(profile_tws)
        except KeyError:
            ip_profileid_twid[profileid] = str({twid})                   # add key-pair to the dict if does not exist
        data = json.dumps(ip_profileid_twid)
        __database__.set_malicious_ip(ip, data)

    def set_maliciousIP_to_IPInfo(self, ip, ip_description):
        '''
        Set malicious IP in IPsInfo.
        '''

        ip_data = {}
        # Maybe we should change the key to 'status' or something like that.
        ip_data['threatintelligence'] = ip_description
        __database__.setInfoForIPs(ip, ip_data)  # Set in the IP info that IP is blacklisted

    def is_outgoing_icmp_packet(self, protocol: str, ip_state: str) -> bool:
        """
        Check whether this IP is our computer sending an ICMP unreacheable packet to
        a blacklisted IP or not.
        """

        if protocol == 'ICMP' and ip_state == 'dstip':
            return True
        return False


    def run(self):
        try:
            # Load the local Threat Intelligence files that are stored in the local folder
            # The remote files are being loaded by the UpdateManager
            if not self.load_malicious_local_files(self.path_to_local_threat_intelligence_data):
                self.print(f'Could not load the local file of TI data {self.path_to_local_threat_intelligence_data}')
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            self.print(traceback.format_exc())
            return True

        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time
                # (see at logsProcess.py), we will stop slips automatically.
                # The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                # Check that the message is for you.
                # The channel now can receive an IP address or a domain name
                elif message['channel'] == 'give_threat_intelligence' and type(message['data']) is not int:
                    # Data is sent in the channel as a json dict so we need to deserialize it first
                    data = json.loads(message['data'])
                    # Extract data from dict
                    profileid = data.get('profileid')
                    twid = data.get('twid')
                    ip_state = data.get('ip_state') # ip state is either 'srcip' or 'dstip'
                    protocol = data.get('proto')
                    # Data should contain either an ip or a domain so one of them will be None
                    ip = data.get('ip')
                    domain = data.get('host') or data.get('server_name') or data.get('query')
                    # Check if the new data is an ip or a domain
                    if ip:
                        # Search for this IP in our database of IoC
                        ip_description = __database__.search_IP_in_IoC(ip)
                        # Block only if the traffic isn't outgoing ICMP port unreachable packet
                        if (ip_description != False
                                and self.is_outgoing_icmp_packet(protocol,ip_state)==False): # Dont change this condition. This is the only way it works
                            # If the IP is in the blacklist of IoC. Add it as Malicious
                            ip_description = json.loads(ip_description)
                            ip_source = ip_description['source'] # this is a .csv file
                            self.set_evidence_ip(ip, ip_source, profileid, twid, ip_state)
                            # set malicious IP in IPInfo
                            self.set_maliciousIP_to_IPInfo(ip,ip_description)
                            # set malicious IP in MaliciousIPs
                            self.set_maliciousIP_to_MaliousIPs(ip,profileid,twid)

                    if domain:
                        # Search for this domain in our database of IoC
                        domain_description = __database__.search_Domain_in_IoC(domain)
                        if domain_description != False: # Dont change this condition. This is the only way it works
                            # If the domain is in the blacklist of IoC. Set an evidence
                            self.set_evidence_domain(domain, domain_description, profileid, twid)
                            # set malicious domain in DomainInfo
                            self.set_maliciousDomain_to_DomainInfo(domain, domain_description)
                            # set malicious domain in MaliciousDomains
                            self.set_maliciousDomain_to_MaliciousDomains(domain, profileid, twid)
            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                self.print('Problem on the run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                self.print(traceback.format_exc())
                return True
