# Must imports
from slips_files.common.abstracts import Module
from slips_files.common.slips_utils import utils
import multiprocessing
from slips_files.core.database import __database__
import platform
import sys

# Your imports
import ipaddress
import os
import configparser
import json
import traceback
import validators
import ast


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'threatintelligence1'
    description = 'Check if the srcIP or dstIP are in a malicious list of IPs'
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
        self.timeout = 0.0000001
        self.__read_configuration()

    def __read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
            # Read the path to where to store and read the malicious files
            self.path_to_local_threat_intelligence_data = self.config.get('threatintelligence',
                                                                          'download_path_for_local_threat_intelligence')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.path_to_local_threat_intelligence_data = 'modules/ThreatIntelligence1/local_data_files/'

    def set_evidence_malicious_ip(self, ip, uid, timestamp, ip_info: dict, profileid='', twid='', ip_state=''):
        '''
        Set an evidence for a malicious IP met in the timewindow
        :param ip: the ip source file
        :param uid: Zeek uid of the flow that generated the evidence
        :param timestamp: Exact time when the evidence happened
        :param ip_info: is all the info we have about that IP in the db source, confidence, description, etc.
        :param profileid: profile where the alert was generated. It includes the src ip
        :param twid: name of the timewindow when it happened.
        :param ip_state: If the IP was a srcip or dstip
        '''

        type_detection = ip_state
        detection_info = ip
        type_evidence = 'ThreatIntelligenceBlacklistIP'

        threat_level = ip_info.get('threat_level', 'medium')

        confidence = 1
        category = 'Anomaly.Traffic'
        dns_resolution = __database__.get_dns_resolution(ip)
        dns_resolution = f' ({dns_resolution[0:3]}), ' if dns_resolution else ''

        if 'src' in ip_state:
            direction = 'from'
        elif 'dst' in ip_state:
            direction = 'to'

        description = f'connection {direction} blacklisted IP {ip}{dns_resolution}.' \
                      f' Source: {ip_info["source"]}. Description: {ip_info["description"]}'

        tags_temp = ip_info.get('tags',False)
        if tags_temp:
            # We need tags_temp so we avoid doing a replace on a bool.
            tags = tags_temp.replace("[",'').replace(']','').replace("'",'')
        else:
            tags = ''
        if tags:
            description += f' tags={tags}'
            source_target_tag = tags.capitalize()
        else:
            source_target_tag = "BlacklistedIP"

        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag,
                                 profileid=profileid, twid=twid, uid=uid)

        # mark this ip as malicious in our database
        ip_info = {'threatintelligence': ip_info}
        __database__.setInfoForIPs(ip, ip_info)

        # add this ip to our MaliciousIPs hash in the database
        __database__.set_malicious_ip(ip, profileid, twid)

    def set_evidence_domain(self, domain, uid, timestamp, domain_info: dict, is_subdomain, profileid='', twid=''):
        '''
        Set an evidence for malicious domain met in the timewindow
        :param source_file: is the domain source file
        :param domain_info: is all the info we have about this domain in the db source, confidence , description etc...
        '''

        type_detection = 'dstdomain'
        detection_info = domain
        category = 'Anomaly.Traffic'
        type_evidence = 'ThreatIntelligenceBlacklistDomain'
        # in case of finding a subdomain in our blacklists
        # print that in the description of the alert and change the confidence accordingly
        # in case of a domain, confidence=1
        confidence = 1
        if is_subdomain:
            confidence = 0.7

        # when we comment ti_files and run slips, we get the error of not being able to get feed threat_level
        threat_level = domain_info.get('threat_level', 'high')

        tags = domain_info.get('tags', False).replace("[",'').replace(']','').replace("'",'')
        if tags:
            source_target_tag = tags.capitalize()
        else:
            source_target_tag = "BlacklistedDomain"


        description = f'connection to a blacklisted domain {domain}. ' \
                      f'Found in feed {domain_info["source"]}, with tags {tags}. ' \
                      f'Confidence {confidence}.'
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description, timestamp,
                                 category, source_target_tag=source_target_tag,
                                 profileid=profileid, twid=twid, uid=uid)

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

    def parse_ti_file(self, ti_file_path: str) -> bool:
        """
        Read all the files holding IP addresses and a description and store in the db.
        This also helps in having unique ioc across files
        Returns nothing, but the dictionary should be filled
        :param ti_file_path: full path_to local threat intel file
        """
        try:
            data_file_name = ti_file_path.split('/')[-1]
            malicious_ips_dict = {}
            malicious_domains_dict = {}
            # used for debugging
            line_number = 0
            with open(ti_file_path) as local_ti_file:

                self.print('Reading local file {}'.format(ti_file_path), 2, 0)

                # skip comments
                while True:
                    line_number+=1
                    line = local_ti_file.readline()
                    if not line.startswith('#'):
                        break

                for line in local_ti_file:
                    line_number+=1
                    # The format of the file should be
                    # "103.15.53.231","critical", "Karel from our village. He is bad guy."
                    data = line.replace("\n","").replace("\"","").split(",")

                    # the column order is hardcoded because it's owr own ti file and we know the format,
                    # we shouldn't be trying to find it
                    ioc, threat_level, description,  = data[0], data [1].lower(), data[2]

                    # validate the threat level taken from the user
                    if threat_level not in ('info', 'low', 'medium', 'high', 'critical'):
                        # default value
                        threat_level = 'medium'

                    # is the IoC an IPv4, IPv6 or domain?
                    try:
                        ip_address = ipaddress.IPv4Address(ioc.strip())
                        self.print(f'The data in line {line_number} is valid and is ipv4: {ip_address}', 2,0)
                        # Store the ip in our local dict
                        malicious_ips_dict[str(ip_address)] = json.dumps({'description': description,
                                                                          'source': data_file_name,
                                                                          'threat_level': threat_level})
                    except ipaddress.AddressValueError:
                        # Is it ipv6?
                        try:
                            ip_address = ipaddress.IPv6Address(ioc.strip())
                            self.print(f'The data in line {line_number} is valid and is ipv6: {ioc}', 2,0)
                            malicious_ips_dict[str(ip_address)] = json.dumps({'description': description,
                                                                              'source': data_file_name,
                                                                              'threat_level': threat_level})
                        except ipaddress.AddressValueError:
                            # It does not look as IP address.
                            # So it should be a domain
                            if validators.domain(ioc.strip()):
                                self.print(f'The data in line {line_number} is valid and is a domain: {ioc}', 2,0)
                                malicious_domains_dict[ioc] = json.dumps({'description': description,
                                                                          'source': data_file_name,
                                                                          'threat_level': threat_level})
                            else:
                                # invalid ioc, skip it
                                self.print(f'Error while reading the TI file {local_ti_file}.'
                                           f' Line {line_number} has invalid data: {ioc}', 0, 1)

            # Add all loaded malicious ips to the database
            __database__.add_ips_to_IoC(malicious_ips_dict)
            # Add all loaded malicious domains to the database
            __database__.add_domains_to_IoC(malicious_domains_dict)
            return True
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on parse_ti_file() line {exception_line}', 0, 1)
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

    def parse_ja3_file(self, path):
        """
        Reads the file holding JA3 hashes and store in the db.
        Returns nothing, but the dictionary should be filled
        :param path: full path_to local threat intel file
        """
        try:
            data_file_name = path.split('/')[-1]
            ja3_dict = {}
            # used for debugging
            line_number = 0

            with open(path) as local_ja3_file:
                self.print('Reading local file {}'.format(path), 2, 0)

                # skip comments
                while True:
                    line_number+=1
                    line = local_ja3_file.readline()
                    if not line.startswith('#'):
                        break

                for line in local_ja3_file:
                    line_number+=1
                    # The format of the file should be
                    # "JA3 hash", "Threat level", "Description"
                    data = line.replace("\n","").replace("\"","").split(",")

                    # the column order is hardcoded because it's owr own ti file and we know the format,
                    # we shouldn't be trying to find it
                    ja3, threat_level, description = data[0], data [1].lower(), data[2]

                    # validate the threat level taken from the user
                    if threat_level not in ('info', 'low', 'medium', 'high', 'critical'):
                        # default value
                        threat_level = 'medium'

                    # validate the ja3 hash taken from the user
                    if not validators.md5(ja3):
                        continue

                    ja3_dict[ja3] = json.dumps({'description': description,
                                                'source': data_file_name,
                                                'threat_level': threat_level})
            # Add all loaded JA3 to the database
            __database__.add_ja3_to_IoC(ja3_dict)
            return True
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on parse_ti_file() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            print(traceback.format_exc())
            return True

    def check_local_ti_files(self, path_to_files: str) -> bool:
        """
        Checks if a local TI file was changed based
        on it's hash. if so, update its content and delete old data
        """
        try:
            local_ti_files = os.listdir(path_to_files)
            for localfile in local_ti_files:
                self.print(f'Loading local TI file {localfile}', 2, 0)
                # Get what files are stored in cache db and their E-TAG to comapre with current files
                data = __database__.get_TI_file_info(localfile)
                old_hash = data.get('e-tag', False)

                # In the case of the local file, we dont store the e-tag
                # we calculate the hash
                new_hash = utils.get_hash_from_file(path_to_files + '/' + localfile)

                if not new_hash:
                    # Something failed. Do not download
                    self.print(f'Some error ocurred on calculating file hash. Not loading  the file {localfile}', 0, 3)
                    return False

                if old_hash == new_hash:
                    # The 2 hashes are identical. File is up to date.
                    self.print(f'File {localfile} is up to date.', 2, 0)

                    return True
                elif old_hash != new_hash:
                    # Our malicious file was changed. Load the new one
                    self.print(f'Updating the local TI file {localfile}', 2, 0)
                    if old_hash:
                        # File is updated and was in database.
                        # Delete previous data of this file.
                        self.__delete_old_source_data_from_database(localfile)

                    full_path_to_file = f'{path_to_files}/{localfile}'
                    # we have 2 types of local files, TI and JA3 files
                    if 'ja3' in localfile.lower():
                        self.parse_ja3_file(full_path_to_file)
                    else:
                        # Load updated data to the database
                        self.parse_ti_file(full_path_to_file)

                    # Store the new etag and time of file in the database
                    malicious_file_info = {}
                    malicious_file_info['e-tag'] = new_hash
                    malicious_file_info['time'] =  ''
                    __database__.set_TI_file_info(localfile, malicious_file_info)
                    return True

        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on __load_malicious_local_files() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)



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
            # check if we should update the files
            if not self.check_local_ti_files(self.path_to_local_threat_intelligence_data):
                self.print(f'Could not load the local TI files {self.path_to_local_threat_intelligence_data}')
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on the run() line {exception_line}', 0, 1)
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
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                # Check that the message is for you.
                # The channel now can receive an IP address or a domain name
                if utils.is_msg_intended_for(message, 'give_threat_intelligence' ):
                    # Data is sent in the channel as a json dict so we need to deserialize it first
                    data = json.loads(message['data'])
                    # Extract data from dict
                    profileid = data.get('profileid')
                    twid = data.get('twid')
                    timestamp = data.get('stime')
                    uid = data.get('uid')
                    protocol = data.get('proto')
                    # IP is the IP that we want the TI for. It can be a SRC or DST IP
                    ip = data.get('ip')
                    # ip_state will say if it is a srcip or if it was a dst_ip
                    ip_state = data.get('ip_state')
                    #self.print(ip)

                    # If given an IP, ask for it
                    if ip:
                        # Block only if the traffic isn't outgoing ICMP port unreachable packet
                        if self.is_outgoing_icmp_packet(protocol,ip_state): continue

                        # Search for this IP in our database of IoC
                        ip_info = __database__.search_IP_in_IoC(ip)
                        # check if it's a blacklisted ip
                        if ip_info != False: # Dont change this condition. This is the only way it works
                            # If the IP is in the blacklist of IoC. Add it as Malicious
                            ip_info = json.loads(ip_info)
                            # Set the evidence on this detection
                            self.set_evidence_malicious_ip(ip, uid, timestamp, ip_info, profileid, twid, ip_state)

                        # check if this ip belongs to any of our blacklisted ranges
                        ip_ranges = __database__.get_malicious_ip_ranges()
                        if not ip_ranges: continue

                        for range,info in ip_ranges.items():
                            if ipaddress.ip_address(ip) in ipaddress.ip_network(range):
                                # ip was found in one of the blacklisted ranges
                                ip_info = json.loads(info)
                                # Set the evidence on this detection
                                self.set_evidence_malicious_ip(ip, uid, timestamp, ip_info, profileid, twid, ip_state)
                                break
                    else:
                        # We were not given an IP. Check if we were given a domain

                        # Process any type of domain. Each connection will have only of of these each time
                        domain = data.get('host') or data.get('server_name') or data.get('query')
                        if domain:
                            # Search for this domain in our database of IoC
                            domain_info, is_subdomain= __database__.search_Domain_in_IoC(domain)
                            if domain_info != False: # Dont change this condition. This is the only way it works
                                # If the domain is in the blacklist of IoC. Set an evidence
                                domain_info = json.loads(domain_info)
                                self.set_evidence_domain(domain, uid, timestamp, domain_info, is_subdomain, profileid, twid)

                                # mark this domain as malicious in our database
                                domain_info =  {'threatintelligence': domain_info }
                                __database__.setInfoForDomains(domain, domain_info)

                                # add this domain to our MaliciousDomains hash in the database
                                __database__.set_malicious_domain(domain, profileid, twid)

            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                self.print(traceback.format_exc())
                return True
