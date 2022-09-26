# Must imports
from slips_files.common.abstracts import Module
from slips_files.common.slips_utils import utils
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
import sys

# Your imports
import ipaddress
import os
import json
import traceback
import validators
import dns
import requests

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'threatintelligence1'
    description = 'Check if the source IP or destination IP are in a malicious list of IPs'
    authors = ['Frantisek Strasak, Sebastian Garcia']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        # Get a separator from the database
        self.separator = __database__.getFieldSeparator()
        self.c1 = __database__.subscribe('give_threat_intelligence')
        self.c2 = __database__.subscribe('new_downloaded_file')
        self.timeout = 0.0000001
        self.__read_configuration()
        self.get_malicious_ip_ranges()
        self.create_urlhaus_session()
        self.create_circl_lu_session()

    def create_urlhaus_session(self):
        self.urlhaus_session = requests.session()
        self.urlhaus_session.verify = True

    def create_circl_lu_session(self):
        self.circl_session = requests.session()
        self.circl_session.verify = True
        self.circl_session.headers = {'accept':'application/json'}

    def get_malicious_ip_ranges(self):
        """
        Cache the IoC IP ranges instead of retrieving them from the db
        """
        ip_ranges = __database__.get_malicious_ip_ranges()
        self.cached_ipv6_ranges = {}
        self.cached_ipv4_ranges = {}
        for range in ip_ranges.keys():
            if '.' in range:
                first_octet = range.split('.')[0]
                try:
                    self.cached_ipv4_ranges[first_octet].append(range)
                except KeyError:
                    # first time seeing this octect
                    self.cached_ipv4_ranges[first_octet] = [range]
            else:
                # ipv6 range
                first_octet = range.split(':')[0]
                try:
                    self.cached_ipv6_ranges[first_octet].append(range)
                except KeyError:
                    # first time seeing this octect
                    self.cached_ipv6_ranges[first_octet] = [range]

    def __read_configuration(self):
        conf = ConfigParser()
        self.path_to_local_ti_files = conf.local_ti_data_path()
        if not os.path.exists(self.path_to_local_ti_files):
            os.mkdir(self.path_to_local_ti_files)

    def set_evidence_malicious_ip(
        self,
        ip,
        uid,
        timestamp,
        ip_info: dict,
        profileid='',
        twid='',
        ip_state='',
    ):
        """
        Set an evidence for a malicious IP met in the timewindow
        :param ip: the ip source file
        :param uid: Zeek uid of the flow that generated the evidence
        :param timestamp: Exact time when the evidence happened
        :param ip_info: is all the info we have about that IP in the db source, confidence, description, etc.
        :param profileid: profile where the alert was generated. It includes the src ip
        :param twid: name of the timewindow when it happened.
        :param ip_state: can be 'srcip' or 'dstip'
        """

        type_detection = ip_state
        detection_info = ip
        type_evidence = 'ThreatIntelligenceBlacklistIP'

        threat_level = ip_info.get('threat_level', 'medium')

        confidence = 1
        category = 'Anomaly.Traffic'
        if 'src' in type_detection:
            direction = 'from'
        elif 'dst' in type_detection:
            direction = 'to'
        ip_identification = __database__.getIPIdentification(ip)

        description = (
            f'connection {direction} blacklisted IP {ip} {ip_identification}.'
            f' Source: {ip_info["source"]}.'
        )
        tags = ''
        if tags_temp := ip_info.get('tags', False):
            # We need tags_temp so we avoid doing a replace on a bool.
            tags = tags_temp.replace('[', '').replace(']', '').replace("'", '')

        if tags != '':
            # description += f' tags={tags}'
            source_target_tag = tags.capitalize()
        else:
            source_target_tag = 'BlacklistedIP'

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            source_target_tag=source_target_tag,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

        # mark this ip as malicious in our database
        ip_info = {'threatintelligence': ip_info}
        __database__.setInfoForIPs(ip, ip_info)

        # add this ip to our MaliciousIPs hash in the database
        __database__.set_malicious_ip(ip, profileid, twid)

    def set_evidence_malicious_domain(
        self,
        domain,
        uid,
        timestamp,
        domain_info: dict,
        is_subdomain,
        profileid='',
        twid='',
    ):
        """
        Set an evidence for malicious domain met in the timewindow
        :param source_file: is the domain source file
        :param domain_info: is all the info we have about this domain in the db source, confidence , description etc...
        """

        type_detection = 'dstdomain'
        detection_info = domain
        category = 'Anomaly.Traffic'
        type_evidence = 'ThreatIntelligenceBlacklistDomain'
        # in case of finding a subdomain in our blacklists
        # print that in the description of the alert and change the confidence accordingly
        # in case of a domain, confidence=1
        confidence = 0.7 if is_subdomain else 1
        # when we comment ti_files and run slips, we get the error of not being able to get feed threat_level
        threat_level = domain_info.get('threat_level', 'high')

        tags = (
            domain_info.get('tags', False)
                .replace('[', '')
                .replace(']', '')
                .replace("'", '')
        )
        source_target_tag = tags.capitalize() if tags else 'BlacklistedDomain'
        description = (
            f'connection to a blacklisted domain {domain}. '
            f'Description: {domain_info.get("description", "")}, '
            f'Found in feed: {domain_info["source"]}, '
            f'with tags: {tags}. '
            f'Confidence: {confidence}.'
        )
        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            source_target_tag=source_target_tag,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

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
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    def is_valid_threat_level(self, threat_level):
        if threat_level in utils.threat_levels:
            return True
        return False

    def parse_local_ti_file(self, ti_file_path: str) -> bool:
        """
        Read all the files holding IP addresses and a description and store in the db.
        This also helps in having unique ioc across files
        Returns nothing, but the dictionary should be filled
        :param ti_file_path: full path_to local threat intel file
        """
        data_file_name = ti_file_path.split('/')[-1]
        malicious_ips_dict = {}
        malicious_domains_dict = {}
        # used for debugging
        line_number = 0
        with open(ti_file_path) as local_ti_file:

            self.print(f'Reading local file {ti_file_path}', 2, 0)

            # skip comments
            while True:
                line_number += 1
                line = local_ti_file.readline()
                if not line.startswith('#'):
                    break

            for line in local_ti_file:
                line_number += 1
                # The format of the file should be
                # "103.15.53.231","critical", "Karel from our village. He is bad guy."
                data = line.replace('\n', '').replace('"', '').split(',')

                # the column order is hardcoded because it's owr own ti file and we know the format,
                # we shouldn't be trying to find it
                ioc, threat_level, description, = (
                    data[0],
                    data[1].lower(),
                    data[2],
                )

                # validate the threat level taken from the user
                if not self.is_valid_threat_level(threat_level):
                    # default value
                    threat_level = 'medium'

                data_type = utils.detect_data_type(ioc.strip())
                if data_type == 'ip':
                    ip_address = ipaddress.ip_address(ioc.strip())
                    # Only use global addresses. Ignore multicast, broadcast, private, reserved and undefined
                    if ip_address.is_global:
                        # Store the ip in our local dict
                        malicious_ips_dict[str(ip_address)] = json.dumps(
                            {
                                'description': description,
                                'source': data_file_name,
                                'threat_level': threat_level,
                                'tags': 'local TI file',
                            }
                        )
                elif data_type == 'domain':
                    malicious_domains_dict[ioc] = json.dumps(
                        {
                            'description': description,
                            'source': data_file_name,
                            'threat_level': threat_level,
                            'tags': 'local TI file',
                        }
                    )
                else:
                    # invalid ioc, skip it
                    self.print(
                        f'Error while reading the TI file {local_ti_file}.'
                        f' Line {line_number} has invalid data: {ioc}',
                        0, 1,
                    )

        # Add all loaded malicious ips to the database
        __database__.add_ips_to_IoC(malicious_ips_dict)
        # Add all loaded malicious domains to the database
        __database__.add_domains_to_IoC(malicious_domains_dict)
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
            if data['source'] == file:
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
            if data['source'] == file:
                old_data.append(domain)
        if old_data:
            __database__.delete_domains_from_IoC_domains(old_data)

    def __delete_old_source_data_from_database(self, data_file):
        """
        Delete old IPs of the source from the database.
        :param data_file: the name of source to delete old IPs from.
        """
        # Only read the files with .txt or .csv
        self.__delete_old_source_IPs(data_file)
        self.__delete_old_source_Domains(data_file)

    def parse_ja3_file(self, path):
        """
        Reads the file holding JA3 hashes and store in the db.
        Returns nothing, but the dictionary should be filled
        :param path: full path_to local threat intel file
        """
        data_file_name = path.split('/')[-1]
        ja3_dict = {}
        # used for debugging
        line_number = 0

        with open(path) as local_ja3_file:
            self.print(f'Reading local file {path}', 2, 0)

            # skip comments
            while True:
                line_number += 1
                line = local_ja3_file.readline()
                if not line.startswith('#'):
                    break

            for line in local_ja3_file:
                line_number += 1
                # The format of the file should be
                # "JA3 hash", "Threat level", "Description"
                data = line.replace('\n', '').replace('"', '').split(',')

                # the column order is hardcoded because it's owr own ti file and we know the format,
                # we shouldn't be trying to find it
                ja3, threat_level, description = (
                    data[0],
                    data[1].lower(),
                    data[2],
                )

                # validate the threat level taken from the user
                if threat_level not in (
                    'info',
                    'low',
                    'medium',
                    'high',
                    'critical',
                ):
                    # default value
                    threat_level = 'medium'

                # validate the ja3 hash taken from the user
                if not validators.md5(ja3):
                    continue

                ja3_dict[ja3] = json.dumps(
                    {
                        'description': description,
                        'source': data_file_name,
                        'threat_level': threat_level,
                    }
                )
        # Add all loaded JA3 to the database
        __database__.add_ja3_to_IoC(ja3_dict)
        return True

    def check_local_ti_files_for_update(self, path_to_files: str) -> bool:
        """
        Checks if a local TI file was changed based
        on it's hash. if so, update its content and delete old data
        """
        local_ti_files = os.listdir(path_to_files)
        for localfile in local_ti_files:
            self.print(f'Loading local TI file {localfile}', 2, 0)
            # Get what files are stored in cache db and their E-TAG to comapre with current files
            data = __database__.get_TI_file_info(localfile)
            old_hash = data.get('hash', False)

            # In the case of the local file, we dont store the e-tag
            # we calculate the hash
            new_hash = utils.get_hash_from_file(f'{path_to_files}/{localfile}')

            if not new_hash:
                # Something failed. Do not download
                self.print(
                    f'Some error ocurred on calculating file hash.'
                    f' Not loading the file {localfile}', 0, 3,
                )
                return False

            if old_hash == new_hash:
                # The 2 hashes are identical. File is up to date.
                self.print(f'File {localfile} is up to date.', 2, 0)

            else:
                # Our malicious file was changed. Load the new one
                self.print(f'Updating the local TI file {localfile}', 2, 0)
                if old_hash:
                    # File is updated and was in database.
                    # Delete previous data of this file.
                    self.__delete_old_source_data_from_database(localfile)
                full_path_to_file = os.path.join(path_to_files, localfile)
                # we have 2 types of local files, TI and JA3 files
                if 'ja3' in localfile.lower():
                    self.parse_ja3_file(full_path_to_file)
                else:
                    # Load updated data to the database
                    self.parse_local_ti_file(full_path_to_file)

                # Store the new etag and time of file in the database
                malicious_file_info = {'hash': new_hash}
                __database__.set_TI_file_info(localfile, malicious_file_info)
        return True

    def set_maliciousIP_to_IPInfo(self, ip, ip_description):
        """
        Set malicious IP in IPsInfo.
        """

        ip_data = {'threatintelligence': ip_description}
        __database__.setInfoForIPs(
            ip, ip_data
        )  # Set in the IP info that IP is blacklisted

    def is_outgoing_icmp_packet(self, protocol: str, ip_state: str) -> bool:
        """
        Check whether this IP is our computer sending an ICMP unreacheable packet to
        a blacklisted IP or not.
        """

        return protocol == 'ICMP' and ip_state == 'dstip'

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)
        return True

    def spamhaus(self, ip):
        """
        Supports IP lookups only
        """
        # these are spamhaus datasets
        lists_names = {
            '127.0.0.2' :'SBL Data',
            '127.0.0.3' :'SBL CSS Data',
            '127.0.0.4' :'XBL CBL Data',
            '127.0.0.9' :'SBL DROP/EDROP Data',
            '127.0.0.10':'PBL ISP Maintained',
            '127.0.0.11':'PBL Spamhaus Maintained',
                    0: False
        }

        list_description = {'127.0.0.2' :'IP under the control of, used by, or made available for use'
                                          ' by spammers and abusers in unsolicited bulk '
                                          'email or other types of Internet-based abuse that '
                                          'threatens networks or users',
                             '127.0.0.3' :'IP involved in sending low-reputation email, '
                                          'may display a risk to users or a compromised host',
                             '127.0.0.4' :'IP address of exploited systems.'
                                          'This includes machines operating open proxies, systems infected '
                                          'with trojans, and other malware vectors.',
                             '127.0.0.9' :'IP is part of a netblock that is ‘hijacked’ or leased by professional spam '
                                          'or cyber-crime operations and therefore used for dissemination of malware, '
                                          'trojan downloaders, botnet controllers, etc.',
                             '127.0.0.10':'IP address should not -according to the ISP controlling it- '
                                          'be delivering unauthenticated SMTP email to any Internet mail server',
                             '127.0.0.11': 'IP is not expected be delivering unauthenticated SMTP email to any Internet mail server,'
                                           ' such as dynamic and residential IP space'}


        spamhaus_dns_hostname = ".".join(ip.split(".")[::-1]) + ".zen.spamhaus.org"

        try:
            spamhaus_result = dns.resolver.resolve(spamhaus_dns_hostname, 'A')
        except:
            spamhaus_result = 0

        if not spamhaus_result:
            return

        # convert dns answer to text
        lists_that_have_this_ip = [data.to_text() for data in spamhaus_result]

        # get the source and description of the ip
        source_dataset = ''
        description =''
        for list in lists_that_have_this_ip:
            name = lists_names.get(list, False)
            if not name:
                continue
            source_dataset += f'{name}, '
            description = list_description.get(list, '')
        if not source_dataset:
            return False

        ip_info = {
            'source': source_dataset[:-2],
            'description': description,
            'therat_level': 'medium',
            'tags': 'spam'
        }
        return ip_info

    def is_ignored_domain(self, domain):
        if not domain:
            return True
        # to reduce the number of requests sent, don't send google domains
        # requests to spamhaus and urlhaus domains are done by slips
        ignored_TLDs = ('.arpa',
                        '.local')

        for keyword in ignored_TLDs:
            if domain.endswith(keyword):
                return True


    def urlhaus(self, ioc):
        """
        Supports IPs, domains, and hashes (MD5, sha256) lookups
        :param ioc: can be domain or ip
        """
        def get_description(url: dict):
            """
            returns a meaningful description from the given list of urls
            """

            description = f"{url['threat']}, url status: {url['url_status']}"
            return description

        urlhaus_base_url = 'https://urlhaus-api.abuse.ch/v1'

        # available types at urlhaus are host, md5 or sha256
        types = {
            'ip': 'host',
            'domain': 'host',
            'md5': 'md5',
        }
        ioc_type = utils.detect_data_type(ioc)
        # urlhaus doesn't support ipv6
        if not ioc_type or validators.ipv6(ioc):
            # not a valid ip, domain or hash
            return

        # get the urlhause supported type
        indicator_type = types[ioc_type]
        urlhaus_data = {
            indicator_type: ioc
        }
        try:

            if indicator_type == 'host':
                urlhaus_api_response = self.urlhaus_session.post(
                    f'{urlhaus_base_url}/host/',
                    urlhaus_data,
                    headers=self.urlhaus_session.headers
                )
            else:
                # md5
                urlhaus_api_response = self.urlhaus_session.post(
                    f'{urlhaus_base_url}/payload/',
                    urlhaus_data,
                    headers=self.urlhaus_session.headers
                )
        except requests.exceptions.ConnectionError:
            self.create_urlhaus_session()
            return

        if urlhaus_api_response.status_code != 200:
            return

        response = json.loads(urlhaus_api_response.text)
        if response['query_status'] == 'no_results' or response['urls'] == []:
            # no response or empty response
            return

        # get the first description available
        url = response['urls'][0]
        description = get_description(url)
        try:
            tags = " ".join(tag for tag in url['tags'])
        except TypeError:
            # no tags available
            tags = ''

        info = {
            # get all the blacklists where this ioc is listed
            'source': 'URLhaus',
            'description': description,
            'therat_level': 'medium',
            'tags': tags
        }
        return info

    def set_evidence_malicious_hash(self,
                                    file_info: dict
                                    ):
        """
        :param file_info: dict with uid, ts, profileid, twid, md5 and confidence of file
        """
        type_detection = 'file'
        category = 'Malware'
        type_evidence = 'MaliciousDownloadedFile'

        detection_info = file_info["md5"]
        saddr = file_info["saddr"]
        confidence = file_info["confidence"]
        threat_level = utils.threat_level_to_string(file_info["threat_level"])

        ip_identification = __database__.getIPIdentification(saddr)
        description = (
            f'Malicious downloaded file {detection_info}. '
            f'size: {file_info["size"]} '
            f'from IP: {saddr}. Detected by: {file_info["blacklist"]}, circl.lu. '
            f'Score: {confidence}. {ip_identification}'
        )


        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            file_info["ts"],
            category,
            profileid=file_info["profileid"],
            twid=file_info["twid"],
            uid=file_info["uid"],
        )



    def circl_lu(self, md5):
        """
        Supports lookup of MD5 hashes on Circl.lu
        """
        def calculate_threat_level(circl_trust: str):
            """
            Converts circl.lu trust to a valid slips threat level
            :param circl_trust: from 0 to 100, how legitimate the file is
            """
            # the lower the value, the more malicious the file is
            benign_percentage = float(circl_trust)
            malicious_percentage = 100 - benign_percentage
            # scale the benign percentage from 0 to 1
            threat_level = malicious_percentage/100
            return threat_level

        def calculate_confidence(blacklists):
            """
            calculates the confidence based on the number of blacklists detecting the file as malicious
            """
            blacklists = len(blacklists.split(' '))
            if blacklists == 1:
                confidence = 0.5
            elif blacklists == 2:
                confidence = 0.7
            else:
                confidence = 1
            return confidence


        circl_base_url = 'https://hashlookup.circl.lu/lookup/'
        circl_api_response = self.circl_session.get(
            f"{circl_base_url}/md5/{md5}",
           headers=self.circl_session.headers
        )

        if circl_api_response.status_code != 200:
            return

        response = json.loads(circl_api_response.text)
        # KnownMalicious: List of source considering the hashed file as being malicious (CIRCL)
        # TODO Circl.lu has very low trust levels of known malicious files
        if 'KnownMalicious' not in response:
            return

        file_info = {
            'confidence': calculate_confidence(response["KnownMalicious"]),
            'threat_level': calculate_threat_level(response["hashlookup:trust"]),
            'blacklist': response["KnownMalicious"]
        }
        return file_info

    def search_online_for_hash(self, md5):
        return self.circl_lu(md5)

    def search_offline_for_ip(self, ip):
        """ Searches the TI files for the given ip """
        ip_info = __database__.search_IP_in_IoC(ip)
        # check if it's a blacklisted ip
        if not ip_info:
            return False

        return json.loads(ip_info)

    def search_online_for_ip(self, ip):
        spamhaus_res = self.spamhaus(ip)
        if spamhaus_res:
            return spamhaus_res
        urlhaus_res = self.urlhaus(ip)
        if urlhaus_res:
            return urlhaus_res


    def ip_belongs_to_blacklisted_range(self, ip, uid, timestamp, profileid, twid, ip_state):
        """ check if this ip belongs to any of our blacklisted ranges"""
        ip_obj = ipaddress.ip_address(ip)
        if validators.ipv4(ip):
            first_octet = ip.split('.')[0]
            ranges_starting_with_octet = self.cached_ipv4_ranges.get(first_octet, [])
        elif validators.ipv6(ip):
            first_octet = ip.split(':')[0]
            ranges_starting_with_octet = self.cached_ipv6_ranges.get(first_octet, [])
        else:
            return False

        for range in ranges_starting_with_octet:
            if ip_obj in ipaddress.ip_network(range):
                # ip was found in one of the blacklisted ranges
                ip_info = __database__.get_malicious_ip_ranges()[range]
                ip_info = json.loads(ip_info)
                # Set the evidence on this detection
                self.set_evidence_malicious_ip(
                    ip,
                    uid,
                    timestamp,
                    ip_info,
                    profileid,
                    twid,
                    ip_state,
                )
                return True

    def search_offline_for_domain(self, domain):
        # Search for this domain in our database of IoC
        (
            domain_info,
            is_subdomain,
        ) = __database__.is_domain_malicious(domain)
        if (
            domain_info != False
        ):   # Dont change this condition. This is the only way it works
            # If the domain is in the blacklist of IoC. Set an evidence
            domain_info = json.loads(domain_info)
            return domain_info, is_subdomain
        return False, False

    def search_online_for_domain(self, domain):
        return self.urlhaus(domain)

    def is_malicious_ip(self, ip,  uid, timestamp, profileid, twid, ip_state):
        """Search for this IP in our database of IoC"""
        ip_info = self.search_offline_for_ip(ip)
        if not ip_info:
            ip_info = self.search_online_for_ip(ip)
            if not ip_info:
                # not malicious
                return False
        __database__.add_ips_to_IoC({
                ip: json.dumps(ip_info)
        })
        self.set_evidence_malicious_ip(
            ip,
            uid,
            timestamp,
            ip_info,
            profileid,
            twid,
            ip_state,
        )
        return True

    def is_malicious_hash(self,flow_info):
        """
        :param flow_info: dict with uid, twid, ts, md5 etc.
        """
        md5 = flow_info['md5']
        file_info:dict = self.search_online_for_hash(md5)
        if file_info:
            # is malicious.
            # update the file_info dict with uid, twid, ts etc.
            file_info.update(flow_info)
            self.set_evidence_malicious_hash(
                file_info
            )


    def is_malicious_domain(
            self,
            domain,
            uid,
            timestamp,
            profileid,
            twid
    ):
        if self.is_ignored_domain(domain):
            return False

        domain_info, is_subdomain = self.search_offline_for_domain(domain)
        if not domain_info:
            is_subdomain = False
            domain_info = self.search_online_for_domain(domain)
            if not domain_info:
                # not malicious
                return False

        self.set_evidence_malicious_domain(
                domain,
                uid,
                timestamp,
                domain_info,
                is_subdomain,
                profileid,
                twid,
            )

        # mark this domain as malicious in our database
        domain_info = {
            'threatintelligence': domain_info
        }
        __database__.setInfoForDomains(
            domain, domain_info
        )

        # add this domain to our MaliciousDomains hash in the database
        __database__.set_malicious_domain(
            domain, profileid, twid
        )


    def run(self):
        try:
            utils.drop_root_privs()
            # Load the local Threat Intelligence files that are stored in the local folder
            # The remote files are being loaded by the update_manager
            # check if we should update the files
            if not self.check_local_ti_files_for_update(
                self.path_to_local_ti_files
            ):
                self.print(
                    f'Could not load the local TI files {self.path_to_local_ti_files}'
                )
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on the run() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            self.print(traceback.format_exc())
            return True

        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time
                # (see at logsProcess.py), we will stop slips automatically.
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                # Check that the message is for you.
                # The channel now can receive an IP address or a domain name
                if utils.is_msg_intended_for(
                    message, 'give_threat_intelligence'
                ):
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
                    # self.print(ip)

                    # If given an IP, ask for it
                    # Block only if the traffic isn't outgoing ICMP port unreachable packet
                    if ip:
                        ip_obj = ipaddress.ip_address(ip)
                        if not (
                                ip_obj.is_multicast
                                or ip_obj.is_private
                                or ip_obj.is_link_local
                                or ip_obj.is_reserved
                                or self.is_outgoing_icmp_packet(protocol, ip_state)
                            ):
                            self.is_malicious_ip(ip, uid, timestamp, profileid, twid, ip_state)
                            self.ip_belongs_to_blacklisted_range(ip, uid, timestamp, profileid, twid, ip_state)
                    else:
                        # We were not given an IP. Check if we were given a domain

                        # Process any type of domain. Each connection will have only of of these each time
                        domain = (
                            data.get('host')
                            or data.get('server_name')
                            or data.get('query')
                        )


                        self.is_malicious_domain(
                            domain,
                            uid,
                            timestamp,
                            profileid,
                            twid
                        )

                message = self.c2.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_downloaded_file'):
                    file_info = json.loads(message['data'])
                    self.is_malicious_hash(file_info)

            except KeyboardInterrupt:
                self.shutdown_gracefully()
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                self.print(traceback.format_exc())
