import ipaddress
import os
import json
import validators
import dns
import requests
import threading
import time
from typing import Dict

from slips_files.common.slips_utils import utils
from slips_files.common.imports import *
from modules.threat_intelligence.urlhaus import URLhaus
from slips_files.core.evidence_structure.evidence import \
    (
        Evidence,
        ProfileID,
        TimeWindow,
        Victim,
        Attacker,
        Proto,
        ThreatLevel,
        EvidenceType,
        IoCType,
        Direction,
        IDEACategory,
        Tag
    )


class ThreatIntel(IModule, URLhaus):
    name = 'Threat Intelligence'
    description = 'Check if the source IP or destination IP' \
                  ' are in a malicious list of IPs'
    authors = ['Frantisek Strasak, Sebastian Garcia, Alya Gomaa']

    def init(self):
        # Get a separator from the database
        self.separator = self.db.get_field_separator()
        self.c1 = self.db.subscribe('give_threat_intelligence')
        self.c2 = self.db.subscribe('new_downloaded_file')
        self.channels = {
            'give_threat_intelligence': self.c1,
            'new_downloaded_file': self.c2,
        }
        self.__read_configuration()
        self.get_malicious_ip_ranges()
        self.create_circl_lu_session()
        self.circllu_queue = multiprocessing.Queue()
        self.circllu_calls_thread = threading.Thread(
            target=self.make_pending_query, daemon=True
        )
        self.urlhaus = URLhaus(self.db)

    def make_pending_query(self):
        """
        This thread starts if there's a circllu calls queue,
        it operates every 2 mins, and does 10 queries
        from the queue then sleeps again.
        """
        max_queries = 10
        while True:
            time.sleep(120)
            try:
                flow_info = self.circllu_queue.get(timeout=0.5)
            except Exception:
                # queue is empty wait extra 2 min
                continue

            queries_done = 0
            while self.circllu_queue != [] and queries_done <= max_queries:
                self.is_malicious_hash(flow_info)
                queries_done += 1

    def create_circl_lu_session(self):
        self.circl_session = requests.session()
        self.circl_session.verify = True
        self.circl_session.headers = {'accept':'application/json'}

    def get_malicious_ip_ranges(self):
        """
        Cache the IoC IP ranges instead of retrieving them from the db
        """
        ip_ranges = self.db.get_malicious_ip_ranges()
        self.cached_ipv6_ranges = {}
        self.cached_ipv4_ranges = {}
        for range in ip_ranges.keys():
            if '.' in range:
                first_octet = range.split('.')[0]
                try:
                    self.cached_ipv4_ranges[first_octet].append(range)
                except KeyError:
                    # first time seeing this octet
                    self.cached_ipv4_ranges[first_octet] = [range]
            else:
                # ipv6 range
                first_octet = range.split(':')[0]
                try:
                    self.cached_ipv6_ranges[first_octet].append(range)
                except KeyError:
                    # first time seeing this octet
                    self.cached_ipv6_ranges[first_octet] = [range]

    def __read_configuration(self):
        conf = ConfigParser()
        self.path_to_local_ti_files = conf.local_ti_data_path()
        if not os.path.exists(self.path_to_local_ti_files):
            os.mkdir(self.path_to_local_ti_files)


    def set_evidence_malicious_asn(
        self,
        attacker: str,
        uid: str,
        timestamp: str,
        profileid: str,
        twid: str,
        asn: str,
        asn_info: dict,
    ):
        """
        :param asn_info: the malicious ASN info taken from own_malicious_iocs.csv
        """

        confidence: float = 0.8
        saddr = profileid.split("_")[-1]

        # when we comment ti_files and run slips, we get the
        # error of not being able to get feed threat_level
        threat_level: float = utils.threat_levels[
            asn_info.get('threat_level', 'medium')
        ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)

        tags = asn_info.get('tags', '')
        identification: str = self.db.get_ip_identification(attacker)

        description: str = (
            f'Connection to IP: {attacker} with blacklisted ASN: {asn} '
            f'Description: {asn_info["description"]}, '
            f'Found in feed: {asn_info["source"]}, '
            f'Confidence: {confidence}. Tags: {tags} {identification}'
        )
        attacker = Attacker(
                direction=Direction.SRC,
                attacker_type=IoCType.IP,
                value=saddr
            )
        evidence = Evidence(
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_ASN,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
            category=IDEACategory.ANOMALY_TRAFFIC,
            source_target_tag=Tag.BLACKLISTED_ASN,
        )

        self.db.set_evidence(evidence)


    def set_evidence_malicious_ip(
            self,
            ip: str,
            uid: str,
            dstip: str,
            timestamp: str,
            ip_info: dict,
            profileid: str = '',
            twid: str = '',
            ip_state: str = '',
        ):
        """
        Set an evidence for a malicious IP met in the timewindow
        :param ip: the ip source file
        :param uid: Zeek uid of the flow that generated the evidence
        :param timestamp: Exact time when the evidence happened
        :param ip_info: is all the info we have about that IP in the db source, confidence, description, etc.
        :param profileid: profile where the alert was generated. It includes the src ip
        :param twid: name of the timewindow when it happened.
        :param ip_state: is basically the answer to "which one is the
        blacklisted IP"? can be 'srcip' or 'dstip'
        """
        threat_level: float = utils.threat_levels[
            ip_info.get('threat_level', 'medium')
        ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)
        confidence: float = 1.0
        srcip = profileid.split("_")[-1]

        if 'src' in ip_state:
            description: str = f'connection from blacklisted ' \
                               f'IP: {ip} to {dstip}. '
            attacker = Attacker(
                direction=Direction.SRC,
                attacker_type=IoCType.IP,
                value=ip
            )
        elif 'dst' in ip_state:
            if self.is_dns_response:
                description: str = f'DNS answer with a blacklisted ' \
                                   f'IP: {ip} for query: {self.dns_query}'
            else:
                description: str = f'connection to blacklisted ' \
                                   f'IP: {ip} from {srcip}. '

            attacker = Attacker(
                direction=Direction.DST,
                attacker_type=IoCType.IP,
                value=ip
            )
        else:
            # ip_state is not specified?
            return

        ip_identification: str = self.db.get_ip_identification(
            ip, get_ti_data=False
            ).strip()
        description += (f'{ip_identification} Description: '
                        f'{ip_info["description"]}. '
                        f'Source: {ip_info["source"]}.')


        evidence = Evidence(
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_IP,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=attacker.value),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
            category=IDEACategory.ANOMALY_TRAFFIC,
            source_target_tag=Tag.BLACKLISTED_IP,
        )

        self.db.set_evidence(evidence)


        # mark this ip as malicious in our database
        ip_info = {'threatintelligence': ip_info}
        self.db.setInfoForIPs(ip, ip_info)

        # add this ip to our MaliciousIPs hash in the database
        self.db.set_malicious_ip(ip, profileid, twid)

    def set_evidence_malicious_domain(
        self,
        domain: str,
        uid: str,
        timestamp: str,
        domain_info: dict,
        is_subdomain: bool,
        profileid: str = '',
        twid: str = '',
    ):
        """
        Set an evidence for a malicious domain met in the timewindow
        :param source_file: is the domain source file
        :param domain_info: is all the info we have about
        this domain in the db source, confidence , description etc...
        """

        if not domain_info:
            return

        srcip = profileid.split("_")[-1]
        # in case of finding a subdomain in our blacklists
        # print that in the description of the alert and change the
        # confidence accordingly in case of a domain, confidence=1
        confidence: float = 0.7 if is_subdomain else 1

        # when we comment ti_files and run slips, we
        # get the error of not being able to get feed threat_level
        threat_level: float = utils.threat_levels[
                domain_info.get('threat_level', 'high')
            ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)


        if self.is_dns_response:
            description: str = (f'DNS answer with a blacklisted '
                                f'CNAME: {domain} '
                                f'for query: {self.dns_query} ')
        else:
            description: str = f'connection to a blacklisted domain {domain}. '

        description += f'Description: {domain_info.get("description", "")},' \
                       f' Found in feed: {domain_info["source"]}, ' \
                       f'Confidence: {confidence}. '

        tags = domain_info.get('tags', None)
        if tags:
            description += f'with tags: {tags}. '

        attacker = Attacker(
                direction=Direction.SRC,
                attacker_type=IoCType.IP,
                value=srcip
            )

        evidence = Evidence(
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
            category=IDEACategory.ANOMALY_TRAFFIC,
            source_target_tag=Tag.BLACKLISTED_DOMAIN,
        )

        self.db.set_evidence(evidence)

    def is_valid_threat_level(self, threat_level):
        return threat_level in utils.threat_levels

    def parse_local_ti_file(self, ti_file_path: str) -> bool:
        """
        Read all the files holding IP addresses and a description and store in the db.
        This also helps in having unique ioc across files
        Returns nothing, but the dictionary should be filled
        :param ti_file_path: full path_to local threat intel file
        """
        data_file_name = ti_file_path.split('/')[-1]
        malicious_ips = {}
        malicious_asns = {}
        malicious_domains = {}
        malicious_ip_ranges = {}
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
                    data[2].strip(),
                )

                # validate the threat level taken from the user
                if not self.is_valid_threat_level(threat_level):
                    # default value
                    threat_level = 'medium'

                ioc_info = {
                    'description': description,
                    'source': data_file_name,
                    'threat_level': threat_level,
                    'tags': 'local TI file',
                }
                ioc_info: str = json.dumps(ioc_info)

                data_type = utils.detect_data_type(ioc.strip())
                if data_type == 'ip':
                    ip_address = ipaddress.ip_address(ioc.strip())
                    # Only use global addresses. Ignore multicast,
                    # broadcast, private, reserved and undefined
                    if ip_address.is_global:
                        malicious_ips[str(ip_address)] = ioc_info

                elif data_type == 'domain':
                    malicious_domains[ioc] = ioc_info

                elif data_type == 'ip_range':
                    net_addr = ioc[: ioc.index('/')]
                    if (
                        utils.is_ignored_ip(net_addr)
                        or net_addr in utils.home_networks
                    ):
                        continue
                    malicious_ip_ranges[ioc] = ioc_info

                elif data_type == 'asn':
                    malicious_asns[ioc] = ioc_info

                else:
                    # invalid ioc, skip it
                    self.print(
                        f'Error while reading the TI file {ti_file_path}.'
                        f' Line {line_number} has invalid data: {ioc}',
                        0, 1
                    )

        # Add all loaded malicious ips to the database
        self.db.add_ips_to_IoC(malicious_ips)
        # Add all loaded malicious domains to the database
        self.db.add_domains_to_IoC(malicious_domains)
        self.db.add_ip_range_to_IoC(malicious_ip_ranges)
        self.db.add_asn_to_IoC(malicious_asns)
        return True

    def __delete_old_source_IPs(self, file):
        """
        When file is updated, delete the old IPs in the cache
        """
        all_data = self.db.get_IPs_in_IoC()
        old_data = []
        for ip_data in all_data.items():
            ip = ip_data[0]
            data = json.loads(ip_data[1])
            if data['source'] == file:
                old_data.append(ip)
        if old_data:
            self.db.delete_ips_from_IoC_ips(old_data)

    def __delete_old_source_Domains(self, file):
        """
        When file is updated, delete the old Domains in the cache
        """
        all_data = self.db.get_Domains_in_IoC()
        old_data = []
        for domain_data in all_data.items():
            domain = domain_data[0]
            data = json.loads(domain_data[1])
            if data['source'] == file:
                old_data.append(domain)
        if old_data:
            self.db.delete_domains_from_IoC_domains(old_data)

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
        filename = os.path.basename(path)
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

                # the column order is hardcoded because it's owr
                # own ti file and we know the format,
                # we shouldn't be trying to find it
                ja3, threat_level, description = (
                    data[0].strip(),
                    data[1].lower().strip(),
                    data[2],
                )

                # validate the threat level taken from the user
                if utils.is_valid_threat_level(threat_level):
                    # default value
                    threat_level = 'medium'

                # validate the ja3 hash taken from the user
                if not validators.md5(ja3):
                    continue

                ja3_dict[ja3] = json.dumps(
                    {
                        'description': description,
                        'source': filename,
                        'threat_level': threat_level,
                    }
                )
        # Add all loaded JA3 to the database
        self.db.add_ja3_to_IoC(ja3_dict)
        return True

    def parse_jarm_file(self, path):
        """
        Reads the file holding JA3 hashes and store in the db.
        Returns nothing, but the dictionary should be filled
        :param path: full path_to local threat intel file
        """
        filename = os.path.basename(path)
        jarm_dict = {}
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
                # "JARM hash", "Threat level", "Description"
                data = line.replace('\n', '').replace('"', '').split(',')
                if len(data) < 3:
                    # invalid line
                    continue

                # the column order is hardcoded because
                # it's owr own ti file and we know the format,
                # we shouldn't be trying to find it
                jarm, threat_level, description = (
                    data[0].strip(),
                    data[1].lower().strip(),
                    data[2],
                )

                # validate the threat level taken from the user
                if utils.is_valid_threat_level(threat_level):
                    # default value
                    threat_level = 'medium'

                jarm_dict[jarm] = json.dumps(
                    {
                        'description': description,
                        'source': filename,
                        'threat_level': threat_level,
                    }
                )
        # Add all loaded JARM to the database
        self.db.add_jarm_to_IoC(jarm_dict)
        return True

    def should_update_local_ti_file(self, path_to_local_ti_file: str) -> bool:
        """
        Checks if a local TI file was changed based on it's hash.
        If the file should be updated, its hash will be returned
        :param path_to_local_ti_file: full path to a local ti file in our config/local_ti_files
        """
        filename = os.path.basename(path_to_local_ti_file)

        self.print(f'Loading local TI file {path_to_local_ti_file}', 2, 0)
        # Get what files are stored in cache db and their E-TAG to comapre with current files
        data = self.db.get_TI_file_info(filename)
        old_hash = data.get('hash', False)

        # In the case of the local file, we dont store the e-tag
        # we calculate the hash
        new_hash = utils.get_hash_from_file(path_to_local_ti_file)

        if not new_hash:
            # Something failed. Do not download
            self.print(
                f'Some error ocurred on calculating file hash.'
                f' Not loading the file {path_to_local_ti_file}', 0, 3,
            )
            return False

        if old_hash == new_hash:
            # The 2 hashes are identical. File is up to date.
            self.print(f'File {path_to_local_ti_file} is up to date.', 2, 0)
            return False

        else:
            # Our TI file was changed. Load the new one
            self.print(f'Updating the local TI file {path_to_local_ti_file}', 2, 0)

            if old_hash:
                # File is updated and was in database.
                # Delete previous data of this file from the db.
                self.__delete_old_source_data_from_database(filename)
            return new_hash

    def is_outgoing_icmp_packet(self, protocol: str, ip_state: str) -> bool:
        """
        Check whether this IP is our computer sending an ICMP unreacheable packet to
        a blacklisted IP or not.
        """
        return protocol == 'ICMP' and ip_state == 'dstip'

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

        list_description = {
            '127.0.0.2': 'IP under the control of, used by, or made '
                         'available for use'
                         ' by spammers and abusers in unsolicited bulk '
                         'email or other types of Internet-based abuse that '
                         'threatens networks or users',
            '127.0.0.3': 'IP involved in sending low-reputation email, '
                         'may display a risk to users or a compromised host',
            '127.0.0.4': 'IP address of exploited systems.'
                         'This includes machines operating open proxies, '
                         'systems infected with trojans, and other '
                         'malware vectors.',
            '127.0.0.9': 'IP is part of a netblock that is ‘hijacked’ '
                         'or leased by professional spam '
                         'or cyber-crime operations and therefore used '
                         'for dissemination of malware, '
                         'trojan downloaders, botnet controllers, etc.',
            '127.0.0.10': 'IP address should not -according to the ISP '
                          'controlling it- '
                          'be delivering unauthenticated SMTP email to '
                          'any Internet mail server',
            '127.0.0.11': 'IP is not expected be delivering unauthenticated'
                          ' SMTP email to any Internet mail server,'
                          ' such as dynamic and residential IP space'
            }


        spamhaus_dns_hostname = ".".join(ip.split(".")[::-1]) + ".zen.spamhaus.org"

        try:
            spamhaus_result = dns.resolver.resolve(spamhaus_dns_hostname, 'A')
        except Exception:
            spamhaus_result = 0

        if not spamhaus_result:
            return

        # convert dns answer to text
        lists_that_have_this_ip = [data.to_text() for data in spamhaus_result]

        # get the source and description of the ip
        source_dataset = ''
        description = ''
        for list in lists_that_have_this_ip:
            name = lists_names.get(list, False)
            if not name:
                continue
            source_dataset += f'{name}, '
            description = list_description.get(list, '')

        if not source_dataset:
            return False

        source_dataset += 'spamhaus'

        return {
            'source': source_dataset,
            'description': description,
            'threat_level': 'medium',
            'tags': 'spam',
        }

    def is_ignored_domain(self, domain):
        if not domain:
            return True
        ignored_TLDs = ('.arpa',
                        '.local')

        for keyword in ignored_TLDs:
            if domain.endswith(keyword):
                return True



    def set_evidence_malicious_hash(self, file_info: Dict[str, any]):
        """
        :param file_info: dict with flow, profileid,
        twid, and confidence of file
        """
        srcip = file_info['flow']['saddr']
        threat_level: str = utils.threat_level_to_string(
            file_info["threat_level"]
            )
        threat_level: ThreatLevel = ThreatLevel[threat_level.upper()]
        confidence: float = file_info["confidence"]
        daddr = file_info["flow"]["daddr"]

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = (
            f'Malicious downloaded file {file_info["flow"]["md5"]}. '
            f'size: {file_info["flow"]["size"]} '
            f'from IP: {daddr}. '
            f'Detected by: {file_info["blacklist"]}. '
            f'Score: {confidence}. {ip_identification}'
        )
        attacker = Attacker(
                direction=Direction.SRC,
                attacker_type=IoCType.IP,
                value=srcip
            )
        ts = utils.convert_format(
            file_info['flow']["starttime"], utils.alerts_format
            )
        twid = TimeWindow(number=int(
            file_info["twid"].replace("timewindow", "")
            ))
        evidence = Evidence(
            evidence_type=EvidenceType.MALICIOUS_DOWNLOADED_FILE,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=twid,
            uid=[file_info['flow']["uid"]],
            timestamp=ts,
            category=IDEACategory.MALWARE
        )
    
        self.db.set_evidence(evidence)

    def circl_lu(self, flow_info: dict):
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
            threat_level = float(malicious_percentage)/100
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

        md5 = flow_info['flow']['md5']
        circl_base_url = 'https://hashlookup.circl.lu/lookup/'
        try:
            circl_api_response = self.circl_session.get(
                f"{circl_base_url}/md5/{md5}",
               headers=self.circl_session.headers
            )
        except Exception:
            # add the hash to the cirllu queue and ask for it later
            self.circllu_queue.put(flow_info)
            return

        if circl_api_response.status_code != 200:
            return
        response = json.loads(circl_api_response.text)
        # KnownMalicious: List of source considering the hashed file as being malicious (CIRCL)
        if 'KnownMalicious' not in response:
            return

        file_info = {
            'confidence': calculate_confidence(response["KnownMalicious"]),
            'threat_level': calculate_threat_level(response["hashlookup:trust"]),
            'blacklist': f'{response["KnownMalicious"]}, circl.lu'
        }
        return file_info

    def search_online_for_hash(self, flow_info: dict):
        """
        :param flow_info: dict with 'type', 'flow', 'profileid','twid',
        returns a dict containing confidence, threat level and blacklist or the
        reporting website
        """
        if circllu_info := self.circl_lu(flow_info):
            return circllu_info

        if urlhaus_info := self.urlhaus.urlhaus_lookup(
            flow_info['flow']['md5'], 'md5_hash'
        ):
            return urlhaus_info

    def search_offline_for_ip(self, ip):
        """ Searches the TI files for the given ip """
        ip_info = self.db.search_IP_in_IoC(ip)
        # check if it's a blacklisted ip
        return json.loads(ip_info) if ip_info else False

    def search_online_for_ip(self, ip):
        if spamhaus_res := self.spamhaus(ip):
            return spamhaus_res

    def ip_has_blacklisted_ASN(
            self, ip, uid, timestamp, profileid, twid, ip_state
    ):
        """
        Check if this ip has any of our blacklisted ASNs.
        blacklisted asns are taken from own_malicious_iocs.csv
        """
        ip_info = self.db.get_ip_info(ip)
        if not ip_info:
            # we dont know the asn of this ip
            return

        if 'asn' not in ip_info:
            return

        asn = ip_info['asn'].get('number','')
        if not asn:
            return

        if asn_info := self.db.is_blacklisted_ASN(asn):
            asn_info = json.loads(asn_info)
            self.set_evidence_malicious_asn(
                ip,
                uid,
                timestamp,
                profileid,
                twid,
                asn,
                asn_info,
            )

    def ip_belongs_to_blacklisted_range(
            self, ip, uid, daddr, timestamp, profileid, twid, ip_state
    ):
        """ check if this ip belongs to any of our blacklisted ranges"""
        ip_obj = ipaddress.ip_address(ip)
        # Malicious IP ranges are stored in slips sorted by the first octet
        # so get the ranges that match the fist octet of the given IP
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
                ip_info = self.db.get_malicious_ip_ranges()[range]
                ip_info = json.loads(ip_info)
                self.set_evidence_malicious_ip(
                    ip,
                    uid,
                    daddr,
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
        ) = self.db.is_domain_malicious(domain)
        if (
            domain_info is not False
        ):   # Dont change this condition. This is the only way it works
            # If the domain is in the blacklist of IoC. Set an evidence
            domain_info = json.loads(domain_info)
            return domain_info, is_subdomain
        return False, False

    def search_online_for_url(self, url):
        return self.urlhaus.urlhaus_lookup(url, 'url')

    def is_malicious_ip(self,
                        ip: str,
                        uid: str,
                        daddr: str,
                        timestamp: str,
                        profileid: str,
                        twid: str,
                        ip_state: str) -> bool:
        """
        Search for this IP in our database of IoC
        :param ip_state: is basically the answer to "which one is the
        blacklisted IP"? can be 'srcip' or 'dstip'
        """
        ip_info = self.search_offline_for_ip(ip)
        if not ip_info:
            ip_info = self.search_online_for_ip(ip)
        if not ip_info:
            # not malicious
            return False
        self.db.add_ips_to_IoC({
                ip: json.dumps(ip_info)
        })
        self.set_evidence_malicious_ip(
            ip,
            uid,
            daddr,
            timestamp,
            ip_info,
            profileid,
            twid,
            ip_state,
        )
        return True

    def is_malicious_hash(self, flow_info: dict):
        """
        :param flow_info: dict with uid, twid, ts, md5 etc.
        """
        if not flow_info['flow']['md5']:
            # some lines in the zeek files.log doesn't have a hash for example
            # {"ts":293.713187,"fuid":"FpvjEj3U0Qoj1fVCQc","tx_hosts":["94.127.78.125"],"rx_hosts":["10.0.2.19"],
            # "conn_uids":["CY7bgw3KI8QyV67jqa","CZEkWx4wAvHJv0HTw9","CmM1ggccDvwnwPCl3","CBwoAH2RcIueFH4eu9","CZVfkc4BGLqRR7wwD5"],
            # "source":"HTTP","depth":0,"analyzers":["SHA1","SHA256","MD5"] .. }
            return

        if blacklist_details := self.search_online_for_hash(flow_info):
            # the md5 appeared in a blacklist
            # update the blacklist_details dict with uid,
            # twid, ts etc. of the detected file/flow
            blacklist_details.update(flow_info)
            # is the detection done by urlhaus or circllu?
            if 'URLhaus' in blacklist_details['blacklist']:
                self.urlhaus.set_evidence_malicious_hash(blacklist_details)
            else:
                self.set_evidence_malicious_hash(blacklist_details)


    def is_malicious_url(
            self,
            url,
            uid,
            timestamp,
            profileid,
            twid
    ):

        url_info = self.search_online_for_url(url)
        if not url_info:
            # not malicious
            return False
        self.set_evidence_malicious_url(
            url_info,
            uid,
            timestamp,
            profileid,
            twid
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
        self.db.setInfoForDomains(
            domain, domain_info
        )

        # add this domain to our MaliciousDomains hash in the database
        self.db.set_malicious_domain(
            domain, profileid, twid
        )


    def update_local_file(self, filename):
        """
        Updates the given local ti file if the hash of it has changed
        : param filename: local ti file, has to be plased in config/local_ti_files/ dir
        """
        fullpath = os.path.join(self.path_to_local_ti_files, filename)
        if filehash := self.should_update_local_ti_file(fullpath):
            if 'JA3' in filename:
                # Load updated data to the database
                self.parse_ja3_file(fullpath)
            elif 'JARM' in filename:
                # Load updated data to the database
                self.parse_jarm_file(fullpath)
            else:
                # Load updated data to the database
                self.parse_local_ti_file(fullpath)
            # Store the new etag and time of file in the database
            malicious_file_info = {'hash': filehash}
            self.db.set_TI_file_info(filename, malicious_file_info)
            return True

    def pre_main(self):
        utils.drop_root_privs()
        # Load the local Threat Intelligence files that are
        # stored in the local folder self.path_to_local_ti_files
        # The remote files are being loaded by the update_manager
        local_files = (
            'own_malicious_iocs.csv',
            'own_malicious_JA3.csv',
            'own_malicious_JARM.csv',
        )
        for local_file in local_files:
            self.update_local_file(local_file)

        self.circllu_calls_thread.start()

    def main(self):
        # The channel now can receive an IP address or a domain name
        if msg:= self.get_msg('give_threat_intelligence'):
            # Data is sent in the channel as a json dict so we need to deserialize it first
            data = json.loads(msg['data'])
            # Extract data from dict
            profileid = data.get('profileid')
            twid = data.get('twid')
            timestamp = data.get('stime')
            uid = data.get('uid')
            protocol = data.get('proto')
            daddr = data.get('daddr')
            # these 2 are only available when looking up dns answers
            # the query is needed when a malicious answer is found,
            # for more detailed description of the evidence
            self.is_dns_response = data.get('is_dns_response')
            self.dns_query = data.get('dns_query')
            # IP is the IP that we want the TI for. It can be a SRC or DST IP
            to_lookup = data.get('to_lookup', '')
            # detect the type given because sometimes, http.log host field has ips OR domains
            type_ = utils.detect_data_type(to_lookup)

            # ip_state will say if it is a srcip or if it was a dst_ip
            ip_state = data.get('ip_state')

            # If given an IP, ask for it
            # Block only if the traffic isn't outgoing ICMP port unreachable packet
            if type_ == 'ip':
                ip = to_lookup
                if not (
                        utils.is_ignored_ip(ip)
                        or self.is_outgoing_icmp_packet(protocol, ip_state)
                    ):
                    self.is_malicious_ip(
                        ip, uid, daddr, timestamp, profileid, twid, ip_state
                        )
                    self.ip_belongs_to_blacklisted_range(
                        ip, uid, daddr, timestamp, profileid, twid, ip_state
                        )
                    self.ip_has_blacklisted_ASN(
                        ip, uid, timestamp, profileid, twid, ip_state
                        )
            elif type_ == 'domain':
                self.is_malicious_domain(
                    to_lookup,
                    uid,
                    timestamp,
                    profileid,
                    twid
                )
            elif type_ == 'url':
                self.is_malicious_url(
                    to_lookup,
                    uid,
                    timestamp,
                    profileid,
                    twid
                )

        if msg:= self.get_msg('new_downloaded_file'):
            file_info: dict = json.loads(msg['data'])
            # the format of file_info is as follows
            #  {
            #     'flow': asdict(self.flow),
            #     'type': 'suricata' or 'zeek',
            #     'profileid': str,
            #     'twid': str,
            # }

            if file_info['type'] == 'zeek':
                self.is_malicious_hash(file_info)
