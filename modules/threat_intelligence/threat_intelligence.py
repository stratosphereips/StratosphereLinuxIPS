# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import multiprocessing
import os
import json
import threading
import time
from uuid import uuid4
import validators
from typing import (
    Dict,
    List,
    Union,
    Tuple,
    Optional,
)
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address

from modules.threat_intelligence.circl_lu import Circllu
from modules.threat_intelligence.spamhaus import Spamhaus
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import IModule
from modules.threat_intelligence.urlhaus import URLhaus
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
    Victim,
)


class ThreatIntel(IModule, URLhaus, Spamhaus):
    name = "Threat Intelligence"
    description = (
        "Check if the source IP or destination IP"
        " are in a malicious list of IPs"
    )
    authors = ["Frantisek Strasak, Sebastian Garcia, Alya Gomaa"]

    def init(self):
        """Initializes the ThreatIntel module. This includes setting up database
        subscriptions for threat intelligence and new downloaded file notifications,
        reading configuration settings, caching malicious IP ranges, creating a session
        for Circl.lu API queries, initializing the URLhaus module, and starting a
        background thread for handling pending Circl.lu queries.

        Attributes:
            separator (str): A field separator value retrieved from the
            database.
            channels (dict): Subscriptions to database channels for receiving
            threat intelligence and file download notifications.
            urlhaus (URLhaus): An instance of the URLhaus module for
            querying URLhaus data.
        """
        self.separator = self.db.get_field_separator()
        self.c1 = self.db.subscribe("give_threat_intelligence")
        self.c2 = self.db.subscribe("new_downloaded_file")
        self.channels = {
            "give_threat_intelligence": self.c1,
            "new_downloaded_file": self.c2,
        }
        self.__read_configuration()
        self.get_all_blacklisted_ip_ranges()
        self.urlhaus = URLhaus(self.db)
        self.spamhaus = Spamhaus(self.db)
        self.pending_queries = multiprocessing.Queue()
        self.pending_circllu_calls_thread = threading.Thread(
            target=self.handle_pending_queries,
            daemon=True,
            name="ti_pending_circllu_calls_thread",
        )
        self.circllu = Circllu(self.db, self.pending_queries)

    def get_all_blacklisted_ip_ranges(self):
        """Retrieves and caches the malicious IP ranges from the database,
        separating them into IPv4 and IPv6 ranges. These ranges are stored in
        dictionaries indexed by the first octet (or hextet for IPv6) of
        the range, to optimize lookup times.

        Side Effects:
            - Populates `cached_ipv4_ranges` and `cached_ipv6_ranges`
            dictionaries with malicious IP ranges categorized by their
            first octet or hextet.
        """
        ip_ranges = self.db.get_all_blacklisted_ip_ranges()
        self.cached_ipv6_ranges = {}
        self.cached_ipv4_ranges = {}
        for range in ip_ranges.keys():
            if "." in range:
                first_octet = range.split(".")[0]
                try:
                    self.cached_ipv4_ranges[first_octet].append(range)
                except KeyError:
                    # first time seeing this octet
                    self.cached_ipv4_ranges[first_octet] = [range]
            else:
                # ipv6 range
                first_octet = range.split(":")[0]
                try:
                    self.cached_ipv6_ranges[first_octet].append(range)
                except KeyError:
                    # first time seeing this octet
                    self.cached_ipv6_ranges[first_octet] = [range]

    def __read_configuration(self):
        """Reads the module's configuration settings from a configuration file or
        source. This includes settings such as the path to local threat intelligence
        files. If the directory for local threat intelligence files does not exist, it
        creates it.

        Side Effects:
            - Sets `path_to_local_ti_files` with the configured
            path to local threat intelligence files.
            - Creates the directory at `path_to_local_ti_files`
            if it does not already exist.
        """
        conf = ConfigParser()
        self.path_to_local_ti_files = conf.local_ti_data_path()
        if not os.path.exists(self.path_to_local_ti_files):
            os.mkdir(self.path_to_local_ti_files)
        self.client_ips: List[
            Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]
        ]
        self.client_ips = conf.client_ips()

    def set_evidence_malicious_asn(
        self,
        daddr: str,
        uid: str,
        timestamp: str,
        profileid: str,
        twid: str,
        asn: str,
        asn_info: dict,
        is_dns_response: bool = False,
    ):
        """Sets evidence for an interaction with a malicious ASN (Autonomous System
        Number).

        This function generates and stores evidence of traffic
        associated with a malicious ASN,
        whether as part of a DNS response or a direct IP connection.

        Parameters:
            daddr (str): The destination IP address involved
            in the interaction.
            uid (str): Unique identifier for the network flow
            generating this evidence.
            timestamp (str): The timestamp when the interaction occurred.
            profileid (str): Identifier for the profile associated
            with the source IP.
            twid (str): Identifier for the time window during which the
            interaction occurred.
            asn (str): The ASN considered malicious.
            asn_info (dict): Dictionary containing details about
                            the malicious ASN, including its threat level,
                            description, and source.
            is_dns_response (bool, optional): Flag indicating whether the
            interaction was part of a DNS response.

        Side Effects:
            Creates and stores two pieces of evidence regarding the
            malicious ASN interaction,
            one from the perspective of the source IP and another
            from the destination IP.
        """

        confidence: float = 0.8
        saddr = profileid.split("_")[-1]

        # Use the get method with a default value to handle invalid threat levels
        threat_level: float = utils.threat_levels.get(
            asn_info.get("threat_level"), utils.threat_levels["medium"]
        )
        threat_level: ThreatLevel = ThreatLevel(threat_level)

        tags = asn_info.get("tags", "")
        if is_dns_response:
            description: str = (
                f"Connection to IP: {daddr} with blacklisted ASN: {asn} "
            )
        else:
            description: str = (
                f"DNS response with IP: {daddr} with blacklisted ASN: {asn} "
            )

        description += (
            f'Description: {asn_info["description"]}, '
            f'Found in feed: {asn_info["source"]}, '
            f"Confidence: {confidence}. Tags: {tags} "
        )
        twid_int = int(twid.replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_ASN,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            victim=Victim(
                direction=Direction.DST, ioc_type=IoCType.IP, value=daddr
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
        )

        self.db.set_evidence(evidence)
        evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_ASN,
            attacker=Attacker(
                direction=Direction.DST, ioc_type=IoCType.IP, value=daddr
            ),
            victim=Victim(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=daddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
        )

        self.db.set_evidence(evidence)

    def set_evidence_malicious_ip_in_dns_response(
        self,
        ip: str,
        uid: str,
        timestamp: str,
        ip_info: dict,
        dns_query: str,
        profileid: str,
        twid: str,
    ):
        """
        Sets evidence for a DNS response containing a blacklisted IP.

        This function records evidence when a DNS query response
        includes an IP address known to be malicious based on threat
        intelligence data.

        Parameters:
            ip (str): The malicious IP address found in the DNS response.
            uid (str): Unique identifier for the network flow that
             generated this evidence.
            timestamp (str): The exact time when the DNS query was made.
            ip_info (dict): Information about the malicious IP,
            including its threat level,
                            description, and source from the threat
                            intelligence database.
            dns_query (str): The DNS query that led to the malicious
             IP response.
            profileid (str): Identifier for the profile associated with
            the source IP of the DNS query.
            twid (str): Identifier for the time window during which the
            DNS query occurred.

        Side Effects:
            Creates and stores evidence regarding the DNS response containing
             a malicious IP address,
            marking the interaction in the threat intelligence database.
        """
        threat_level: float = utils.threat_levels[
            ip_info.get("threat_level", "medium")
        ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)
        saddr = profileid.split("_")[-1]

        description: str = (
            "DNS answer with a blacklisted "
            f"IP: {ip} for query: {dns_query} "
            f"Description: {ip_info['description']} "
            f"Source: {ip_info['source']}."
        )

        twid_int = int(twid.replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_DNS_ANSWER,
            attacker=Attacker(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=ip,
            ),
            victim=Victim(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            threat_level=threat_level,
            confidence=1.0,
            description=description,
            profile=ProfileID(ip=ip),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
        )

        self.db.set_evidence(evidence)

        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_DNS_ANSWER,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=ip,
            ),
            threat_level=threat_level,
            confidence=1.0,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
        )

        self.db.set_evidence(evidence)

        # mark this ip as malicious in our database
        ip_info = {"threatintelligence": ip_info}
        self.db.set_ip_info(ip, ip_info)

    def set_evidence_malicious_ip(
        self,
        ip: str,
        uid: str,
        daddr: str,
        timestamp: str,
        ip_info: dict,
        profileid: str = "",
        twid: str = "",
        ip_state: str = "",
    ):
        # map of ip_state to corresponding methods
        state_map = {
            "src": self.set_evidence_conn_from_malicious_ip,
            "dst": self.set_evidence_conn_to_malicious_ip,
        }

        # call the appropriate method based on ip_state
        for state in state_map:
            if state in ip_state:
                state_map[state](
                    ip, uid, daddr, timestamp, ip_info, profileid, twid
                )

    def set_evidence_conn_from_malicious_ip(
        self,
        ip: str,
        uid: str,
        daddr: str,
        timestamp: str,
        ip_info: dict,
        profileid: str = "",
        twid: str = "",
    ):
        threat_level: float = utils.threat_levels[
            ip_info.get("threat_level", "medium")
        ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)
        saddr = profileid.split("_")[-1]
        description: str = (
            f"connection from blacklisted IP: {ip} to {daddr}. "
            f"Description: {ip_info['description']}. "
            f"Source: {ip_info['source'].strip()}."
        )

        twid_int = int(twid.replace("timewindow", ""))

        evidence = Evidence(
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_TO_BLACKLISTED_IP,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            victim=Victim(
                direction=Direction.DST, ioc_type=IoCType.IP, value=daddr
            ),
            threat_level=threat_level,
            confidence=1.0,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
        )
        self.db.set_evidence(evidence)
        # mark this ip as malicious in our database
        ip_info = {"threatintelligence": ip_info}
        self.db.set_ip_info(ip, ip_info)

    def set_evidence_conn_to_malicious_ip(
        self,
        ip: str,
        uid: str,
        daddr: str,
        timestamp: str,
        ip_info: dict,
        profileid: str = "",
        twid: str = "",
    ):
        threat_level: float = utils.threat_levels[
            ip_info.get("threat_level", "medium")
        ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)
        saddr = profileid.split("_")[-1]

        description: str = (
            f"connection to blacklisted IP: {ip} from {saddr}. "
            f"Description: {ip_info['description']}. "
            f"Source: {ip_info['source']}."
        )

        twid_int = int(twid.replace("timewindow", ""))

        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_TO_BLACKLISTED_IP,
            attacker=Attacker(
                direction=Direction.DST, ioc_type=IoCType.IP, value=daddr
            ),
            victim=Victim(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            threat_level=threat_level,
            confidence=1.0,
            description=description,
            profile=ProfileID(ip=daddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
        )
        self.db.set_evidence(evidence)

        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_TO_BLACKLISTED_IP,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            victim=Victim(
                direction=Direction.DST, ioc_type=IoCType.IP, value=daddr
            ),
            threat_level=ThreatLevel.LOW,
            confidence=1.0,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
        )
        self.db.set_evidence(evidence)
        # mark this ip as malicious in our database
        ip_info = {"threatintelligence": ip_info}
        self.db.set_ip_info(ip, ip_info)

    def set_evidence_malicious_domain(
        self,
        domain: str,
        uid: str,
        timestamp: str,
        domain_info: dict,
        is_subdomain: bool,
        profileid: str = "",
        twid: str = "",
    ):
        """
        Records evidence of activity involving a malicious domain
         within a specific time window.

        Parameters:
            domain (str): The domain name identified as malicious.
            uid (str): Unique identifier for the network flow that
             triggered this evidence.
            timestamp (str): Timestamp when the event occurred.
            domain_info (dict): Contains metadata about the domain
            such as source, description, and threat level.
            is_subdomain (bool): Indicates if the malicious domain
            is a subdomain.
            profileid (str): Identifier for the network profile involved
             in the event.
            twid (str): Time window identifier during which the event was
            observed.

        Depending on whether the domain was resolved in the
         DNS query, the function creates
        and stores evidence related to the domain. It also
         marks the domain as malicious
        in the database for future reference.

        Side Effects:
            - Creates and stores evidence related to the
            malicious domain in the database.
            - Marks the domain as malicious in the database.
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
            domain_info.get("threat_level", "high")
        ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)
        description: str = (
            f"connection to a blacklisted domain {domain}. "
            f"Description: {domain_info.get('description', '')}, "
            f"Found in feed: {domain_info['source']}, "
            f"Confidence: {confidence}. "
        )

        tags = domain_info.get("tags", None)
        if tags:
            description += f"with tags: {tags}. "
        twid_number = int(twid.replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.DOMAIN,
                value=domain,
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
        )

        self.db.set_evidence(evidence)
        domain_resolution: List[str] = self.db.get_domain_resolution(domain)
        if domain_resolution:
            domain_resolution: str = domain_resolution[0]
            evidence = Evidence(
                id=evidence_id_of_dstip_as_the_attacker,
                rel_id=[evidence_id_of_srcip_as_the_attacker],
                evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN,
                attacker=Attacker(
                    direction=Direction.DST,
                    ioc_type=IoCType.DOMAIN,
                    value=domain,
                ),
                victim=Victim(
                    direction=Direction.SRC,
                    ioc_type=IoCType.IP,
                    value=srcip,
                ),
                threat_level=threat_level,
                confidence=confidence,
                description=description,
                profile=ProfileID(ip=domain_resolution),
                timewindow=TimeWindow(number=twid_number),
                uid=[uid],
                timestamp=utils.convert_format(timestamp, utils.alerts_format),
            )

            self.db.set_evidence(evidence)

    def is_valid_threat_level(self, threat_level):
        return threat_level in utils.threat_levels

    def parse_known_fp_hashes(self, fullpath: str):
        fp_hashes = {}
        with open(fullpath) as fps:
            # skip comments
            for line in fps:
                if line.startswith("#"):
                    continue

                # split the line into parts
                parts = line.split(", ")
                description = parts[0]
                hashes = parts[1:]
                for hash in hashes:
                    fp_hashes[hash] = description

        self.db.store_known_fp_md5_hashes(fp_hashes)

    def parse_local_ti_file(self, ti_file_path: str) -> bool:
        """Parses a local threat intelligence (TI) file to extract
         and store various indicators of compromise (IoCs), including IP
         addresses,
         domains, ASN numbers, and IP ranges, in the database.
         The function handles IoCs by categorizing them
        based on their types and stores them with associated metadata
        like threat level, description, and tags.

        Each line in the TI file is expected to follow a specific
         format, typically CSV, with entries for the IoC, its threat level,
         and a description. The function validates the threat level
         of each IoC against a predefined set of valid threat levels
         and skips any entries that do not conform to
          expected data types or formats.

        Parameters:
            ti_file_path (str): The absolute path to the local
            TI file being parsed. This file should contain
            the IoCs to be extracted and stored.

        Returns:
            bool: Returns True if the file was successfully
             parsed and the IoCs were stored in the database.
              Currently, the function always returns True.

        Side Effects:
            - Populates the database with new IoCs extracted from the
            provided TI file.
            - Logs errors to the console for entries that cannot be
            processed due to invalid data types or formats.
            - Skips lines that are commented out in the TI file.
        """
        data_file_name = ti_file_path.split("/")[-1]
        malicious_ips = {}
        malicious_asns = {}
        malicious_domains = {}
        malicious_ip_ranges = {}
        # used for debugging
        line_number = 0
        with open(ti_file_path) as local_ti_file:
            self.print(f"Reading local file {ti_file_path}", 2, 0)

            # skip comments
            while True:
                line_number += 1
                line = local_ti_file.readline()
                if not line.startswith("#"):
                    break

            for line in local_ti_file:
                line_number += 1
                # The format of the file should be
                # "103.15.53.231","critical", "Karel from our village. He is bad guy."
                data = line.replace("\n", "").replace('"', "").split(",")

                # the column order is hardcoded because it's owr
                # own ti file and we know the format,
                # we shouldn't be trying to find it
                (
                    ioc,
                    threat_level,
                    description,
                ) = (
                    data[0],
                    data[1].lower(),
                    data[2].strip(),
                )

                # validate the threat level taken from the user
                if not self.is_valid_threat_level(threat_level):
                    # default value
                    threat_level = "medium"

                ioc_info: dict = {
                    "description": description,
                    "source": data_file_name,
                    "threat_level": threat_level,
                    "tags": "local TI file",
                }
                ioc_info: str = json.dumps(ioc_info)

                data_type = utils.detect_ioc_type(ioc.strip())
                if data_type == "ip":
                    ip_address = ipaddress.ip_address(ioc.strip())
                    # Only use global addresses. Ignore multicast,
                    # broadcast, private, reserved and undefined
                    if ip_address.is_global:
                        malicious_ips[str(ip_address)] = ioc_info

                elif data_type == "domain":
                    malicious_domains[ioc] = ioc_info

                elif data_type == "ip_range":
                    net_addr = ioc[: ioc.index("/")]
                    if (
                        utils.is_ignored_ip(net_addr)
                        or net_addr in utils.home_networks
                    ):
                        continue
                    malicious_ip_ranges[ioc] = ioc_info

                elif data_type == "asn":
                    malicious_asns[ioc] = ioc_info

                else:
                    # invalid ioc, skip it
                    self.print(
                        (
                            f"Error while reading the TI file {ti_file_path}."
                            f" Line {line_number} has invalid data: {ioc}"
                        ),
                        0,
                        1,
                    )

        # Add all loaded malicious ips to the database
        self.db.add_ips_to_ioc(malicious_ips)
        # Add all loaded malicious domains to the database
        self.db.add_domains_to_ioc(malicious_domains)
        self.db.add_ip_range_to_ioc(malicious_ip_ranges)
        self.db.add_asn_to_ioc(malicious_asns)
        return True

    def __delete_old_source_ips(self, file):
        """When file is updated, delete the old IPs in the cache.

        Deletes IPs associated with a specific source file from the
        threat intelligence cache in the database. This is typically
        done before re-parsing the same TI file to ensure that
        outdated IoCs are removed.

        Parameters:
            file (str): The name of the source file whose associated
            IPs are to be deleted from the cache.

        Side Effects:
            - Modifies the database by removing IPs that are associated
            with the specified source file.
        """
        all_data = self.db.get_all_blacklisted_ips()
        old_data = []
        for ip_data in all_data.items():
            ip = ip_data[0]
            data = json.loads(ip_data[1])
            if data["source"] == file:
                old_data.append(ip)
        if old_data:
            self.db.delete_ips_from_ioc_ips(old_data)

    def __delete_old_source_domains(self, file):
        """Deletes all domain indicators of compromise (IoCs) associated with a specific
        source file from the database. This method is typically called when the source
        file is updated to ensure the database reflects the most current data.

        Parameters:
            file (str): The filename (including extension) of the
            source file whose associated domains are to be deleted.

        Side Effects:
            - Domains associated with the specified source file
            are removed from the database. This operation directly
            modifies the database's domain IoCs records.
        """
        all_data = self.db.get_all_blacklisted_domains()
        old_data = []
        for domain_data in all_data.items():
            domain = domain_data[0]
            data = json.loads(domain_data[1])
            if data["source"] == file:
                old_data.append(domain)
        if old_data:
            self.db.delete_domains_from_ioc_domains(old_data)

    def __delete_old_source_data_from_database(self, data_file):
        """Deletes old indicators of compromise (IoCs) associated with a specific source
        file from the database. This includes both IP addresses and domains. This method
        ensures that the database is updated to reflect the most recent IoCs when a
        source file is re-parsed.

        Parameters:
            data_file (str): The name of the source file
            (including extension) to delete old IoCs from.

        Side Effects:
            - Invokes __delete_old_source_IPs and __delete_old_source_Domains
             methods to remove outdated IoCs from the database. This
              operation directly modifies the database's records.
        """
        # Only read the files with .txt or .csv
        self.__delete_old_source_ips(data_file)
        self.__delete_old_source_domains(data_file)

    def parse_ja3_file(self, path):
        """Parses a file containing JA3 hashes, their threat levels, and descriptions,
        then stores this information in the database. The file is expected to be
        formatted with one entry per line, each containing a JA3 hash, a threat level,
        and a description, separated by commas.

        Parameters:
            path (str): The absolute path to the local file containing
            JA3 hashes.

        Returns:
            bool: Returns True if the file is successfully parsed and
            its contents stored in the database, False otherwise.

        Side Effects:
            - Populates the database with JA3 hash IoCs extracted from
            the file. If a JA3 hash is already present, its entry is
             updated with the new data.
            - Validates the format of JA3 hashes using MD5 validation
            and skips any invalid entries.
        """
        filename = os.path.basename(path)
        ja3_dict = {}
        # used for debugging
        line_number = 0

        with open(path) as local_ja3_file:
            self.print(f"Reading local file {path}", 2, 0)

            # skip comments
            while True:
                line_number += 1
                line = local_ja3_file.readline()
                if not line.startswith("#"):
                    break

            for line in local_ja3_file:
                line_number += 1
                # The format of the file should be
                # "JA3 hash", "Threat level", "Description"
                data = line.replace("\n", "").replace('"', "").split(",")

                # the column order is hardcoded because it's owr
                # own ti file and we know the format,
                # we shouldn't be trying to find it
                ja3, threat_level, description = (
                    data[0].strip(),
                    data[1].lower().strip(),
                    data[2].strip(),
                )

                # validate the threat level taken from the user
                if utils.is_valid_threat_level(threat_level):
                    # default value
                    threat_level = "medium"

                # validate the ja3 hash taken from the user
                if not validators.md5(ja3):
                    continue

                ja3_dict[ja3] = json.dumps(
                    {
                        "description": description,
                        "source": filename,
                        "threat_level": threat_level,
                    }
                )
        # Add all loaded JA3 to the database
        self.db.add_ja3_to_ioc(ja3_dict)
        return True

    def parse_jarm_file(self, path):
        """
        Parses a file of JARM hashes with their threat levels and descriptions, then stores the data in the database.

        Parameters:
        path (str): Absolute path to the JARM hash file.
        Returns:

        bool: Always True, indicating execution success (may change in the future).
        Details:

        Processes each line, skipping comments and invalid formats.
        Validates threat levels, defaulting to 'medium' if unrecognized.
        Populates the database with parsed JARM hash records (duplicates are not handled).
        Logs progress, including errors for invalid lines.
        """
        filename = os.path.basename(path)
        jarm_dict = {}
        # used for debugging
        line_number = 0

        with open(path) as local_ja3_file:
            self.print(f"Reading local file {path}", 2, 0)

            # skip comments
            while True:
                line_number += 1
                line = local_ja3_file.readline()
                if not line.startswith("#"):
                    break

            for line in local_ja3_file:
                line_number += 1
                # The format of the file should be
                # "JARM hash", "Threat level", "Description"
                data = line.replace("\n", "").replace('"', "").split(",")
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
                    threat_level = "medium"

                jarm_dict[jarm] = json.dumps(
                    {
                        "description": description,
                        "source": filename,
                        "threat_level": threat_level,
                    }
                )
        self.db.add_jarm_to_ioc(jarm_dict)
        return True

    def should_update_local_ti_file(self, path_to_local_ti_file: str) -> bool:
        """Determines whether a local threat intelligence (TI) file needs to be updated
        by comparing its current hash value against the stored hash value in the
        database.

        Parameters:
            path_to_local_ti_file (str): Absolute path to the local TI file.

        Returns:
            str or bool: Returns the new hash as a string if the file's hash
             has changed (indicating an update is needed), or False otherwise.

        The method calculates the hash of the provided file and compares it
         to the previously stored hash value for that file in the database.
          If the hashes differ, it implies the file has been updated and
          should be re-parsed.
         This function is designed to work with the walrus operator in
          conditional statements, allowing for efficient file update checks.

        Note:
        - This method prints messages indicating the file's status
        (e.g., up to date, updating) to the console.
        - Deletes old source data from the database if the file has
         been updated.
        """
        filename = os.path.basename(path_to_local_ti_file)

        self.print(f"Loading local TI file {path_to_local_ti_file}", 2, 0)
        data = self.db.get_ti_feed_info(filename)
        old_hash = data.get("hash", False)

        new_hash = utils.get_sha256_hash_of_file_contents(
            path_to_local_ti_file
        )

        if not new_hash:
            self.print(
                (
                    "Some error occurred on calculating file hash. "
                    f"Not loading the file {path_to_local_ti_file}"
                ),
                0,
                3,
            )
            return False

        if old_hash == new_hash:
            self.print(f"File {path_to_local_ti_file} is up to date.", 2, 0)
            return False
        else:
            self.print(
                f"Updating the local TI file {path_to_local_ti_file}", 2, 0
            )
            if old_hash:
                self.__delete_old_source_data_from_database(filename)
            return new_hash

    def is_outgoing_icmp_packet(self, protocol: str, ip_state: str) -> bool:
        """Determines if a packet is an outgoing ICMP packet based on protocol and IP
        state information.

        Parameters:
        protocol (str): The protocol of the packet, expected to be 'ICMP'
        for Internet Control Message Protocol.
        ip_state (str): The state of the IP address in the packet flow,
        expected to be 'dstip' for outgoing packets.

        Returns:
        bool: True if the packet is identified as an outgoing ICMP packet,
         otherwise False.

        This method is useful for filtering or identifying outbound ICMP
        traffic, such as unreachable packets sent by the host.
        """
        return protocol == "ICMP" and ip_state == "dstip"

    def is_ignored_domain(self, domain):
        """Checks if the given domain should be ignored based on its top-level domain
        (TLD).

        Parameters:
            domain (str): The domain name to check.

        Returns:
            bool: True if the domain ends with a TLD that is typically not
            relevant to threat intelligence analysis (e.g., .arpa, .local),
             otherwise False.

        This method helps in filtering out domain names that are unlikely
        to be involved in malicious activities based on their TLDs.
         It is particularly useful in preprocessing steps where irrelevant
         domains are excluded from further analysis.
        """
        if not domain:
            return True
        ignored_tlds = (".arpa", ".local")

        for keyword in ignored_tlds:
            if domain.endswith(keyword):
                return True

    def set_evidence_malicious_hash(self, file_info: Dict[str, any]):
        """Creates and records evidence of a malicious file based on
        its hash value, incorporating various pieces of information
        such as the file's source and destination IP addresses, its threat
        level, and the detection confidence.

        Parameters:
            file_info (Dict[str, any]): A dictionary containing information
            about the malicious file, including:
                - 'flow': A dictionary containing details about the network
                flow where the malicious file was detected, including source
                and destination IPs, the file's MD5 hash, and its size.
                - 'profileid', 'twid': Identifiers for the network profile
                and time window in which the detection occurred.
                - 'threat_level', 'confidence': The assessed threat level
                 and confidence score for the detection.

        This method constructs evidence entries for both the source and
        destination IP addresses involved in the transfer of the malicious
        file. It leverages the provided information to detail the nature
        of the threat and its detection, storing these entries in the
        database for further analysis and response.
        """
        # this srcip is tx_hosts in the zeek files.log, aka sender of the
        # file, aka server
        srcip = file_info["flow"]["saddr"]
        threat_level: str = utils.threat_level_to_string(
            file_info["threat_level"]
        )
        threat_level: ThreatLevel = ThreatLevel[threat_level.upper()]
        confidence: float = file_info["confidence"]
        daddr = file_info["flow"]["daddr"]

        description: str = (
            f'Malicious downloaded file {file_info["flow"]["md5"]}. '
            f'size: {file_info["flow"]["size"]} bytes. '
            f"File was downloaded from server: {srcip}. "
            f'Detected by: {file_info["blacklist"]}. '
            f"Confidence: {confidence}. "
        )
        ts = utils.convert_format(
            file_info["flow"]["starttime"], utils.alerts_format
        )
        twid = TimeWindow(
            number=int(file_info["twid"].replace("timewindow", ""))
        )
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_DOWNLOADED_FILE,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=twid,
            uid=[file_info["flow"]["uid"]],
            timestamp=ts,
        )

        self.db.set_evidence(evidence)

        evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_DOWNLOADED_FILE,
            attacker=Attacker(
                direction=Direction.DST, ioc_type=IoCType.IP, value=daddr
            ),
            victim=Victim(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=daddr),
            timewindow=twid,
            uid=[file_info["flow"]["uid"]],
            timestamp=ts,
        )

        self.db.set_evidence(evidence)

    def search_online_for_hash(self, flow_info: dict):
        """
        Attempts to find information about a file hash by
        querying online sources.
        Currently, it queries the Circl.lu and URLhaus.

        Parameters:
            - flow_info (dict): Contains information about the flow,
            including 'type', 'flow' (which contains the 'md5' hash),
        'profileid', and 'twid'.

        Returns:
            - dict: Information about the hash if found, including
            confidence level, threat level, and the source of the information.
            - None: If no information is found about the hash in
            the queried sources.
        """
        if circllu_info := self.circllu.lookup(flow_info):
            return circllu_info

        if urlhaus_info := self.urlhaus.lookup(
            flow_info["flow"]["md5"], "md5_hash"
        ):
            return urlhaus_info

    def search_offline_for_ip(self, ip):
        """
        Searches for the given IP address in the local
        threat intelligence files to
        determine if it is known to be malicious.

        Parameters:
            - ip (str): The IP address to search for in the
            threat intelligence.

        Returns:
            - dict: Information about the IP if it is found in
            the local threat intelligence files, indicating it is malicious.
            - False: If the IP is not found in the local threat
             intelligence files.

        This function queries the local database for any matches
        to the provided IP address.
        """
        ip_info: Dict[str, str] = self.db.is_blacklisted_ip(ip)
        return ip_info

    def is_inbound_traffic(self, ip: str, ip_state: str) -> bool:
        """
        checks if the given ip is connecting to us
        returns true on the given conditions
        1. the given ip is a saddr (aka someone connecting TO us)
        2. ip is public
        3. ip is not our host ip
        """
        host_ip: str = self.db.get_host_ip()
        return (
            "src" in ip_state
            and ipaddress.ip_address(ip).is_global
            and ip != host_ip
            and not utils.is_ip_in_client_ips(ip, self.client_ips)
        )

    def search_online_for_ip(self, ip: str, ip_state: str):
        if self.is_inbound_traffic(ip, ip_state):
            # we're excluding outbound traffic from spamhaus queries
            # to reduce FPs
            if spamhaus_res := self.spamhaus.query(ip):
                return spamhaus_res

    def ip_has_blacklisted_asn(
        self,
        ip,
        uid,
        timestamp,
        profileid,
        twid,
        is_dns_response: bool = False,
    ):
        """Checks if the given IP address is associated with a
        blacklisted Autonomous System Number (ASN).

        Parameters:
            - ip (str): IP address to check.
            - uid (str): Unique identifier for the network flow.
            - timestamp (str): Timestamp when the network flow occurred.
            - profileid (str): Identifier for the profile associated
             with the network flow.
            - twid (str): Time window identifier.
            - is_dns_response (bool): Indicates if the check is
            for a DNS response.

        Side Effects:
            - Generates and stores evidence if the IP's ASN is
             found to be blacklisted.

        Returns:
            - None: The function does not return a value but stores
            evidence if a blacklisted ASN is associated with the IP.

        This function queries the local database to determine if
        the IP's ASN is known to be malicious.
        """
        ip_info = self.db.get_ip_info(ip)
        if not ip_info:
            # we dont know the asn of this ip
            return

        if "asn" not in ip_info:
            return

        asn = ip_info["asn"].get("number", "")
        if not asn:
            return

        if asn_info := self.db.is_blacklisted_asn(asn):
            asn_info = json.loads(asn_info)
            self.set_evidence_malicious_asn(
                ip,
                uid,
                timestamp,
                profileid,
                twid,
                asn,
                asn_info,
                is_dns_response=is_dns_response,
            )

    def ip_belongs_to_blacklisted_range(
        self, ip, uid, daddr, timestamp, profileid, twid, ip_state
    ):
        """
        Verifies if the provided IP address falls within any known malicious IP
        ranges.

        Parameters:
            - ip (str): The IP address to check.
            - uid (str): Unique identifier for the network flow.
            - daddr (str): Destination IP address in the flow
             (for context in evidence).
            - timestamp (str): Timestamp when the flow was captured.
            - profileid (str): Identifier of the profile associated with the flow.
            - twid (str): Time window identifier for when the flow occurred.
            - ip_state (str): Indicates whether the IP was a source or
             destination in the network flow.

        Returns:
            - True: If the IP is within a blacklisted range.
            - False: If the IP is not within a blacklisted range
            or cannot be processed.

        Side Effects:
            - Records evidence using `set_evidence_malicious_ip` if
            the IP is found within a blacklisted range.
        """

        ip_obj = ipaddress.ip_address(ip)
        # Malicious IP ranges are stored in slips sorted by the first octet
        # so get the ranges that match the fist octet of the given IP
        if validators.ipv4(ip):
            first_octet = ip.split(".")[0]
            ranges_starting_with_octet = self.cached_ipv4_ranges.get(
                first_octet, []
            )
        elif validators.ipv6(ip):
            first_octet = ip.split(":")[0]
            ranges_starting_with_octet = self.cached_ipv6_ranges.get(
                first_octet, []
            )
        else:
            return False

        for range in ranges_starting_with_octet:
            if ip_obj in ipaddress.ip_network(range):
                # ip was found in one of the blacklisted ranges
                ip_info = self.db.get_all_blacklisted_ip_ranges()[range]
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
        return False

    def search_offline_for_domain(
        self, domain
    ) -> Tuple[Optional[Dict[str, str]], bool]:
        """Checks if the provided domain name is listed in the
        local threat intelligence
        as malicious.

        Parameters:
            - domain (str): The domain name to be checked.

        Returns:
            - Tuple: (domain_info, is_subdomain) where `domain_info`
            is the information about the domain if it's found in the local
             threat intelligence, and `is_subdomain` is a boolean
             indicating whether the domain
            is a subdomain of a known malicious domain.
            Returns (None, None) if the domain is not found or not malicious.

        This function queries the local threat intelligence database for
        the provided domain name and determines if it is considered malicious.
        """
        # Search for this domain in our database of IoC
        domain_info: Dict[str, str]
        is_subdomain: bool
        domain_info, is_subdomain = self.db.is_blacklisted_domain(domain)
        if domain_info:
            return domain_info, is_subdomain
        return None, False

    def search_online_for_url(self, url):
        return self.urlhaus.lookup(url, "url")

    def is_malicious_ip(
        self,
        ip: str,
        uid: str,
        daddr: str,
        timestamp: str,
        profileid: str,
        twid: str,
        ip_state: str,
        is_dns_response: bool = False,
        dns_query: str = False,
    ) -> bool:
        """Checks whether an IP address is malicious by looking it up
         in both offline
        and online threat intelligence databases.

        Parameters:
            - ip (str): The IP address to check.
            - uid (str): Unique identifier for the flow.
            - daddr (str): Destination IP address in the flow.
            - timestamp (str): Timestamp when the flow.
            - profileid (str): Identifier of the profile associated with
             the network flow.
            - twid (str): Time window identifier for when the network
            flow occurred.
            - ip_state (str): Specifies whether the IP was a source or
            destination ('srcip' or 'dstip').
            - is_dns_response (bool, optional): Indicates if the lookup
             is for an IP found in a DNS response.
            - dns_query (str, optional): The DNS query associated with
            the DNS response containing the IP. should be passed if
            is_dns_response is True

        Returns:
            - bool: True if the IP address is found to be malicious,
             False otherwise.

        Side Effects:
            - If the IP is found to be malicious, evidence is recorded
            using either `set_evidence_malicious_ip_in_dns_response`
            or `set_evidence_malicious_ip` methods depending on the context.
        """
        ip_info = self.search_offline_for_ip(ip)
        if not ip_info:
            ip_info = self.search_online_for_ip(ip, ip_state)
            if not ip_info:
                # not malicious
                return False

        self.db.add_ips_to_ioc({ip: json.dumps(ip_info)})
        if is_dns_response:
            self.set_evidence_malicious_ip_in_dns_response(
                ip,
                uid,
                timestamp,
                ip_info,
                dns_query,
                profileid,
                twid,
            )
        else:
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
        """Checks if a file hash is considered malicious based on online threat
        intelligence sources.

        Parameters:
            - flow_info (dict): A dictionary containing information about
             the network flow, including the file's MD5 hash.

        Returns:
            - None: The function does not return a value but triggers
            evidence creation if the hash is found to be malicious.

        Side Effects:
            - If the hash is found to be malicious based on online sources,
            evidence is recorded using `set_evidence_malicious_hash`.
        """
        if not flow_info["flow"]["md5"]:
            # some lines in the zeek files.log doesn't have a hash for example
            # {"ts":293.713187,"fuid":"FpvjEj3U0Qoj1fVCQc",
            # "tx_hosts":["94.127.78.125"],"rx_hosts":["10.0.2.19"],
            # "conn_uids":["CY7bgw3KI8QyV67jqa","CZEkWx4wAvHJv0HTw9",
            # "CmM1ggccDvwnwPCl3","CBwoAH2RcIueFH4eu9","CZVfkc4BGLqRR7wwD5"],
            # "source":"HTTP","depth":0,"analyzers":["SHA1","SHA256","MD5"]
            # .. }
            return

        if self.db.is_known_fp_md5_hash(flow_info["flow"]["md5"]):
            # this is a known FP https://github.com/Neo23x0/ti-falsepositives/tree/master
            # its benign so dont look it up
            return

        if blacklist_details := self.search_online_for_hash(flow_info):
            # the md5 appeared in a blacklist
            # update the blacklist_details dict with uid,
            # twid, ts etc. of the detected file/flow
            blacklist_details.update(flow_info)
            # is the detection done by urlhaus or circllu?
            if "URLhaus" in blacklist_details["blacklist"]:
                self.urlhaus.set_evidence_malicious_hash(blacklist_details)
            else:
                self.set_evidence_malicious_hash(blacklist_details)

    def is_malicious_url(self, url, uid, timestamp, daddr, profileid, twid):
        """Determines if a URL is considered malicious by querying online threat
        intelligence sources.

        Returns:
            - None: The function does not return a value but triggers
            evidence creation if the URL is found to be malicious.

        Side Effects:
            - If the URL is found to be malicious, evidence is recorded
            using the `set_evidence_malicious_url` method.
        """
        url_info = self.search_online_for_url(url)

        if not url_info:
            # not malicious
            return False

        self.urlhaus.set_evidence_malicious_url(
            daddr, url_info, uid, timestamp, profileid, twid
        )

    def set_evidence_malicious_cname_in_dns_response(
        self,
        cname: str,
        dns_query: str,
        uid: str,
        timestamp: str,
        cname_info: dict,
        is_subdomain: bool,
        profileid: str = "",
        twid: str = "",
    ):
        """Records evidence that a CNAME found in a DNS
        response is associated with a known malicious domain.

        Parameters:
            - cname (str): The CNAME that was looked up and found to be
             malicious.
            - dns_query (str): The original DNS query that resulted in
            the malicious CNAME response.
            - uid (str): Unique identifier for the network flow.
            - timestamp (str): Timestamp when the network flow occurred.
            - cname_info (dict): Information about the malicious nature of
            the CNAME.
            - is_subdomain (bool): Indicates whether the CNAME is a subdomain
            of a known malicious domain.
            - profileid (str, optional): Identifier of the profile associated
             with the network flow.
            - twid (str, optional): Time window identifier for when the
            network flow occurred.

        Returns:
            - None: The function directly triggers evidence creation for
            the malicious CNAME and does not return a value.

        Side Effects:
            - Records evidence of the malicious CNAME in the system.
        """
        if not cname_info:
            return

        srcip = profileid.split("_")[-1]
        # in case of finding a subdomain in our blacklists
        # print that in the description of the alert and change the
        # confidence accordingly in case of a domain, confidence=1
        confidence: float = 0.7 if is_subdomain else 1

        # when we comment ti_files and run slips, we
        # get the error of not being able to get feed threat_level
        threat_level: float = utils.threat_levels[
            cname_info.get("threat_level", "high")
        ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)
        description: str = (
            f"blacklisted CNAME: {cname} when resolving "
            f"{dns_query} "
            f"Description: {cname_info.get('description', '')}, "
            f"Found in feed: {cname_info['source']}, "
            f"Confidence: {confidence} "
        )

        tags = cname_info.get("tags", None)
        if tags:
            description += f"with tags: {tags}. "

        evidence = Evidence(
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_DNS_ANSWER,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
            ),
            victim=Victim(
                ioc_type=IoCType.DOMAIN,
                direction=Direction.DST,
                value=dns_query,
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=utils.convert_format(timestamp, utils.alerts_format),
        )

        self.db.set_evidence(evidence)

    def is_malicious_cname(
        self,
        dns_query,
        cname,
        uid,
        timestamp,
        profileid,
        twid,
    ):
        """
        Evaluates whether a CNAME (Canonical Name) record returned
        in a DNS response is associated with a known malicious domain. If
        the CNAME is found to be malicious based on offline threat
        intelligence sources, evidence is recorded, and the domain
        information is updated in the database.

        Parameters:
            - dns_query (str): The DNS query that resulted in the
            CNAME response.
            - cname (str): The CNAME record value to be checked for
             malicious activity.
            - uid (str): Unique identifier of the network flow where the
            DNS response was observed.
            - timestamp (str): The timestamp when the DNS response
            was captured.
            - profileid (str): Identifier of the user or entity profile
             associated with the network flow.
            - twid (str): Identifier of the time window during which the
             network flow occurred.

        Returns:
            - False: If the CNAME is determined to be non-malicious or
            belongs to an ignored domain category.
            - True: If the CNAME is found to be malicious and evidence
             is recorded successfully.

        The function first checks if the CNAME belongs to a domain category
        that should be ignored (e.g., local domains). If not ignored,
        it proceeds to search for the CNAME in offline threat intelligence
         sources. If the
         CNAME is identified as malicious, it records evidence of the
          malicious CNAME in a DNS response, updates domain information
           in the database to mark
         it as malicious, and adds the domain to a list of known
         malicious domains.

        Side Effects:
            - Records evidence of malicious CNAME using
            `set_evidence_malicious_cname_in_dns_response`.
            - Updates domain information in the database with the
            malicious status and additional threat intelligence data.
            - Adds the domain to a list of known malicious domains in the
             database.
        """

        if self.is_ignored_domain(cname):
            return False

        domain_info, is_subdomain = self.search_offline_for_domain(cname)
        if not domain_info:
            return False

        self.set_evidence_malicious_cname_in_dns_response(
            cname,
            dns_query,
            uid,
            timestamp,
            domain_info,
            is_subdomain,
            profileid,
            twid,
        )
        # mark this domain as malicious in our database
        domain_info = {"threatintelligence": domain_info}
        self.db.set_info_for_domains(cname, domain_info)

    def is_malicious_domain(
        self,
        domain,
        uid,
        timestamp,
        profileid,
        twid,
    ):
        """Evaluates a domain to determine if it is recognized as
        malicious based on
        threat intelligence data stored offline. If the domain is
        identified as
        malicious, it records an evidence entry and marks the
        domain in the database.

        Returns:
            bool: False if the domain is ignored or not found in the
            offline threat intelligence data, indicating no further action
             is required. Otherwise, it does not explicitly return
             a value but performs operations to record the
              malicious domain evidence.

        Side Effects:
            - Generates and stores an evidence entry for the malicious
            domain in the database.
            - Marks the domain as malicious in the database, enhancing
            the system's future recognition of this threat.
        """
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
        domain_info = {"threatintelligence": domain_info}
        self.db.set_info_for_domains(domain, domain_info)

    def update_local_file(self, filename):
        """Checks for updates to a specified local threat intelligence
        (TI) file by comparing its hash value against the stored hash in
        the database.
        If the file has been updated (i.e., the hash value has changed),
        the method updates the file's content in the database.

        Parameters:
            filename (str): The name of the local TI file.
            The file must be located in the `config/local_ti_files/`
            directory as specified by the `path_to_local_ti_files` attribute.

        Returns:
            bool: True if the file was updated in the database, False if no
             update was needed or if the operation failed.

        Note:
            - The method supports different types of TI files, including
             those containing JA3 and JARM hashes, by examining the
             `filename` for specific substrings (e.g., 'JA3', 'JARM')
             to determine the appropriate parsing method.
            - Ensures the database reflects the most current version
             of the TI file by updating both the content and the stored
             hash value upon detecting changes.

        Side Effects:
            - Modifies the database by adding new threat intelligence data
             and updating the stored hash for the processed file.
            - Implicitly depends on the correct implementation of
            `parse_ja3_file`, `parse_jarm_file`, and `parse_local_ti_file`
            methods to accurately update the database with the contents
             of the TI file.
        """
        fullpath = os.path.join(self.path_to_local_ti_files, filename)
        parsers = {
            "own_malicious_iocs.csv": self.parse_local_ti_file,
            "own_malicious_JA3.csv": self.parse_ja3_file,
            "own_malicious_JARM.csv": self.parse_jarm_file,
            "known_fp_md5_hashes.csv": self.parse_known_fp_hashes,
        }
        if filehash := self.should_update_local_ti_file(fullpath):
            parsers[filename](fullpath)
            # Store the new etag and time of file in the database
            malicious_file_info = {"hash": filehash}
            self.db.set_ti_feed_info(filename, malicious_file_info)
            return True

    def handle_pending_queries(self):
        """Processes the pending Circl.lu queries stored in the queue.
        This method runs as a daemon thread, executing a batch of up to 10
        queries every 2 minutes. After processing a batch, it waits for
        another 2 minutes before attempting the next batch of queries.
        This method continuously checks the queue for new items and
        processes them accordingly.

        Side Effects:
            - Calls `is_malicious_hash` for each flow information
            item retrieved from the queue.
            - Modifies the state of the `circllu_queue` by
            removing processed items.
        """
        max_queries = 10
        while not self.should_stop():
            time.sleep(120)
            try:
                flow_info = self.pending_queries.get(timeout=0.5)
            except Exception:
                # queue is empty wait extra 2 mins
                continue

            queries_done = 0
            while (
                not self.pending_queries.empty()
                and queries_done <= max_queries
            ):
                self.is_malicious_hash(flow_info)
                queries_done += 1

    def should_lookup(self, ip: str, protocol: str, ip_state: str) -> bool:
        """Return whether slips should lookup the given ip or not."""
        if utils.is_ignored_ip(ip):
            return False
        if self.is_outgoing_icmp_packet(protocol, ip_state):
            return False
        return True

    def pre_main(self):
        utils.drop_root_privs()
        # Load the local Threat Intelligence files that are
        # stored in the local folder self.path_to_local_ti_files
        # The remote files are being loaded by the update_manager
        local_files = (
            "own_malicious_iocs.csv",
            "own_malicious_JA3.csv",
            "own_malicious_JARM.csv",
            "known_fp_md5_hashes.csv",
        )
        for local_file in local_files:
            self.update_local_file(local_file)

        utils.start_thread(self.pending_circllu_calls_thread, self.db)

    def main(self):
        # The channel can receive an IP address or a domain name
        if msg := self.get_msg("give_threat_intelligence"):
            data = json.loads(msg["data"])
            profileid = data.get("profileid")
            twid = data.get("twid")
            timestamp = data.get("stime")
            uid = data.get("uid")
            protocol = data.get("proto")
            daddr = data.get("daddr")
            # these 2 are only available when looking up dns answers
            # the query is needed when a malicious answer is found,
            # for more detailed description of the evidence
            is_dns_response = data.get("is_dns_response")
            dns_query = data.get("dns_query")
            # this is the IP/domain that we want the TI for.
            to_lookup = data.get("to_lookup", "")
            # detect the type given because sometimes,
            # http.log host field has ips OR domains
            type_ = utils.detect_ioc_type(to_lookup)

            # ip_state can be "srcip" or "dstip"
            ip_state = data.get("ip_state")
            if type_ == "ip":
                ip = to_lookup
                if self.should_lookup(ip, protocol, ip_state):
                    self.is_malicious_ip(
                        ip,
                        uid,
                        daddr,
                        timestamp,
                        profileid,
                        twid,
                        ip_state,
                        dns_query=dns_query,
                        is_dns_response=is_dns_response,
                    )
                    self.ip_belongs_to_blacklisted_range(
                        ip, uid, daddr, timestamp, profileid, twid, ip_state
                    )
                    self.ip_has_blacklisted_asn(
                        ip,
                        uid,
                        timestamp,
                        profileid,
                        twid,
                        is_dns_response=is_dns_response,
                    )
            elif type_ == "domain":
                if is_dns_response:
                    self.is_malicious_cname(
                        dns_query, to_lookup, uid, timestamp, profileid, twid
                    )
                else:
                    self.is_malicious_domain(
                        to_lookup, uid, timestamp, profileid, twid
                    )
            elif type_ == "url":
                self.is_malicious_url(
                    to_lookup, uid, timestamp, daddr, profileid, twid
                )

        if msg := self.get_msg("new_downloaded_file"):
            file_info: dict = json.loads(msg["data"])
            # the format of file_info is as follows
            #  {
            #     'flow': asdict(self.flow),
            #     'type': 'suricata' or 'zeek',
            #     'profileid': str,
            #     'twid': str,
            # }

            if file_info["type"] == "zeek":
                self.is_malicious_hash(file_info)
