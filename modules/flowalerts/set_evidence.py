import datetime
import json
import sys
import time
from typing import List

from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import \
    (
        Evidence,
        ProfileID,
        TimeWindow,
        Victim,
        Attacker,
        ThreatLevel,
        EvidenceType,
        IoCType,
        Direction,
        IDEACategory,
        Tag
    )

class SetEvidnceHelper:
    def __init__(
            self,
            db
            ):
        self.db = db

    def young_domain(
        self,
        domain: str,
        age: int,
        stime: str,
        profileid: ProfileID,
        twid: str,
        uid: str
    ):
        saddr: str = profileid.split("_")[-1]
        victim = Victim(
                    direction=Direction.SRC,
                    victim_type=IoCType.IP,
                    value=saddr,
                    )
        attacker = Attacker(
                    direction=Direction.DST,
                    attacker_type=IoCType.DOMAIN,
                    value=domain,
                )
        twid_number: int =  int(twid.replace("timewindow", ""))
        description = f'connection to a young domain: {domain} ' \
                      f'registered {age} days ago.',
        evidence = Evidence(
                evidence_type=EvidenceType.YOUNG_DOMAIN,
                attacker=attacker,
                threat_level=ThreatLevel.LOW,
                category=IDEACategory.ANOMALY_TRAFFIC,
                description=description,
                victim=victim,
                profile=ProfileID(ip=saddr),
                timewindow=TimeWindow(number=twid_number),
                uid=[uid],
                timestamp=stime,
                conn_count=1,
                confidence=1.0
            )
        self.db.set_evidence(evidence)

    def multiple_ssh_versions(
        self,
        srcip: str,
        cached_versions: str,
        current_versions: str,
        timestamp: str,
        twid: str,
        uid: List[str],
        role: str = ''
    ):
        """
        :param cached_versions: major.minor
        :param current_versions: major.minor
        :param role: can be 'SSH::CLIENT' or
            'SSH::SERVER' as seen in zeek software.log flows
        """
        attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=srcip
            )
        role = 'client' if 'CLIENT' in role.upper() else 'server'
        description = f'SSH {role} version changing from ' \
                      f'{cached_versions} to {current_versions}'

        evidence = Evidence(
            evidence_type=EvidenceType.MULTIPLE_SSH_VERSIONS,
            attacker=attacker,
            threat_level=ThreatLevel.MEDIUM,
            category=IDEACategory.ANOMALY_TRAFFIC,
            description=description,
            profile=ProfileID(ip=attacker.value),
            timewindow=TimeWindow(int(twid.replace("timewindow", ''))),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=0.9,
            source_target_tag=Tag.RECON
        )
        self.db.set_evidence(evidence)

    def different_localnet_usage(
            self,
            daddr: str,
            portproto: str,
            profileid: ProfileID,
            timestamp: str,
            twid: str,
            uid: str,
            ip_outside_localnet: str = ''
    ):
        """
        :param ip_outside_localnet: was the
        'srcip' outside the localnet or the 'dstip'?
        """
        srcip = profileid.split('_')[-1]
        # the attacker here is the IP found to be private and outside the localnet
        if ip_outside_localnet == 'srcip':
            attacker = Attacker(
                direction=Direction.SRC,
                attacker_type=IoCType.IP,
                value=srcip
            )
            victim = Victim(
                direction=Direction.DST,
                victim_type=IoCType.IP,
                value=daddr
            )
            description = f'A connection from a private IP ({srcip}) ' \
                          f'outside of the used local network ' \
                          f'{self.db.get_local_network()}. To IP: {daddr} '
        else:
            attacker = Attacker(
                direction=Direction.DST,
                attacker_type=IoCType.IP,
                value=daddr
            )
            victim = Victim(
                direction=Direction.SRC,
                victim_type=IoCType.IP,
                value=srcip
            )
            description = f'A connection to a private IP ({daddr}) ' \
                          f'outside of the used local network ' \
                          f'{self.db.get_local_network()}. ' \
                          f'From IP: {srcip} '
            description += 'using ARP' if 'arp' in portproto \
                else f'on port: {portproto}'


        confidence = 1.0
        threat_level = ThreatLevel.HIGH

        evidence = Evidence(
            evidence_type=EvidenceType.DIFFERENT_LOCALNET,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory.ANOMALY_TRAFFIC,
            description=description,
            victim=victim,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )
        self.db.set_evidence(evidence)

    def device_changing_ips(
            self,
            smac: str,
            old_ip: str,
            profileid: str,
            twid: str,
            uid: str,
            timestamp: str
    ):
        confidence = 0.8
        threat_level = ThreatLevel.MEDIUM
        saddr: str = profileid.split("_")[-1]

        attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        description = f'A device changing IPs. IP {saddr} was found ' \
                      f'with MAC address {smac} but the MAC belongs ' \
                      f'originally to IP: {old_ip}. '

        twid_number = int(twid.replace("timewindow", ""))

        evidence = Evidence(
            evidence_type=EvidenceType.DEVICE_CHANGING_IP,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory.ANOMALY_TRAFFIC,
            description=description,
            victim=None,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)

    def non_http_port_80_conn(
            self,
            daddr: str,
            profileid: str,
            timestamp: str,
            twid: str,
            uid: str
    ) -> None:
        confidence = 0.8
        threat_level = ThreatLevel.MEDIUM
        saddr: str = profileid.split("_")[-1]

        attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        ip_identification: str = self.db.get_ip_identification(daddr)

        description: str = f'non-HTTP established connection to port 80. ' \
                           f'destination IP: {daddr} {ip_identification}'

        twid_number: int = int(twid.replace("timewindow", ""))

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.NON_HTTP_PORT_80_CONNECTION,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory.ANOMALY_TRAFFIC,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)

    def non_ssl_port_443_conn(
                self,
                daddr: str,
                profileid: str,
                timestamp: str,
                twid: str,
                uid: str
        ) -> None:
        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.MEDIUM
        saddr: str = profileid.split("_")[-1]

        attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )
        victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=daddr
            )

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = f'non-SSL established connection to port 443. ' \
                           f'destination IP: {daddr} {ip_identification}'

        twid_number: int = int(twid.replace("timewindow", ""))

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.NON_SSL_PORT_443_CONNECTION,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            category=IDEACategory.ANOMALY_TRAFFIC,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)

    def weird_http_method(
            self,
            profileid: str,
            twid: str,
            flow: dict
    ) -> None:
        daddr: str = flow['daddr']
        weird_method: str = flow['addl']
        uid: str = flow['uid']
        timestamp: str = flow['starttime']

        confidence = 0.9
        threat_level: ThreatLevel = ThreatLevel.MEDIUM
        saddr: str = profileid.split("_")[-1]

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        victim: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=daddr
        )

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = f'Weird HTTP method "{weird_method}" to IP: ' \
                           f'{daddr} {ip_identification}. by Zeek.'

        twid_number: int = int(twid.replace("timewindow", ""))

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.WEIRD_HTTP_METHOD,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            category=IDEACategory.ANOMALY_TRAFFIC,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)

    def incompatible_CN(
            self,
            org: str,
            timestamp: str,
            daddr: str,
            profileid: str,
            twid: str,
            uid: str
    ) -> None:
        confidence: float = 0.9
        threat_level: ThreatLevel = ThreatLevel.MEDIUM
        saddr: str = profileid.split("_")[-1]

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        victim: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=daddr
        )

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = f'Incompatible certificate CN to IP: {daddr} ' \
                           f'{ip_identification} claiming to ' \
                           f'belong {org.capitalize()}.'

        twid_number: int = int(twid.replace("timewindow", ""))
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.INCOMPATIBLE_CN,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            category=IDEACategory.ANOMALY_TRAFFIC,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)

    def DGA(
            self,
            nxdomains: int,
            stime: str,
            profileid: str,
            twid: str,
            uid: List[str]
    ) -> None:
        # for each non-existent domain beyond the threshold of 100,
        # the confidence score is increased linearly.
        # +1 ensures that the minimum confidence score is 1.
        confidence: float = max(0, (1 / 100) * (nxdomains - 100) + 1)
        confidence = round(confidence, 2)  # for readability
        threat_level = ThreatLevel.HIGH
        saddr = profileid.split("_")[-1]
        description = f'Possible DGA or domain scanning. {saddr} ' \
                      f'failed to resolve {nxdomains} domains'

        attacker = Attacker(
                direction=Direction.SRC,
                attacker_type=IoCType.IP,
                value=saddr
            )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.DGA_NXDOMAINS,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory.ANOMALY_BEHAVIOUR,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uid,
            timestamp=stime,
            conn_count=nxdomains,
            confidence=confidence,
            source_target_tag=Tag.ORIGIN_MALWARE
        )

        self.db.set_evidence(evidence)

    def DNS_without_conn(
        self,
        domain: str,
        timestamp: str,
        profileid: str,
        twid: str,
        uid: str
    ) -> None:
        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.LOW
        saddr: str = profileid.split("_")[-1]

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        description: str = f'domain {domain} resolved with no connection'

        twid_number: int = int(twid.replace("timewindow", ""))

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.DNS_WITHOUT_CONNECTION,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory.ANOMALY_TRAFFIC,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)

    def pastebin_download(
            self,
            bytes_downloaded: int,
            timestamp: str,
            profileid: str,
            twid: str,
            uid: str
    ) -> bool:

        threat_level: ThreatLevel = ThreatLevel.INFO
        confidence: float = 1.0
        saddr: str = profileid.split("_")[-1]
        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        response_body_len: float = utils.convert_to_mb(bytes_downloaded)
        description: str = f'A downloaded file from pastebin.com. ' \
                           f'size: {response_body_len} MBs'

        twid_number: int = int(twid.replace("timewindow", ""))
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.PASTEBIN_DOWNLOAD,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory.ANOMALY_BEHAVIOUR,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            source_target_tag=Tag.MALWARE,
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)
        return True

    def conn_without_dns(
            self,
            daddr: str,
            timestamp: str,
            profileid: str,
            twid: str,
            uid: str
    ) -> None:
        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.HIGH
        saddr: str = profileid.split("_")[-1]
        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        # The first 5 hours the confidence of connection w/o DNS
        # is 0.1 in case of interface only, until slips learns all the DNS
        start_time: float = self.db.get_slips_start_time()
        now: float = time.time()
        if '-i' in sys.argv or self.db.is_growing_zeek_dir():
            diff: float = utils.get_time_diff(
                start_time, now, return_type='hours'
                )
            if diff < 5:
                confidence = 0.1

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = f'A connection without DNS resolution to IP: ' \
                           f'{daddr} {ip_identification}'

        twid_number: int = int(twid.replace("timewindow", ""))
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.CONNECTION_WITHOUT_DNS,
            attacker=attacker,
            threat_level=threat_level,
            source_target_tag=Tag.MALWARE,
            category=IDEACategory.ANOMALY_CONNECTION,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)

    def dns_arpa_scan(
        self,
        arpa_scan_threshold: int,
        stime: str,
        profileid: str,
        twid: str,
        uid: List[str]
    ) -> bool:

        threat_level = ThreatLevel.MEDIUM
        confidence = 0.7
        saddr = profileid.split("_")[-1]

        description = f"Doing DNS ARPA scan. Scanned {arpa_scan_threshold}" \
                      f" hosts within 2 seconds."
        # Store attacker details in a local variable
        attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        # Create Evidence object using local variables
        evidence = Evidence(
            evidence_type=EvidenceType.DNS_ARPA_SCAN,
            description=description,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory.RECON_SCANNING,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uid,
            timestamp=stime,
            conn_count=arpa_scan_threshold,
            confidence=confidence,
        )

        # Store evidence in the database
        self.db.set_evidence(evidence)

        return True


    def unknown_port(
            self,
            daddr: str,
            dport: int,
            proto: str,
            timestamp: str,
            profileid: str,
            twid: str,
            uid: str
    ) -> None:
        confidence: float = 1.0
        twid_number: int = int(twid.replace("timewindow", ""))
        saddr = profileid.split('_')[-1]

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        victim: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=daddr
        )

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = (
            f'Connection to unknown destination port {dport}/{proto.upper()} '
            f'destination IP {daddr}. {ip_identification}'
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.UNKNOWN_PORT,
            attacker=attacker,
            victim=victim,
            threat_level=ThreatLevel.HIGH,
            category=IDEACategory.ANOMALY_CONNECTION,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)

    def pw_guessing(
            self,
            msg: str,
            timestamp: str,
            twid: str,
            uid: str,
            by: str = ''
    ) -> None:
        # 222.186.30.112 appears to be guessing SSH passwords
        # (seen in 30 connections)
        # confidence = 1 because this detection is comming
        # from a zeek file so we're sure it's accurate
        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.HIGH
        twid_number: int = int(twid.replace("timewindow", ""))
        scanning_ip: str = msg.split(' appears')[0]

        description: str = f'password guessing. {msg}. by {by}.'

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=scanning_ip
        )

        conn_count: int = int(msg.split('in ')[1].split('connections')[0])

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.PASSWORD_GUESSING,
            attacker=attacker,
            threat_level=threat_level,
            category= IDEACategory.ATTEMPT_LOGIN,
            description=description,
            profile=ProfileID(ip=scanning_ip),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=conn_count,
            confidence=confidence,
            source_target_tag=Tag.MALWARE
        )

        self.db.set_evidence(evidence)


    def horizontal_portscan(
            self,
            msg: str,
            timestamp: str,
            profileid: str,
            twid: str,
            uid: str
    ) -> None:
        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.HIGH
        twid_number: int = int(twid.replace("timewindow", ""))
        saddr = profileid.split('_')[-1]

        description: str = f'horizontal port scan by Zeek engine. {msg}'
        # get the number of unique hosts scanned on a specific port
        conn_count: int = int(msg.split('least')[1].split('unique')[0])

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.HORIZONTAL_PORT_SCAN,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory.RECON_SCANNING,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=conn_count,
            confidence=confidence,
            source_target_tag=Tag.RECON
        )

        self.db.set_evidence(evidence)


    def conn_to_private_ip(
            self,
            proto: str,
            daddr: str,
            dport: str,
            saddr: str,
            twid: str,
            uid: str,
            timestamp: str
    ) -> None:
        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.INFO
        twid_number: int = int(twid.replace("timewindow", ""))
        description: str = f'Connecting to private IP: {daddr} '

        if proto.lower() == 'arp' or dport == '':
            pass
        elif proto.lower() == 'icmp':
            description += 'protocol: ICMP'
        else:
            description += f'on destination port: {dport}'

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )
        victim: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=daddr
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.CONNECTION_TO_PRIVATE_IP,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory.RECON,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence,
            victim=victim
        )

        self.db.set_evidence(evidence)


    def GRE_tunnel(
            self,
            tunnel_info: dict
    ) -> None:
        profileid: str = tunnel_info['profileid']
        twid: str = tunnel_info['twid']
        tunnel_flow: str = tunnel_info['flow']

        action = tunnel_flow['action']
        daddr = tunnel_flow['daddr']
        ts = tunnel_flow['starttime']
        uid: str = tunnel_flow['uid']

        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.INFO
        twid_number: int = int(twid.replace("timewindow", ""))


        ip_identification: str = self.db.get_ip_identification(daddr)
        saddr: str = profileid.split('_')[-1]
        description: str = f'GRE tunnel from {saddr} ' \
                          f'to {daddr} {ip_identification} ' \
                          f'tunnel action: {action}'


        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )
        victim: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=daddr
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.GRE_TUNNEL,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            category=IDEACategory.INFO,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=ts,
            conn_count=1,
            confidence=confidence
        )

        self.db.set_evidence(evidence)


    def vertical_portscan(
            self,
            msg: str,
            scanning_ip: str,
            timestamp: str,
            twid: str,
            uid: str
    ) -> None:
        # confidence = 1 because this detection is coming
        # from a Zeek file so we're sure it's accurate
        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.HIGH
        twid: int = int(twid.replace("timewindow", ""))
        # msg example: 192.168.1.200 has scanned 60 ports of 192.168.1.102
        description: str = f'vertical port scan by Zeek engine. {msg}'
        conn_count: int = int(msg.split('least ')[1].split(' unique')[0])

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=scanning_ip
        )

        victim: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=msg.split('ports of host ')[-1].split(" in")[0]
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.VERTICAL_PORT_SCAN,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            category=IDEACategory.RECON_SCANNING,
            description=description,
            profile=ProfileID(ip=scanning_ip),
            timewindow=TimeWindow(number=twid),
            uid=[uid],
            timestamp=timestamp,
            conn_count=conn_count,
            confidence=confidence,
            source_target_tag=Tag.RECON

        )

        self.db.set_evidence(evidence)

    def ssh_successful(
            self,
            twid: str,
            saddr: str,
            daddr: str,
            size,
            uid: str,
            timestamp: str,
            by='',
        ) -> None:
        """
        Set an evidence for a successful SSH login.
        This is not strictly a detection, but we don't have
        a better way to show it.
        The threat_level is 0.01 to show that this is not a detection
        """

        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.INFO
        twid: int = int(twid.replace("timewindow", ""))

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )
        victim: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=daddr
        )

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = (
            f'SSH successful to IP {daddr}. {ip_identification}. '
            f'From IP {saddr}. Size: {str(size)}. Detection model {by}.'
            f' Confidence {confidence}'
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.SSH_SUCCESSFUL,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid),
            uid=[uid],
            timestamp=timestamp,
            category=IDEACategory.INFO,
        )

        self.db.set_evidence(evidence)

    def long_connection(
        self,
        daddr: str,
        duration,
        profileid: str,
        twid: str,
        uid: str,
        timestamp,
    ) -> None:
        """
        Set an evidence for a long connection.
        """
        threat_level: ThreatLevel = ThreatLevel.LOW
        twid: int = int(twid.replace("timewindow", ""))
        # Confidence depends on how long the connection.
        # Scale the confidence from 0 to 1; 1 means 24 hours long.
        confidence: float = 1 / (3600 * 24) * (duration - 3600 * 24) + 1
        confidence = round(confidence, 2)
        # Get the duration in minutes.
        duration_minutes: int = int(duration / 60)
        srcip: str = profileid.split('_')[1]

        attacker_obj: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=srcip
        )

        victim_obj: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=daddr
        )

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = (
            f'Long Connection. Connection from {srcip} '
            f'to destination address: {daddr} '
            f'{ip_identification} took {duration_minutes} mins'
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.LONG_CONNECTION,
            attacker=attacker_obj,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=twid),
            uid=[uid],
            timestamp=timestamp,
            category=IDEACategory.ANOMALY_CONNECTION,
            victim=victim_obj
        )

        self.db.set_evidence(evidence)

    def self_signed_certificates(
            self,
            profileid,
            twid,
            daddr,
            uid: str,
            timestamp,
            server_name
    ) -> None:
        """
        Set evidence for self-signed certificates.
        """
        confidence: float = 0.5
        threat_level: ThreatLevel = ThreatLevel.LOW
        saddr: str = profileid.split("_")[-1]
        twid: int = int(twid.replace("timewindow", ""))

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        ip_identification: str = self.db.get_ip_identification(daddr)
        description = f'Self-signed certificate. Destination IP: {daddr}.' \
                      f' {ip_identification}'

        if server_name:
            description += f' SNI: {server_name}.'

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.SELF_SIGNED_CERTIFICATE,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid),
            uid=[uid],
            timestamp=timestamp,
            category=IDEACategory.ANOMALY_BEHAVIOUR
        )

        self.db.set_evidence(evidence)

    def multiple_reconnection_attempts(
            self,
            profileid,
            twid,
            daddr,
            uid: List[str],
            timestamp,
            reconnections
    ) -> None:
        """
        Set evidence for Reconnection Attempts.
        """
        confidence: float = 0.5
        threat_level: ThreatLevel = ThreatLevel.MEDIUM
        saddr: str = profileid.split("_")[-1]
        twid: int = int(twid.replace("timewindow", ""))

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )

        victim: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=daddr
        )

        ip_identification = self.db.get_ip_identification(daddr)
        description = (
            f'Multiple reconnection attempts to Destination IP:'
            f' {daddr} {ip_identification} '
            f'from IP: {saddr} reconnections: {reconnections}'
        )
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.MULTIPLE_RECONNECTION_ATTEMPTS,
            attacker=attacker,
            victim = victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid),
            uid=uid,
            timestamp=timestamp,
            category=IDEACategory.ANOMALY_TRAFFIC
        )

        self.db.set_evidence(evidence)

    def connection_to_multiple_ports(
            self,
            profileid: str,
            twid: str,
            uid: List[str],
            timestamp: str,
            dstports: list,
            victim: str,
            attacker: str,
    ) -> None:
        """
        Set evidence for connection to multiple ports.
        """
        confidence: float = 0.5
        threat_level: ThreatLevel = ThreatLevel.INFO
        twid: int = int(twid.replace("timewindow", ""))
        ip_identification = self.db.get_ip_identification(attacker)
        description = f'Connection to multiple ports {dstports} of ' \
                      f'IP: {attacker}. {ip_identification}'

        if attacker in profileid:
            attacker_direction = Direction.SRC
            victim_direction = Direction.DST
            profile_ip = attacker
        else:
            attacker_direction = Direction.DST
            victim_direction = Direction.SRC
            profile_ip = victim

        victim: Victim = Victim(
                direction=victim_direction,
                victim_type=IoCType.IP,
                value=victim
            )
        attacker: Attacker = Attacker(
            direction=attacker_direction,
            attacker_type=IoCType.IP,
            value=attacker
        )

        evidence = Evidence(
            evidence_type=EvidenceType.CONNECTION_TO_MULTIPLE_PORTS,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=profile_ip),
            timewindow=TimeWindow(number=twid),
            uid=uid,
            timestamp=timestamp,
            category=IDEACategory.ANOMALY_CONNECTION
        )

        self.db.set_evidence(evidence)

    def suspicious_dns_answer(
            self,
            query: str,
            answer: str,
            entropy: float,
            daddr: str,
            profileid: str,
            twid: str,
            stime: str,
            uid: str
    ) -> None:
        confidence: float = 0.6
        threat_level: ThreatLevel = ThreatLevel.MEDIUM
        twid: int = int(twid.replace("timewindow", ""))
        saddr: str = profileid.split("_")[-1]

        attacker: Attacker = Attacker(
            direction=Direction.DST,
            attacker_type=IoCType.IP,
            value=daddr
        )
        victim: Victim = Victim(
                direction=Direction.SRC,
                victim_type=IoCType.IP,
                value=saddr
            )

        description: str = f'A DNS TXT answer with high entropy. ' \
                           f'query: {query} answer: "{answer}" ' \
                           f'entropy: {round(entropy, 2)} '

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.HIGH_ENTROPY_DNS_ANSWER,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=daddr),
            timewindow=TimeWindow(number=twid),
            uid=[uid],
            timestamp=stime,
            category=IDEACategory.ANOMALY_TRAFFIC
        )

        self.db.set_evidence(evidence)

    def invalid_dns_answer(
            self,
            query: str,
            answer: str,
            daddr: str,
            profileid: str,
            twid: str,
            stime: str,
            uid: str
    ) -> None:
        threat_level: ThreatLevel = ThreatLevel.INFO
        confidence: float = 0.7
        twid: int = int(twid.replace("timewindow", ""))
        saddr: str = profileid.split("_")[-1]

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )
        victim: Victim = Victim(
                direction=Direction.DST,
                victim_type=IoCType.IP,
                value=daddr
            )

        description: str = f"The DNS query {query} was resolved to {answer}"

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.INVALID_DNS_RESOLUTION,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid),
            uid=[uid],
            timestamp=stime,
            category=IDEACategory.ANOMALY_BEHAVIOUR
        )

        self.db.set_evidence(evidence)


    def for_port_0_connection(
        self,
        saddr: str,
        daddr: str,
        sport: int,
        dport: int,
        profileid: str,
        twid: str,
        uid: str,
        timestamp: str,
        victim: str,
        attacker: str
    ) -> None:
        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.HIGH

        if attacker in profileid:
            attacker_direction = Direction.SRC
            victim_direction = Direction.DST
            profile_ip = attacker
        else:
            attacker_direction = Direction.DST
            victim_direction = Direction.SRC
            profile_ip = victim

        victim: Victim = Victim(
                direction=victim_direction,
                victim_type=IoCType.IP,
                value=victim
            )
        attacker: Attacker = Attacker(
            direction=attacker_direction,
            attacker_type=IoCType.IP,
            value=attacker
        )

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = f'Connection on port 0 from {saddr}:{sport} ' \
                           f'to {daddr}:{dport}. {ip_identification}.'


        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.PORT_0_CONNECTION,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=profile_ip),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=timestamp,
            category=IDEACategory.ANOMALY_CONNECTION,
            source_target_tag=Tag.RECON,
            conn_count=1
        )

        self.db.set_evidence(evidence)


    def malicious_ja3(
        self,
        malicious_ja3_dict: dict,
        twid: str,
        uid: str,
        timestamp: str,
        victim: str,
        attacker: str,
        type_: str = '',
        ja3: str = '',
    ) -> None:
        """
        """
        ja3_info: dict = json.loads(malicious_ja3_dict[ja3])

        threat_level: str = ja3_info['threat_level'].upper()
        threat_level: ThreatLevel = ThreatLevel[threat_level]

        tags: str = ja3_info.get('tags', '')
        ja3_description: str = ja3_info['description']

        if type_ == 'ja3':
            description = f'Malicious JA3: {ja3} from source address ' \
                          f'{attacker} '
            evidence_type: EvidenceType = EvidenceType.MALICIOUS_JA3
            source_target_tag: Tag = Tag.BOTNET
            attacker_direction: Direction = Direction.SRC
            victim_direction: Direction = Direction.DST

        elif type_ == 'ja3s':
            description = (
                f'Malicious JA3s: (possible C&C server): {ja3} to server '
                f'{attacker} '
            )

            evidence_type: EvidenceType = EvidenceType.MALICIOUS_JA3S
            source_target_tag: Tag = Tag.CC
            attacker_direction: Direction = Direction.DST
            victim_direction: Direction = Direction.SRC
        else:
            return

        # append daddr identification to the description
        ip_identification: str = self.db.get_ip_identification(attacker)
        description += f'{ip_identification} '
        if ja3_description != 'None':
            description += f'description: {ja3_description} '
        description += f'tags: {tags}'

        attacker: Attacker = Attacker(
            direction=attacker_direction,
            attacker_type=IoCType.IP,
            value=attacker
        )
        victim: Victim = Victim(
                direction=victim_direction,
                victim_type=IoCType.IP,
                value=victim
        )
        confidence: float = 1
        evidence: Evidence = Evidence(
            evidence_type=evidence_type,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=attacker.value),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=timestamp,
            category=IDEACategory.INTRUSION_BOTNET,
            source_target_tag=source_target_tag
        )

        self.db.set_evidence(evidence)

    def data_exfiltration(
        self,
        daddr: str,
        src_mbs: float,
        profileid: str,
        twid: str,
        uid: List[str],
        timestamp
    ) -> None:
        confidence: float = 0.6
        threat_level: ThreatLevel = ThreatLevel.HIGH
        saddr: str = profileid.split("_")[-1]
        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )
        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = f'Large data upload. {src_mbs} MBs ' \
                           f'sent to {daddr} {ip_identification}'
        timestamp: str = utils.convert_format(timestamp, utils.alerts_format)

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.DATA_UPLOAD,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uid,
            timestamp=timestamp,
            category=IDEACategory.MALWARE,
            source_target_tag=Tag.ORIGIN_MALWARE
        )

        self.db.set_evidence(evidence)

    def bad_smtp_login(
            self,
            saddr: str,
            daddr: str,
            stime: str,
            twid: str,
            uid: str
    ) -> None:
        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.HIGH

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )
        victim = Victim(
                direction=Direction.DST,
                victim_type=IoCType.IP,
                value=daddr
            )
        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = f'doing bad SMTP login to {daddr} ' \
                           f'{ip_identification}'

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.BAD_SMTP_LOGIN,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=stime,
            category=IDEACategory.ATTEMPT_LOGIN
        )

        self.db.set_evidence(evidence)

    def smtp_bruteforce(
        self,
        flow: dict,
        twid: str,
        uid: List[str],
        smtp_bruteforce_threshold: int,
    ) -> None:
        saddr: str = flow['saddr']
        daddr: str = flow['daddr']
        stime: str = flow['starttime']

        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.HIGH

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = (
            f'doing SMTP login bruteforce to {daddr}. '
            f'{smtp_bruteforce_threshold} logins in 10 seconds. '
            f'{ip_identification}'
        )
        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
        )
        victim = Victim(
                direction=Direction.DST,
                victim_type=IoCType.IP,
                value=daddr
            )
        conn_count: int = smtp_bruteforce_threshold

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.SMTP_LOGIN_BRUTEFORCE,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uid,
            timestamp=stime,
            category=IDEACategory.ATTEMPT_LOGIN,
            conn_count=conn_count
        )

        self.db.set_evidence(evidence)

    def malicious_ssl(
            self,
            ssl_info: dict,
            ssl_info_from_db: dict
    ) -> None:
        flow: dict = ssl_info['flow']
        ts: str = flow.get('starttime', '')
        daddr: str = flow.get('daddr', '')
        uid: str = flow.get('uid', '')
        twid: str = ssl_info.get('twid', '')

        ssl_info_from_db: dict = json.loads(ssl_info_from_db)
        tags: str = ssl_info_from_db['tags']
        cert_description: str = ssl_info_from_db['description']

        confidence: float = 1.0
        threat_level: float = utils.threat_levels[
            ssl_info_from_db['threat_level']
        ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)

        ip_identification: str = self.db.get_ip_identification(daddr)
        description: str = f'Malicious SSL certificate to server {daddr}.' \
                           f'{ip_identification} description: ' \
                           f'{cert_description} {tags}  '


        attacker: Attacker = Attacker(
            direction=Direction.DST,
            attacker_type=IoCType.IP,
            value=daddr
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.MALICIOUS_SSL_CERT,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=daddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=ts,
            category=IDEACategory.INTRUSION_BOTNET,
            source_target_tag=Tag.CC
        )

        self.db.set_evidence(evidence)
