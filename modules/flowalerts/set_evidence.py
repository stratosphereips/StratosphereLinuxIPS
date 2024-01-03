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
        Anomaly,
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
        uid: List[str]
    ):
        src_profile = ProfileID(ip=profileid.split("_")[-1])
        victim = Victim(
                    direction=Direction.SRC,
                    victim_type=IoCType.IP,
                    value=src_profile.ip,
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
                category=IDEACategory(anomaly=Anomaly.TRAFFIC),
                description=description,
                victim=victim,
                profile=src_profile,
                timewindow=TimeWindow(number=twid_number),
                uid=uid,
                timestamp=stime,
                conn_count=1,
                confidence=1.0
            )
        self.db.setEvidence(evidence)

    def multiple_ssh_versions(
        self,
        srcip: str,
        dstip: str,
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
        profileid = ProfileID(ip=srcip)
        if role.upper() == 'CLIENT':
            attacker_direction = Direction.SRC
            victim_direction = Direction.DST
        else:
            attacker_direction = Direction.DST
            victim_direction = Direction.SRC

        attacker = Attacker(
            direction=attacker_direction,
            attacker_type=IoCType.IP,
            value=srcip
            )
        victim = Victim(
            direction=victim_direction,
            victim_type=IoCType.IP,
            value=dstip
            )
        role = 'client' if 'CLIENT' in role.upper() else 'server'
        description = f'SSH {role} version changing from ' \
                      f'{cached_versions} to {current_versions}'

        evidence = Evidence(
            evidence_type=EvidenceType.MULTIPLE_SSH_VERSIONS,
            attacker=attacker,
            threat_level=ThreatLevel.MEDIUM,
            category=IDEACategory(anomaly=Anomaly.TRAFFIC),
            description=description,
            victim=victim,
            profile=profileid,
            timewindow=TimeWindow(int(twid.replace("timewindow", ''))),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=0.9,
            source_target_tag=Tag.RECON
        )
        self.db.setEvidence(evidence)

    def different_localnet_usage(
            self,
            daddr: str,
            portproto: str,
            profileid: ProfileID,
            timestamp: str,
            twid: str,
            uid,
            ip_outside_localnet: str = ''
    ):
        """
        :param ip_outside_localnet: was the 'srcip' outside the localnet or the 'dstip'?
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
                          f'outside of the used local network {self.db.get_local_network()}. ' \
                          f'To IP: {daddr} '
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
                          f'outside of the used local network {self.db.get_local_network()}. ' \
                          f'From IP: {srcip} '
            description += 'using ARP' if 'arp' in portproto else f'on port: {portproto}'


        confidence = 1.0
        threat_level = ThreatLevel.HIGH
        category = IDEACategory(anomaly=Anomaly.TRAFFIC)
        evidence_type = EvidenceType.DIFFERENT_LOCALNET
        twid_number = int(twid.replace("timewindow", ""))

        evidence = Evidence(
            evidence_type=evidence_type,
            attacker=attacker,
            threat_level=threat_level,
            category=category,
            description=description,
            victim=victim,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )
        self.db.setEvidence(evidence)

    def device_changing_ips(
            self,
            smac: str,
            old_ip: str,
            profileid: str,
            twid: str,
            uid: List[str],
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
            category=IDEACategory(anomaly=Anomaly.TRAFFIC),
            description=description,
            victim=None,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.setEvidence(evidence)

    def non_http_port_80_conn(
            self,
            daddr: str,
            profileid: str,
            timestamp: str,
            twid: str,
            uid: List[str]
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
            category=IDEACategory(anomaly=Anomaly.TRAFFIC),
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.setEvidence(evidence)

    def non_ssl_port_443_conn(
                self,
                daddr: str,
                profileid: str,
                timestamp: str,
                twid: str,
                uid: List[str]
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
            category=IDEACategory(anomaly=Anomaly.TRAFFIC),
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.setEvidence(evidence)

    def weird_http_method(
            self,
            profileid: str,
            twid: str,
            flow: dict
    ) -> None:
        daddr: str = flow['daddr']
        weird_method: str = flow['addl']
        uid: List[str] = flow['uid']
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
        description: str = f'Weird HTTP method "{weird_method}" to IP: {daddr} ' \
                           f'{ip_identification}. by Zeek.'

        twid_number: int = int(twid.replace("timewindow", ""))

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.WEIRD_HTTP_METHOD,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            category=IDEACategory(anomaly=Anomaly.TRAFFIC),
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.setEvidence(evidence)

    def incompatible_CN(
            self,
            org: str,
            timestamp: str,
            daddr: str,
            profileid: str,
            twid: str,
            uid: List[str]
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
            category=IDEACategory(anomaly=Anomaly.TRAFFIC),
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.setEvidence(evidence)

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
                value=profileid.split('_')[1]
            )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.DGA_NXDOMAINS,
            attacker=attacker,
            threat_level=threat_level,
            category=IDEACategory(anomaly=Anomaly.BEHAVIOUR),
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uid,
            timestamp=stime,
            conn_count=nxdomains,
            confidence=confidence,
            source_target_tag=Tag.ORIGIN_MALWARE
        )

        self.db.setEvidence(evidence)

    def DNS_without_conn(
        self,
        domain: str,
        timestamp: str,
        profileid: str,
        twid: str,
        uid: List[str]
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
            category=IDEACategory(anomaly=Anomaly.TRAFFIC),
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.setEvidence(evidence)

    def pastebin_download(
            self,
            bytes_downloaded: int,
            timestamp: str,
            profileid: str,
            twid: str,
            uid: List[str]
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
            category=IDEACategory(anomaly=Anomaly.BEHAVIOUR),
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            source_target_tag=Tag.MALWARE,
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.setEvidence(evidence)
        return True

    def conn_without_dns(
            self,
            daddr: str,
            timestamp: str,
            profileid: str,
            twid: str,
            uid: List[str]
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
            category=IDEACategory(anomaly=Anomaly.CONNECTION),
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.setEvidence(evidence)

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
            category=IDEACategory.recon,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uid,
            timestamp=stime,
            conn_count=arpa_scan_threshold,
            confidence=confidence,
        )

        # Store evidence in the database
        self.db.setEvidence(evidence)

        return True


    def unknown_port(
            self,
            daddr: str,
            dport: int,
            proto: str,
            timestamp: str,
            profileid: str,
            twid: str,
            uid: List[str]
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
            category=IDEACategory(anomaly=Anomaly.CONNECTION),
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=1,
            confidence=confidence
        )

        self.db.setEvidence(evidence)

    def pw_guessing(
            self,
            msg: str,
            timestamp: str,
            twid: str,
            uid: List[str],
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
            category= IDEACategory.attempt_login,
            description=description,
            profile=ProfileID(ip=scanning_ip),
            timewindow=TimeWindow(number=twid_number),
            uid=uid,
            timestamp=timestamp,
            conn_count=conn_count,
            confidence=confidence,
            source_target_tag=Tag.MALWARE
        )

        self.db.setEvidence(evidence)

    def horizontal_portscan(
            self,
            msg,
            timestamp,
            profileid,
            twid,
            uid
            ):
        # 10.0.2.15 scanned at least 25 unique hosts on port 80/tcp in 0m33s
        confidence = 1
        threat_level = 'high'
        description = f'horizontal port scan by Zeek engine. {msg}'
        evidence_type = 'HorizontalPortscan'
        attacker_direction = 'srcip'
        source_target_tag = 'Recon'
        attacker = profileid.split('_')[-1]
        category = 'Recon.Scanning'
        # get the number of unique hosts scanned on a specific port
        conn_count = int(msg.split('least')[1].split('unique')[0])
        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence, description,
            timestamp,
			category,
			source_target_tag=source_target_tag,
            conn_count=conn_count,
            profileid=profileid,
            twid=twid,
            uid=uid
            )

    def conn_to_private_ip(
            self,
            proto,
            daddr,
            dport,
            saddr,
            profileid,
            twid,
            uid,
            timestamp
            ):

        confidence = 1
        threat_level = 'info'
        description = f'Connecting to private IP: {daddr} '
        if proto.lower() == 'arp' or dport == '':
            pass
        elif proto.lower() == 'icmp':
            description += 'protocol: ICMP'
        else:
            description += f'on destination port: {dport}'

        evidence_type = 'ConnectionToPrivateIP'
        category = 'Recon'
        attacker_direction = 'srcip'
        attacker = saddr
        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence, description,
            timestamp, category,
            profileid=profileid,
            twid=twid,
            uid=uid,
            victim=daddr
            )

    def GRE_tunnel(
            self,
            tunnel_info: dict
            ):
        tunnel_flow = tunnel_info['flow']
        profileid = tunnel_info['profileid']
        twid = tunnel_info['twid']

        action = tunnel_flow['action']
        daddr = tunnel_flow['daddr']
        ts = tunnel_flow['starttime']
        uid = tunnel_flow['uid']

        ip_identification = self.db.get_ip_identification(daddr)
        saddr = profileid.split('_')[-1]
        description = f'GRE tunnel from {saddr} ' \
                      f'to {daddr} {ip_identification} ' \
                      f'tunnel action: {action}'
        confidence = 1
        threat_level = 'info'
        evidence_type = 'GRETunnel'
        category = 'Info'
        self.db.setEvidence(
            evidence_type,
            'dstip',
            daddr,
            threat_level,
            confidence,
            description,
            ts,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
            )

    def vertical_portscan(
            self,
            msg,
            scanning_ip,
            timestamp,
            profileid,
            twid,
            uid
            ):
        """

        @rtype: object
        """
        # confidence = 1 because this detection is comming
        # from a zeek file so we're sure it's accurate
        confidence = 1
        threat_level = 'high'
        # msg example: 192.168.1.200 has scanned 60 ports of 192.168.1.102
        description = f'vertical port scan by Zeek engine. {msg}'
        evidence_type = 'VerticalPortscan'
        category = 'Recon.Scanning'
        attacker_direction = 'dstip'
        source_target_tag = 'Recon'
        conn_count = int(msg.split('least ')[1].split(' unique')[0])
        attacker = scanning_ip
        victim = msg.split('ports of ')[-1]
        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence, description,
            timestamp,
			category,
			source_target_tag=source_target_tag,
            conn_count=conn_count,
            profileid=profileid, twid=twid,
			uid=uid,
			victim=victim
            )

    def ssh_successful(
            self,
            profileid,
            twid,
            saddr,
            daddr,
            size,
            uid,
            timestamp,
            by='',
            ip_state='ip',
            ):
        """
        Set an evidence for a successful SSH login.
        This is not strictly a detection, but we don't have
        a better way to show it.
        The threat_level is 0.01 to show that this is not a detection
        """

        attacker_direction = 'srcip'
        attacker = saddr
        evidence_type = f'SSHSuccessful-by-{saddr}'
        threat_level = 'info'
        confidence = 0.8
        category = 'Infomation'
        ip_identification = self.db.get_ip_identification(daddr)
        description = (
            f'SSH successful to IP {daddr}. {ip_identification}. '
            f'From IP {saddr}. Size: {str(size)}. Detection model {by}.'
            f' Confidence {confidence}'
        )

        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence, description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
            victim=daddr
            )

    def long_connection(
            self,
            attacker,
            duration,
            profileid,
            twid,
            uid,
            timestamp,
            attacker_direction=''
            ):
        """
        Set an evidence for a long connection.
        """

        evidence_type = 'LongConnection'
        threat_level = 'low'
        category = 'Anomaly.Connection'
        # confidence depends on how long the connection
        # scale the confidence from 0 to 1, 1 means 24 hours long
        confidence = 1 / (3600 * 24) * (duration - 3600 * 24) + 1
        confidence = round(confidence, 2)
        ip_identification = self.db.get_ip_identification(attacker)
        # get the duration in minutes
        duration = int(duration / 60)
        srcip = profileid.split('_')[1]
        description = f'Long Connection. Connection from {srcip} ' \
                      f'to destination address: {attacker} ' \
                      f'{ip_identification} took {duration} mins'
        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence,
            description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
            victim=srcip
            )

    def self_signed_certificates(
            self,
            profileid,
            twid,
            attacker,
            description,
            uid,
            timestamp
            ):
        """
        Set evidence for self signed certificates.
        """
        confidence = 0.5
        threat_level = 'low'
        category = 'Anomaly.Behaviour'
        attacker_direction = 'dstip'
        evidence_type = 'SelfSignedCertificate'
        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence, description,
            timestamp, category, profileid=profileid, twid=twid, uid=uid
            )

    def for_multiple_reconnection_attempts(
            self,
            profileid,
            twid,
            attacker,
            description,
            uid,
            timestamp
            ):
        """
        Set evidence for Reconnection Attempts.
        """
        confidence = 0.5
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'dstip'
        evidence_type = 'MultipleReconnectionAttempts'

        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence, description,
            timestamp, category, profileid=profileid, twid=twid, uid=uid
            )

    def for_connection_to_multiple_ports(
            self,
            profileid,
            twid,
            ip,
            description,
            uid,
            timestamp
            ):
        """
        Set evidence for connection to multiple ports.
        """
        confidence = 0.5
        threat_level = 'medium'
        category = 'Anomaly.Connection'
        attacker_direction = 'dstip'
        evidence_type = 'ConnectionToMultiplePorts'
        attacker = ip

        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence, description,
            timestamp,
            category,
            profileid=profileid, twid=twid, uid=uid
            )

    def suspicious_dns_answer(
            self,
            query,
            answer,
            entropy,
            daddr,
            profileid,
            twid,
            stime,
            uid
            ):
        confidence = 0.6
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        evidence_type = 'HighEntropyDNSanswer'
        attacker_direction = 'dstip'
        attacker = daddr
        description = f'A DNS TXT answer with high entropy. ' \
                      f'query: {query} answer: "{answer}" entropy: {round(entropy, 2)} '
        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence,
            description,
            stime,
			category,
			profileid=profileid,
			twid=twid,
			uid=uid
            )

    def invalid_dns_answer(
            self,
            query,
            answer,
            daddr,
            profileid,
            twid,
            stime,
            uid
            ):
        evidence_type = "InvalidDNSResolution"
        attacker_direction = "dst_domain"
        attacker = query
        threat_level = "info"
        confidence = 0.7
        description = f"The DNS query {query} was resolved to {answer}"
        timestamp = stime
        category = "Anamoly.Behaviour"
        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence, description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid
            )

    def for_port_0_connection(
            self,
            saddr,
            daddr,
            sport,
            dport,
            direction,
            profileid,
            twid,
            uid,
            timestamp
            ):
        """:param direction: 'source' or 'destination'"""
        confidence = 0.8
        threat_level = 'high'
        category = 'Anomaly.Connection'
        source_target_tag = 'Recon'
        evidence_type = 'Port0Connection'

        if direction == 'source':
            attacker = saddr
            attacker_direction = 'srcip'
            victim = daddr
        else:
            attacker = daddr
            attacker_direction = 'dstip'
            victim = saddr

        ip_identification = self.db.get_ip_identification(daddr)
        description = f'Connection on port 0 from {saddr}:{sport} ' \
                      f'to {daddr}:{dport}. {ip_identification}.'

        conn_count = 1

        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence, description,
            timestamp,
			category,
			source_target_tag=source_target_tag,
            conn_count=conn_count,
            profileid=profileid,
            twid=twid,
            uid=uid,
            victim=victim
            )

    def malicious_JA3(
            self,
            malicious_ja3_dict,
            ip,
            profileid,
            twid,
            uid,
            timestamp,
            victim,
            type_='',
            ioc='',
            ):
        malicious_ja3_dict = json.loads(malicious_ja3_dict[ioc])
        tags = malicious_ja3_dict.get('tags', '')
        ja3_description = malicious_ja3_dict['description']
        threat_level = malicious_ja3_dict['threat_level']

        if type_ == 'ja3':
            description = f'Malicious JA3: {ioc} from source address {ip} '
            evidence_type = 'MaliciousJA3'
            category = 'Intrusion.Botnet'
            source_target_tag = 'Botnet'
            attacker_direction = 'srcip'

        elif type_ == 'ja3s':
            description = (
                f'Malicious JA3s: (possible C&C server): {ioc} to server {ip} '
            )
            evidence_type = 'MaliciousJA3s'
            category = 'Intrusion.Botnet'
            source_target_tag = 'CC'
            attacker_direction = 'dstip'

        # append daddr identification to the description
        ip_identification = self.db.get_ip_identification(ip)
        description += f'{ip_identification}  '

        if ja3_description != 'None':
            description += f'description: {ja3_description} '

        description += f'tags: {tags}'
        attacker = ip
        confidence = 1

        self.db.setEvidence(
            evidence_type,
			attacker_direction,
			attacker,
			threat_level,
            confidence,
            description,
            timestamp,
			category,
			source_target_tag=source_target_tag,
            profileid=profileid,
            twid=twid,
			uid=uid,
			victim=victim
            )

    def data_exfiltration(
            self,
            daddr,
            src_mbs,
            profileid,
            twid,
            uid,
            ):
        confidence = 0.6
        threat_level = 'high'
        attacker_direction = 'dstip'
        source_target_tag = 'OriginMalware'
        evidence_type = 'DataUpload'
        category = 'Malware'
        attacker = daddr
        ip_identification = self.db.get_ip_identification(
            daddr
            )
        description = f'Large data upload. {src_mbs} MBs sent to {daddr} '
        description += f'{ip_identification}'
        timestamp = utils.convert_format(
            datetime.datetime.now(), utils.alerts_format
            )
        self.db.setEvidence(
            evidence_type,
            attacker_direction,
            attacker,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            source_target_tag=source_target_tag,
            profileid=profileid,
            twid=twid,
            uid=uid
            )

    def bad_smtp_login(
            self,
            saddr,
            daddr,
            stime,
            profileid,
            twid,
            uid
            ):
        confidence = 1
        threat_level = 'high'
        category = 'Attempt.Login'
        evidence_type = 'BadSMTPLogin'
        attacker_direction = 'srcip'
        attacker = saddr
        ip_identification = self.db.get_ip_identification(daddr)
        description = (
            f'doing bad SMTP login to {daddr} {ip_identification}'
        )

        self.db.setEvidence(
            evidence_type,
            attacker_direction,
            attacker,
            threat_level,
            confidence,
            description,
            stime,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
            victim=daddr
            )

    def smtp_bruteforce(
            self,
            flow: dict,
            profileid,
            twid,
            uid,
            smtp_bruteforce_threshold,
            ):
        saddr = flow['saddr']
        daddr = flow['daddr']
        stime = flow['starttime']

        confidence = 1
        threat_level = 'high'
        category = 'Attempt.Login'
        attacker_direction = 'srcip'
        evidence_type = 'SMTPLoginBruteforce'
        ip_identification = self.db.get_ip_identification(daddr)
        description = f'doing SMTP login bruteforce to {daddr}. ' \
                      f'{smtp_bruteforce_threshold} logins in 10 seconds. ' \
                      f'{ip_identification}'
        attacker = saddr
        conn_count = smtp_bruteforce_threshold

        self.db.setEvidence(
            evidence_type,
            attacker_direction,
            attacker,
            threat_level,
            confidence,
            description,
            stime,
            category,
            conn_count=conn_count,
            profileid=profileid,
            twid=twid,
            uid=uid,
            victim=daddr
            )

    def malicious_ssl(
            self,
            ssl_info: dict,
            ssl_info_from_db: dict
            ):
        """
        This function only works on zeek files.log flows
        :param ssl_info: info about this ssl cert as found in zeek
        :param ssl_info_from_db: ti feed, tags, description of this malicious cert
        """
        flow: dict = ssl_info['flow']
        ts = flow.get('starttime', '')
        daddr = flow.get('daddr', '')
        uid = flow.get('uid', '')

        profileid = ssl_info.get('profileid', '')
        twid = ssl_info.get('twid', '')

        ssl_info_from_db = json.loads(ssl_info_from_db)
        tags = ssl_info_from_db['tags']
        cert_description = ssl_info_from_db['description']
        threat_level = ssl_info_from_db['threat_level']

        description = f'Malicious SSL certificate to server {daddr}.'
        # append daddr identification to the description
        ip_identification = self.db.get_ip_identification(daddr)
        description += (
            f'{ip_identification} description: {cert_description} {tags}  '
        )

        evidence_type = 'MaliciousSSLCert'
        category = 'Intrusion.Botnet'
        source_target_tag = 'CC'
        attacker_direction = 'dstip'

        attacker = daddr
        confidence = 1
        self.db.setEvidence(
            evidence_type,
            attacker_direction,
            attacker,
            threat_level,
            confidence,
            description,
            ts,
            category,
            source_target_tag=source_target_tag,
            profileid=profileid,
            twid=twid,
            uid=uid
            )
