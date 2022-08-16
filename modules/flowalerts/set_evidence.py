# Must imports
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils

# Your imports
import json
import datetime
import time
import sys


class Helper:
    def set_evidence_young_domain(
        self, domain, age, stime, profileid, twid, uid
    ):
        confidence = 1
        threat_level = 'low'
        category = 'Anomaly.Traffic'
        type_evidence = 'YoungDomain'
        type_detection = 'dstdomain'
        detection_info = domain
        description = f'connection to a young domain: {domain} registered {age} days ago.'

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            stime,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_multiple_ssh_versions(
        self, srcip, cached_versions, current_versions, timestamp, twid, uid
    ):
        """
        :param cached_versions: major.minor
        :param current_versions: major.minor
        """
        profileid = f'profile_{srcip}'
        confidence = 0.9
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        type_detection = 'srcip'
        type_evidence = 'MultipleSSHVersions'
        detection_info = srcip
        description = f'Possible SSH bruteforce by using multiple SSH versions {cached_versions} then {current_versions}'
        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_DGA(self, nxdomains: int, stime, profileid, twid, uid):
        confidence = (1 / 100) * (nxdomains - 100) + 1
        confidence = round(confidence, 2)   # for readability
        threat_level = 'high'
        category = 'Intrusion.Botnet'
        # the srcip performing all the dns queries
        type_detection = 'srcip'
        source_target_tag = 'OriginMalware'
        type_evidence = f'DGA-{nxdomains}-NXDOMAINs'
        detection_info = profileid.split('_')[1]
        description = f'possible DGA or domain scanning. {detection_info} failed to resolve {nxdomains} domains'
        conn_count = nxdomains

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            stime,
            category,
            source_target_tag=source_target_tag,
            conn_count=conn_count,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_DNS_without_conn(
        self, domain, timestamp, profileid, twid, uid
    ):
        confidence = 0.8
        threat_level = 'low'
        category = 'Anomaly.Traffic'
        type_detection = 'dstdomain'
        type_evidence = 'DNSWithoutConnection'
        detection_info = domain
        description = f'domain {domain} resolved with no connection'
        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_conn_without_dns(
        self, daddr, timestamp, profileid, twid, uid
    ):
        # uid {uid}. time {datetime.datetime.now()}')
        threat_level = 'high'
        category = 'Anomaly.Connection'
        type_detection = 'dstip'
        source_target_tag = 'Malware'
        type_evidence = 'ConnectionWithoutDNS'
        detection_info = daddr
        # the first 5 hours the confidence of connection w/o dns
        # is 0.1  in case of interface only, until slips learns all the dns
        start_time = __database__.get_slips_start_time()
        now = time.time()
        confidence = 0.8
        if '-i' in sys.argv:
            diff = utils.get_time_diff(start_time, now, return_type='hours')
            if diff < 5:
                confidence = 0.1


        ip_identification = __database__.getIPIdentification(daddr)
        description = f'a connection without DNS resolution to IP: {daddr} {ip_identification}'
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

    def set_evidence_dns_arpa_scan(
        self, arpa_scan_threshold, stime, profileid, twid, uid
    ):
        confidence = 0.7
        threat_level = 'medium'
        category = 'Recon.Scanning'
        type_detection = 'srcip'
        type_evidence = 'DNS-ARPA-Scan'
        description = f'performing DNS ARPA scan. Scanned {arpa_scan_threshold} hosts within 2 seconds.'
        detection_info = profileid.split('_')[1]

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            stime,
            category,
            conn_count=arpa_scan_threshold,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_unknown_port(
        self, daddr, dport, proto, timestamp, profileid, twid, uid
    ):
        confidence = 1
        threat_level = 'high'
        category = 'Anomaly.Connection'
        type_detection = 'dstip'
        type_evidence = 'UnknownPort'
        detection_info = daddr
        ip_identification = __database__.getIPIdentification(daddr)
        description = (
            f'Connection to unknown destination port {dport}/{proto.upper()} '
            f'destination IP {daddr}. {ip_identification}'
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
            port=dport,
            proto=proto,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_pw_guessing(self, msg, timestamp, profileid, twid, uid):
        # 222.186.30.112 appears to be guessing SSH passwords (seen in 30 connections)
        # confidence = 1 because this detection is comming from a zeek file so we're sure it's accurate
        confidence = 1
        threat_level = 'high'
        category = 'Attempt.Login'
        description = f'password guessing by Zeek enegine. {msg}'
        type_evidence = 'Password_Guessing'
        type_detection = 'srcip'
        source_target_tag = 'Malware'
        detection_info = msg.split(' appears')[0]
        conn_count = int(msg.split('in ')[1].split('connections')[0])
        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            conn_count=conn_count,
            source_target_tag=source_target_tag,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_horizontal_portscan(
        self, msg, scanned_port, timestamp, profileid, twid, uid
    ):
        # 10.0.2.15 scanned at least 25 unique hosts on port 80/tcp in 0m33s
        confidence = 1
        threat_level = 'medium'
        description = f'horizontal port scan by Zeek engine. {msg}'
        type_evidence = 'PortScanType2'
        type_detection = 'dport'
        source_target_tag = 'Recon'
        detection_info = scanned_port
        category = 'Recon.Scanning'
        # get the number of unique hosts scanned on a specific port
        conn_count = int(msg.split('least')[1].split('unique')[0])
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
            conn_count=conn_count,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_vertical_portscan(
        self, msg, scanning_ip, timestamp, profileid, twid, uid
    ):
        # confidence = 1 because this detection is comming from a zeek file so we're sure it's accurate
        confidence = 1
        threat_level = 'medium'
        # msg example: 192.168.1.200 has scanned 60 ports of 192.168.1.102
        description = f'vertical port scan by Zeek engine. {msg}'
        type_evidence = 'PortScanType1'
        category = 'Recon.Scanning'
        type_detection = 'dstip'
        source_target_tag = 'Recon'
        conn_count = int(msg.split('scanned')[1].split('ports')[0])
        detection_info = scanning_ip
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
            conn_count=conn_count,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_ssh_successful(
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

        type_detection = 'srcip'
        detection_info = saddr
        type_evidence = f'SSHSuccessful-by-{saddr}'
        threat_level = 'info'
        confidence = 0.5
        category = 'Infomation'
        ip_identification = __database__.getIPIdentification(daddr)
        description = (
            f'SSH successful to IP {daddr}. {ip_identification}. '
            f'From IP {saddr}. Size: {str(size)}. Detection model {by}.'
            f' Confidence {confidence}'
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
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_long_connection(
        self, ip, duration, profileid, twid, uid, timestamp, ip_state='ip'
    ):
        """
        Set an evidence for a long connection.
        """

        type_detection = ip_state
        detection_info = ip
        type_evidence = 'LongConnection'
        threat_level = 'low'
        category = 'Anomaly.Connection'
        # confidence depends on how long the connection
        # scale the confidence from 0 to 1, 1 means 24 hours long
        confidence = 1 / (3600 * 24) * (duration - 3600 * 24) + 1
        confidence = round(confidence, 2)
        ip_identification = __database__.getIPIdentification(ip)
        # get the duration in minutes
        duration = int(duration / 60)
        srcip = profileid.split('_')[1]
        description = f'Long Connection. Connection from {srcip} to destination address: {ip} ' \
                      f'{ip_identification} took {duration} mins'
        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_self_signed_certificates(
        self, profileid, twid, ip, description, uid, timestamp
    ):
        """
        Set evidence for self signed certificates.
        """
        confidence = 0.5
        threat_level = 'low'
        category = 'Anomaly.Behaviour'
        type_detection = 'dstip'
        type_evidence = 'SelfSignedCertificate'
        detection_info = ip

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_for_multiple_reconnection_attempts(
        self, profileid, twid, ip, description, uid, timestamp
    ):
        """
        Set evidence for Reconnection Attempts.
        """
        confidence = 0.5
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        type_detection = 'dstip'
        type_evidence = 'MultipleReconnectionAttempts'
        detection_info = ip

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_for_connection_to_multiple_ports(
        self, profileid, twid, ip, description, uid, timestamp
    ):
        """
        Set evidence for connection to multiple ports.
        """
        confidence = 0.5
        threat_level = 'medium'
        category = 'Anomaly.Connection'
        type_detection = 'dstip'
        type_evidence = 'ConnectionToMultiplePorts'
        detection_info = ip

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_for_invalid_certificates(
        self, profileid, twid, ip, description, uid, timestamp
    ):
        """
        Set evidence for Invalid SSL certificates.
        """
        confidence = 0.5
        threat_level = 'low'
        category = 'Anomaly.Behaviour'
        type_detection = 'dstip'
        type_evidence = 'InvalidCertificate'
        detection_info = ip

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_for_port_0_connection(
        self, saddr, daddr, direction, profileid, twid, uid, timestamp
    ):
        """:param direction: 'source' or 'destination'"""
        confidence = 0.8
        threat_level = 'high'
        category = 'Anomaly.Connection'
        type_detection = 'srcip' if direction == 'source' else 'dstip'
        source_target_tag = 'Recon'
        type_evidence = 'Port0Connection'
        detection_info = saddr if direction == 'source' else daddr

        if direction == 'source':
            ip_identification = __database__.getIPIdentification(daddr)
            description = f'Connection on port 0 from {saddr} to {daddr}. {ip_identification}.'
        else:
            ip_identification = __database__.getIPIdentification(saddr)
            description = f'Connection on port 0 from {daddr} to {saddr}. {ip_identification}'

        conn_count = 1

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
            conn_count=conn_count,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_malicious_JA3(
        self,
        malicious_ja3_dict,
        ip,
        profileid,
        twid,
        uid,
        timestamp,
        type_='',
        ioc='',
    ):
        malicious_ja3_dict = json.loads(malicious_ja3_dict[ioc])
        tags = malicious_ja3_dict['tags']
        ja3_description = malicious_ja3_dict['description']
        threat_level = malicious_ja3_dict['threat_level']

        if type_ == 'ja3':
            description = f'Malicious JA3: {ioc} from source address {ip} '
            type_evidence = 'MaliciousJA3'
            category = 'Intrusion.Botnet'
            source_target_tag = 'Botnet'
            type_detection = 'srcip'
        elif type_ == 'ja3s':
            description = (
                f'Malicious JA3s: (possible C&C server): {ioc} to server {ip} '
            )
            type_evidence = 'MaliciousJA3s'
            category = 'Intrusion.Botnet'
            source_target_tag = 'CC'
            type_detection = 'dstip'

        # append daddr identification to the description
        ip_identification = __database__.getIPIdentification(ip)
        description += (
            f'{ip_identification} description: {ja3_description} {tags}'
        )

        detection_info = ip
        confidence = 1

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

    def set_evidence_data_exfiltration(
        self,
        most_contacted_daddr,
        total_mbytes,
        times_contacted,
        profileid,
        twid,
        uid,
    ):
        confidence = 0.6
        threat_level = 'high'
        type_detection = 'dstip'
        source_target_tag = 'OriginMalware'
        type_evidence = 'DataUpload'
        category = 'Malware'
        detection_info = most_contacted_daddr
        ip_identification = __database__.getIPIdentification(
            most_contacted_daddr
        )
        description = f'possible data upload. {total_mbytes} MBs sent to {most_contacted_daddr} '
        description += f'IP contacted {times_contacted} times in the past 1h. {ip_identification}'
        timestamp = utils.convert_format(datetime.datetime.now(), utils.alerts_format)
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
            uid=uid
        )

    def set_evidence_bad_smtp_login(
        self, saddr, daddr, stime, profileid, twid, uid
    ):
        confidence = 1
        threat_level = 'high'
        category = 'Attempt.Login'
        type_evidence = 'BadSMTPLogin'
        type_detection = 'srcip'
        detection_info = saddr
        ip_identification = __database__.getIPIdentification(daddr)
        description = (
            f'performing bad SMTP login to {daddr} {ip_identification}'
        )

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            stime,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_smtp_bruteforce(
        self,
        saddr,
        daddr,
        stime,
        profileid,
        twid,
        uid,
        smtp_bruteforce_threshold,
    ):
        confidence = 1
        threat_level = 'high'
        category = 'Attempt.Login'
        type_detection = 'srcip'
        type_evidence = 'SMTPLoginBruteforce'
        ip_identification = __database__.getIPIdentification(daddr)
        description = f'performing SMTP login bruteforce to {daddr}. {smtp_bruteforce_threshold} logins in 10 seconds. {ip_identification}'
        detection_info = saddr
        conn_count = smtp_bruteforce_threshold

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            stime,
            category,
            conn_count=conn_count,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def set_evidence_malicious_ssl(
        self, ssl_info: dict, ssl_info_from_db: dict
    ):
        """
        :param ssl_info: info about this ssl cert as found in zeek
        :param ssl_info_from_db: ti feed, tags, description of this malicious cert
        """
        profileid = ssl_info.get('profileid', '')
        twid = ssl_info.get('twid', '')
        ts = ssl_info.get('ts', '')
        daddr = ssl_info.get('daddr', '')
        uid = ssl_info.get('uid', '')
        ssl_info_from_db = json.loads(ssl_info_from_db)
        tags = ssl_info_from_db['tags']
        cert_description = ssl_info_from_db['description']
        threat_level = ssl_info_from_db['threat_level']
        description = f'Malicious SSL certificate to server {daddr}.'
        # append daddr identification to the description
        ip_identification = __database__.getIPIdentification(daddr)
        description += (
            f'{ip_identification} description: {cert_description} {tags}  '
        )

        type_evidence = 'MaliciousSSLCert'
        category = 'Intrusion.Botnet'
        source_target_tag = 'CC'
        type_detection = 'dstip'

        detection_info = daddr
        confidence = 1
        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            ts,
            category,
            source_target_tag=source_target_tag,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )
