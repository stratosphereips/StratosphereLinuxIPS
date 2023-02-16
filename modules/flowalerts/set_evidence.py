# Must imports
from slips_files.core.database.database import __database__
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
        evidence_type = 'YoungDomain'
        attacker_direction = 'dstdomain'
        attacker = domain
        description = f'connection to a young domain: {domain} registered {age} days ago.'

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 stime, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_multiple_ssh_versions(
        self, srcip, cached_versions, current_versions, timestamp, twid, uid, role=''
    ):
        """
        :param cached_versions: major.minor
        :param current_versions: major.minor
        :param role: can be 'SSH::CLIENT' or 'SSH::SERVER' as seen in zeek software.log flows
        """
        profileid = f'profile_{srcip}'
        confidence = 0.9
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'srcip'
        evidence_type = 'MultipleSSHVersions'
        attacker = srcip
        role = 'client' if 'CLIENT' in role else 'server'
        description = f'SSH {role} version changing from {cached_versions} to {current_versions}'
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_different_localnet_usage(
            self,
            daddr,
            portproto,
            profileid,
            timestamp,
            twid,
            uid,
            ip_outside_localnet: str=''
    ):
        """
        :param ip_outside_localnet: was the 'srcip' outside the localnet or the 'dstip'?
        """
        srcip = profileid.split('_')[-1]
        # the attacker here is the IP found to be private and outside th localnet
        if ip_outside_localnet == 'srcip':
            attacker = srcip
            victim = daddr
            direction = 'from'
            rev_direction = 'to'
        else:
            attacker = daddr
            victim = srcip
            direction = 'to'
            rev_direction = 'from'

        confidence = 1
        threat_level = 'high'
        category = 'Anomaly.Traffic'
        attacker_direction = ip_outside_localnet
        evidence_type = 'DifferentLocalnet'
        localnet = __database__.get_local_network()
        description = f'A connection {direction} a private IP ({attacker}) ' \
                      f'outside of the used local network {localnet}.' \
                      f' {rev_direction} IP: {victim} '\

        if ip_outside_localnet == 'dstip':
            if 'arp' in portproto:
                description += f'using ARP'
            else:
                description += f'on port: {portproto}'

        __database__.setEvidence(
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
            uid=uid
        )


    def set_evidence_device_changing_ips(
            self,
            smac,
            old_ip,
            profileid,
            twid,
            uid,
            timestamp
    ):
        confidence = 0.8
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'srcip'
        evidence_type = 'DeviceChangingIP'
        saddr = profileid.split("_")[-1]
        attacker = saddr
        description = f'A device changing IPs. IP {saddr} was found ' \
                      f'with MAC address {smac} but the MAC belongs originally to IP: {old_ip}. '

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_non_http_port_80_conn(
        self, daddr ,profileid,timestamp, twid, uid
    ):
        confidence = 0.8
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'dstip'
        evidence_type = 'Non-HTTP-Port-80-Connection'
        attacker = daddr
        ip_identification = __database__.getIPIdentification(daddr)

        description = f'non-HTTP established connection to port 80.' \
                      f' destination IP: {daddr} {ip_identification}'
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_non_ssl_port_443_conn(
        self, daddr ,profileid,timestamp, twid, uid
    ):
        confidence = 0.8
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'dstip'
        evidence_type = 'Non-SSL-Port-443-Connection'
        attacker = daddr
        ip_identification = __database__.getIPIdentification(daddr)
        description = f'non-SSL established connection to port 443.' \
                      f' destination IP: {daddr} {ip_identification}'

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)


    def set_evidence_weird_http_method(
        self,
        profileid,
        twid,
        daddr,
        weird_method,
        uid,
        timestamp,
    ):
        confidence = 0.9
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'srcip'
        evidence_type = 'WeirdHTTPMethod'
        attacker = profileid.split("_")[-1]
        ip_identification = __database__.getIPIdentification(daddr)
        description = f'Weird HTTP method "{weird_method}" to IP: {daddr} {ip_identification}. by Zeek.'
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)


    def set_evidence_incompatible_CN(
        self, org, timestamp, daddr, profileid, twid, uid
    ):
        """
        :param prg: the org this ip/domain claims it belongs to
        """
        confidence = 0.9
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'srcip'
        evidence_type = 'IncompatibleCN'
        attacker = daddr
        ip_identification = __database__.getIPIdentification(daddr)
        description = f'Incompatible certificate CN to IP: {daddr} {ip_identification} claiming to belong {org.capitalize()}.'
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)


    def set_evidence_DGA(self, nxdomains: int, stime, profileid, twid, uid):
        confidence = (1 / 100) * (nxdomains - 100) + 1
        confidence = round(confidence, 2)   # for readability
        threat_level = 'high'
        category = 'Intrusion.Botnet'
        # the srcip doing all the dns queries
        attacker_direction = 'srcip'
        source_target_tag = 'OriginMalware'
        evidence_type = f'DGA-{nxdomains}-NXDOMAINs'
        attacker = profileid.split('_')[1]
        description = f'possible DGA or domain scanning. {attacker} failed to resolve {nxdomains} domains'
        conn_count = nxdomains

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 stime, category, source_target_tag=source_target_tag, conn_count=conn_count,
                                 profileid=profileid, twid=twid, uid=uid)

    def set_evidence_DNS_without_conn(
        self, domain, timestamp, profileid, twid, uid
    ):
        confidence = 0.8
        threat_level = 'low'
        category = 'Anomaly.Traffic'
        attacker_direction = 'dstdomain'
        evidence_type = 'DNSWithoutConnection'
        attacker = domain
        description = f'domain {domain} resolved with no connection'
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)


    def set_evidence_pastebin_download(
            self, daddr, bytes_downloaded, timestamp, profileid, twid, uid
       ):
        attacker_direction = 'dstip'
        source_target_tag = 'Malware'
        attacker = daddr
        evidence_type = 'PastebinDownload'
        threat_level = 'info'
        category = 'Anomaly.Behaviour'
        confidence = 1
        response_body_len = utils.convert_to_mb(bytes_downloaded)
        description = (
           f'A downloaded file from pastebin.com. size: {response_body_len} MBs'
        )
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)
        return True

    def set_evidence_conn_without_dns(
        self, daddr, timestamp, profileid, twid, uid
    ):
        # uid {uid}. time {datetime.datetime.now()}')
        threat_level = 'high'
        category = 'Anomaly.Connection'
        attacker_direction = 'dstip'
        source_target_tag = 'Malware'
        evidence_type = 'ConnectionWithoutDNS'
        attacker = daddr
        # the first 5 hours the confidence of connection w/o dns
        # is 0.1  in case of interface only, until slips learns all the dns
        start_time = __database__.get_slips_start_time()
        now = time.time()
        confidence = 0.8
        running_on_interface = '-i' in sys.argv or __database__.is_growing_zeek_dir()
        if running_on_interface:
            diff = utils.get_time_diff(start_time, now, return_type='hours')
            if diff < 5:
                confidence = 0.1


        ip_identification = __database__.getIPIdentification(daddr)
        description = f'a connection without DNS resolution to IP: {daddr} {ip_identification}'
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)

    def set_evidence_dns_arpa_scan(
        self, arpa_scan_threshold, stime, profileid, twid, uid
    ):
        confidence = 0.7
        threat_level = 'medium'
        category = 'Recon.Scanning'
        attacker_direction = 'srcip'
        evidence_type = 'DNS-ARPA-Scan'
        description = f'doing DNS ARPA scan. Scanned {arpa_scan_threshold} hosts within 2 seconds.'
        attacker = profileid.split('_')[1]

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 stime, category, conn_count=arpa_scan_threshold, profileid=profileid, twid=twid,
                                 uid=uid)

    def set_evidence_unknown_port(
        self, daddr, dport, proto, timestamp, profileid, twid, uid
    ):
        confidence = 1
        threat_level = 'high'
        category = 'Anomaly.Connection'
        attacker_direction = 'srcip'
        evidence_type = 'UnknownPort'
        attacker = profileid.split('_')[-1]
        ip_identification = __database__.getIPIdentification(daddr)
        description = (
            f'Connection to unknown destination port {dport}/{proto.upper()} '
            f'destination IP {daddr}. {ip_identification}'
        )

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, port=dport, proto=proto, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_pw_guessing(self, msg, timestamp, profileid, twid, uid, by=''):
        # 222.186.30.112 appears to be guessing SSH passwords (seen in 30 connections)
        # confidence = 1 because this detection is comming from a zeek file so we're sure it's accurate
        confidence = 1
        threat_level = 'high'
        category = 'Attempt.Login'
        evidence_type = 'Password_Guessing'
        attacker_direction = 'srcip'
        source_target_tag = 'Malware'
        description = f'password guessing. {msg}. by {by}.'
        scanning_ip = msg.split(' appears')[0]
        conn_count = int(msg.split('in ')[1].split('connections')[0])

        __database__.setEvidence(evidence_type, attacker_direction, scanning_ip, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=conn_count,
                                 profileid=profileid, twid=twid, uid=uid)

    def set_evidence_horizontal_portscan(
        self, msg, timestamp, profileid, twid, uid
    ):
        # 10.0.2.15 scanned at least 25 unique hosts on port 80/tcp in 0m33s
        confidence = 1
        threat_level = 'medium'
        description = f'horizontal port scan by Zeek engine. {msg}'
        evidence_type = 'HorizontalPortscan'
        attacker_direction = 'srcip'
        source_target_tag = 'Recon'
        attacker = profileid.split('_')[-1]
        category = 'Recon.Scanning'
        # get the number of unique hosts scanned on a specific port
        conn_count = int(msg.split('least')[1].split('unique')[0])
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=conn_count,
                                 profileid=profileid, twid=twid, uid=uid)

    def set_evidence_conn_to_private_ip(
            self, daddr, dport, saddr, profileid, twid, uid, timestamp
    ):

        confidence = 1
        threat_level = 'info'
        description = f'Connecting to private IP: {daddr} '
        if dport != '':
            # arp flows dont have dport
            description += f'on destination port: {dport}'

        evidence_type = 'ConnectionToPrivateIP'
        category = 'Recon'
        attacker_direction = 'srcip'
        attacker = saddr
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid,
                                 twid=twid, uid=uid)


    def set_evidence_vertical_portscan(
        self, msg, scanning_ip, timestamp, profileid, twid, uid
    ):
        # confidence = 1 because this detection is comming from a zeek file so we're sure it's accurate
        confidence = 1
        threat_level = 'medium'
        # msg example: 192.168.1.200 has scanned 60 ports of 192.168.1.102
        description = f'vertical port scan by Zeek engine. {msg}'
        evidence_type = 'VerticalPortscan'
        category = 'Recon.Scanning'
        attacker_direction = 'dstip'
        source_target_tag = 'Recon'
        conn_count = int(msg.split('least ')[1].split(' unique')[0])
        attacker = scanning_ip
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=conn_count,
                                 profileid=profileid, twid=twid, uid=uid)

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

        attacker_direction = 'srcip'
        attacker = saddr
        evidence_type = f'SSHSuccessful-by-{saddr}'
        threat_level = 'info'
        confidence = 0.8
        category = 'Infomation'
        ip_identification = __database__.getIPIdentification(daddr)
        description = (
            f'SSH successful to IP {daddr}. {ip_identification}. '
            f'From IP {saddr}. Size: {str(size)}. Detection model {by}.'
            f' Confidence {confidence}'
        )

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_long_connection(
        self, ip, duration, profileid, twid, uid, timestamp, ip_state='ip'
    ):
        """
        Set an evidence for a long connection.
        """

        attacker_direction = ip_state
        attacker = ip
        evidence_type = 'LongConnection'
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
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_self_signed_certificates(
        self, profileid, twid, ip, description, uid, timestamp
    ):
        """
        Set evidence for self signed certificates.
        """
        confidence = 0.5
        threat_level = 'low'
        category = 'Anomaly.Behaviour'
        attacker_direction = 'dstip'
        evidence_type = 'SelfSignedCertificate'
        attacker = ip

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_for_multiple_reconnection_attempts(
        self, profileid, twid, ip, description, uid, timestamp
    ):
        """
        Set evidence for Reconnection Attempts.
        """
        confidence = 0.5
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'dstip'
        evidence_type = 'MultipleReconnectionAttempts'
        attacker = ip

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_for_connection_to_multiple_ports(
        self, profileid, twid, ip, description, uid, timestamp
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

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_suspicious_dns_answer(self, query, answer, entropy, daddr, profileid, twid, stime, uid):
        confidence = 0.6
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        evidence_type = 'HighEntropyDNSanswer'
        attacker_direction = 'dstip'
        attacker = daddr
        description = f'A DNS TXT answer with high entropy. ' \
                      f'query: {query} answer: "{answer}" entropy: {round(entropy, 2)} '
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 stime, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_for_port_0_connection(
        self, saddr, daddr, sport, dport, direction, profileid, twid, uid, timestamp
    ):
        """:param direction: 'source' or 'destination'"""
        confidence = 0.8
        threat_level = 'high'
        category = 'Anomaly.Connection'
        attacker_direction = 'srcip' if direction == 'source' else 'dstip'
        source_target_tag = 'Recon'
        evidence_type = 'Port0Connection'
        attacker = saddr if direction == 'source' else daddr

        ip_identification = __database__.getIPIdentification(daddr)
        description = f'Connection on port 0 from {saddr}:{sport} to {daddr}:{dport}. {ip_identification}.'

        conn_count = 1

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=conn_count,
                                 profileid=profileid, twid=twid, uid=uid)

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
        tags = malicious_ja3_dict.get('tags','')
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
        ip_identification = __database__.getIPIdentification(ip)
        description += (
            f'{ip_identification} description: {ja3_description} {tags}'
        )

        attacker = ip
        confidence = 1

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)

    def set_evidence_data_exfiltration(
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
        ip_identification = __database__.getIPIdentification(
            daddr
        )
        description = f'Large data upload. {src_mbs} MBs sent to {daddr} '
        description += f'{ip_identification}'
        timestamp = utils.convert_format(datetime.datetime.now(), utils.alerts_format)
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)

    def set_evidence_bad_smtp_login(
        self, saddr, daddr, stime, profileid, twid, uid
    ):
        confidence = 1
        threat_level = 'high'
        category = 'Attempt.Login'
        evidence_type = 'BadSMTPLogin'
        attacker_direction = 'srcip'
        attacker = saddr
        ip_identification = __database__.getIPIdentification(daddr)
        description = (
            f'doing bad SMTP login to {daddr} {ip_identification}'
        )

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 stime, category, profileid=profileid, twid=twid, uid=uid)

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
        attacker_direction = 'srcip'
        evidence_type = 'SMTPLoginBruteforce'
        ip_identification = __database__.getIPIdentification(daddr)
        description = f'doing SMTP login bruteforce to {daddr}. {smtp_bruteforce_threshold} logins in 10 seconds. {ip_identification}'
        attacker = saddr
        conn_count = smtp_bruteforce_threshold

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 stime, category, conn_count=conn_count, profileid=profileid, twid=twid, uid=uid)

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

        evidence_type = 'MaliciousSSLCert'
        category = 'Intrusion.Botnet'
        source_target_tag = 'CC'
        attacker_direction = 'dstip'

        attacker = daddr
        confidence = 1
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 ts, category, source_target_tag=source_target_tag, profileid=profileid, twid=twid,
                                 uid=uid)
