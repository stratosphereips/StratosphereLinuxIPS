# Must imports
from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager

# Your imports
import json
import datetime
import time
import sys


class Helper:
    def __init__(self, db):
        self.db =  db
        
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
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 stime, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_multiple_ssh_versions(
            self, srcip, cached_versions, current_versions, timestamp, twid, uid, daddr, role=''
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
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid, victim=daddr)

    def set_evidence_different_localnet_usage(
            self,
            daddr,
            portproto,
            profileid,
            timestamp,
            twid,
            uid,
            ip_outside_localnet: str = ''
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
        localnet = self.db.get_local_network()
        description = f'A connection {direction} a private IP ({attacker}) ' \
                          f'outside of the used local network {localnet}.' \
                          f' {rev_direction} IP: {victim} '

        if attacker_direction == 'dstip':
            description += 'using ARP' if 'arp' in portproto else f'on port: {portproto}'
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
            victim=victim
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

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid, victim=old_ip)

    def set_evidence_non_http_port_80_conn(
            self, daddr, profileid, timestamp, twid, uid
    ):
        confidence = 0.8
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'dstip'
        evidence_type = 'Non-HTTP-Port-80-Connection'
        attacker = daddr
        ip_identification = self.db.get_ip_identification(daddr)

        description = f'non-HTTP established connection to port 80.' \
                      f' destination IP: {daddr} {ip_identification}'
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_non_ssl_port_443_conn(
            self, daddr, profileid, timestamp, twid, uid
    ):
        confidence = 0.8
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'dstip'
        evidence_type = 'Non-SSL-Port-443-Connection'
        attacker = daddr
        ip_identification = self.db.get_ip_identification(daddr)
        description = f'non-SSL established connection to port 443.' \
                      f' destination IP: {daddr} {ip_identification}'

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_weird_http_method(
            self,
            profileid,
            twid,
            flow: dict
    ):
        daddr = flow['daddr']
        weird_method = flow['addl']
        uid = flow['uid']
        timestamp = flow['starttime']

        confidence = 0.9
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'srcip'
        evidence_type = 'WeirdHTTPMethod'
        attacker = profileid.split("_")[-1]
        ip_identification = self.db.get_ip_identification(daddr)
        description = f'Weird HTTP method "{weird_method}" to IP: {daddr} {ip_identification}. by Zeek.'
        self.db.setEvidence(evidence_type,
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
                                 victim=daddr,
                            )

    def set_evidence_incompatible_CN(
            self, org, timestamp, daddr, profileid, twid, uid
    ):
        """
        :param prg: the org this ip/domain claims it belongs to
        """
        confidence = 0.9
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'dstip'
        evidence_type = 'IncompatibleCN'
        attacker = daddr
        ip_identification = self.db.get_ip_identification(daddr)
        description = f'Incompatible certificate CN to IP: {daddr} {ip_identification} claiming to belong {org.capitalize()}.'
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_DGA(self, nxdomains: int, stime, profileid, twid, uid):
        confidence = (1 / 100) * (nxdomains - 100) + 1
        confidence = round(confidence, 2)  # for readability
        threat_level = 'high'
        category = 'Intrusion.Botnet'
        # the srcip doing all the dns queries
        attacker_direction = 'srcip'
        source_target_tag = 'OriginMalware'
        evidence_type = f'DGA-{nxdomains}-NXDOMAINs'
        attacker = profileid.split('_')[1]
        description = f'possible DGA or domain scanning. {attacker} failed to resolve {nxdomains} domains'
        conn_count = nxdomains

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
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
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
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
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
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
        start_time = self.db.get_slips_start_time()
        now = time.time()
        confidence = 0.8
        if (
            '-i' in sys.argv
            or self.db.is_growing_zeek_dir()
        ):
            diff = utils.get_time_diff(start_time, now, return_type='hours')
            if diff < 5:
                confidence = 0.1

        ip_identification = self.db.get_ip_identification(daddr)
        description = f'a connection without DNS resolution to IP: {daddr} {ip_identification}'
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
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

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
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
        ip_identification = self.db.get_ip_identification(daddr)
        description = (
            f'Connection to unknown destination port {dport}/{proto.upper()} '
            f'destination IP {daddr}. {ip_identification}'
        )

        self.db.setEvidence(evidence_type,
                            attacker_direction,
                            attacker,
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
                            victim=daddr)

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

        self.db.setEvidence(evidence_type, attacker_direction, scanning_ip, threat_level, confidence, description,
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
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=conn_count,
                                 profileid=profileid, twid=twid, uid=uid)

    def set_evidence_conn_to_private_ip(
            self, proto, daddr, dport, saddr, profileid, twid, uid, timestamp
    ):

        if daddr in ['0.0.0.0', '255.255.255.255']:
            return
        if saddr in ['0.0.0.0', '255.255.255.255']:
            return

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
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid,
                                 twid=twid, uid=uid, victim=daddr)

    def set_evidence_GRE_tunnel(
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



    def set_evidence_vertical_portscan(
            self, msg, scanning_ip, timestamp, profileid, twid, uid
    ):
        """

        @rtype: object
        """
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
        victim = msg.splt('ports of ')[-1]
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=conn_count,
                                 profileid=profileid, twid=twid, uid=uid, victim=victim)

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
        ip_identification = self.db.get_ip_identification(daddr)
        description = (
            f'SSH successful to IP {daddr}. {ip_identification}. '
            f'From IP {saddr}. Size: {str(size)}. Detection model {by}.'
            f' Confidence {confidence}'
        )

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid, victim=daddr)

    def set_evidence_long_connection(
            self, attacker, duration, profileid, twid, uid, timestamp, attacker_direction=''
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
        description = f'Long Connection. Connection from {srcip} to destination address: {attacker} ' \
                      f'{ip_identification} took {duration} mins'
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid, victim=srcip)

    def set_evidence_self_signed_certificates(
            self, profileid, twid, attacker, description, uid, timestamp
    ):
        """
        Set evidence for self signed certificates.
        """
        confidence = 0.5
        threat_level = 'low'
        category = 'Anomaly.Behaviour'
        attacker_direction = 'dstip'
        evidence_type = 'SelfSignedCertificate'
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_for_multiple_reconnection_attempts(
            self, profileid, twid, attacker, description, uid, timestamp
    ):
        """
        Set evidence for Reconnection Attempts.
        """
        confidence = 0.5
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        attacker_direction = 'dstip'
        evidence_type = 'MultipleReconnectionAttempts'

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
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

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
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
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 stime, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_invalid_dns_answer(self, query, answer, daddr, profileid, twid, stime, uid):
        evidence_type = "InvalidDNSResolution"
        attacker_direction = "dst_domain"
        attacker = query
        threat_level = "info"
        confidence = 0.7
        description = f"The DNS query {query} was resolved to {answer}"
        timestamp = stime
        category = "Anamoly.Behaviour"
        self.db.setEvidence(evidence_type , attacker_direction , attacker , threat_level , confidence , description ,
                                 timestamp , category , profileid=profileid , twid=twid , uid=uid)

    def set_evidence_for_port_0_connection(
            self, saddr, daddr, sport, dport, direction, profileid, twid, uid, timestamp
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
        description = f'Connection on port 0 from {saddr}:{sport} to {daddr}:{dport}. {ip_identification}.'

        conn_count = 1

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=conn_count,
                                 profileid=profileid, twid=twid, uid=uid, victim=victim)

    def set_evidence_malicious_JA3(
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
        description += (
            f'{ip_identification} description: {ja3_description} {tags}'
        )

        attacker = ip
        confidence = 1

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid, victim=victim)

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
        ip_identification = self.db.get_ip_identification(
            daddr
        )
        description = f'Large data upload. {src_mbs} MBs sent to {daddr} '
        description += f'{ip_identification}'
        timestamp = utils.convert_format(datetime.datetime.now(), utils.alerts_format)
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
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
        ip_identification = self.db.get_ip_identification(daddr)
        description = (
            f'doing bad SMTP login to {daddr} {ip_identification}'
        )

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 stime, category, profileid=profileid, twid=twid, uid=uid, victim=daddr)

    def set_evidence_smtp_bruteforce(
            self,
            flow:dict,
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

    def set_evidence_malicious_ssl(
            self, ssl_info: dict, ssl_info_from_db: dict
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
        self.db.setEvidence(evidence_type, attacker_direction,
                                 attacker, threat_level, confidence,
                                 description, ts, category,
                                 source_target_tag=source_target_tag,
                                 profileid=profileid, twid=twid,
                                 uid=uid)
