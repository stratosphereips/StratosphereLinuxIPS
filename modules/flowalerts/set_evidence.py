# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import platform
from .TimerThread import TimerThread

# Your imports
import json
import configparser
import ipaddress
import datetime
import time
import sys
import socket
import validators
class Helper:
    def set_evidence_ssh_successful(self, profileid, twid, saddr,
                                    daddr, size, uid, timestamp,
                                    by='', ip_state='ip'):
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
        description = f'SSH successful to IP {daddr}. {ip_identification}. ' \
                      f'From IP {saddr}. Size: {str(size)}. Detection model {by}.' \
                      f' Confidence {confidence}'
        if not twid:
            twid = ''
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_long_connection(self, ip, duration, profileid, twid,
                                     uid, timestamp, ip_state='ip'):
        '''
        Set an evidence for a long connection.
        '''


        type_detection = ip_state
        detection_info = ip
        type_evidence = 'LongConnection'
        threat_level = 'low'
        category = 'Anomaly.Connection'
        # confidence depends on how long the connection
        # scale the confidence from 0 to 1, 1 means 24 hours long
        confidence = 1/(3600*24)*(duration-3600*24)+1
        confidence = round(confidence, 2)
        ip_identification = __database__.getIPIdentification(ip)
        # get the duration in minutes
        duration = int(duration/60)
        description = f'Long Connection. Connection to: {ip} {ip_identification} took {duration} mins'
        if not twid:
            twid = ''
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, profileid=profileid,
                                 twid=twid, uid=uid)

    def set_evidence_self_signed_certificates(self, profileid, twid, ip,
                                              description, uid, timestamp, ip_state='ip'):
        '''
        Set evidence for self signed certificates.
        '''
        confidence = 0.5
        threat_level = 'low'
        category = 'Anomaly.Behaviour'
        type_detection = 'dstip'
        type_evidence = 'SelfSignedCertificate'
        detection_info = ip
        if not twid:
            twid = ''
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_for_multiple_reconnection_attempts(self,profileid, twid, ip, description, uid, timestamp):
        '''
        Set evidence for Reconnection Attempts.
        '''
        confidence = 0.5
        threat_level = 'medium'
        category = 'Anomaly.Traffic'
        type_detection  = 'dstip'
        type_evidence = 'MultipleReconnectionAttempts'
        detection_info = ip
        if not twid:
            twid = ''
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, profileid=profileid,
                                 twid=twid, uid=uid)

    def set_evidence_for_connection_to_multiple_ports(self,profileid, twid, ip, description, uid, timestamp):
        '''
        Set evidence for connection to multiple ports.
        '''
        confidence = 0.5
        threat_level = 'medium'
        category = 'Anomaly.Connection'
        type_detection  = 'dstip'
        type_evidence = 'ConnectionToMultiplePorts'
        detection_info = ip
        if not twid:
            twid = ''
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_for_invalid_certificates(self, profileid, twid, ip, description, uid, timestamp):
        '''
        Set evidence for Invalid SSL certificates.
        '''
        confidence = 0.5
        threat_level = 'low'
        category = "Anomaly.Behaviour"
        type_detection  = 'dstip'
        type_evidence = 'InvalidCertificate'
        detection_info = ip
        if not twid:
            twid = ''
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)


    def set_evidence_for_port_0_connection(self, saddr, daddr, direction, profileid, twid, uid, timestamp):
        """ :param direction: 'source' or 'destination' """
        confidence = 0.8
        threat_level = 'high'
        category = 'Anomaly.Connection'
        type_detection  = 'srcip' if direction == 'source' else 'dstip'
        source_target_tag = "Recon"
        type_evidence = 'Port0Connection'
        detection_info = saddr if direction == 'source' else daddr

        if direction == 'source':
            ip_identification = __database__.getIPIdentification(daddr)
            description = f'Connection on port 0 from {saddr} to {daddr}. {ip_identification}.'
        else:
            ip_identification = __database__.getIPIdentification(saddr)
            description = f'Connection on port 0 from {daddr} to {saddr}. {ip_identification}'

        conn_count = 1
        if not twid: twid = ''
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag,
                                 conn_count=conn_count, profileid=profileid, twid=twid, uid=uid)


    def set_evidence_malicious_JA3(self, malicious_ja3_dict, ip, profileid, twid, uid, timestamp, type_='', ioc=''):
        """
        :param alert: is True only if the confidence of the JA3 feed is > 0.5 so we generate an alert
        """
        malicious_ja3_dict = json.loads(malicious_ja3_dict[ioc])
        tags = malicious_ja3_dict['tags']
        ja3_description = malicious_ja3_dict['description']
        threat_level = malicious_ja3_dict['threat_level']

        if type_ == 'ja3':
            description = f'Malicious JA3: {ioc} from source address {ip} '
            type_evidence = 'MaliciousJA3'
            category = 'Intrusion.Botnet'
            source_target_tag = "Botnet"
            type_detection  = 'srcip'
        elif type_ == 'ja3s':
            description = f'Malicious JA3s: (possible C&C server): {ioc} to server {ip} '
            type_evidence = 'MaliciousJA3s'
            category =  'Intrusion.Botnet'
            source_target_tag = "CC"
            type_detection  = 'dstip'

        # append daddr identification to the description
        ip_identification = __database__.getIPIdentification(ip)
        description += f'{ip_identification} description: {ja3_description} {tags}'


        detection_info = ip
        confidence = 1
        if not twid:
            twid = ''
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag,
                                 profileid=profileid, twid=twid, uid=uid)

    def set_evidence_data_exfiltration(self, most_contacted_daddr, total_bytes, times_contacted, profileid, twid, uid):
        confidence = 0.6
        threat_level = 'high'
        type_detection  = 'dstip'
        source_target_tag = 'OriginMalware'
        type_evidence = 'DataUpload'
        category = 'Malware'
        detection_info = most_contacted_daddr
        bytes_sent_in_MB = int(total_bytes / (10**6))
        ip_identification = __database__.getIPIdentification(most_contacted_daddr)
        description = f'possible data upload. {bytes_sent_in_MB} MBs sent to {most_contacted_daddr}.'
        description+= f'{ip_identification}. IP contacted {times_contacted} times in the past 1h'
        timestamp = datetime.datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        if not twid:
            twid = ''
        __database__.setEvidence(type_evidence, type_detection, detection_info, threat_level,
                                 confidence, description, timestamp, category,
                                 source_target_tag=source_target_tag, profileid=profileid, twid=twid)

    def set_evidence_bad_smtp_login(self, saddr, daddr, stime, profileid, twid, uid):
            confidence = 1
            threat_level = 'high'
            category = 'Attempt.Login'
            type_evidence = 'BadSMTPLogin'
            type_detection  = 'srcip'
            detection_info = saddr
            description = f'performing bad SMTP login to {daddr}'
            if not twid: twid = ''
            __database__.setEvidence(type_evidence, type_detection, detection_info,
                                     threat_level, confidence, description,
                                     stime, category,
                                     profileid=profileid, twid=twid, uid=uid)

    def set_evidence_smtp_bruteforce(self, saddr, daddr, stime, profileid, twid, uid):
            confidence = 1
            threat_level = 'high'
            category = 'Attempt.Login'
            type_detection  = 'srcip'
            type_evidence = 'SMTPLoginBruteforce'
            description = f'performing SMTP login bruteforce to {daddr}. {self.smtp_bruteforce_threshold} logins in 10 seconds.'
            detection_info = saddr
            conn_count = self.smtp_bruteforce_threshold
            if not twid: twid = ''
            __database__.setEvidence(type_evidence, type_detection, detection_info, threat_level, confidence,
                                     description, stime, category,
                                     conn_count=conn_count, profileid=profileid, twid=twid)

    def set_evidence_malicious_ssl(self, ssl_info: dict, ssl_info_from_db: dict):
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

            description = f'Malicious SSL certificate to server {daddr}. '
            # append daddr identification to the description
            ip_identification = __database__.getIPIdentification(daddr)
            description += f'{ip_identification} description: {cert_description} {tags}  '

            type_evidence = 'MaliciousSSLCert'
            category =  'Intrusion.Botnet'
            source_target_tag = "CC"
            type_detection  = 'dstip'

            detection_info = daddr
            confidence = 1
            __database__.setEvidence(type_evidence, type_detection, detection_info,
                                     threat_level, confidence, description,
                                     ts, category, source_target_tag=source_target_tag,
                                     profileid=profileid, twid=twid, uid=uid)

