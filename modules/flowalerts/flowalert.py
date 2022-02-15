# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import platform

# Your imports
import json
import configparser
import ipaddress
import datetime
import time
import sys
import socket
import validators
import threading

class Module(Module, multiprocessing.Process):
    name = 'flowalerts'
    description = 'Alerts about flows: long connection, successful ssh, password guessing, self-signed certificate, data exfiltration, etc.'
    authors = ['Kamila Babayeva', 'Sebastian Garcia', 'Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # Read the configuration
        self.read_configuration()
        # Retrieve the labels
        self.normal_label = __database__.normal_label
        self.malicious_label = __database__.malicious_label
        self.c1 = __database__.subscribe('new_flow')
        self.c2 = __database__.subscribe('new_ssh')
        self.c3 = __database__.subscribe('new_notice')
        self.c4 = __database__.subscribe('new_ssl')
        self.c5 = __database__.subscribe('new_service')
        self.c6 = __database__.subscribe('new_dns_flow')
        self.c7 = __database__.subscribe('new_downloaded_file')
        self.timeout = 0.0000001
        self.p2p_daddrs = {}
        # get the default gateway
        self.gateway = __database__.get_default_gateway()
        # Cache list of connections that we already checked in the timer thread (we waited for the connection of these dns resolutions)
        self.connections_checked_in_dns_conn_timer_thread = []
        # Cache list of connections that we already checked in the timer thread (we waited for the dns resolution for these connections)
        self.connections_checked_in_conn_dns_timer_thread = []
        # Cache list of connections that we already checked in the timer thread for ssh check
        self.connections_checked_in_ssh_timer_thread = []
        # Threshold how much time to wait when capturing in an interface, to start reporting connections without DNS
        # Usually the computer resolved DNS already, so we need to wait a little to report
        # In seconds
        self.conn_without_dns_interface_wait_time = 180
        # this dict will contain the number of nxdomains found in every profile
        self.nxdomains = {}
        # if nxdomains are >= this threshold, it's probably DGA
        self.nxdomains_threshold = 10

    def is_ignored_ip(self, ip) -> bool:
        """
        This function checks if an IP is an special list of IPs that
        should not be alerted for different reasons
        """
        try:
            ip_obj =  ipaddress.ip_address(ip)
            # Is the IP multicast, private? (including localhost)
            # local_link or reserved?
            # The broadcast address 255.255.255.255 is reserved.
            if ip_obj.is_multicast or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_reserved or '.255' in ip_obj.exploded:
                return True
            return False
        except Exception as inst:
            self.print(f'Problem on function is_ignored_ip()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return False

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the pcap filter
        try:
            self.long_connection_threshold = int(self.config.get('flowalerts', 'long_connection_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # this value is in seconds, =25 mins
            self.long_connection_threshold = 1500
        try:
            self.ssh_succesful_detection_threshold = int(self.config.get('flowalerts', 'ssh_succesful_detection_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.ssh_succesful_detection_threshold = 4290
        try:
            self.data_exfiltration_threshold = int(self.config.get('flowalerts', 'data_exfiltration_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # threshold in MBs
            self.data_exfiltration_threshold = 700

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

    def check_long_connection(self, dur, daddr, saddr, profileid, twid, uid, timestamp):
        """
        Check if a duration of the connection is
        above the threshold (more than 25 minutess by default).
        :param dur: duration of the flow in seconds
        """
        if type(dur) == str:
            dur = float(dur)
        # If duration is above threshold, we should set an evidence
        if dur > self.long_connection_threshold:
            # set "flowalerts-long-connection:malicious" label in the flow (needed for Ensembling module)
            module_name = "flowalerts-long-connection"
            module_label = self.malicious_label

            __database__.set_module_label_to_flow(profileid,
                                                  twid,
                                                  uid,
                                                  module_name,
                                                  module_label)
            self.set_evidence_long_connection(daddr, dur, profileid, twid, uid, timestamp, ip_state='ip')
        else:
            # set "flowalerts-long-connection:normal" label in the flow (needed for Ensembling module)
            module_name = "flowalerts-long-connection"
            module_label = self.normal_label
            __database__.set_module_label_to_flow(profileid,
                                                  twid,
                                                  uid,
                                                  module_name,
                                                  module_label)

    def is_p2p(self, dport, proto, daddr):
        """
        P2P is defined as following : proto is udp, port numbers are higher than 30000 at least 5 connections to different daddrs
        OR trying to connct to 1 ip on more than 5 unkown 30000+/udp ports
        """
        if proto.lower() == 'udp' and int(dport)>30000:
            try:
                # trying to connct to 1 ip on more than 5 unknown ports
                if self.p2p_daddrs[daddr] >= 6:
                    return True
                self.p2p_daddrs[daddr] = self.p2p_daddrs[daddr] +1
                # now check if we have more than 4 different dst ips
            except KeyError:
                # first time seeing this daddr
                self.p2p_daddrs[daddr] = 1

            if len(self.p2p_daddrs) == 5:
                # this is another connection on port 3000+/udp and we already have 5 of them
                # probably p2p
                return True

        return False

    def get_ip_info(self, ip):
        """ Return ani domain/server/dns info we have about this daddr """

        # Get info from our cache db ip data may have SNI or reverse_dns or both
        ip_data = __database__.getIPData(ip)
        if ip_data:
            rev_dns = ip_data.get('reverse_dns',False)
            if rev_dns :
                return rev_dns

            ip_sni = ip_data.get('SNI',False)
            if ip_sni:
                server_name = ip_sni[0]['server_name']
                if server_name:
                    return server_name
        # we don't have cached info about this ip, was it resolved?
        ip_info = __database__.get_dns_resolution(ip)
        if ip_info:
            return ip_info

        # we have no info about this ip in our db, resolve it
        try:
            dns_resolution = socket.gethostbyaddr(ip)[0]
            # make sure we were able to resolve it
            if validators.domain(dns_resolution):
                return dns_resolution
        except socket.herror:
           # can't resolve this ip
            return False

        return False

    def port_belongs_to_an_org(self, daddr, portproto, profileid):
        """
        Checks weather a port is known to be used by a specific organization or not
        """
        organization_info = __database__.get_organization_of_port(portproto)
        if organization_info:
            # there's an organization that's known to use this port,
            # check if the daddr belongs to the range of this org
            organization_info = json.loads(organization_info)
            # can be an ip or a range
            org_ip = organization_info['ip']
            # org_name = organization_info['org_name']
            # it's an ip and it belongs to this org, consider the port as known
            if daddr in org_ip:
                return False
            # is it a range?
            try:
                # we have the org range in our database, check if the daddr belongs to this range
                if ipaddress.ip_address(daddr) in ipaddress.ip_network(org_ip):
                    # it does, consider the port as known
                    return False
            except ValueError:
                # not a range either since nothing is specified,
                # check the source and dst mac address vendors
                src_mac_vendor = str(__database__.get_mac_vendor_from_profile(profileid))
                dst_mac_vendor = str(__database__.get_mac_vendor_from_profile(f'profile_{daddr}'))
                org_name = organization_info['org_name'].lower()
                if (org_name in src_mac_vendor.lower()
                        and org_name in dst_mac_vendor.lower()):
                    return True

        # consider this port as unknown
        return False

    def check_unknown_port(self, dport, proto, daddr, profileid, twid, uid, timestamp):
        """ Checks dports that are not in our slips_files/ports_info/ files"""
        portproto = f'{dport}/{proto}'
        port_info = __database__.get_port_info(portproto)
        if not port_info:
            # we don't have port info in our database
            # is it a port that is known to be used by a specific organization
            if self.port_belongs_to_an_org(daddr, portproto, profileid):
                return False


        if (not port_info
            and not 'icmp' in proto
            and not self.is_p2p(dport, proto, daddr)
            and not __database__.is_ftp_port(dport)):
            # we don't have info about this port
            confidence = 1
            threat_level = 'high'
            category = 'Anomaly.Connection'
            type_detection  = 'dstip'
            type_evidence = 'UnknownPort'
            detection_info = daddr
            ip_identification = __database__.getIPIdentification(daddr)
            description = f'Connection to unknown destination port {dport}/{proto.upper()} ' \
                          f'destination IP {daddr}. {ip_identification}'
            # get the sni/reverse dns of this daddr
            ip_info = self.get_ip_info(daddr)
            if ip_info:
                description += f' ({ip_info})'

            if not twid:
                twid = ''
            __database__.setEvidence(type_evidence, type_detection, detection_info,
                                     threat_level, confidence, description,
                                     timestamp, category, port=dport, proto=proto,profileid=profileid,
                                     twid=twid, uid=uid)

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

    def check_connection_without_dns_resolution(self, daddr, twid, profileid, timestamp, uid):
        """ Checks if there's a flow to a dstip that has no cached DNS answer """

        # Ignore some IP
        ## - All dhcp servers. Since is ok to connect to them without a DNS request.
        # We dont have yet the dhcp in the redis, when is there check it
        #if __database__.get_dhcp_servers(daddr):
            #continue

        # to avoid false positives in case of an interface don't alert
        # ConnectionWithoutDNS until 2 minutes has passed
        # after starting slips because the dns may have happened before starting slips
        if '-i' in sys.argv:
            start_time = __database__.get_slips_start_time()
            now = datetime.datetime.now()
            diff = now - start_time
            diff = diff.seconds
            if not int(diff) >= 120:
                # less than 2 minutes have passed
                return False

        answers_dict = __database__.get_dns_resolution(daddr, all_info=True)
        if not answers_dict:
            #self.print(f'No DNS resolution in {answers_dict}')
            # There is no DNS resolution, but it can be that Slips is
            # still reading it from the files.
            # To give time to Slips to read all the files and get all the flows
            # don't alert a Connection Without DNS until 5 seconds has passed
            # in real time from the time of this checking.

            # Create a timer thread that will wait 5 seconds for the dns to arrive and then check again
            #self.print(f'Cache of conns not to check: {self.conn_checked_dns}')
            if uid not in self.connections_checked_in_conn_dns_timer_thread:
                # comes here if we haven't started the timer thread for this connection before
                # mark this connection as checked
                self.connections_checked_in_conn_dns_timer_thread.append(uid)
                params = [daddr, twid, profileid, timestamp, uid]
                #self.print(f'Starting the timer to check on {daddr}, uid {uid}.
                # time {datetime.datetime.now()}')
                timer = TimerThread(15, self.check_connection_without_dns_resolution, params)
                timer.start()
            elif uid in self.connections_checked_in_conn_dns_timer_thread:
                # It means we already checked this conn with the Timer process
                # (we waited 5 seconds for the dns to arrive after the connection was made)
                # but still no dns resolution for it. So now alert
                #self.print(f'Alerting after timer conn without dns on {daddr},
                # uid {uid}. time {datetime.datetime.now()}')
                threat_level = 'high'
                category = 'Anomaly.Connection'
                type_detection  = 'dstip'
                source_target_tag = 'Malware'
                type_evidence = 'ConnectionWithoutDNS'
                detection_info = daddr
                # the first 5 hours the confidence of connection w/o dns
                # is 0.1  in case of interface only, until slips learns all the dns
                start_time = __database__.get_slips_start_time()
                now = time.time()
                confidence = 0.8
                if type(start_time) == datetime.datetime:
                    if '-i' in sys.argv and (now - start_time.timestamp() < 18000):
                        confidence = 0.1
                else:
                    # start_time is float
                    if '-i' in sys.argv and (now - start_time < 18000):
                        confidence = 0.1

                ip_identification = __database__.getIPIdentification(daddr)
                description = f'a connection without DNS resolution to IP: {daddr}. {ip_identification}'
                if not twid:
                    twid = ''
                __database__.setEvidence(type_evidence, type_detection, detection_info,
                                         threat_level, confidence, description,
                                         timestamp, category, source_target_tag=source_target_tag,
                                         profileid=profileid, twid=twid, uid=uid)
                # This UID will never appear again, so we can remove it and
                # free some memory
                try:
                    self.connections_checked_in_conn_dns_timer_thread.remove(uid)
                except ValueError:
                    pass

    def check_dns_resolution_without_connection(self, domain, answers, timestamp, profileid, twid, uid):
        """
        Makes sure all cached DNS answers are used in contacted_ips
        :param contacted_ips:  dict of ips used in a specific tw {ip: uid}
        """
        # Ignore some domains because its is ok if they do DNS without a connection
        ## - All reverse dns resolutions
        ## - All .local domains
        ## - The wildcard domain *
        ## - Subdomains of cymru.com, since it is used by the ipwhois library in Slips to get the ASN of an IP and its range. This DNS is meant not to have a connection later
        ## - Domains check from Chrome, like xrvwsrklpqrw
        ## - The WPAD domain of windows

        if 'arpa' in domain or '.local' in domain or '*' in domain or '.cymru.com' in domain[-10:] or len(domain.split('.')) == 1 or domain == 'WPAD':
            return False

        # One DNS query may not be answered exactly by UID, but the computer can re-ask the donmain, and the next DNS resolution can be
        # answered. So dont check the UID, check if the domain has an IP

        #self.print(f'The DNS query to {domain} had as answers {answers} ')

        # It can happen that this domain was already resolved previously, but with other IPs
        # So we get from the DB all the IPs for this domain first and append them to the answers
        # This happens, for example, when there is 1 DNS resolution with A, then 1 DNS resolution
        # with AAAA, and the computer chooses the A address. Therefore, the 2nd DNS resolution
        # would be treated as 'without connection', but this is false.

        previous_data_for_domain =  __database__.getDomainData(domain)
        if previous_data_for_domain:
            try:
                previous_ips_for_domain =  previous_data_for_domain['IPs']
                answers.extend(previous_ips_for_domain)
            except KeyError:
                pass

        #self.print(f'The extended DNS query to {domain} had as answers {answers} ')

        contacted_ips = __database__.get_all_contacted_ips_in_profileid_twid(profileid,twid)
        # If contacted_ips is empty it can be because we didnt read yet all the flows.
        # This is automatically captured later in the for loop and we start a Timer

        # every dns answer is a list of ips that correspond to a spicific query,
        # one of these ips should be present in the contacted ips
        # check each one of the resolutions of this domain
        if answers == ['']:
            # If no IPs are in the answer, we can not expect the computer to connect to anything
            #self.print(f'No ips in the answer, so ignoring')
            return False
        for ip in answers:
            #self.print(f'Checking if we have a connection to ip {ip}')
            if ip in contacted_ips:
                # this dns resolution has a connection. We can exit
                return False
        #self.print(f'It seems that none of the IPs were contacted')
        # Found a DNS query which none of its IPs was contacted
        # It can be that Slips is still reading it from the files. Lets check back in some time
        # Create a timer thread that will wait some seconds for the connection to arrive and then check again
        if uid not in self.connections_checked_in_dns_conn_timer_thread:
            # comes here if we haven't started the timer thread for this dns before
            # mark this dns as checked
            self.connections_checked_in_dns_conn_timer_thread.append(uid)
            params = [ domain, answers, timestamp, profileid, twid, uid]
            #self.print(f'Starting the timer to check on {domain}, uid {uid}. time {datetime.datetime.now()}')
            timer = TimerThread(15, self.check_dns_resolution_without_connection, params)
            timer.start()
        elif uid in self.connections_checked_in_dns_conn_timer_thread:
            #self.print(f'Alerting on {domain}, uid {uid}. time {datetime.datetime.now()}')
            # It means we already checked this dns with the Timer process
            # but still no connection for it. So now alert
            confidence = 0.8
            threat_level = 'low'
            category = 'Anomaly.Traffic'
            type_detection  = 'dstdomain'
            type_evidence = 'DNSWithoutConnection'
            detection_info = domain
            description = f'domain {domain} resolved with no connection'
            __database__.setEvidence(type_evidence, type_detection, detection_info, threat_level, confidence,
                                     description, timestamp, category, profileid=profileid, twid=twid, uid=uid)
            # This UID will never appear again, so we can remove it and
            # free some memory
            try:
                self.connections_checked_in_dns_conn_timer_thread.remove(uid)
            except ValueError:
                pass

    def check_ssh(self, message):
        """
        Function to check if an SSH connection logged in successfully
        """
        try:
            data = message['data']
            # Convert from json to dict
            data = json.loads(data)
            profileid = data['profileid']
            twid = data['twid']
            # Get flow as a json
            flow = data['flow']
            # Convert flow to a dict
            flow_dict = json.loads(flow)
            timestamp = flow_dict['stime']
            uid = flow_dict['uid']
            # Try Zeek method to detect if SSh was successful or not.
            auth_success = flow_dict['auth_success']
            if auth_success:
                original_ssh_flow = __database__.get_flow(profileid, twid, uid)
                original_flow_uid = next(iter(original_ssh_flow))
                if original_ssh_flow[original_flow_uid]:
                    ssh_flow_dict = json.loads(original_ssh_flow[original_flow_uid])
                    daddr = ssh_flow_dict['daddr']
                    saddr = ssh_flow_dict['saddr']
                    size = ssh_flow_dict['allbytes']
                    self.set_evidence_ssh_successful(profileid, twid, saddr, daddr, size, uid, timestamp, by='Zeek')
                    try:
                        self.connections_checked_in_ssh_timer_thread.remove(uid)
                    except ValueError:
                        pass
                    return True
                else:
                    # It can happen that the original SSH flow is not in the DB yet
                    if uid not in self.connections_checked_in_ssh_timer_thread:
                        # comes here if we haven't started the timer thread for this connection before
                        # mark this connection as checked
                        #self.print(f'Starting the timer to check on {flow_dict}, uid {uid}. time {datetime.datetime.now()}')
                        self.connections_checked_in_ssh_timer_thread.append(uid)
                        params = [message]
                        timer = TimerThread(15, self.check_ssh, params)
                        timer.start()
            else:
                # Try Slips method to detect if SSH was successful.
                original_ssh_flow = __database__.get_flow(profileid, twid, uid)
                original_flow_uid = next(iter(original_ssh_flow))
                if original_ssh_flow[original_flow_uid]:
                    ssh_flow_dict = json.loads(original_ssh_flow[original_flow_uid])
                    daddr = ssh_flow_dict['daddr']
                    saddr = ssh_flow_dict['saddr']
                    size = ssh_flow_dict['allbytes']
                    if size > self.ssh_succesful_detection_threshold:
                        # Set the evidence because there is no
                        # easier way to show how Slips detected
                        # the successful ssh and not Zeek
                        self.set_evidence_ssh_successful(profileid, twid, saddr, daddr, size, uid, timestamp, by='Slips')
                        try:
                            self.connections_checked_in_ssh_timer_thread.remove(uid)
                        except ValueError:
                            pass
                        return True
                    else:
                        # self.print(f'NO Successsul SSH recived: {data}', 1, 0)
                        pass
                else:
                    # It can happen that the original SSH flow is not in the DB yet
                    if uid not in self.connections_checked_in_ssh_timer_thread:
                        # comes here if we haven't started the timer thread for this connection before
                        # mark this connection as checked
                        #self.print(f'Starting the timer to check on {flow_dict}, uid {uid}. time {datetime.datetime.now()}')
                        self.connections_checked_in_ssh_timer_thread.append(uid)
                        params = [message]
                        timer = TimerThread(15, self.check_ssh, params)
                        timer.start()
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on check_ssh() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)

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


    def detect_DGA(self, rcode_name, query, stime, profileid, twid, uid):
        """
        Detect DGA based on the amount of NXDOMAINs seen in dns.log
        """

        if not 'NXDOMAIN' in rcode_name or 'in-addr.arpa' in query or query.endswith('.local'):
            return False

        profileid_twid = f'{profileid}_{twid}'

        # found NXDOMAIN by this profile
        try:
            self.nxdomains[profileid_twid] +=1
        except KeyError:
            # first time seeing nxdomain in this profile and tw
            self.nxdomains.update({profileid_twid: 1})
            return False

        # every 10,15,20 .. etc. nxdomains, generate an alert.
        if (self.nxdomains[profileid_twid] % 5 == 0 and
            self.nxdomains[profileid_twid] >= self.nxdomains_threshold):
            confidence = (1/100)*(self.nxdomains[profileid_twid]-100)+1
            confidence = round(confidence, 2) # for readability
            threat_level = 'high'
            category = 'Intrusion.Botnet'
            # the srcip performing all the dns queries
            type_detection  = 'srcip'
            source_target_tag = 'OriginMalware'
            type_evidence = f'DGA-{self.nxdomains[profileid_twid]}-NXDOMAINs'
            detection_info = profileid.split('_')[1]
            description = f'possible DGA or domain scanning. {detection_info} failed to resolve {self.nxdomains[profileid_twid]} domains'
            conn_count = self.nxdomains[profileid_twid]
            if not twid: twid = ''
            __database__.setEvidence(type_evidence, type_detection, detection_info, threat_level, confidence,
                                     description, stime, category, source_target_tag=source_target_tag,
                                     conn_count=conn_count, profileid=profileid, twid=twid)
            return True

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
        import pprint
        pprint.pp(ssl_info_from_db)
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

    def run(self):
        # Main loop function
        while True:
            try:
                # ---------------------------- new_flow channel
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time, Slips is stopped automatically.
                if message and message['data'] == 'stop_process':
                    # confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                if utils.is_msg_intended_for(message, 'new_flow'):
                    data = message['data']
                    # Convert from json to dict
                    data = json.loads(data)
                    profileid = data['profileid']
                    twid = data['twid']
                    # Get flow as a json
                    flow = data['flow']
                    # Convert flow to a dict
                    flow = json.loads(flow)

                    # Convert the common fields to something that can
                    # be interpreted
                    uid = next(iter(flow))
                    flow_dict = json.loads(flow[uid])
                    # Flow type is 'conn' or 'dns', etc.
                    flow_type = flow_dict['flow_type']
                    dur = flow_dict['dur']
                    saddr = flow_dict['saddr']
                    daddr = flow_dict['daddr']
                    origstate = flow_dict['origstate']
                    state = flow_dict['state']
                    timestamp = data['stime']
                    # ports are of type int
                    sport = flow_dict['sport']
                    dport = flow_dict.get('dport', None)
                    proto = flow_dict.get('proto')
                    appproto = flow_dict.get('appproto', '')
                    if not appproto or appproto == '-':
                        appproto = flow_dict.get('type', '')
                    # stime = flow_dict['ts']
                    # timestamp = data['stime']
                    # pkts = flow_dict['pkts']
                    # allbytes = flow_dict['allbytes']

                    # --- Detect long Connections ---
                    # Do not check the duration of the flow if the daddr or
                    # saddr is multicast.
                    if not ipaddress.ip_address(daddr).is_multicast and not ipaddress.ip_address(saddr).is_multicast:
                        self.check_long_connection(dur, daddr, saddr, profileid, twid, uid, timestamp)

                    # --- Detect unknown destination ports ---
                    if dport:
                        self.check_unknown_port(dport, proto.lower(), daddr, profileid, twid, uid, timestamp)

                    # --- Detect Multiple Reconnection attempts ---
                    key = saddr + '-' + daddr + ':' + str(dport)
                    if dport != 0 and origstate == 'REJ':
                        current_reconnections = __database__.getReconnectionsForTW(profileid,twid)
                        current_reconnections[key] = current_reconnections.get(key, 0) + 1
                        __database__.setReconnections(profileid, twid, current_reconnections)
                        for key, count_reconnections in current_reconnections.items():
                            if count_reconnections >= 5:
                                description = "Multiple reconnection attempts to Destination IP: {} from IP: {}".format(daddr,saddr)
                                self.set_evidence_for_multiple_reconnection_attempts(profileid, twid, daddr, description, uid, timestamp)

                    # --- Detect Connection to port 0 ---
                    if proto not in ('igmp', 'icmp', 'ipv6-icmp') and (sport == 0 or dport == 0):
                        direction = 'source' if sport==0 else 'destination'
                        self.set_evidence_for_port_0_connection(saddr, daddr, direction, profileid, twid, uid, timestamp)

                    # --- Detect if this is a connection without a DNS resolution ---
                    # The exceptions are:
                    # 1- Do not check for DNS requests
                    # 2- Ignore some IPs like private IPs, multicast, and broadcast
                    if flow_type == 'conn' and appproto != 'dns' and not self.is_ignored_ip(daddr):
                        # To avoid false positives in case of an interface don't alert ConnectionWithoutDNS until 2 minutes has passed
                        # after starting slips because the dns may have happened before starting slips
                        if '-i' in sys.argv:
                            start_time = __database__.get_slips_start_time()
                            now = datetime.datetime.now()
                            diff = now - start_time
                            diff = diff.seconds
                            if int(diff) >= self.conn_without_dns_interface_wait_time:
                                self.check_connection_without_dns_resolution(daddr, twid, profileid, timestamp, uid)
                        else:
                                self.check_connection_without_dns_resolution(daddr, twid, profileid, timestamp, uid)

                    # --- Detect Connection to multiple ports (for RAT) ---
                    if proto == 'tcp' and state == 'Established':
                        dport_name = appproto
                        if not dport_name:
                            dport_name = __database__.get_port_info(str(dport) + '/' + proto.lower())
                            if dport_name:
                                dport_name = dport_name.upper()
                        # Consider only unknown services
                        else:
                            dport_name = dport_name.upper()
                        # Consider only unknown services
                        if not dport_name:
                            # Connection to multiple ports to the destination IP
                            if profileid.split('_')[1] == saddr:
                                direction = 'Dst'
                                state = 'Established'
                                protocol = 'TCP'
                                role = 'Client'
                                type_data = 'IPs'
                                dst_IPs_ports = __database__.getDataFromProfileTW(profileid, twid, direction, state, protocol, role, type_data)
                                # make sure we find established connections to this daddr
                                if daddr in dst_IPs_ports:
                                    dstports = list(dst_IPs_ports[daddr]['dstports'])
                                    if len(dstports) > 1:
                                        description = "Connection to multiple ports {} of Destination IP: {}".format(dstports, daddr)
                                        self.set_evidence_for_connection_to_multiple_ports(profileid, twid, daddr, description, uid, timestamp)

                            # Connection to multiple port to the Source IP. Happens in the mode 'all'
                            elif profileid.split('_')[1] == daddr:
                                direction = 'Src'
                                state = 'Established'
                                protocol = 'TCP'
                                role = 'Server'
                                type_data = 'IPs'
                                src_IPs_ports = __database__.getDataFromProfileTW(profileid, twid, direction, state, protocol, role, type_data)
                                dstports = list(src_IPs_ports[saddr]['dstports'])
                                if len(dstports) > 1:
                                    description = "Connection to multiple ports {} of Source IP: {}".format(dstports, saddr)
                                    self.set_evidence_for_connection_to_multiple_ports(profileid, twid, daddr, description, uid, timestamp)

                    # --- Detect Data exfiltration ---
                    # we’re looking for systems that are transferring large amount of data in 20 mins span
                    all_flows = __database__.get_all_flows_in_profileid(profileid)
                    if all_flows:
                        # get a list of flows without uids
                        flows_list =[]
                        for flow_dict in all_flows:
                            flows_list.append(list(flow_dict.items())[0][1])
                        # sort flows by ts
                        flows_list = sorted(flows_list, key = lambda i: i['ts'])
                        # get first and last flow ts
                        time_of_first_flow = datetime.datetime.fromtimestamp(flows_list[0]['ts'])
                        time_of_last_flow = datetime.datetime.fromtimestamp(flows_list[-1]['ts'])
                        # get the difference between them in seconds

                        diff = str(time_of_last_flow - time_of_first_flow)
                        # if there are days diff between the flows , diff will be something like 1 day, 17:25:57.458395
                        try:
                            # calculate the days difference
                            diff_in_days = int(diff.split(', ')[0].split(' ')[0])
                            diff = diff.split(', ')[1]
                        except (IndexError,ValueError):
                            # no days different
                            diff = diff.split(', ')[0]
                            diff_in_days = 0

                        diff_in_hrs = int(diff.split(':')[0])
                        diff_in_mins = int(diff.split(':')[1])
                        # total diff in mins
                        diff_in_mins = 24*diff_in_days*60 + diff_in_hrs*60 + diff_in_mins

                        # we need the flows that happend in 20 mins span
                        if diff_in_mins >= 20:
                            contacted_daddrs= {}
                            # get a dict of all contacted daddr in the past hour and how many times they were ccontacted
                            for flow in flows_list:
                                daddr = flow['daddr']
                                try:
                                    contacted_daddrs[daddr] = contacted_daddrs[daddr]+1
                                except:
                                    contacted_daddrs.update({daddr: 1})
                            # most of the times the default gateway will be the most contacted daddr, we don't want that
                            # remove it from the dict if it's there
                            contacted_daddrs.pop(self.gateway, None)

                            # get the most contacted daddr in the past hour, if there is any
                            if contacted_daddrs:
                                most_contacted_daddr = max(contacted_daddrs, key=contacted_daddrs.get)
                                times_contacted = contacted_daddrs[most_contacted_daddr]
                                # get the sum of all bytes send to that ip in the past hour
                                total_bytes = 0
                                for flow in flows_list:
                                    daddr = flow['daddr']
                                    # In ARP the sbytes is actually ''
                                    if flow['sbytes'] == '':
                                        sbytes = 0
                                    else:
                                        sbytes = flow['sbytes']
                                    if daddr == most_contacted_daddr:
                                        total_bytes = total_bytes + sbytes
                                # print(f'total_bytes:{total_bytes} most_contacted_daddr: {most_contacted_daddr} times_contacted: {times_contacted} ')
                                if total_bytes >= self.data_exfiltration_threshold*(10**6):
                                    # get the first uid of these flows to use for setEvidence
                                    for flow_dict in all_flows:
                                        for uid, flow in flow_dict.items():
                                            if flow['daddr'] == daddr:
                                                break
                                    self.set_evidence_data_exfiltration(most_contacted_daddr, total_bytes, times_contacted, profileid, twid, uid)

                # --- Detect successful SSH connections ---
                message = self.c2.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_ssh'):
                    self.check_ssh(message)

                # --- Detect alerts from Zeek: Self-signed certs, invalid certs, port-scans and address scans, and password guessing ---
                message = self.c3.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_notice'):
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        data = json.loads(data)
                        profileid = data['profileid']
                        twid = data['twid']
                        # Get flow as a json
                        flow = data['flow']
                        # Convert flow to a dict
                        flow = json.loads(flow)
                        timestamp = flow['stime']
                        uid = data['uid']
                        msg = flow['msg']
                        note = flow['note']

                        # --- Self signed CERTS ---
                        # We're looking for self signed certs in notice.log in the 'msg' field
                        # The self-signed certs apear in both ssl and notice log. But if we check both
                        # we are going to have repeated evidences. So we only check the ssl log for those
                        """
                        if 'self signed' in msg or 'self-signed' in msg:
                            profileid = data['profileid']
                            twid = data['twid']
                            ip = flow['daddr']
                            ip_identification = __database__.getIPIdentification(ip)
                            description = f'Self-signed certificate. Destination IP {ip}. {ip_identification}'
                            confidence = 0.5
                            threat_level = 'low'
                            category = "Anomaly.Behaviour"
                            type_detection = 'dstip'
                            type_evidence = 'SelfSignedCertificate'
                            detection_info = ip
                            __database__.setEvidence(type_evidence, type_detection, detection_info,
                                                     threat_level, confidence, description,
                                                     timestamp, category, profileid=profileid,
                                                     twid=twid, uid=uid)
                        """

                        # --- Detect port scans from Zeek logs---
                        # We're looking for port scans in notice.log in the note field
                        if 'Port_Scan' in note:
                            # Vertical port scan
                            # confidence = 1 because this detection is comming from a zeek file so we're sure it's accurate
                            confidence = 1
                            threat_level = 'medium'
                            # msg example: 192.168.1.200 has scanned 60 ports of 192.168.1.102
                            description = 'vertical port scan by Zeek engine. ' + msg
                            type_evidence = 'PortScanType1'
                            category = 'Recon.Scanning'
                            type_detection = 'dstip'
                            source_target_tag = "Recon"
                            conn_count = int(msg.split("scanned")[1].split("ports")[0])
                            detection_info = flow.get('scanning_ip','')
                            __database__.setEvidence(type_evidence, type_detection, detection_info, threat_level,
                                                     confidence, description, timestamp, category,
                                                     source_target_tag=source_target_tag, conn_count=conn_count,
                                                     profileid=profileid, twid=twid, uid=uid)

                        if 'SSL certificate validation failed' in msg \
                                and 'unable to get local issuer certificate' not in msg:
                                ip = flow['daddr']
                                # get the description inside parenthesis
                                ip_identification = __database__.getIPIdentification(ip)
                                description = msg + f' Destination IP: {ip}. {ip_identification}'
                                self.set_evidence_for_invalid_certificates(profileid, twid, ip,
                                                                           description, uid, timestamp)
                                #self.print(description, 3, 0)

                        if 'Address_Scan' in note:
                            # Horizontal port scan
                            # 10.0.2.15 scanned at least 25 unique hosts on port 80/tcp in 0m33s
                            confidence = 1
                            threat_level = 'medium'
                            description = 'horizontal port scan by Zeek engine. ' + msg
                            type_evidence = 'PortScanType2'
                            type_detection = 'dport'
                            source_target_tag = 'Recon'
                            detection_info = flow.get('scanned_port','')
                            category = 'Recon.Scanning'
                            # get the number of unique hosts scanned on a specific port
                            conn_count = int(msg.split("least")[1].split("unique")[0])
                            __database__.setEvidence(type_evidence, type_detection, detection_info, threat_level,
                                                     confidence, description, timestamp, category,
                                                     source_target_tag=source_target_tag, conn_count=conn_count,
                                                     profileid=profileid, twid=twid, uid=uid)

                        if 'Password_Guessing' in note:
                            # Vertical port scan
                            # confidence = 1 because this detection is comming from a zeek file so we're sure it's accurate
                            confidence = 1
                            threat_level = 'high'
                            category = 'Attempt.Login'
                            # msg example: 192.168.1.200 has scanned 60 ports of 192.168.1.102
                            description = 'password guessing by Zeek enegine. ' + msg
                            type_evidence = 'Password_Guessing'
                            type_detection = 'srcip'
                            source_target_tag = 'Malware'
                            detection_info = flow.get('scanning_ip','')
                            conn_count = int(msg.split("in ")[1].split("connections")[0])
                            __database__.setEvidence(type_evidence, type_detection, detection_info, threat_level,
                                                     confidence, description, timestamp, category,
                                                     conn_count=conn_count, source_target_tag=source_target_tag,
                                                     profileid=profileid, twid=twid, uid=uid)

                # --- Detect maliciuos JA3 TLS servers ---
                message = self.c4.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_ssl'):
                    # Check for self signed certificates in new_ssl channel (ssl.log)
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        data = json.loads(data)
                        # Get flow as a json
                        flow = data['flow']
                        # Convert flow to a dict
                        flow = json.loads(flow)
                        uid = flow['uid']
                        timestamp = flow['stime']
                        ja3 = flow.get('ja3',False)
                        ja3s = flow.get('ja3s',False)
                        profileid = data['profileid']
                        twid = data['twid']
                        daddr = flow['daddr']
                        saddr = profileid.split('_')[1]

                        if 'self signed' in flow['validation_status']:
                            ip = flow['daddr']
                            ip_identification = __database__.getIPIdentification(ip)
                            server_name = flow.get('server_name') # returns None if not found
                            # if server_name is not None or not empty
                            if not server_name:
                                description = f'Self-signed certificate. Destination IP: {ip}. {ip_identification}'
                            else:
                                description = f'Self-signed certificate. Destination IP: {ip}, SNI: {server_name}. {ip_identification}'
                            self.set_evidence_self_signed_certificates(profileid,twid, ip, description, uid, timestamp)
                            self.print(description, 3, 0)

                        if ja3 or ja3s:

                            # get the dict of malicious ja3 stored in our db
                            malicious_ja3_dict = __database__.get_ja3_in_IoC()

                            if ja3 in malicious_ja3_dict:
                                self.set_evidence_malicious_JA3(malicious_ja3_dict, saddr, profileid, twid, uid, timestamp,  type_='ja3', ioc=ja3)

                            if ja3s in malicious_ja3_dict:
                                self.set_evidence_malicious_JA3(malicious_ja3_dict, daddr, profileid, twid, uid, timestamp, type_='ja3s', ioc=ja3s)

                # --- Learn ports that Zeek knows but Slips doesn't ---
                message = self.c5.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_service'):
                    data = json.loads(message['data'])
                    # uid = data['uid']
                    # profileid = data['profileid']
                    # uid = data['uid']
                    # saddr = data['saddr']
                    port = data['port_num']
                    proto = data['port_proto']
                    service = data['service']
                    port_info = __database__.get_port_info(f'{port}/{proto}')
                    if not port_info and len(service) > 0:
                        # zeek detected a port that we didn't know about
                        # add to known ports
                        __database__.set_port_info(f'{port}/{proto}', service[0])

                # --- Detect DNS resolutions without connection ---
                message = self.c6.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_dns_flow'):
                    data = json.loads(message["data"])
                    profileid = data['profileid']
                    twid = data['twid']
                    uid = data['uid']
                    flow_data = json.loads(data['flow']) # this is a dict {'uid':json flow data}
                    domain = flow_data.get('query', False)
                    answers = flow_data.get('answers', False)
                    rcode_name = flow_data.get('rcode_name', False)
                    stime = data.get('stime',False)

                    # only check dns without connection if we have answers(we're sure the query is resolved)
                    if answers:
                        self.check_dns_resolution_without_connection(domain, answers, stime, profileid, twid, uid)
                    if rcode_name:
                        self.detect_DGA(rcode_name, domain, stime, profileid, twid, uid)

                message = self.c7.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_downloaded_file'):
                    data = json.loads(message['data'])
                    source = data.get('source', '')
                    analyzers = data.get('analyzers', '')
                    sha1 = data.get('sha1', '')
                    if 'SSL' not in source or 'SHA1' not in analyzers:
                        # not an ssl cert
                        continue

                    # check if we have this sha1 marked as malicious from one of our feeds
                    ssl_info_from_db = __database__.get_ssl_info(sha1)
                    if not ssl_info_from_db: continue
                    self.set_evidence_malicious_ssl(data, ssl_info_from_db)

            except KeyboardInterrupt:
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True

class TimerThread(threading.Thread):
    """Thread that executes 1 task after N seconds. Only to run the process_global_data."""
    
    def __init__(self, interval, function, parameters):
        threading.Thread.__init__(self)
        self._finished = threading.Event()
        self._interval = interval
        self.function = function 
        self.parameters = parameters

    def shutdown(self):
        """Stop this thread"""
        self._finished.set()
    
    def run(self):
        try:
            if self._finished.isSet(): return True

            # sleep for interval or until shutdown
            self._finished.wait(self._interval)

            self.task()
            return True
            
        except KeyboardInterrupt:
            return True
    
    def task(self):
        #print(f'Executing the function with {self.parameters} on {datetime.datetime.now()}')
        self.function(*self.parameters)
