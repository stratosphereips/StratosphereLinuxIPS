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
from .set_evidence import Helper
from slips_files.core.whitelist import Whitelist



class Module(Module, multiprocessing.Process):
    name = 'flowalerts'
    description = (
        'Alerts about flows: long connection, successful ssh, '
        'password guessing, self-signed certificate, data exfiltration, etc.'
    )
    authors = ['Kamila Babayeva', 'Sebastian Garcia', 'Alya Gomaa']

    def __init__(self, outputqueue, config, redis_port):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config, redis_port)
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
        self.c8 = __database__.subscribe('new_smtp')
        self.c9 = __database__.subscribe('new_software')
        self.whitelist = Whitelist(outputqueue, config, redis_port)
        # helper contains all functions used to set evidence
        self.helper = Helper()
        self.timeout = 0.0000001
        self.p2p_daddrs = {}
        # get the default gateway
        self.gateway = __database__.get_gateway_ip()
        # Cache list of connections that we already checked in the timer
        # thread (we waited for the connection of these dns resolutions)
        self.connections_checked_in_dns_conn_timer_thread = []
        # Cache list of connections that we already checked in the timer
        # thread (we waited for the dns resolution for these connections)
        self.connections_checked_in_conn_dns_timer_thread = []
        # Cache list of connections that we already checked in the timer thread for ssh check
        self.connections_checked_in_ssh_timer_thread = []
        # Threshold how much time to wait when capturing in an interface, to start reporting connections without DNS
        # Usually the computer resolved DNS already, so we need to wait a little to report
        # In mins
        self.conn_without_dns_interface_wait_time = 30
        # this dict will contain the number of nxdomains found in every profile
        self.nxdomains = {}
        # if nxdomains are >= this threshold, it's probably DGA
        self.nxdomains_threshold = 10
        # when the ctr reaches the threshold in 10 seconds, we detect an smtp bruteforce
        self.smtp_bruteforce_threshold = 3
        # dict to keep track of bad smtp logins to check for bruteforce later
        # format {profileid: [ts,ts,...]}
        self.smtp_bruteforce_cache = {}
        # dict to keep track of arpa queries to check for DNS arpa scans later
        # format {profileid: [ts,ts,...]}
        self.dns_arpa_queries = {}
        # after this number of arpa queries, slips will detect an arpa scan
        self.arpa_scan_threshold = 10

    def is_ignored_ip(self, ip) -> bool:
        """
        This function checks if an IP is a special list of IPs that
        should not be alerted for different reasons
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Is the IP multicast, private? (including localhost)
            # local_link or reserved?
            # The broadcast address 255.255.255.255 is reserved.
            if (
                ip_obj.is_multicast
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or '.255' in ip_obj.exploded
            ):
                return True
            return False
        except Exception as inst:
            self.print('Problem on function is_ignored_ip()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return False

    def read_configuration(self):
        """Read the configuration file for what we need"""
        # Get the pcap filter
        try:
            self.long_connection_threshold = int(
                self.config.get('flowalerts', 'long_connection_threshold')
            )
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
        ):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # this value is in seconds, =25 mins
            self.long_connection_threshold = 1500
        try:
            self.ssh_succesful_detection_threshold = int(
                self.config.get(
                    'flowalerts', 'ssh_succesful_detection_threshold'
                )
            )
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
        ):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.ssh_succesful_detection_threshold = 4290
        try:
            self.data_exfiltration_threshold = int(
                self.config.get('flowalerts', 'data_exfiltration_threshold')
            )
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
        ):
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
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    def check_long_connection(
        self, dur, daddr, saddr, profileid, twid, uid, timestamp
    ):
        """
        Check if a duration of the connection is
        above the threshold (more than 25 minutess by default).
        :param dur: duration of the flow in seconds
        """
        if type(dur) == str:
            dur = float(dur)
        module_name = 'flowalerts-long-connection'
        # If duration is above threshold, we should set an evidence
        if dur > self.long_connection_threshold:
            # set "flowalerts-long-connection:malicious" label in the flow (needed for Ensembling module)

            module_label = self.malicious_label
            self.helper.set_evidence_long_connection(
                daddr, dur, profileid, twid, uid, timestamp, ip_state='ip'
            )
        else:
            # set "flowalerts-long-connection:normal" label in the flow (needed for Ensembling module)
            module_label = self.normal_label

        __database__.set_module_label_to_flow(
            profileid, twid, uid, module_name, module_label
        )

    def is_p2p(self, dport, proto, daddr):
        """
        P2P is defined as following : proto is udp, port numbers are higher than 30000 at least 5 connections to different daddrs
        OR trying to connct to 1 ip on more than 5 unkown 30000+/udp ports
        """
        if proto.lower() == 'udp' and int(dport) > 30000:
            try:
                # trying to connct to 1 ip on more than 5 unknown ports
                if self.p2p_daddrs[daddr] >= 6:
                    return True
                self.p2p_daddrs[daddr] = self.p2p_daddrs[daddr] + 1
                # now check if we have more than 4 different dst ips
            except KeyError:
                # first time seeing this daddr
                self.p2p_daddrs[daddr] = 1

            if len(self.p2p_daddrs) == 5:
                # this is another connection on port 3000+/udp and we already have 5 of them
                # probably p2p
                return True

        return False

    def port_belongs_to_an_org(self, daddr, portproto, profileid):
        """
        Checks wehether a port is known to be used by a specific
        organization or not, and returns true if the daddr belongs to the
        same org as the port
        """
        if organization_info := __database__.get_organization_of_port(
                portproto
        ):
            # there's an organization that's known to use this port,
            # check if the daddr belongs to the range of this org
            organization_info = json.loads(organization_info)
            # get the organization ip or range
            org_ip = organization_info['ip']
            # org_name = organization_info['org_name']

            if daddr in org_ip:
                # it's an ip and it belongs to this org, consider the port as known
                return True

            # is it a range?
            try:
                # we have the org range in our database, check if the daddr belongs to this range
                if ipaddress.ip_address(daddr) in ipaddress.ip_network(org_ip):
                    # it does, consider the port as known
                    return True
            except ValueError:
                # not a range either since nothing is specified,
                # check the source and dst mac address vendors
                src_mac_vendor = str(
                    __database__.get_mac_vendor_from_profile(profileid)
                )
                dst_mac_vendor = str(
                    __database__.get_mac_vendor_from_profile(
                        f'profile_{daddr}'
                    )
                )
                org_name = organization_info['org_name'].lower()
                if (
                        org_name in src_mac_vendor.lower()
                        or org_name in dst_mac_vendor.lower()
                ):
                    return True
                # check if the SNI, hostname, rDNS of this ip belong to org_name
                ip_identification = __database__.getIPIdentification(daddr)
                if org_name in ip_identification.lower():
                    return True

        # consider this port as unknown
        return False

    def check_data_upload(self, profileid, twid):
        def remove_ignored_ips(contacted_addresses):
            """
            remove IPs that we shouldn't alert about if they are most contacted
            If the gw is contacted 10 times,
             and 8.8.8.8 is contacted 8 times, we use 8.8.8.8 as the most contacted
            """
            # most of the times the default gateway will be the most contacted daddr, we don't want that
            # remove it from the dict if it's there
            res = {}
            for ip, ip_info in contacted_addresses.items():
                ip_obj = ipaddress.ip_address(ip)
                if not  (ip == self.gateway
                    or ip_obj.is_multicast
                    or ip_obj.is_link_local
                    or ip_obj.is_reserved) :
                    res[ip] = ip_info
            return res


        # we’re looking for systems that are transferring large amount of data in 20 mins span
        all_flows = __database__.get_all_flows_in_profileid(
            profileid
        )
        if not all_flows:
            return

        # get a list of flows without uids
        flows_list = []
        for flow_dict in all_flows:
            flows_list.append(list(flow_dict.items())[0][1])
        # sort flows by ts
        flows_list = sorted(flows_list, key=lambda i: i['ts'])

        time_of_first_flow = flows_list[0]['ts']
        time_of_last_flow = flows_list[-1]['ts']

        # get the time difference between them in mins
        diff_in_mins = utils.get_time_diff(
            time_of_first_flow,
            time_of_last_flow,
            return_type='minutes'
        )
        # we need the flows that happend in 20 mins span
        if diff_in_mins < 20:
            return

        contacted_daddrs = {}
        # get a dict of all contacted daddr in the past hour and how many times they were ccontacted
        for flow in flows_list:
            daddr = flow['daddr']
            try:
                contacted_daddrs[daddr] = (
                    contacted_daddrs[daddr] + 1
                )
            except KeyError:
                contacted_daddrs.update({daddr: 1})

        contacted_daddrs = remove_ignored_ips(contacted_daddrs)
        if not contacted_daddrs:
            return
        # get the top most contacted daddr
        most_contacted_daddr = max(
            contacted_daddrs, key=contacted_daddrs.get
        )
        times_contacted = contacted_daddrs[
            most_contacted_daddr
        ]

        # get the sum of all bytes sent to that ip in the past hour
        total_bytes = 0
        for flow in flows_list:
            daddr = flow['daddr']
            if daddr == most_contacted_daddr:
                # In arp the sbytes is actually ''
                if flow['sbytes'] == '':
                    sbytes = 0
                else:
                    sbytes = flow['sbytes']
                total_bytes += sbytes
        total_mbs = total_bytes / (10**6)

        if (
            total_mbs >= self.data_exfiltration_threshold
        ):
            # get the first uid of these flows to use for setEvidence
            for flow_dict in all_flows:
                for uid, flow in flow_dict.items():
                    if flow['daddr'] == most_contacted_daddr:
                        self.helper.set_evidence_data_exfiltration(
                            most_contacted_daddr,
                            total_mbs,
                            times_contacted,
                            profileid,
                            twid,
                            uid,
                        )
                        return True

    def check_unknown_port(
            self, dport, proto, daddr, profileid, twid, uid, timestamp
    ):
        """
        Checks dports that are not in our
        slips_files/ports_info/services.csv
        """

        portproto = f'{dport}/{proto}'
        if port_info := __database__.get_port_info(portproto):
            # it's a known port
            return False
        # we don't have port info in our database
        # is it a port that is known to be used by
        # a specific organization
        if self.port_belongs_to_an_org(daddr, portproto, profileid):
            return False

        if (
            not 'icmp' in proto
            and not self.is_p2p(dport, proto, daddr)
            and not __database__.is_ftp_port(dport)
        ):
            # we don't have info about this port
            self.helper.set_evidence_unknown_port(
                daddr, dport, proto, timestamp, profileid, twid, uid
            )
            return True

    def check_if_resolution_was_made_by_different_version(
        self, profileid, daddr
    ):
        """
        Sometimes the same computer makes dns requests using its ipv4 and ipv6 address, check if this is the case
        """
        # get the other ip version of this computer
        other_ip = __database__.get_the_other_ip_version(profileid)
        if other_ip:
            other_ip = json.loads(other_ip)
        # get the domain of this ip
        dns_resolution = __database__.get_reverse_dns(daddr)

        try:
            if other_ip and other_ip in dns_resolution.get('resolved-by', []):
                return True
        except AttributeError:
            # It can be that the dns_resolution sometimes gives back a list and gets this error
            return False

    def check_if_connection_was_made_by_different_version(
        self, profileid, twid, daddr
    ):
        """
        :param daddr: the ip this connection is made to (destination ip)
        """
        # get the other ip version of this computer
        other_ip = __database__.get_the_other_ip_version(profileid)
        if not other_ip:
            return False

        # get the ips contacted by the other_ip
        contacted_ips = __database__.get_all_contacted_ips_in_profileid_twid(
            f'profile_{other_ip}', twid
        )
        if not contacted_ips:
            return False

        if daddr in contacted_ips:
            # now we're sure that the connection was made
            # by this computer but using a different ip version
            return True

    def check_dns_arpa_scan(self, domain, stime, profileid, twid, uid):
        """
        Detect and ARPA scan if an ip performed 10(arpa_scan_threshold) or more arpa queries within 2 seconds
        """
        if not domain.endswith('.in-addr.arpa'):
            return False

        try:
            # format of this dict is {profileid: [stime of first arpa query, stime eof second, etc..]}
            timestamps, uids, domains_scanned = self.dns_arpa_queries[profileid]
            timestamps.append(stime)
            uids.append(uid)
            uids.append(uid)
            domains_scanned.add(domain)
            self.dns_arpa_queries[profileid] = (timestamps, uids, domains_scanned)
        except KeyError:
            # first time for this profileid to perform an arpa query
            self.dns_arpa_queries[profileid] = (
                [stime], [uid], {domain}
            )
            return False

        if len(domains_scanned) < self.arpa_scan_threshold:
            # didn't reach the threshold yet
            return False

        # reached the threshold, did the 10 queries happen within 2 seconds?
        diff = utils.get_time_diff(
            timestamps[0],
            timestamps[-1]
        )
        if diff > 2:
            # happened within more than 2 seconds
            return False

        self.helper.set_evidence_dns_arpa_scan(
            self.arpa_scan_threshold, stime, profileid, twid, uids
        )
        # empty the list of arpa queries for this profile, we don't need them anymore
        self.dns_arpa_queries.pop(profileid)
        return True

    def is_well_known_org(self, ip):
        """get the SNI, ASN, and  rDNS of the IP to check if it belongs
        to a well-known org"""

        ip_data = __database__.getIPData(ip)
        try:
            ip_asn = ip_data['asn']['asnorg']
        except (KeyError, TypeError):
            # No asn data for this ip
            ip_asn = False

        try:
            SNI = ip_data['SNI']
            if type(SNI) == list:
                # SNI is a list of dicts, each dict contains the 'server_name' and 'port'
                SNI = SNI[0]
                if SNI in (None, ''):
                    SNI = False
                elif type(SNI) == dict:
                    SNI = SNI.get('server_name', False)
        except (KeyError, TypeError):
            # No SNI data for this ip
            SNI = False

        try:
            rdns = ip_data['reverse_dns']
        except (KeyError, TypeError):
            # No SNI data for this ip
            rdns = False

        flow_domain = rdns or SNI
        for org in utils.supported_orgs:
            if ip_asn and ip_asn != 'Unknown':
                org_asn = json.loads(__database__.get_org_info(org, 'asn'))
                if org.lower() in ip_asn.lower() or ip_asn in org_asn:
                    return True
            # remove the asn from ram
            org_asn = ''

            if flow_domain:
                # we have the rdns or sni of this flow , now check
                if org in flow_domain:
                    # self.print(f"The domain of this flow ({flow_domain}) belongs to the domains of {org}")
                    return True

                org_domains = json.loads(
                    __database__.get_org_info(org, 'domains')
                )

                flow_TLD = flow_domain.split('.')[-1]

                for org_domain in org_domains:
                    org_domain_TLD = org_domain.split('.')[-1]
                    # make sure the 2 domains have the same same top level domain
                    if flow_TLD != org_domain_TLD:
                        continue

                    # match subdomains too
                    # return true if org has org.com, and the flow_domain is xyz.org.com
                    # or if org has xyz.org.com, and the flow_domain is org.com return true
                    if org_domain in flow_domain or flow_domain in org_domain:
                        return True

                # remove from ram
                org_domains = ''

            # check if the ip belongs to the range of a well known org (fb, twitter, microsoft, etc.)
            org_ips = __database__.get_org_IPs(org)

            if '.' in ip:
                first_octet = ip.split('.')[0]
                ip_obj = ipaddress.IPv4Address(ip)
            elif ':' in ip:
                first_octet = ip.split(':')[0]
                ip_obj = ipaddress.IPv6Address(ip)
            else:
                return False
            # organization IPs are sorted by first octet for faster search
            for range in org_ips.get(first_octet, {}):
                if ip_obj in ipaddress.ip_network(range):
                    return True

    def check_connection_without_dns_resolution(
        self, daddr, twid, profileid, timestamp, uid
    ):
        """Checks if there's a flow to a dstip that has no cached DNS answer"""
        # Ignore some IP
        ## - All dhcp servers. Since is ok to connect to them without a DNS request.
        # We dont have yet the dhcp in the redis, when is there check it
        # if __database__.get_dhcp_servers(daddr):
        # continue

        # To avoid false positives in case of an interface don't alert ConnectionWithoutDNS
        # until 30 minutes has passed
        # after starting slips because the dns may have happened before starting slips
        if '-i' in sys.argv:
            start_time = __database__.get_slips_start_time()
            now = datetime.datetime.now()
            diff = utils.get_time_diff(start_time, now, return_type='minutes')
            if diff >= self.conn_without_dns_interface_wait_time:
                # less than 2=30 minutes have passed
                return False

        answers_dict = __database__.get_reverse_dns(daddr)
        if answers_dict:
            return False
        # self.print(f'No DNS resolution in {answers_dict}')
        # There is no DNS resolution, but it can be that Slips is
        # still reading it from the files.
        # To give time to Slips to read all the files and get all the flows
        # don't alert a Connection Without DNS until 5 seconds has passed
        # in real time from the time of this checking.

        # Create a timer thread that will wait 5 seconds for the dns to arrive and then check again
        # self.print(f'Cache of conns not to check: {self.conn_checked_dns}')
        if uid not in self.connections_checked_in_conn_dns_timer_thread:
            # comes here if we haven't started the timer thread for this connection before
            # mark this connection as checked
            self.connections_checked_in_conn_dns_timer_thread.append(uid)
            params = [daddr, twid, profileid, timestamp, uid]
            # self.print(f'Starting the timer to check on {daddr}, uid {uid}.

            # time {datetime.datetime.now()}')
            timer = TimerThread(
                15, self.check_connection_without_dns_resolution, params
            )
            timer.start()
        else:
            # It means we already checked this conn with the Timer process
            # (we waited 15 seconds for the dns to arrive after the connection was made)
            # but still no dns resolution for it.
            # Sometimes the same computer makes requests using its ipv4 and ipv6 address, check if this is the case
            if self.check_if_resolution_was_made_by_different_version(
                    profileid, daddr
            ):
                return False

            if self.is_well_known_org(daddr):
                # if the SNI or rDNS of the IP matches a well-known org, then this is a FP
                return False
            # self.print(f'Alerting after timer conn without dns on {daddr},
            self.helper.set_evidence_conn_without_dns(
                daddr, timestamp, profileid, twid, uid
            )
            # This UID will never appear again, so we can remove it and
            # free some memory
            try:
                self.connections_checked_in_conn_dns_timer_thread.remove(
                    uid
                )
            except ValueError:
                pass

    def is_CNAME_contacted(self, answers, contacted_ips) -> bool:
        """
        check if any ip of the given CNAMEs is contacted
        """
        for CNAME in answers:
            if not validators.domain(CNAME):
                # it's an ip
                continue
            ips = __database__.get_domain_resolution(CNAME)
            for ip in ips:
                if ip in contacted_ips:
                    return True
        return False

    def check_dns_without_connection(
            self, domain, answers, timestamp, profileid, twid, uid
    ):
        """
        Makes sure all cached DNS answers are used in contacted_ips
        :param contacted_ips:  dict of ips used in a specific tw {ip: uid}
        """
        ## - All reverse dns resolutions
        ## - All .local domains
        ## - The wildcard domain *
        ## - Subdomains of cymru.com, since it is used by the ipwhois library in Slips to get the ASN
        # of an IP and its range. This DNS is meant not to have a connection later
        ## - Domains check from Chrome, like xrvwsrklpqrw
        ## - The WPAD domain of windows

        if (
            'arpa' in domain
            or '.local' in domain
            or '*' in domain
            or '.cymru.com' in domain[-10:]
            or len(domain.split('.')) == 1
            or domain == 'WPAD'
        ):
            return False

        # One DNS query may not be answered exactly by UID, but the computer can re-ask the donmain,
        # and the next DNS resolution can be
        # answered. So dont check the UID, check if the domain has an IP

        # self.print(f'The DNS query to {domain} had as answers {answers} ')

        # It can happen that this domain was already resolved previously, but with other IPs
        # So we get from the DB all the IPs for this domain first and append them to the answers
        # This happens, for example, when there is 1 DNS resolution with A, then 1 DNS resolution
        # with AAAA, and the computer chooses the A address. Therefore, the 2nd DNS resolution
        # would be treated as 'without connection', but this is false.

        previous_data_for_domain = __database__.getDomainData(domain)
        if previous_data_for_domain:
            try:
                previous_ips_for_domain = previous_data_for_domain['IPs']
                if type(answers) == set:
                    answers = list(answers)
                answers.extend(previous_ips_for_domain)
            except KeyError:
                pass

        # self.print(f'The extended DNS query to {domain} had as answers {answers} ')

        contacted_ips = __database__.get_all_contacted_ips_in_profileid_twid(
            profileid, twid
        )
        # If contacted_ips is empty it can be because we didnt read yet all the flows.
        # This is automatically captured later in the for loop and we start a Timer

        # every dns answer is a list of ips that correspond to a spicific query,
        # one of these ips should be present in the contacted ips
        # check each one of the resolutions of this domain
        if answers == ['']:
            # If no IPs are in the answer, we can not expect the computer to connect to anything
            # self.print(f'No ips in the answer, so ignoring')
            return False
        # to avoid checking the same answer twice
        answers = set(answers)
        for ip in answers:
            # self.print(f'Checking if we have a connection to ip {ip}')
            if ip in contacted_ips:
                # this dns resolution has a connection. We can exit
                return False

        # Check if there was a connection to any of the CNAMEs
        if self.is_CNAME_contacted(answers, contacted_ips):
            # this is not a DNS without resolution
            return False

        for ip in answers:
            if self.check_if_connection_was_made_by_different_version(
                    profileid, twid, ip
            ):
                return False

        # self.print(f'It seems that none of the IPs were contacted')
        # Found a DNS query which none of its IPs was contacted
        # It can be that Slips is still reading it from the files. Lets check back in some time
        # Create a timer thread that will wait some seconds for the connection to arrive and then check again
        if uid not in self.connections_checked_in_dns_conn_timer_thread:
            # comes here if we haven't started the timer thread for this dns before
            # mark this dns as checked
            self.connections_checked_in_dns_conn_timer_thread.append(uid)
            params = [domain, answers, timestamp, profileid, twid, uid]
            # self.print(f'Starting the timer to check on {domain}, uid {uid}.
            # time {datetime.datetime.now()}')
            timer = TimerThread(
                15, self.check_dns_without_connection, params
            )
            timer.start()
        else:
            # self.print(f'Alerting on {domain}, uid {uid}. time {datetime.datetime.now()}')
            # It means we already checked this dns with the Timer process
            # but still no connection for it.
            self.helper.set_evidence_DNS_without_conn(
                domain, timestamp, profileid, twid, uid
            )
            # This UID will never appear again, so we can remove it and
            # free some memory
            try:
                self.connections_checked_in_dns_conn_timer_thread.remove(uid)
            except ValueError:
                pass

    def detect_successful_ssh_by_zeek(self, uid, timestamp, profileid, twid, message):
        """
        Check for auth_success: true in the given zeek flow
        """
        original_ssh_flow = __database__.get_flow(profileid, twid, uid)
        original_flow_uid = next(iter(original_ssh_flow))
        if original_ssh_flow[original_flow_uid]:
            ssh_flow_dict = json.loads(
                original_ssh_flow[original_flow_uid]
            )
            daddr = ssh_flow_dict['daddr']
            saddr = ssh_flow_dict['saddr']
            size = ssh_flow_dict['allbytes']
            self.helper.set_evidence_ssh_successful(
                profileid,
                twid,
                saddr,
                daddr,
                size,
                uid,
                timestamp,
                by='Zeek',
            )
            try:
                self.connections_checked_in_ssh_timer_thread.remove(
                    uid
                )
            except ValueError:
                pass
            return True
        elif uid not in self.connections_checked_in_ssh_timer_thread:
            # It can happen that the original SSH flow is not in the DB yet
            # comes here if we haven't started the timer thread for this connection before
            # mark this connection as checked
            # self.print(f'Starting the timer to check on {flow_dict}, uid {uid}. time {datetime.datetime.now()}')
            self.connections_checked_in_ssh_timer_thread.append(
                uid
            )
            params = [message]
            timer = TimerThread(
                15, self.check_successful_ssh, params
            )
            timer.start()

    def detect_successful_ssh_by_slips(self, uid, timestamp, profileid, twid, message):
        """
        Try Slips method to detect if SSH was successful by
        comparing all bytes sent and received to our threshold
        """
        original_ssh_flow = __database__.get_flow(profileid, twid, uid)
        original_flow_uid = next(iter(original_ssh_flow))
        if original_ssh_flow[original_flow_uid]:
            ssh_flow_dict = json.loads(
                original_ssh_flow[original_flow_uid]
            )
            daddr = ssh_flow_dict['daddr']
            saddr = ssh_flow_dict['saddr']
            size = ssh_flow_dict['allbytes']
            if size > self.ssh_succesful_detection_threshold:
                # Set the evidence because there is no
                # easier way to show how Slips detected
                # the successful ssh and not Zeek
                self.helper.set_evidence_ssh_successful(
                    profileid,
                    twid,
                    saddr,
                    daddr,
                    size,
                    uid,
                    timestamp,
                    by='Slips',
                )
                try:
                    self.connections_checked_in_ssh_timer_thread.remove(
                        uid
                    )
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
                # self.print(f'Starting the timer to check on {flow_dict}, uid {uid}.
                # time {datetime.datetime.now()}')
                self.connections_checked_in_ssh_timer_thread.append(
                    uid
                )
                params = [message]
                timer = TimerThread(
                    15, self.check_successful_ssh, params
                )
                timer.start()

    def check_successful_ssh(self, message):
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
            if auth_success := flow_dict['auth_success']:
                self.detect_successful_ssh_by_zeek(uid, timestamp, profileid, twid, message)
            else:
                self.detect_successful_ssh_by_slips(uid, timestamp, profileid, twid, message)

        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on check_ssh() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return False

    def detect_incompatible_CN(
            self,
            daddr,
            server_name,
            issuer,
            profileid,
            twid,
            uid,
            timestamp
       ):
        """
        Detects if a certificate claims that it's CN (common name) belongs
        to an org that the domain doesn't belong to
        """
        if not issuer:
            return False
        found_org_in_cn = ''
        for org in utils.supported_orgs:
            if org not in issuer.lower():
                continue

            # save the org this domain/ip is claiming to belong to, to use it to set evidence later
            found_org_in_cn = org

            # check that the domain belongs to that same org
            if self.whitelist.is_ip_in_org(daddr, org):
                return False

            # check that the ip belongs to that same org
            if server_name and self.whitelist.is_domain_in_org(server_name, org):
                return False

        if not found_org_in_cn:
            return False

        # found one of our supported orgs in the cn but it doesn't belong to any of this org's
        # domains or ips
        self.helper.set_evidence_incompatible_CN(
            found_org_in_cn,
            timestamp,
            daddr,
            profileid,
            twid,
            uid
        )


    def check_multiple_ssh_clients(
        self,
        starttime,
        saddr,
        used_software,
        major_v,
        minor_v,
        twid,
        uid,
    ):
        """
        function to check if this srcip was detected using a different ssh client versions before
        """
        profileid = f'profile_{saddr}'
        # returns a dict with software, 'version-major', 'version-minor'
        cached_ssh_versions: dict = __database__.get_software_from_profile(
            profileid
        )
        if not cached_ssh_versions:
            # we have no previous software info about this saddr in out db
            return False

        cached_software = cached_ssh_versions['software']
        if cached_software != used_software:
            # we need them both to be "SSH::CLIENT"
            return False

        cached_major_v = cached_ssh_versions['version-major']
        cached_minor_v = cached_ssh_versions['version-minor']
        cached_versions = f'{cached_major_v}_{cached_minor_v}'
        current_versions = f'{major_v}_{minor_v}'
        if cached_versions == current_versions:
            # they're using the same ssh client version
            return False
        # get the uid of the cached versions, and the uid of the current used versions
        uids = [cached_ssh_versions['uid'], uid]
        self.helper.set_evidence_multiple_ssh_versions(
            saddr, cached_versions, current_versions, starttime, twid, uids
        )
        return True

    def detect_DGA(self, rcode_name, query, stime, profileid, twid, uid):
        """
        Detect DGA based on the amount of NXDOMAINs seen in dns.log
        alerts when 10 15 20 etc. nxdomains are found
        """

        if (
            not 'NXDOMAIN' in rcode_name
            or 'in-addr.arpa' in query
            or query.endswith('.local')
        ):
            return False

        profileid_twid = f'{profileid}_{twid}'

        # found NXDOMAIN by this profile
        try:
            # make sure all domains are unique
            if query not in self.nxdomains[profileid_twid]:
                queries, uids = self.nxdomains[profileid_twid]
                queries.append(query)
                uids.append(uid)
                self.nxdomains[profileid_twid] = (queries, uids)
        except KeyError:
            # first time seeing nxdomain in this profile and tw
            self.nxdomains.update({profileid_twid: ([query], [uid])})
            return False

        # every 5 nxdomains, generate an alert.
        queries, uids = self.nxdomains[profileid_twid]
        number_of_nxdomains = len(queries)
        if (
            number_of_nxdomains % 5 == 0
            and number_of_nxdomains >= self.nxdomains_threshold
        ):
            self.helper.set_evidence_DGA(
                number_of_nxdomains, stime, profileid, twid, uids
            )
            # clear the list of alerted queries and uids
            self.nxdomains[profileid_twid] = ([],[])
            return True


    def detect_young_domains(self, domain, stime, profileid, twid, uid):

        age_threshold = 60

        if domain.endswith('.arpa') or domain.endswith('.local'):
            return False

        domain_info = __database__.getDomainData(domain)
        if not domain_info:
            return False

        if 'Age' not in domain_info:
            # we don't have age info about this domain
            return False

        # age is in days
        age = domain_info['Age']
        if age >= age_threshold:
            return False

        self.helper.set_evidence_young_domain(
            domain, age, stime, profileid, twid, uid
        )
        return True

    def shutdown_gracefully(self):
        __database__.publish('finished_modules', self.name)

    def check_smtp_bruteforce(self, stime, saddr, daddr, profileid, twid, uid):

        try:
            timestamps, uids = self.smtp_bruteforce_cache[profileid]
            timestamps.append(stime)
            uids.append(uid)
            self.smtp_bruteforce_cache[profileid] = (timestamps, uids)
        except KeyError:
            # first time for this profileid to make bad smtp login
            self.smtp_bruteforce_cache.update(
                {
                    profileid: ([stime], [uid])
                }
            )

        self.helper.set_evidence_bad_smtp_login(
            saddr, daddr, stime, profileid, twid, uid
        )

        timestamps = self.smtp_bruteforce_cache[profileid][0]
        uids = self.smtp_bruteforce_cache[profileid][1]

        # check if 3 bad login attemps happened within 10 seconds or less
        if not (
            len(timestamps) == self.smtp_bruteforce_threshold
        ):
            return

        # check if they happened within 10 seconds or less
        diff = utils.get_time_diff(
            timestamps[0],
            timestamps[-1]
        )

        if diff > 10:
            # remove the first login from cache so we can check the next 3 logins
            self.smtp_bruteforce_cache[profileid][0].pop(0)
            self.smtp_bruteforce_cache[profileid][1].pop(0)
            return

        self.helper.set_evidence_smtp_bruteforce(
            saddr,
            daddr,
            stime,
            profileid,
            twid,
            uids,
            self.smtp_bruteforce_threshold,
        )

        # remove all 3 logins that caused this alert
        self.smtp_bruteforce_cache[profileid] = ([],[])



    def detect_connection_to_multiple_ports(
            self,
            saddr,
            daddr,
            proto,
            state,
            appproto,
            dport,
            timestamp,
            profileid,
            twid
    ):
        if not (
            proto == 'tcp'
            and state == 'Established'
        ):
            return

        dport_name = appproto
        if not dport_name:
            dport_name = __database__.get_port_info(
                f'{dport}/{proto}'
            )

        if dport_name:
            # dport is known, we are considering only unknown services
            return

        # Connection to multiple ports to the destination IP
        if profileid.split('_')[1] == saddr:
            direction = 'Dst'
            state = 'Established'
            protocol = 'TCP'
            role = 'Client'
            type_data = 'IPs'

            # get all the dst ips with established tcp connections
            daddrs = (
                __database__.getDataFromProfileTW(
                    profileid,
                    twid,
                    direction,
                    state,
                    protocol,
                    role,
                    type_data,
                )
            )

            # make sure we find established connections to this daddr
            if daddr not in daddrs:
                return

            dstports = list(
                daddrs[daddr]['dstports']
            )
            if len(dstports) <= 1:
                return

            ip_identification = __database__.getIPIdentification(daddr)
            description = (
                f'Connection to multiple ports {dstports} of '
                f'Destination IP: {daddr}. {ip_identification}'
            )
            uids = daddrs[daddr]['uid']
            self.helper.set_evidence_for_connection_to_multiple_ports(
                profileid,
                twid,
                daddr,
                description,
                uids,
                timestamp,
            )

        # Connection to multiple port to the Source IP. Happens in the mode 'all'
        elif profileid.split('_')[1] == daddr:
            direction = 'Src'
            state = 'Established'
            protocol = 'TCP'
            role = 'Server'
            type_data = 'IPs'

            # get all the src ips with established tcp connections
            saddrs = (
                __database__.getDataFromProfileTW(
                    profileid,
                    twid,
                    direction,
                    state,
                    protocol,
                    role,
                    type_data,
                )
            )
            dstports = list(
                saddrs[saddr]['dstports']
            )
            if len(dstports) <= 1:
                return

            uids = saddrs[saddr]['uid']
            description = f'Connection to multiple ports {dstports} of Source IP: {saddr}'

            self.helper.set_evidence_for_connection_to_multiple_ports(
                profileid,
                twid,
                daddr,
                description,
                uids,
                timestamp,
            )


    def run(self):
        utils.drop_root_privs()
        # Main loop function
        while True:
            try:
                # ---------------------------- new_flow channel
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time, Slips is stopped automatically.
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
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
                    if (
                        not ipaddress.ip_address(daddr).is_multicast
                        and not ipaddress.ip_address(saddr).is_multicast
                    ):
                        self.check_long_connection(
                            dur, daddr, saddr, profileid, twid, uid, timestamp
                        )

                    # --- Detect unknown destination ports ---
                    if dport:
                        self.check_unknown_port(
                            dport,
                            proto.lower(),
                            daddr,
                            profileid,
                            twid,
                            uid,
                            timestamp,
                        )

                    # --- Detect Multiple Reconnection attempts ---
                    key = f'{saddr}-{daddr}-{dport}'
                    if origstate == 'REJ':
                        # add this conn to the stored number of reconnections
                        current_reconnections = __database__.getReconnectionsForTW(profileid, twid)

                        try:
                            reconnections, uids = current_reconnections[key]
                            reconnections += 1
                            uids.append(uid)
                            current_reconnections[key] = (reconnections, uids)
                        except KeyError:
                            current_reconnections[key] = (1, [uid])
                            reconnections = 1

                        if reconnections >= 5:
                            ip_identification = (
                                __database__.getIPIdentification(daddr)
                            )
                            description = (
                                f'Multiple reconnection attempts to Destination IP: {daddr} {ip_identification} '
                                f'from IP: {saddr} reconnections: {reconnections}'
                            )
                            self.helper.set_evidence_for_multiple_reconnection_attempts(
                                profileid,
                                twid,
                                daddr,
                                description,
                                uids,
                                timestamp,
                            )
                            # reset the reconnection attempts of this src->dst
                            current_reconnections[key] = (0, [])

                        __database__.setReconnections(
                            profileid, twid, current_reconnections
                        )


                    # --- Detect Connection to port 0 ---
                    if proto not in ('igmp', 'icmp', 'ipv6-icmp') and (
                        sport == 0 or dport == 0
                    ):
                        direction = 'source' if sport == 0 else 'destination'
                        self.helper.set_evidence_for_port_0_connection(
                            saddr,
                            daddr,
                            direction,
                            profileid,
                            twid,
                            uid,
                            timestamp,
                        )

                    # --- Detect if this is a connection without a DNS resolution ---
                    # The exceptions are:
                    # 1- Do not check for DNS requests
                    # 2- Ignore some IPs like private IPs, multicast, and broadcast
                    if (
                        flow_type == 'conn'
                        and appproto != 'dns'
                        and not self.is_ignored_ip(daddr)
                    ):

                        self.check_connection_without_dns_resolution(
                            daddr, twid, profileid, timestamp, uid
                        )

                    # --- Detect Connection to multiple ports (for RAT) ---
                    self.detect_connection_to_multiple_ports(
                        saddr,
                        daddr,
                        proto,
                        state,
                        appproto,
                        dport,
                        timestamp,
                        profileid,
                        twid
                    )

                    # --- Detect Data exfiltration ---
                    self.check_data_upload(profileid, twid)

                # --- Detect successful SSH connections ---
                message = self.c2.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_ssh'):
                    self.check_successful_ssh(message)

                # --- Detect alerts from Zeek: Self-signed certs, invalid certs, port-scans and address scans, and password guessing ---
                message = self.c3.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
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

                        # --- Detect port scans from Zeek logs ---
                        # We're looking for port scans in notice.log in the note field
                        if 'Port_Scan' in note:
                            # Vertical port scan
                            scanning_ip = flow.get('scanning_ip', '')
                            self.helper.set_evidence_vertical_portscan(
                                msg,
                                scanning_ip,
                                timestamp,
                                profileid,
                                twid,
                                uid,
                            )

                        # --- Detect SSL cert validation failed ---
                        if (
                            'SSL certificate validation failed' in msg
                            and 'unable to get local issuer certificate'
                            not in msg
                        ):
                            ip = flow['daddr']
                            # get the description inside parenthesis
                            ip_identification = (
                                __database__.getIPIdentification(ip)
                            )
                            description = (
                                msg
                                + f' Destination IP: {ip}. {ip_identification}'
                            )
                            self.helper.set_evidence_for_invalid_certificates(
                                profileid,
                                twid,
                                ip,
                                description,
                                uid,
                                timestamp,
                            )
                            # self.print(description, 3, 0)

                        # --- Detect horizontal portscan by zeek ---
                        if 'Address_Scan' in note:
                            # Horizontal port scan
                            scanned_port = flow.get('scanned_port', '')
                            self.helper.set_evidence_horizontal_portscan(
                                msg,
                                scanned_port,
                                timestamp,
                                profileid,
                                twid,
                                uid,
                            )
                        # --- Detect password guessing by zeek ---
                        if 'Password_Guessing' in note:
                            self.helper.set_evidence_pw_guessing(
                                msg, timestamp, profileid, twid, uid
                            )

                # --- Detect maliciuos JA3 TLS servers ---
                message = self.c4.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
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
                        ja3 = flow.get('ja3', False)
                        ja3s = flow.get('ja3s', False)
                        issuer = flow.get('issuer', False)
                        profileid = data['profileid']
                        twid = data['twid']
                        daddr = flow['daddr']
                        saddr = profileid.split('_')[1]
                        server_name = flow.get('server_name')   # returns None if not found
                        if 'self signed' in flow['validation_status']:
                            ip = flow['daddr']
                            ip_identification = (
                                __database__.getIPIdentification(ip)
                            )
                            if not server_name:
                                description = f'Self-signed certificate. Destination IP: {ip}. {ip_identification}'
                            else:
                                description = f'Self-signed certificate. Destination IP: {ip}, SNI: {server_name}. {ip_identification}'
                            self.helper.set_evidence_self_signed_certificates(
                                profileid,
                                twid,
                                ip,
                                description,
                                uid,
                                timestamp,
                            )
                            self.print(description, 3, 0)

                        if ja3 or ja3s:

                            # get the dict of malicious ja3 stored in our db
                            malicious_ja3_dict = __database__.get_ja3_in_IoC()

                            if ja3 in malicious_ja3_dict:
                                self.helper.set_evidence_malicious_JA3(
                                    malicious_ja3_dict,
                                    saddr,
                                    profileid,
                                    twid,
                                    uid,
                                    timestamp,
                                    type_='ja3',
                                    ioc=ja3,
                                )

                            if ja3s in malicious_ja3_dict:
                                self.helper.set_evidence_malicious_JA3(
                                    malicious_ja3_dict,
                                    daddr,
                                    profileid,
                                    twid,
                                    uid,
                                    timestamp,
                                    type_='ja3s',
                                    ioc=ja3s,
                                )
                        self.detect_incompatible_CN(
                            daddr,
                            server_name,
                            issuer,
                            profileid,
                            twid,
                            uid,
                            timestamp
                        )
                # --- Learn ports that Zeek knows but Slips doesn't ---
                message = self.c5.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
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
                        __database__.set_port_info(
                            f'{port}/{proto}', service[0]
                        )

                # --- Detect DNS issues: 1) DNS resolutions without connection, 2) DGA, 3) young domains, 4) ARPA SCANs
                message = self.c6.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_dns_flow'):
                    data = json.loads(message['data'])
                    profileid = data['profileid']
                    twid = data['twid']
                    uid = data['uid']
                    flow_data = json.loads(
                        data['flow']
                    )   # this is a dict {'uid':json flow data}
                    domain = flow_data.get('query', False)
                    answers = flow_data.get('answers', False)
                    rcode_name = flow_data.get('rcode_name', False)
                    stime = data.get('stime', False)

                    # only check dns without connection if we have answers(we're sure the query is resolved)
                    # sometimes we have 2 dns flows, 1 for ipv4 and 1 fo ipv6, both have the
                    # same uid, this causes FP dns without connection,
                    # so make sure we only check the uid once
                    if answers and uid not in self.connections_checked_in_dns_conn_timer_thread:
                        self.check_dns_without_connection(
                            domain, answers, stime, profileid, twid, uid
                        )
                    if rcode_name:
                        self.detect_DGA(
                            rcode_name, domain, stime, profileid, twid, uid
                        )
                    if domain:
                        # TODO: not sure how to make sure IP_info is done adding domain age to the db or not
                        self.detect_young_domains(
                            domain, stime, profileid, twid, uid
                        )
                        self.check_dns_arpa_scan(
                            domain, stime, profileid, twid, uid
                        )

                # --- Detect malicious SSL certificates ---
                message = self.c7.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
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
                    if not ssl_info_from_db:
                        continue
                    self.helper.set_evidence_malicious_ssl(
                        data, ssl_info_from_db
                    )

                # --- Detect Bad SMTP logins ---
                message = self.c8.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_smtp'):
                    data = json.loads(message['data'])
                    profileid = data['profileid']
                    twid = data['twid']
                    uid = data['uid']
                    daddr = data['daddr']
                    saddr = data['saddr']
                    stime = data.get('ts', False)
                    last_reply = data.get('last_reply', False)

                    if 'bad smtp-auth user' in last_reply:
                      self.check_smtp_bruteforce( stime, saddr, daddr, profileid, twid, uid )


                # --- Detect multiple used SSH versions ---
                message = self.c9.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_software'):
                    flow = json.loads(message['data'])
                    starttime = flow.get('starttime', '')
                    saddr = flow.get('saddr', '')
                    uid = flow.get('uid', '')
                    twid = flow.get('twid', '')
                    software_type = flow.get('software_type', '')
                    if 'ssh' not in software_type.lower():
                        continue
                    major_v = flow.get('version.major', '')
                    minor_v = flow.get('version.minor', '')
                    self.check_multiple_ssh_clients(
                        starttime,
                        saddr,
                        software_type,
                        major_v,
                        minor_v,
                        twid,
                        uid,
                    )

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
