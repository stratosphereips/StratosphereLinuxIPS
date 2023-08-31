import contextlib
from slips_files.common.imports import *
from .TimerThread import TimerThread
from .set_evidence import Helper
from slips_files.core.helpers.whitelist import Whitelist
import multiprocessing
import json
import threading
import ipaddress
import datetime
import sys
import validators
import collections
import math
import time


class FlowAlerts(Module, multiprocessing.Process):
    name = 'Flow Alerts'
    description = (
        'Alerts about flows: long connection, successful ssh, '
        'password guessing, self-signed certificate, data exfiltration, etc.'
    )
    authors = ['Kamila Babayeva', 'Sebastian Garcia', 'Alya Gomaa']

    def init(self):
        # Read the configuration
        self.read_configuration()
        # Retrieve the labels
        self.subscribe_to_channels()
        self.whitelist = Whitelist(self.output_queue, self.db)
        self.conn_counter = 0
        # helper contains all functions used to set evidence
        self.helper = Helper(self.db)
        self.p2p_daddrs = {}
        # get the default gateway
        self.gateway = self.db.get_gateway_ip()
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
        # when the ctr reaches the threshold in 10 seconds,
        # we detect an smtp bruteforce
        self.smtp_bruteforce_threshold = 3
        # dict to keep track of bad smtp logins to check for bruteforce later
        # format {profileid: [ts,ts,...]}
        self.smtp_bruteforce_cache = {}
        # dict to keep track of arpa queries to check for DNS arpa scans later
        # format {profileid: [ts,ts,...]}
        self.dns_arpa_queries = {}
        # after this number of arpa queries, slips will detect an arpa scan
        self.arpa_scan_threshold = 10
        # If 1 flow uploaded this amount of MBs or more, slips will alert data upload
        self.flow_upload_threshold = 100
        # after this number of failed ssh logins, we alert pw guessing
        self.pw_guessing_threshold = 20
        self.password_guessing_cache = {}
        # in pastebin download detection, we wait for each conn.log flow of the seen ssl flow to appear
        # this is the dict of ssl flows we're waiting for
        self.pending_ssl_flows = multiprocessing.Queue()
        # thread that waits for ssl flows to appear in conn.log
        self.ssl_waiting_thread = threading.Thread(
            target=self.wait_for_ssl_flows_to_appear_in_connlog, daemon=True
        )
    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe('new_flow')
        self.c2 = self.db.subscribe('new_ssh')
        self.c3 = self.db.subscribe('new_notice')
        self.c4 = self.db.subscribe('new_ssl')
        self.c5 = self.db.subscribe('tw_closed')
        self.c6 = self.db.subscribe('new_dns')
        self.c7 = self.db.subscribe('new_downloaded_file')
        self.c8 = self.db.subscribe('new_smtp')
        self.c9 = self.db.subscribe('new_software')
        self.c10 = self.db.subscribe('new_weird')
        self.c11 = self.db.subscribe('new_tunnel')
        self.channels = {
            'new_flow': self.c1,
            'new_ssh': self.c2,
            'new_notice': self.c3,
            'new_ssl': self.c4,
            'tw_closed': self.c5,
            'new_dns': self.c6,
            'new_downloaded_file': self.c7,
            'new_smtp': self.c8,
            'new_software': self.c9,
            'new_weird': self.c10,
            'new_tunnel': self.c11,
        }

    def read_configuration(self):
        conf = ConfigParser()
        self.long_connection_threshold = conf.long_connection_threshold()
        self.ssh_succesful_detection_threshold = conf.ssh_succesful_detection_threshold()
        self.data_exfiltration_threshold = conf.data_exfiltration_threshold()
        self.pastebin_downloads_threshold = conf.get_pastebin_download_threshold()
        self.our_ips = utils.get_own_IPs()
        self.shannon_entropy_threshold = conf.get_entropy_threshold()

    def check_connection_to_local_ip(
            self,
            daddr,
            dport,
            proto,
            saddr,
            profileid,
            twid,
            uid,
            timestamp,
    ):
        """
        Alerts when there's a connection from a private IP to another private IP
        except for DNS connections to the gateway
        """
        def is_dns_conn():
            return dport == 53 and proto.lower() == 'udp' and daddr == self.db.get_gateway_ip()

        with contextlib.suppress(ValueError):
            dport = int(dport)

        if is_dns_conn():
            # skip DNS conns to the gw to avoid having tons of this evidence
            return

        # make sure the 2 ips are private
        if not (
                ipaddress.ip_address(saddr).is_private
                and ipaddress.ip_address(daddr).is_private
        ):
            return

        self.helper.set_evidence_conn_to_private_ip(
            proto,
            daddr,
            dport,
            saddr,
            profileid,
            twid,
            uid,
            timestamp,
        )



    def check_long_connection(
        self, dur, daddr, saddr, profileid, twid, uid, timestamp
    ):
        """
        Check if a duration of the connection is
        above the threshold (more than 25 minutes by default).
        :param dur: duration of the flow in seconds
        """

        if (
                ipaddress.ip_address(daddr).is_multicast
                or ipaddress.ip_address(saddr).is_multicast
        ):
            # Do not check the duration of the flow
            return

        if type(dur) == str:
            dur = float(dur)

        # If duration is above threshold, we should set an evidence
        if dur > self.long_connection_threshold:
            self.helper.set_evidence_long_connection(
                daddr, dur, profileid, twid, uid, timestamp, attacker_direction='srcip'
            )
            return True
        return False

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
        organization_info = self.db.get_organization_of_port(
                portproto
        )
        if not organization_info:
            # consider this port as unknown, it doesn't belong to any org
            return False

        # there's an organization that's known to use this port,
        # check if the daddr belongs to the range of this org
        organization_info = json.loads(organization_info)

        # get the organization ip or range
        org_ips: list = organization_info['ip']

        # org_name = organization_info['org_name']

        if daddr in org_ips:
            # it's an ip and it belongs to this org, consider the port as known
            return True

        for ip in org_ips:
            # is any of them a range?
            with contextlib.suppress(ValueError):
                # we have the org range in our database, check if the daddr belongs to this range
                if ipaddress.ip_address(daddr) in ipaddress.ip_network(ip):
                    # it does, consider the port as known
                    return True

        # not a range either since nothing is specified, e.g. ip is set to ""
        # check the source and dst mac address vendors
        src_mac_vendor = str(
            self.db.get_mac_vendor_from_profile(profileid)
        )
        dst_mac_vendor = str(
            self.db.get_mac_vendor_from_profile(
                f'profile_{daddr}'
            )
        )

        # get the list of all orgs known to use this port and proto
        for org_name in organization_info['org_name']:
            org_name = org_name.lower()
            if (
                    org_name in src_mac_vendor.lower()
                    or org_name in dst_mac_vendor.lower()
            ):
                return True

            # check if the SNI, hostname, rDNS of this ip belong to org_name
            ip_identification = self.db.get_ip_identification(daddr)
            if org_name in ip_identification.lower():
                return True

            # if it's an org that slips has info about (apple, fb, google,etc.),
            # check if the daddr belongs to it
            if bool(self.whitelist.is_ip_in_org(daddr, org_name)):
                return True

        return False



    def is_ignored_ip_data_upload(self, ip):
        """
        Ignore the IPs that we shouldn't alert about
        """

        ip_obj = ipaddress.ip_address(ip)
        if (
            ip == self.gateway
            or ip_obj.is_multicast
            or ip_obj.is_link_local
            or ip_obj.is_reserved
        ):
            return True

    def check_data_upload(self, sbytes, daddr, uid, profileid, twid):
        """
        Set evidence when 1 flow is sending >= the flow_upload_threshold bytes
        """
        if (
            not daddr
            or self.is_ignored_ip_data_upload(daddr)
            or not sbytes
        ):
            return False

        src_mbs = utils.convert_to_mb(int(sbytes))
        if src_mbs >= self.flow_upload_threshold:
            self.helper.set_evidence_data_exfiltration(
                daddr,
                src_mbs,
                profileid,
                twid,
                uid,
            )
            return True

    def wait_for_ssl_flows_to_appear_in_connlog(self):
        """
        thread that waits forever for ssl flows to appear in conn.log
        whenever the conn.log of an ssl flow is found, thread calls check_pastebin_download
        ssl flows to wait for are stored in pending_ssl_flows
        """
        # this is the time we give ssl flows to appear in conn.log,
        # when this time is over, we check, then wait again, etc.
        wait_time = 60*2

        # this thread shouldn't run on interface only because in zeek dirs we
        # we should wait for the conn.log to be read too

        while True:
            size = self.pending_ssl_flows.qsize()
            if size == 0:
                # nothing in queue
                time.sleep(30)
                continue

            # try to get the conn of each pending flow only once
            # this is to ensure that re-added flows to the queue aren't checked twice
            for ssl_flow in range(size):
                try:
                    ssl_flow: dict = self.pending_ssl_flows.get(timeout=0.5)
                except Exception:
                    continue

                # unpack the flow
                daddr, server_name, uid, ts, profileid, twid = ssl_flow

                # get the conn.log with the same uid,
                # returns {uid: {actual flow..}}
                # always returns a dict, never returns None
                # flow: dict = self.db.get_flow(profileid, twid, uid)
                flow: dict = self.db.get_flow(uid)
                if flow := flow.get(uid):
                    flow = json.loads(flow)
                    if 'ts' in flow:
                        # this means the flow is found in conn.log
                        self.check_pastebin_download(*ssl_flow, flow)
                else:
                    # flow not found in conn.log yet, re-add it to the queue to check it later
                    self.pending_ssl_flows.put(ssl_flow)

            # give the ssl flows remaining in self.pending_ssl_flows 2 more mins to appear
            time.sleep(wait_time)

    def check_pastebin_download(
            self, daddr, server_name, uid, ts, profileid, twid, flow
    ):
        """
        Alerts on downloads from pastebin.com with more than 12000 bytes
        This function waits for the ssl.log flow to appear in conn.log before alerting
        :param wait_time: the time we wait for the ssl conn to appear in conn.log in seconds
                every time the timer is over, we wait extra 2 min and call the function again
        : param flow: this is the conn.log of the ssl flow we're currently checking
        """

        if 'pastebin' not in server_name:
            return False

        # orig_bytes is number of payload bytes downloaded
        downloaded_bytes = flow.get('resp_bytes', 0)
        if downloaded_bytes >= self.pastebin_downloads_threshold:
            self.helper.set_evidence_pastebin_download(daddr, downloaded_bytes, ts, profileid, twid, uid)
            return True

        else:
            # reaching this point means that the conn to pastebin did appear
            # in conn.log, but the downloaded bytes didnt reach the threshold.
            # maybe an empty file is downloaded
            return False


    def detect_data_upload_in_twid(self, profileid, twid):
        """
        For each contacted ip in this twid,
        check if the total bytes sent to this ip is >= data_exfiltration_threshold
        """
        def get_sent_bytes(all_flows: dict):
            """Returns a dict of sent bytes to all ips {contacted_ip: (mbs_sent, [uids])}"""
            bytes_sent = {}
            for uid, flow in all_flows.items():
                daddr = flow['daddr']
                sbytes: int = flow.get('sbytes', 0)

                if self.is_ignored_ip_data_upload(daddr) or not sbytes:
                    continue

                if daddr in bytes_sent:
                    mbs_sent, uids = bytes_sent[daddr]
                    mbs_sent += sbytes
                    uids.append(uid)
                    bytes_sent[daddr] = (mbs_sent, uids)
                else:
                    bytes_sent[daddr] = (sbytes, [uid])

            return bytes_sent

        all_flows = self.db.get_all_flows_in_profileid(
            profileid
        )
        if not all_flows:
            return
        bytes_sent: dict = get_sent_bytes(all_flows)

        for ip, ip_info in bytes_sent.items():
            # ip_info is a tuple (bytes_sent, [uids])
            uids = ip_info[1]

            bytes_uploaded = ip_info[0]
            mbs_uploaded = utils.convert_to_mb(bytes_uploaded)
            if mbs_uploaded < self.data_exfiltration_threshold:
                continue

            self.helper.set_evidence_data_exfiltration(
                ip,
                mbs_uploaded,
                profileid,
                twid,
                uids,
            )


    def check_unknown_port(
            self, dport, proto, daddr,
            profileid, twid, uid, timestamp, state
    ):
        """
        Checks dports that are not in our
        slips_files/ports_info/services.csv
        """
        if not dport:
            return
        if state != 'Established':
            # detect unknown ports on established conns only
            return False

        portproto = f'{dport}/{proto}'
        if self.db.get_port_info(portproto):
            # it's a known port
            return False

        # we don't have port info in our database
        # is it a port that is known to be used by
        # a specific organization?
        if self.port_belongs_to_an_org(daddr, portproto, profileid):
            return False

        if (
            'icmp' not in proto
            and not self.is_p2p(dport, proto, daddr)
            and not self.db.is_ftp_port(dport)
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
        other_ip = self.db.get_the_other_ip_version(profileid)
        if other_ip:
            other_ip = json.loads(other_ip)
        # get the domain of this ip
        dns_resolution = self.db.get_dns_resolution(daddr)

        try:
            if other_ip and other_ip in dns_resolution.get('resolved-by', []):
                return True
        except AttributeError:
            # It can be that the dns_resolution sometimes gives back a list and gets this error
            pass
        return False

    def is_connection_made_by_different_version(
        self, profileid, twid, daddr
    ):
        """
        :param daddr: the ip this connection is made to (destination ip)
        """
        # get the other ip version of this computer
        other_ip = self.db.get_the_other_ip_version(profileid)
        if not other_ip:
            return False
        other_ip = other_ip[0]
        # get the ips contacted by the other_ip
        contacted_ips = self.db.get_all_contacted_ips_in_profileid_twid(
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
        if not domain:
            return False
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

        ip_data = self.db.getIPData(ip)
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
            if self.whitelist.is_ip_asn_in_org_asn(ip, org):
                return True

            # we have the rdns or sni of this flow , now check
            if flow_domain and self.whitelist.is_domain_in_org(flow_domain, org):
                return True


            # check if the ip belongs to the range of a well known org
            # (fb, twitter, microsoft, etc.)
            if self.whitelist.is_ip_in_org(ip, org):
                return True


    def check_connection_without_dns_resolution(
        self, flow_type, appproto, daddr, twid, profileid, timestamp, uid
    ):
        """
        Checks if there's a flow to a dstip that has no cached DNS answer
        """
        # The exceptions are:
        # 1- Do not check for DNS requests
        # 2- Ignore some IPs like private IPs, multicast, and broadcast

        if (
                flow_type != 'conn'
                or appproto == 'dns'
                or utils.is_ignored_ip(daddr)
        ):
            return

        # disable this alert when running on a zeek conn.log file
        # because there's no dns.log to know if the dns was made
        if self.db.get_input_type() == 'zeek_log_file':
            return False

        # Ignore some IP
        ## - All dhcp servers. Since is ok to connect to them without a DNS request.
        # We dont have yet the dhcp in the redis, when is there check it
        # if self.db.get_dhcp_servers(daddr):
        # continue

        # To avoid false positives in case of an interface don't alert ConnectionWithoutDNS
        # until 30 minutes has passed
        # after starting slips because the dns may have happened before starting slips
        if '-i' in sys.argv or self.db.is_growing_zeek_dir():
            # connection without dns in case of an interface,
            # should only be detected from the srcip of this device,
            # not all ips, to avoid so many alerts of this type when port scanning
            saddr = profileid.split("_")[-1]
            if saddr not in self.our_ips:
                return False

            start_time = self.db.get_slips_start_time()
            now = datetime.datetime.now()
            diff = utils.get_time_diff(start_time, now, return_type='minutes')
            if diff < self.conn_without_dns_interface_wait_time:
                # less than 30 minutes have passed
                return False

        # search 24hs back for a dns resolution
        if self.db.is_ip_resolved(daddr, 24):
            return False
        # self.print(f'No DNS resolution in {answers_dict}')
        # There is no DNS resolution, but it can be that Slips is
        # still reading it from the files.
        # To give time to Slips to read all the files and get all the flows
        # don't alert a Connection Without DNS until 5 seconds has passed
        # in real time from the time of this checking.

        # Create a timer thread that will wait 15 seconds for the dns to arrive and then check again
        # self.print(f'Cache of conns not to check: {self.conn_checked_dns}')
        if uid not in self.connections_checked_in_conn_dns_timer_thread:
            # comes here if we haven't started the timer thread for this connection before
            # mark this connection as checked
            self.connections_checked_in_conn_dns_timer_thread.append(uid)
            params = [flow_type, appproto, daddr, twid, profileid, timestamp, uid]
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
            with contextlib.suppress(ValueError):
                self.connections_checked_in_conn_dns_timer_thread.remove(
                    uid
                )

    def is_CNAME_contacted(self, answers, contacted_ips) -> bool:
        """
        check if any ip of the given CNAMEs is contacted
        """
        for CNAME in answers:
            if not validators.domain(CNAME):
                # it's an ip
                continue
            ips = self.db.get_domain_resolution(CNAME)
            for ip in ips:
                if ip in contacted_ips:
                    return True
        return False

    def check_dns_without_connection(
            self, domain, answers: list, rcode_name: str, timestamp: str, profileid, twid, uid
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
        # - When there is an NXDOMAIN as answer, it means
        # the domain isn't resolved, so we should not expect any connection later

        if (
            'arpa' in domain
            or '.local' in domain
            or '*' in domain
            or '.cymru.com' in domain[-10:]
            or len(domain.split('.')) == 1
            or domain == 'WPAD'
            or rcode_name != 'NOERROR'

        ):
            return False
        # One DNS query may not be answered exactly by UID, but the computer can re-ask the domain,
        # and the next DNS resolution can be
        # answered. So dont check the UID, check if the domain has an IP

        # self.print(f'The DNS query to {domain} had as answers {answers} ')

        # It can happen that this domain was already resolved previously, but with other IPs
        # So we get from the DB all the IPs for this domain first and append them to the answers
        # This happens, for example, when there is 1 DNS resolution with A, then 1 DNS resolution
        # with AAAA, and the computer chooses the A address. Therefore, the 2nd DNS resolution
        # would be treated as 'without connection', but this is false.
        if prev_domain_resolutions := self.db.getDomainData(domain):
            prev_domain_resolutions = prev_domain_resolutions.get('IPs',[])
            # if there's a domain in the cache (prev_domain_resolutions) that is not in the
            # current answers given to this function, append it to the answers list
            answers.extend([ans for ans in prev_domain_resolutions if ans not in answers])


        if answers == ['-']:
            # If no IPs are in the answer, we can not expect the computer to connect to anything
            # self.print(f'No ips in the answer, so ignoring')
            return False
        # self.print(f'The extended DNS query to {domain} had as answers {answers} ')

        contacted_ips = self.db.get_all_contacted_ips_in_profileid_twid(
            profileid, twid
        )
        # If contacted_ips is empty it can be because we didnt read yet all the flows.
        # This is automatically captured later in the for loop and we start a Timer

        # every dns answer is a list of ips that correspond to 1 query,
        # one of these ips should be present in the contacted ips
        # check each one of the resolutions of this domain
        for ip in answers:
            # self.print(f'Checking if we have a connection to ip {ip}')
            if (
                ip in contacted_ips
                or
                self.is_connection_made_by_different_version(
                    profileid, twid, ip)
            ):
                # this dns resolution has a connection. We can exit
                return False

        # Check if there was a connection to any of the CNAMEs
        if self.is_CNAME_contacted(answers, contacted_ips):
            # this is not a DNS without resolution
            return False


        # self.print(f'It seems that none of the IPs were contacted')
        # Found a DNS query which none of its IPs was contacted
        # It can be that Slips is still reading it from the files. Lets check back in some time
        # Create a timer thread that will wait some seconds for the connection to arrive and then check again
        if uid not in self.connections_checked_in_dns_conn_timer_thread:
            # comes here if we haven't started the timer thread for this dns before
            # mark this dns as checked
            self.connections_checked_in_dns_conn_timer_thread.append(uid)
            params = [domain, answers, rcode_name, timestamp, profileid, twid, uid]
            # self.print(f'Starting the timer to check on {domain}, uid {uid}.
            # time {datetime.datetime.now()}')
            timer = TimerThread(
                40, self.check_dns_without_connection, params
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
            with contextlib.suppress(ValueError):
                self.connections_checked_in_dns_conn_timer_thread.remove(uid)

    def detect_successful_ssh_by_zeek(self, uid, timestamp, profileid, twid):
        """
        Check for auth_success: true in the given zeek flow
        """
        original_ssh_flow = self.db.search_tws_for_flow(profileid, twid, uid)
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
            with contextlib.suppress(ValueError):
                self.connections_checked_in_ssh_timer_thread.remove(
                    uid
                )
            return True
        elif uid not in self.connections_checked_in_ssh_timer_thread:
            # It can happen that the original SSH flow is not in the DB yet
            # comes here if we haven't started the timer thread for this connection before
            # mark this connection as checked
            # self.print(f'Starting the timer to check on {flow_dict}, uid {uid}. time {datetime.datetime.now()}')
            self.connections_checked_in_ssh_timer_thread.append(
                uid
            )
            params = [uid, timestamp, profileid, twid]
            timer = TimerThread(
                15, self.detect_successful_ssh_by_zeek, params
            )
            timer.start()

    def detect_successful_ssh_by_slips(self, uid, timestamp, profileid, twid, auth_success):
        """
        Try Slips method to detect if SSH was successful by
        comparing all bytes sent and received to our threshold
        """
        # this is the ssh flow read from conn.log not ssh.log
        original_ssh_flow = self.db.get_flow(uid)
        original_flow_uid = next(iter(original_ssh_flow))
        if original_ssh_flow[original_flow_uid]:
            ssh_flow_dict = json.loads(
                original_ssh_flow[original_flow_uid]
            )
            size = ssh_flow_dict['sbytes'] + ssh_flow_dict['dbytes']
            if size > self.ssh_succesful_detection_threshold:
                daddr = ssh_flow_dict['daddr']
                saddr = ssh_flow_dict['saddr']
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
                with contextlib.suppress(ValueError):
                    self.connections_checked_in_ssh_timer_thread.remove(
                        uid
                    )
                return True

        elif uid not in self.connections_checked_in_ssh_timer_thread:
            # It can happen that the original SSH flow is not in the DB yet
            # comes here if we haven't started the timer thread for this connection before
            # mark this connection as checked
            # self.print(f'Starting the timer to check on {flow_dict}, uid {uid}.
            # time {datetime.datetime.now()}')
            self.connections_checked_in_ssh_timer_thread.append(
                uid
            )
            params = [uid, timestamp, profileid, twid, auth_success]
            timer = TimerThread(
                15, self.check_successful_ssh, params
            )
            timer.start()

    def check_successful_ssh(self, uid, timestamp, profileid, twid, auth_success):
        """
        Function to check if an SSH connection logged in successfully
        """
        # it's true in zeek json files, T in zeke tab files
        if auth_success in ['true', 'T']:
            self.detect_successful_ssh_by_zeek(uid, timestamp, profileid, twid)

        else:
            self.detect_successful_ssh_by_slips(uid, timestamp, profileid, twid, auth_success)



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


    def check_multiple_ssh_versions(
        self,
        flow: dict,
        twid,
        role='SSH::CLIENT'
    ):
        """
        checks if this srcip was detected using a different
         ssh client or server versions before
        :param role: can be 'SSH::CLIENT' or 'SSH::SERVER' as seen in zeek software.log flows
        """
        if role not in flow['software']:
            return

        profileid = f'profile_{flow["saddr"]}'
        # what software was used before for this profile?
        # returns a dict with
        # software:
        #   { 'version-major': ,'version-minor': ,'uid': }
        cached_used_sw: dict = self.db.get_software_from_profile(
            profileid
        )
        if not cached_used_sw:
            # we have no previous software info about this saddr in out db
            return False

        # these are the versions that this profile once used
        cached_ssh_versions = cached_used_sw[flow['software']]
        cached_versions = f"{cached_ssh_versions['version-major']}_" \
                          f"{cached_ssh_versions['version-minor']}"

        current_versions = f"{flow['version_major']}_{flow['version_minor']}"
        if cached_versions == current_versions:
            # they're using the same ssh client version
            return False

        # get the uid of the cached versions, and the uid of the current used versions
        uids = [cached_ssh_versions['uid'], flow['uid']]
        self.helper.set_evidence_multiple_ssh_versions(
            flow['saddr'], cached_versions, current_versions,
            flow['starttime'], twid, uids, flow['daddr'], role=role
        )
        return True

    def estimate_shannon_entropy(self, string):
        m = len(string)
        bases = collections.Counter(list(string))
        shannon_entropy_value = 0
        for base in bases:
            # number of residues
            n_i = bases[base]
            # n_i (# residues type i) / M (# residues in column)
            p_i = n_i / float(m)
            entropy_i = p_i * (math.log(p_i, 2))
            shannon_entropy_value += entropy_i

        return shannon_entropy_value * -1

    def check_suspicious_dns_answers(self, domain, answers, daddr, profileid, twid, stime, uid):
        """
        Uses shannon entropy to detect DNS TXT answers with encoded/encrypted strings
        """
        if not answers:
            return

        for answer in answers:
            if 'TXT' in answer:
                # TXT record
                entropy = self.estimate_shannon_entropy(answer)
                if entropy >= self.shannon_entropy_threshold:
                    self.helper.set_evidence_suspicious_dns_answer(
                        domain,
                        answer,
                        entropy,
                        daddr,
                        profileid,
                        twid,
                        stime,
                        uid
                    )

    def check_invalid_dns_answers(self, domain, answers, daddr, profileid, twid, stime, uid):
        # this function is used to check for certain IP answers to DNS queries being blocked
        # (perhaps by ad blockers) and set to the following IP values
        invalid_answers = {"127.0.0.1" , "0.0.0.0"} # currently hardcoding blocked ips
        if not answers:
            return

        for answer in answers:
            if answer in invalid_answers and domain != "localhost":
                #blocked answer found
                self.helper.set_evidence_invalid_dns_answer(domain, answer, daddr, profileid, twid, stime, uid)
                # delete answer from redis cache to prevent associating this dns answer with this domain/query and
                # avoid FP "DNS without connection" evidence
                self.db.delete_dns_resolution(answer)

    def detect_DGA(self, rcode_name, query, stime, daddr, profileid, twid, uid):

        """
        Detect DGA based on the amount of NXDOMAINs seen in dns.log
        alerts when 10 15 20 etc. nxdomains are found
        Ignore queries done to *.in-addr.arpa domains and to *.local domains
        """
        if not rcode_name:
            return

        saddr = profileid.split('_')[-1]
        # check whitelisted queries because we
        # don't want to count nxdomains to cymru.com or spamhaus as DGA as they're made
        # by slips
        if (
            'NXDOMAIN' not in rcode_name
            or not query
            or query.endswith('.arpa')
            or query.endswith('.local')
            or self.whitelist.is_whitelisted_domain(query, saddr, daddr, 'alerts')
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

    def check_conn_to_port_0(
            self,
            sport,
            dport,
            proto,
            saddr,
            daddr,
            profileid,
            twid,
            uid,
            timestamp
    ):
        """
        Alerts on connections to or from port 0 using protocols other than
        igmp, icmp
        """
        if proto.lower() in ('igmp', 'icmp', 'ipv6-icmp', 'arp'):
            return

        if sport != 0 and dport != 0:
            return

        direction = 'source' if sport == 0 else 'destination'
        self.helper.set_evidence_for_port_0_connection(
            saddr,
            daddr,
            sport,
            dport,
            direction,
            profileid,
            twid,
            uid,
            timestamp,
        )

    def check_multiple_reconnection_attempts(
            self,
            origstate,
            saddr,
            daddr,
            dport,
            uid,
            profileid,
            twid,
            timestamp
    ):
        """
        Alerts when 5+ reconnection attempts from the same source IP to
        the same destination IP occurs
        """
        if origstate != 'REJ':
            return

        key = f'{saddr}-{daddr}-{dport}'

        # add this conn to the stored number of reconnections
        current_reconnections = self.db.get_reconnections_for_tw(profileid, twid)

        try:
            reconnections, uids = current_reconnections[key]
            reconnections += 1
            uids.append(uid)
            current_reconnections[key] = (reconnections, uids)
        except KeyError:
            current_reconnections[key] = (1, [uid])
            reconnections = 1

        if reconnections < 5:
            return

        ip_identification = (
            self.db.get_ip_identification(daddr)
        )
        description = (
            f'Multiple reconnection attempts to Destination IP:'
            f' {daddr} {ip_identification} '
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

        self.db.setReconnections(
            profileid, twid, current_reconnections
        )

    def detect_young_domains(self, domain, stime, profileid, twid, uid):
        """
        Detect domains that are too young.
        The threshold is 60 days
        """
        if not domain:
            return False

        age_threshold = 60

        # Ignore arpa and local domains
        if domain.endswith('.arpa') or domain.endswith('.local'):
            return False

        domain_info: dict = self.db.getDomainData(domain)
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

    def check_smtp_bruteforce(
            self,
            profileid,
            twid,
            flow
    ):
        uid = flow['uid']
        daddr = flow['daddr']
        saddr = flow['saddr']
        stime = flow.get('starttime', False)
        last_reply = flow.get('last_reply', False)

        if 'bad smtp-auth user' not in last_reply:
            return False

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
        if len(timestamps) != self.smtp_bruteforce_threshold:
            return

        # check if they happened within 10 seconds or less
        diff = utils.get_time_diff(
            timestamps[0],
            timestamps[-1]
        )

        if diff > 10:
            # didnt happen within 10s!
            # remove the first login from cache so we can check the next 3 logins
            self.smtp_bruteforce_cache[profileid][0].pop(0)
            self.smtp_bruteforce_cache[profileid][1].pop(0)
            return

        self.helper.set_evidence_smtp_bruteforce(
            flow,
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
        if proto != 'tcp' or state != 'Established':
            return

        dport_name = appproto
        if not dport_name:
            dport_name = self.db.get_port_info(
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
                self.db.getDataFromProfileTW(
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

            ip_identification = self.db.get_ip_identification(daddr)
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
                self.db.getDataFromProfileTW(
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
            description = f'Connection to multiple ports {dstports} ' \
                          f'of Source IP: {saddr}'

            self.helper.set_evidence_for_connection_to_multiple_ports(
                profileid,
                twid,
                daddr,
                description,
                uids,
                timestamp,
            )

    def detect_malicious_ja3(
            self,
            saddr,
            daddr,
            ja3,
            ja3s,
            profileid,
            twid,
            uid,
            timestamp
    ):
        if not (ja3 or ja3s):
            # we don't have info about this flow's ja3 or ja3s fingerprint
            return

        # get the dict of malicious ja3 stored in our db
        malicious_ja3_dict = self.db.get_ja3_in_IoC()

        if ja3 in malicious_ja3_dict:
            self.helper.set_evidence_malicious_JA3(
                malicious_ja3_dict,
                saddr,
                profileid,
                twid,
                uid,
                timestamp,
                daddr,
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
                saddr,
                type_='ja3s',
                ioc=ja3s,
            )

    def check_self_signed_certs(
            self,
            validation_status,
            daddr,
            server_name,
            profileid,
            twid,
            timestamp,
            uid
    ):
        """
        checks the validation status of every azeek ssl flow for self signed certs
        """
        if 'self signed' not in validation_status:
            return


        ip_identification = (
            self.db.get_ip_identification(daddr)
        )
        description = f'Self-signed certificate. Destination IP: {daddr}.' \
                      f' {ip_identification}'

        if server_name:
            description += f' SNI: {server_name}.'

        self.helper.set_evidence_self_signed_certificates(
            profileid,
            twid,
            daddr,
            description,
            uid,
            timestamp,
        )



    def check_ssh_password_guessing(self, daddr, uid, timestamp, profileid, twid, auth_success):
        """
        This detection is only done when there's a failed ssh attempt
        alerts ssh pw bruteforce when there's more than
        20 failed attempts by the same ip to the same IP
        """
        if auth_success in ('true', 'T'):
            return False

        cache_key = f'{profileid}-{twid}-{daddr}'
        # update the number of times this ip performed a failed ssh login
        if cache_key in self.password_guessing_cache:
            self.password_guessing_cache[cache_key].append(uid)
        else:
            self.password_guessing_cache = {cache_key: [uid]}

        conn_count = len(self.password_guessing_cache[cache_key])

        if conn_count >= self.pw_guessing_threshold:
            description = f'SSH password guessing to IP {daddr}'
            uids = self.password_guessing_cache[cache_key]
            self.helper.set_evidence_pw_guessing(
                description, timestamp, profileid, twid, uids, profileid.split('_')[-1], by='Slips'
            )

            #reset the counter
            del self.password_guessing_cache[cache_key]



    def check_malicious_ssl(self, ssl_info):
        if ssl_info['type'] != 'zeek':
            # this detection only supports zeek files.log flows
            return False

        flow: dict = ssl_info['flow']

        source = flow.get('source', '')
        analyzers = flow.get('analyzers', '')
        sha1 = flow.get('sha1', '')

        if 'SSL' not in source or 'SHA1' not in analyzers:
            # not an ssl cert
            return False

        # check if we have this sha1 marked as malicious from one of our feeds
        ssl_info_from_db = self.db.get_ssl_info(sha1)
        if not ssl_info_from_db:
            return False

        self.helper.set_evidence_malicious_ssl(
            ssl_info, ssl_info_from_db
        )

    def check_weird_http_method(self, msg):
        """
        detect weird http methods in zeek's weird.log
        """
        flow = msg['flow']
        profileid = msg['profileid']
        twid = msg['twid']

        # what's the weird.log about
        name = flow['name']

        if 'unknown_HTTP_method' not in name:
            return False

        self.helper.set_evidence_weird_http_method(
            profileid,
            twid,
            flow
        )

    def check_non_http_port_80_conns(
            self,
            state,
            daddr,
            dport,
            proto,
            appproto,
            profileid,
            twid,
            uid,
            timestamp
    ):
        """
        alerts on established connections on port 80 that are not HTTP
        """
        # if it was a valid http conn, the 'service' field aka
        # appproto should be 'http'
        if (
                str(dport) == '80'
                and proto.lower() == 'tcp'
                and appproto.lower() != 'http'
                and state == 'Established'
        ):
            self.helper.set_evidence_non_http_port_80_conn(
                daddr,
                profileid,
                timestamp,
                twid,
                uid
            )
    def check_GRE_tunnel(self, tunnel_info: dict):
        """
        Detects GRE tunnels
        @param tunnel_flow: dict containing tunnel zeek flow
        @return: None
        """
        tunnel_flow = tunnel_info['flow']
        tunnel_type = tunnel_flow['tunnel_type']

        if tunnel_type != 'Tunnel::GRE':
            return

        self.helper.set_evidence_GRE_tunnel(
            tunnel_info
        )

    def check_non_ssl_port_443_conns(
            self,
            state,
            daddr,
            dport,
            proto,
            appproto,
            profileid,
            twid,
            uid,
            timestamp
    ):
        """
        alerts on established connections on port 443 that are not HTTPS (ssl)
        """
        # if it was a valid ssl conn, the 'service' field aka
        # appproto should be 'ssl'
        if (
                str(dport) == '443'
                and proto.lower() == 'tcp'
                and appproto.lower() != 'ssl'
                and state == 'Established'
        ):
            self.helper.set_evidence_non_ssl_port_443_conn(
                daddr,
                profileid,
                timestamp,
                twid,
                uid
            )

    def check_different_localnet_usage(
            self,
            saddr,
            daddr,
            dport,
            proto,
            profileid,
            timestamp,
            twid,
            uid,
            what_to_check=''
    ):
        """
        alerts when a connection to a private ip that doesn't belong to our local network is found
        for example:
        If we are on 192.168.1.0/24 then detect anything coming from/to 10.0.0.0/8
        :param what_to_check: can be 'srcip' or 'dstip'
        """
        ip_to_check = saddr if what_to_check == 'srcip' else daddr
        ip_obj = ipaddress.ip_address(ip_to_check)
        own_local_network = self.db.get_local_network()

        if not own_local_network:
            # the current local network wasn't set in the db yet
            # it's impossible to get here becaus ethe localnet is set before
            # any msg is published in the new_flow channel
            return

        if not (validators.ipv4(ip_to_check) and ip_obj.is_private):
            return

        # if it's a private ipv4 addr, it should belong to our local network
        if ip_obj in ipaddress.IPv4Network(own_local_network):
            return

        self.helper.set_evidence_different_localnet_usage(
            daddr,
            f'{dport}/{proto}',
            profileid,
            timestamp,
            twid,
            uid,
            ip_outside_localnet=what_to_check
        )

    def check_device_changing_ips(
            self,
            flow_type,
            smac,
            profileid,
            twid,
            uid,
            timestamp
    ):
        """
        Every time we have a flow for a new ip (an ip that we're seeing for the first time)
        we check if the MAC of this srcip was associated with another ip
        this check is only done once for each source ip slips sees
        """
        if 'conn' not in flow_type:
            return

        if not smac:
            return

        saddr = profileid.split("_")[-1]

        if self.db.was_ip_seen_in_connlog_before(saddr):
            # we should only check once for the first time we're seeing this flow
            return

        self.db.mark_srcip_as_seen_in_connlog(saddr)

        if not (
                validators.ipv4(saddr)
                and ipaddress.ip_address(saddr).is_private
        ):
            return

        if old_ip_list := self.db.get_ip_of_mac(smac):
            # old_ip is a list that may contain the ipv6 of this MAC
            # this ipv6 may be of the same device that has the given saddr and MAC
            # so this would be fp. make sure we're dealing with ipv4 only
            for ip in json.loads(old_ip_list):
                if validators.ipv4(ip):
                    old_ip = ip
                    break
            else:
                # all the IPs associated with the given macs are ipv6,
                # 1 computer might have several ipv6, AND/OR a combination of ipv6 and 4
                # so this detection will only work if both the old ip and the given saddr are ipv4 private ips
                return

            if old_ip != saddr:
                # we found this smac associated with an ip other than this saddr
                self.helper.set_evidence_device_changing_ips(
                    smac,
                    old_ip,
                    profileid,
                    twid,
                    uid,
                    timestamp
                )

    def pre_main(self):
        utils.drop_root_privs()
        self.ssl_waiting_thread.start()

    def main(self):
        # if timewindows are not updated for a long time, Slips is stopped automatically.
        if msg:= self.get_msg('new_flow'):
            new_flow = json.loads(msg['data'])
            profileid = new_flow['profileid']
            twid = new_flow['twid']
            flow = new_flow['flow']
            flow = json.loads(flow)
            uid = next(iter(flow))
            flow_dict = json.loads(flow[uid])
            # Flow type is 'conn' or 'dns', etc.
            flow_type = flow_dict['flow_type']
            dur = flow_dict['dur']
            saddr = flow_dict['saddr']
            daddr = flow_dict['daddr']
            origstate = flow_dict['origstate']
            state = flow_dict['state']
            timestamp = new_flow['stime']
            sport: int = flow_dict['sport']
            dport: int = flow_dict.get('dport', None)
            proto = flow_dict.get('proto')
            sbytes = flow_dict.get('sbytes', 0)
            appproto = flow_dict.get('appproto', '')
            smac = flow_dict.get('smac', '')
            if not appproto or appproto == '-':
                appproto = flow_dict.get('type', '')
            # dmac = flow_dict.get('dmac', '')
            # stime = flow_dict['ts']
            # timestamp = new_flow['stime']
            # pkts = flow_dict['pkts']
            # allbytes = flow_dict['allbytes']

            self.check_long_connection(
                dur, daddr, saddr, profileid, twid, uid, timestamp
            )
            self.check_unknown_port(
                dport,
                proto.lower(),
                daddr,
                profileid,
                twid,
                uid,
                timestamp,
                state
            )
            self.check_multiple_reconnection_attempts(
                    origstate,
                    saddr,
                    daddr,
                    dport,
                    uid,
                    profileid,
                    twid,
                    timestamp
            )
            self.check_conn_to_port_0(
                sport,
                dport,
                proto,
                saddr,
                daddr,
                profileid,
                twid,
                uid,
                timestamp
            )
            self.check_different_localnet_usage(
                saddr,
                daddr,
                dport,
                proto,
                profileid,
                timestamp,
                twid,
                uid,
                what_to_check='srcip'
            )
            self.check_different_localnet_usage(
                saddr,
                daddr,
                dport,
                proto,
                profileid,
                timestamp,
                twid,
                uid,
                what_to_check='dstip'
            )

            self.check_connection_without_dns_resolution(
                flow_type, appproto, daddr, twid, profileid, timestamp, uid
            )

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
            self.check_data_upload(
                sbytes,
                daddr,
                uid,
                profileid,
                twid
            )

            self.check_non_http_port_80_conns(
                state,
                daddr,
                dport,
                proto,
                appproto,
                profileid,
                twid,
                uid,
                timestamp
            )
            self.check_non_ssl_port_443_conns(
                state,
                daddr,
                dport,
                proto,
                appproto,
                profileid,
                twid,
                uid,
                timestamp
            )
            self.check_connection_to_local_ip(
                daddr,
                dport,
                proto,
                saddr,
                profileid,
                twid,
                uid,
                timestamp,
            )

            self.check_device_changing_ips(
                flow_type, smac, profileid, twid, uid, timestamp
            )
            self.conn_counter += 1

        # --- Detect successful SSH connections ---
        if msg:= self.get_msg('new_ssh'):
            data = msg['data']
            data = json.loads(data)
            profileid = data['profileid']
            twid = data['twid']
            # Get flow as a json
            flow = data['flow']
            flow = json.loads(flow)
            timestamp = flow['stime']
            uid = flow['uid']
            daddr = flow['daddr']
            # it's set to true in zeek json files, T in zeke tab files
            auth_success = flow['auth_success']

            self.check_successful_ssh(
                uid,
                timestamp,
                profileid,
                twid,
                auth_success
            )

            self.check_ssh_password_guessing(
                daddr,
                uid,
                timestamp,
                profileid,
                twid,
                auth_success
            )
        # --- Detect alerts from Zeek: Self-signed certs,
        # invalid certs, port-scans and address scans, and password guessing ---
        if msg:= self.get_msg('new_notice'):
            data = msg['data']
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

            # --- Detect horizontal portscan by zeek ---
            if 'Address_Scan' in note:
                # Horizontal port scan
                # scanned_port = flow.get('scanned_port', '')
                self.helper.set_evidence_horizontal_portscan(
                    msg,
                    timestamp,
                    profileid,
                    twid,
                    uid,
                )
            # --- Detect password guessing by zeek ---
            if 'Password_Guessing' in note:
                self.helper.set_evidence_pw_guessing(
                    msg,
                    timestamp,
                    profileid,
                    twid,
                    uid,
                    by='Zeek'
                )
        # --- Detect maliciuos JA3 TLS servers ---
        if msg:= self.get_msg('new_ssl'):
            # Check for self signed certificates in new_ssl channel (ssl.log)
            data = msg['data']
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
            server_name = flow.get('server_name')

            # we'll be checking pastebin downloads of this ssl flow
            # later
            self.pending_ssl_flows.put(
                (daddr, server_name, uid, timestamp, profileid, twid)
            )

            self.check_self_signed_certs(
                flow['validation_status'],
                daddr,
                server_name,
                profileid,
                twid,
                timestamp,
                uid
            )

            self.detect_malicious_ja3(
                saddr,
                daddr,
                ja3,
                ja3s,
                profileid,
                twid,
                uid,
                timestamp
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

        if msg := self.get_msg('tw_closed'):
            profileid_tw = msg['data'].split('_')
            profileid, twid = f'{profileid_tw[0]}_{profileid_tw[1]}', profileid_tw[-1]
            self.detect_data_upload_in_twid(profileid, twid)

        # --- Detect DNS issues: 1) DNS resolutions without connection, 2) DGA, 3) young domains, 4) ARPA SCANs
        if msg:= self.get_msg('new_dns'):
            data = json.loads(msg['data'])
            profileid = data['profileid']
            twid = data['twid']
            uid = data['uid']
            daddr = data.get('daddr', False)
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
                    domain, answers, rcode_name, stime, profileid, twid, uid
                )

            self.check_suspicious_dns_answers(
                domain, answers, daddr, profileid, twid, stime, uid
            )

            self.check_invalid_dns_answers(
                domain, answers, daddr, profileid, twid, stime, uid
            )

            self.detect_DGA(
                rcode_name, domain, stime, daddr, profileid, twid, uid
            )

            # TODO: not sure how to make sure IP_info is done adding domain age to the db or not
            self.detect_young_domains(
                domain, stime, profileid, twid, uid
            )
            self.check_dns_arpa_scan(
                domain, stime, profileid, twid, uid
            )

        if msg:= self.get_msg('new_downloaded_file'):
            ssl_info = json.loads(msg['data'])
            self.check_malicious_ssl(ssl_info)

        # --- Detect Bad SMTP logins ---
        if msg:= self.get_msg('new_smtp'):
            smtp_info = json.loads(msg['data'])
            profileid = smtp_info['profileid']
            twid = smtp_info['twid']
            flow: dict = smtp_info['flow']

            self.check_smtp_bruteforce(
                profileid,
                twid,
                flow
            )
        # --- Detect multiple used SSH versions ---
        if msg:= self.get_msg('new_software'):
            msg = json.loads(msg['data'])
            flow:dict = msg['sw_flow']
            twid = msg['twid']
            self.check_multiple_ssh_versions(
                flow,
                twid,
                role='SSH::CLIENT'
            )
            self.check_multiple_ssh_versions(
                flow,
                twid,
                role='SSH::SERVER'
            )

        if msg:=self.get_msg('new_weird'):
            msg = json.loads(msg['data'])
            self.check_weird_http_method(msg)

        if msg:= self.get_msg('new_tunnel'):
            msg = json.loads(msg['data'])
            self.check_GRE_tunnel(msg)
