# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import collections
import ipaddress
import json
import math
import queue
import time
from datetime import datetime
from typing import (
    List,
    Tuple,
    Any,
)
import validators
from multiprocessing import Queue
from threading import Thread, Event

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import Direction


class DNS(IFlowalertsAnalyzer):
    def init(self):
        self.read_configuration()
        # this dict will contain the number of nxdomains
        # found in every profile
        self.nxdomains = {}
        # if nxdomains are >= this threshold, it's probably DGA
        self.nxdomains_threshold = 10
        # dict to keep track of arpa queries to check for DNS arpa scans later
        # format {profileid: [ts,ts,...]}
        self.dns_arpa_queries = {}
        # after this number of arpa queries, slips will detect an arpa scan
        self.arpa_scan_threshold = 10
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        self.classifier = FlowClassifier()
        self.our_ips = utils.get_own_ips()
        # In mins
        self.dns_without_conn_interface_wait_time = 30
        # to store dns queries that we should check later. the purpose of
        # this is to give the connection some time to arrive
        self.pending_dns_without_conn = Queue()
        self.dns_without_connection_timeout_checker_thread = Thread(
            target=self.check_dns_without_connection_timeout,
            daemon=True,
            name="dns_without_connection_timeout_checker_thread",
        )
        self.stop_event = Event()
        # used to pass the msgs this analyzer reciecved, to the
        # dns_without_connection_timeout_checker_thread.
        # the reason why we can just use .get_msg() there is because once
        # the msg is handled here, it wont be passed to other analyzers the
        # should analyze it anymore.
        # meaning, only flowalerts.py is allowed to do a get_msg because it
        # manages all the analyzers the msg should be passed to
        self.dns_msgs = Queue()
        self.priv_ips_doing_dns_outside_of_localnet = {}
        self.is_dns_detected = False
        self.detected_dns_ip = "-"

    def name(self) -> str:
        return "DNS_analyzer"

    def read_configuration(self):
        conf = ConfigParser()
        self.shannon_entropy_threshold = conf.get_entropy_threshold()

    def should_detect_dns_without_conn(self, flow) -> bool:
        """
        returns False in the following cases
         - All reverse dns resolutions
         - All .local domains
         - The wildcard domain *
         - Subdomains of cymru.com, since it is used by
         the ipwhois library in Slips to get the ASN
         of an IP and its range. This DNS is meant not
         to have a connection later
         - Domains check from Chrome, like xrvwsrklpqrw
         - The WPAD domain of windows
         - When there is an NXDOMAIN as answer, it means
         the domain isn't resolved, so we should not expect any
            connection later
        """
        if (
            "arpa" in flow.query
            or ".local" in flow.query
            or flow.qtype_name not in ["AAAA", "A"]
            or "*" in flow.query
            or ".cymru.com" in flow.query[-10:]
            or len(flow.query.split(".")) == 1
            or flow.query == "WPAD"
            or flow.rcode_name != "NOERROR"
            or not flow.answers
            # dns without conn in case of an interface,
            # should only be detected from the srcip of this device,
            # not all ips, to avoid so many alerts of this type when port scanning
            or (self.is_running_non_stop and flow.saddr not in self.our_ips)
        ):
            return False
        return True

    def is_cname_contacted(self, answers, contacted_ips) -> bool:
        """
        check if any ip of the given CNAMEs is contacted
        """
        for CNAME in answers:
            if not utils.is_valid_domain(CNAME):
                # it's an ip
                continue
            ips = self.db.get_domain_resolution(CNAME)
            for ip in ips:
                if ip in contacted_ips:
                    return True
        return False

    @staticmethod
    def should_detect_young_domain(domain):
        """
        returns true if it's ok to detect young domains for the given
        domain
        """
        return (
            domain
            and not domain.endswith(".local")
            and not domain.endswith(".arpa")
        )

    def detect_young_domains(self, twid, flow):
        """
        Detect domains that are too young.
        The threshold is 60 days
        """
        if not self.should_detect_young_domain(flow.query):
            return False

        age_threshold = 60

        domain_info: dict = self.db.get_domain_data(flow.query)
        if not domain_info:
            return False

        if "Age" not in domain_info:
            # we don't have age info about this domain
            return False

        # age is in days
        age = domain_info["Age"]
        if age >= age_threshold:
            return False

        ips_returned_in_answer: List[str] = self.extract_ips_from_dns_answers(
            flow.answers
        )
        self.set_evidence.young_domain(twid, flow, age, ips_returned_in_answer)
        return True

    @staticmethod
    def extract_ips_from_dns_answers(answers: List[str]) -> List[str]:
        """
        extracts ipv4 and 6 from DNS answers
        """
        ips = []
        for answer in answers:
            if validators.ipv4(answer) or validators.ipv6(answer):
                ips.append(answer)
        return ips

    def is_connection_made_by_different_version(self, profileid, twid, daddr):
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
            f"profile_{other_ip}", twid
        )
        if not contacted_ips:
            return False

        if daddr in contacted_ips:
            # now we're sure that the connection was made
            # by this computer but using a different ip version
            return True

    def get_previous_domain_resolutions(self, query) -> List[str]:
        prev_resolutions = []
        # It can happen that this domain was already resolved
        # previously, but with other IPs
        # So we get from the DB all the IPs for this domain
        # first and append them to the answers
        # This happens, for example, when there is 1 DNS
        # resolution with A, then 1 DNS resolution
        # with AAAA, and the computer chooses the A address.
        # Therefore, the 2nd DNS resolution
        # would be treated as 'without connection', but this is false.
        if prev_domain_resolutions := self.db.get_domain_data(query):
            prev_resolutions = prev_domain_resolutions.get("IPs", [])
        return prev_resolutions

    def is_any_flow_answer_contacted(self, profileid, twid, flow) -> bool:
        """
        checks if any of the answers of the given dns flow were contacted
        before
        """
        # we're doing this to answer this question, was the query we asked
        # the dns for, resolved before to an IP that is not in the
        # current flow.answer AND that previous resolution IP was contancted?
        # if so, we extend the flow.asnwers to include
        # these IPs. the goal is to avoid FPs
        flow.answers.extend(self.get_previous_domain_resolutions(flow.query))
        # remove duplicates
        flow.answers = list(set(flow.answers))

        if flow.answers == ["-"]:
            # If no IPs are in the answer, we can not expect
            # the computer to connect to anything
            return True

        contacted_ips = self.db.get_all_contacted_ips_in_profileid_twid(
            profileid, twid
        )

        # every dns answer is a list of ips that correspond to 1 query,
        # one of these ips should be present in the contacted ips
        # check each one of the resolutions of this domain
        for ip in self.extract_ips_from_dns_answers(flow.answers):
            if (
                ip in contacted_ips
                or self.is_connection_made_by_different_version(
                    profileid, twid, ip
                )
            ):
                # this dns resolution has a connection. We can exit
                return True

        # Check if there was a connection to any of the CNAMEs
        if self.is_cname_contacted(flow.answers, contacted_ips):
            # this is not a DNS without resolution
            return True

    def is_interface_timeout_reached(self):
        """
        To avoid false positives in case of an interface
        don't alert ConnectionWithoutDNS until 30 minutes has passed after
        starting slips because the dns may have happened before starting slips
        """
        if not self.is_running_non_stop:
            # no timeout
            return True

        start_time = self.db.get_slips_start_time()
        now = datetime.now()
        diff = utils.get_time_diff(start_time, now, return_type="minutes")
        # 30 minutes have passed?
        return diff >= self.dns_without_conn_interface_wait_time

    def check_dns_without_connection_of_all_pending_flows(self):
        """should be called before shutting down, to check all the pending
        flows in the pending_dns_without_conn queue before stopping slips,
        doesnt matter if the 30 mins passed or not"""
        while self.pending_dns_without_conn.qsize() > 0:
            try:
                # flowalerts is closing here. there's no chance that
                profileid, twid, pending_flow = (
                    self.pending_dns_without_conn.get(timeout=5)
                )
            except queue.Empty:
                return

            self.check_dns_without_connection(
                profileid, twid, pending_flow, waited_for_the_conn=True
            )

    def get_dns_flow_from_queue(self):
        """
        Fetch and parse the DNS message from the dns_msgs queue.
        Returns None if the queue is empty.
        """
        try:
            msg: str = self.dns_msgs.get(timeout=4)
        except queue.Empty:
            return None

        msg: dict = json.loads(msg["data"])
        flow = self.classifier.convert_to_flow_obj(msg["flow"])
        return flow

    def check_pending_flows_timeout(
        self, reference_flow: Any
    ) -> List[Tuple[str, str, Any]]:
        """
        Process all pending DNS flows without connections.

        Calls check_dns_without_connection when 10, 20 and 30 mins (zeek
        time) pass since the first encounter of the dns flow.
        :param reference_flow: the current DNS flow slips is nalayzing.
        only used to get the timestamp of the zeek now. just to know if 30
        mins passed in zeek time or not.
        Returns a list of flows that need to be put back into the queue
         and checked later.
        """
        back_to_queue: List[Tuple[str, str, Any]] = []

        while self.pending_dns_without_conn.qsize() > 0:
            try:
                profileid, twid, pending_flow = (
                    self.pending_dns_without_conn.get(timeout=5)
                )
            except queue.Empty:
                return back_to_queue

            diff_in_mins = utils.get_time_diff(
                pending_flow.starttime, reference_flow.starttime, "minutes"
            )

            if diff_in_mins >= 30:
                self.check_dns_without_connection(
                    profileid, twid, pending_flow, waited_for_the_conn=True
                )
            elif 9.5 < diff_in_mins <= 10 or 19.5 < diff_in_mins <= 20:
                self.check_dns_without_connection(
                    profileid, twid, pending_flow, waited_for_the_conn=False
                )
            else:
                back_to_queue.append((profileid, twid, pending_flow))

        return back_to_queue

    def check_dns_without_connection_timeout(self):
        """
        Waits 30 mins in zeek time for the connection of a dns to arrive
        Does so by receiving every dns msg this analyzer receives. then we
        compare the ts of it to the ts of the flow we're waiting the 30
        mins for.
        once we know that >=30 mins passed between them we check for the
        dns without connection evidence.
        The whole point is to give the connection 30 mins in zeek time to
        arrive before setting "dns wihtout conn" evidence.

        - To avoid having thousands of flows in memory for 30 mins. we check
        every 10 mins for the connections, if not found we put it back to
        queue, if found we remove that flow from the pending flows

        This function runs in its own thread
        """
        try:
            while (
                not self.flowalerts.should_stop()
                and not self.stop_event.is_set()
            ):
                # if self.pending_dns_without_conn.empty():
                #     time.sleep(1)
                #     continue

                # we just use it to know the zeek current ts to check if 30
                # mins zeek time passed or not. we are not going to
                # analyze it.
                reference_flow = self.get_dns_flow_from_queue()
                if not reference_flow:
                    # ok wait for more dns flows to be read by slips
                    time.sleep(1)
                    continue

                # back_to_queue will be used to store the flows we're
                # waiting for the conn of temporarily if 30 mins didnt pass
                # since we saw them.
                # the goal of this is to not change the queue size in the
                # below loop
                back_to_queue = self.check_pending_flows_timeout(
                    reference_flow
                )
                # put them back to the queue so we can check them later
                for flow in back_to_queue:
                    flow: Tuple[str, str, Any]
                    self.pending_dns_without_conn.put(flow)

        except KeyboardInterrupt:
            # the rest will be handled in shutdown_gracefully
            return
        except Exception:
            self.print_traceback()

    async def check_dns_without_connection(
        self, profileid, twid, flow, waited_for_the_conn=False
    ) -> bool:
        """
        Makes sure all cached DNS answers are there in contacted_ips
        :kwarg waited_for_the_conn: if True, it means we already waited 30
        mins in zeek time for the conn of this dns to arrive, and it didnt.
        if False, we wait 30 mins zeek time for it to arrive
        """
        if not self.should_detect_dns_without_conn(flow):
            return False

        if not self.is_interface_timeout_reached():
            return False

        if self.is_any_flow_answer_contacted(profileid, twid, flow):
            return False

        if not waited_for_the_conn:
            # wait 30 mins zeek time for the conn of this dns to arrive
            self.pending_dns_without_conn.put((profileid, twid, flow))
            return False

        # Reaching here means we already waited for the connection
        # of this dns to arrive but none was found
        self.set_evidence.dns_without_conn(twid, flow)
        return True

    @staticmethod
    def estimate_shannon_entropy(string):
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

    def check_high_entropy_dns_answers(self, twid, flow):
        """
        Uses shannon entropy to detect DNS TXT answers
        with encoded/encrypted strings
        """
        # to avoid FPs when devices announce their presence in the TXT
        # records of mDNS answers
        if ipaddress.ip_address(flow.saddr).is_multicast:
            return

        if not flow.answers:
            return

        for answer in flow.answers:
            if "TXT" not in answer:
                continue

            entropy = self.estimate_shannon_entropy(answer)
            if entropy >= self.shannon_entropy_threshold:
                self.set_evidence.suspicious_dns_answer(
                    twid,
                    flow,
                    entropy,
                    answer,
                )

    def check_invalid_dns_answers(self, twid, flow):
        """
        this function is used to check for private IPs in the answers of
        a dns queries.
        Can be because of PI holes or DNS rebinding attacks
        """
        if not flow.answers:
            return

        for answer in flow.answers:
            if (
                utils.is_private_ip(answer)
                and flow.query != "localhost"
                # mDNS
                and not flow.query.endswith(".local")
                # arpa queries are rDNS of ipv6 queries. they may return
                # private IPs in Dual-Stack (IPv4 + IPv6) Networks
                and not flow.query.endswith(".arpa")
            ):
                self.set_evidence.invalid_dns_answer(twid, flow, answer)
                # delete answer from redis cache to prevent
                # associating this dns answer with this domain/query and
                # avoid FP "DNS without connection" evidence
                self.db.delete_dns_resolution(answer)

    def detect_dga(self, profileid, twid, flow):
        """
        Detect DGA based on the amount of NXDOMAINs seen in dns.log
        alerts when 10 15 20 etc. nxdomains are found
        Ignore queries done to *.in-addr.arpa domains and to *.local domains
        """
        if not flow.rcode_name:
            return

        # check whitelisted queries because we
        # don't want to count nxdomains to cymru.com or
        # spamhaus as DGA as they're made
        # by slips
        if (
            "NXDOMAIN" not in flow.rcode_name
            or not flow.query
            or flow.query.endswith(".arpa")
            or flow.query.endswith(".local")
            or self.flowalerts.whitelist.domain_analyzer.is_whitelisted(
                flow.query, Direction.DST, "alerts"
            )
        ):
            return False

        profileid_twid = f"{profileid}_{twid}"

        # found NXDOMAIN by this profile
        try:
            # make sure all domains are unique
            if flow.query not in self.nxdomains[profileid_twid]:
                queries, uids = self.nxdomains[profileid_twid]
                queries.append(flow.query)
                uids.append(flow.uid)
                self.nxdomains[profileid_twid] = (queries, uids)
        except KeyError:
            # first time seeing nxdomain in this profile and tw
            self.nxdomains.update({profileid_twid: ([flow.query], [flow.uid])})
            return False

        # every 5 nxdomains, generate an alert.
        queries, uids = self.nxdomains[profileid_twid]
        number_of_nxdomains = len(queries)
        if (
            number_of_nxdomains % 5 == 0
            and number_of_nxdomains >= self.nxdomains_threshold
        ):
            self.set_evidence.dga(twid, flow, number_of_nxdomains, uids)
            # clear the list of alerted queries and uids
            self.nxdomains[profileid_twid] = ([], [])
            return True

    def check_dns_arpa_scan(self, profileid, twid, flow):
        """
        Detect and ARPA scan if an ip performed 10(arpa_scan_threshold)
        or more arpa queries within 2 seconds
        """
        if not flow.query:
            return False
        if not flow.query.endswith(".in-addr.arpa"):
            return False

        try:
            # format of this dict is
            # {profileid: [stime of first arpa query, stime of second, etc..]}
            timestamps, uids, domains_scanned = self.dns_arpa_queries[
                profileid
            ]
            timestamps.append(flow.starttime)
            uids.append(flow.uid)
            domains_scanned.add(flow.query)
            self.dns_arpa_queries[profileid] = (
                timestamps,
                uids,
                domains_scanned,
            )
        except KeyError:
            # first time for this profileid to perform an arpa query
            self.dns_arpa_queries[profileid] = (
                [flow.starttime],
                [flow.uid],
                {flow.query},
            )
            return False

        if len(domains_scanned) < self.arpa_scan_threshold:
            # didn't reach the threshold yet
            return False

        # reached the threshold, did the 10 queries happen within 2 seconds?
        diff = utils.get_time_diff(timestamps[0], timestamps[-1])
        if diff > 2:
            # happened within more than 2 seconds
            return False

        self.set_evidence.dns_arpa_scan(
            twid, flow, self.arpa_scan_threshold, uids
        )
        # empty the list of arpa queries for this profile,
        # we don't need them anymore
        self.dns_arpa_queries.pop(profileid)
        return True

    def _is_dns(self, flow) -> bool:
        return str(flow.dport) == "53" and flow.proto.lower() == "udp"

    def is_possible_dns_misconfiguration(self, ip_to_check, flow) -> bool:
        """
        to avoid fps that happen when a DNS is configured using a private
        IP that's outside of localnet,
        we detect the dns ip as follows:
         - if 5 conns with dns answers on port 53/udp.
        once detected and we dont alert "conn to priv ip outside of
        localnetwork" to that ip+port+proto
        this is not very common but it happens when the dns is misconfigured

        When this returns True, the "conn to priv ip outside of
        local network" evidence is discarded.
        """
        if ip_to_check != flow.daddr:
            # we need 5 conns to the possible dns server to be able to
            # officialy ignore evidence to it. we dont need to check src
            # addresses
            return False

        if self.is_dns_detected:
            # we already detected the dns using this function.
            # disable this function, we'll be using the detected dns in
            # _is_ok_to_connect_to_ip()
            return False

        if not flow.answers:
            # dns ips should only be detected using dns flows with answers
            return False

        try:
            self.priv_ips_doing_dns_outside_of_localnet[flow.daddr] += 1
            if self.priv_ips_doing_dns_outside_of_localnet[flow.daddr] == 5:
                # this ip probably a dns server
                self.is_dns_detected = True
                self.detected_dns_ip = flow.daddr
                del self.priv_ips_doing_dns_outside_of_localnet
            # if we have less than 5 dns connections with answers,
            # wait more.
            # but do not alert bc it will probably be a fp.
            # wait until we get 5 conns with dns answers to that ip

            return True

        except KeyError:
            self.priv_ips_doing_dns_outside_of_localnet[flow.daddr] = 1
            return True

    def check_different_localnet_usage(
        self,
        twid,
        flow,
        what_to_check="",
    ):
        """
        alerts when a connection to a private ip that
        doesn't belong to our local network is found
        for example:
        If we are on 192.168.1.0/24 then detect anything
        coming from/to 10.0.0.0/8
        :param what_to_check: can be 'srcip' or 'dstip'

        only checks connections to dst port 53/UDP. the rest are checked in conn.log
        """
        # if the ip is the dns server that slips detected, it's ok to
        # connect to it
        if (
            flow.saddr == self.detected_dns_ip
            or flow.daddr == self.detected_dns_ip
        ):
            return

        if not self._is_dns(flow):
            # the non dns flows are checked in conn.py
            return

        ip_to_check = flow.saddr if what_to_check == "srcip" else flow.daddr

        ip_obj = ipaddress.ip_address(ip_to_check)
        if not (validators.ipv4(ip_to_check) and utils.is_private_ip(ip_obj)):
            return

        if self.is_possible_dns_misconfiguration(ip_to_check, flow):
            # dns misconfiguration detected, dns is possibly the private ip
            # outside of localnet
            return

        own_local_network = self.db.get_local_network()
        if not own_local_network:
            # the current local network wasn't set in the db yet
            # it's impossible to get here becaus ethe localnet is set before
            # any msg is published in the new_flow channel
            return

        # if it's a private ipv4 addr, it should belong to our local network
        if ip_obj in ipaddress.IPv4Network(own_local_network):
            return

        self.set_evidence.different_localnet_usage(
            twid,
            flow,
            ip_outside_localnet=what_to_check,
        )

    def shutdown_gracefully(self):
        self.check_dns_without_connection_of_all_pending_flows()
        self.stop_event.set()
        self.dns_without_connection_timeout_checker_thread.join(30)
        if self.dns_without_connection_timeout_checker_thread.is_alive():
            self.flowalerts.print(
                f"Problem shutting down "
                f"dns_without_connection_timeout_checker_thread."
                f"Flowalerts should_stop(): "
                f"{self.flowalerts.should_stop()}"
            )

        # close the queue
        # without this, queues are left in memory and flowalerts keeps
        # waiting for them forever
        # to exit the process quickly without blocking on the queue's cleanup
        self.dns_msgs.cancel_join_thread()
        self.dns_msgs.close()

        self.pending_dns_without_conn.cancel_join_thread()

        self.pending_dns_without_conn.close()

    def pre_analyze(self):
        """Code that shouldnt be run in a loop. runs only once in
        flowalerts' pre_main"""
        # we didnt put this in __init__ because it uses self.flowalerts
        # attributes that are not initialized yet in __init__
        utils.start_thread(
            self.dns_without_connection_timeout_checker_thread, self.db
        )

    async def analyze(self, msg):
        """
        is only used by flowalerts.py
        runs whenever we get a new_dns message
        """
        if not utils.is_msg_intended_for(msg, "new_dns"):
            return False

        self.dns_msgs.put(msg)
        msg = json.loads(msg["data"])
        profileid = msg["profileid"]
        twid = msg["twid"]
        flow = self.classifier.convert_to_flow_obj(msg["flow"])

        self.flowalerts.create_task(
            self.check_dns_without_connection, profileid, twid, flow
        )

        self.check_high_entropy_dns_answers(twid, flow)
        self.check_invalid_dns_answers(twid, flow)
        self.detect_dga(profileid, twid, flow)
        self.check_different_localnet_usage(twid, flow, "srcip")
        self.check_different_localnet_usage(twid, flow, "dstip")
        # TODO: not sure how to make sure IP_info is
        #  done adding domain age to the db or not
        self.detect_young_domains(twid, flow)
        self.check_dns_arpa_scan(profileid, twid, flow)
