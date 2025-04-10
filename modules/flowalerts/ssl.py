# SPDX-FileCopyrightText: 2021 Sebastian Garcia
# <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import json
from typing import Union, Optional, List, Dict, Tuple
import re
import bisect
import time
from multiprocessing import Lock
import tldextract
from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.flows.suricata import SuricataTLS
from slips_files.core.flows.zeek import SSL


class SSL(IFlowalertsAnalyzer):
    def init(self):
        self.classifier = FlowClassifier()
        self.ssl_recognized_flows: Dict[Tuple[str, str], List[float]] = {}
        self.ts_of_last_ssl_recognized_flows_cleanup = time.time()
        self.ssl_recognized_flows_lock = Lock()

    def name(self) -> str:
        return "ssl_analyzer"

    def read_configuration(self):
        conf = ConfigParser()
        self.pastebin_downloads_threshold = (
            conf.get_pastebin_download_threshold()
        )

    async def check_pastebin_download(
        self,
        twid: str,
        ssl_flow: Union[SSL, SuricataTLS],
    ):
        """
        Alerts on downloads from pastebin.com with more than 12000 bytes
        This function waits for the ssl.log flow to appear
        in conn.log for 40s before alerting
        """
        if "pastebin" not in ssl_flow.server_name:
            return False

        conn_log_flow = utils.get_original_conn_flow(ssl_flow, self.db)
        if not conn_log_flow:
            await self.wait_for_new_flows_or_timeout(40)
            conn_log_flow = utils.get_original_conn_flow(ssl_flow, self.db)
            if not conn_log_flow:
                return False

        # orig_bytes is number of payload bytes downloaded
        downloaded_bytes = conn_log_flow["resp_bytes"]
        if downloaded_bytes >= self.pastebin_downloads_threshold:
            self.set_evidence.pastebin_download(
                twid, ssl_flow, downloaded_bytes
            )
            return True

        # reaching here means that the conn to pastebin did appear
        # in conn.log, but the downloaded bytes didnt reach the threshold.
        # maybe an empty file is downloaded
        return False

    def check_self_signed_certs(self, twid, flow):
        """
        checks the validation status of every a zeek ssl flow for self
        signed certs
        """
        if "self signed" not in flow.validation_status:
            return

        self.set_evidence.self_signed_certificates(twid, flow)

    def detect_malicious_ja3(self, twid, flow):
        if not (flow.ja3 or flow.ja3s):
            # we don't have info about this flow's ja3 or ja3s fingerprint
            return

        # get the dict of malicious ja3 stored in our db
        malicious_ja3_dict = self.db.get_all_blacklisted_ja3()
        if flow.ja3 in malicious_ja3_dict:
            self.set_evidence.malicious_ja3(twid, flow, malicious_ja3_dict)

        if flow.ja3s in malicious_ja3_dict:
            self.set_evidence.malicious_ja3s(twid, flow, malicious_ja3_dict)

    def detect_incompatible_cn(self, twid, flow):
        """
        Detects if a certificate claims that it's CN (common name) belongs
        to an org that the domain doesn't belong to
        """
        if not flow.subject:
            return False

        org_found_in_cn = ""
        for org in utils.supported_orgs:
            if org not in flow.subject.lower():
                continue

            # save the org this domain/ip is claiming to belong to,
            # to use it to set evidence later
            org_found_in_cn = org

            # check that the ip belongs to that same org
            if self.whitelist.org_analyzer.is_ip_in_org(flow.daddr, org):
                return False

            # check that the domain belongs to that same org
            if (
                flow.server_name
                and self.whitelist.org_analyzer.is_domain_in_org(
                    flow.server_name, org
                )
            ):
                return False

        if not org_found_in_cn:
            # the certificate doesn't claim to belong to any of slips known
            # orgs
            return False

        # found one of our supported orgs in the cn but
        # it doesn't belong to any of this org's
        # domains or ips
        self.set_evidence.incompatible_cn(twid, flow, org_found_in_cn)

    def is_tcp_established_443_non_empty_flow(self, flow) -> bool:
        state = self.db.get_final_state_from_flags(flow.state, flow.pkts)
        return (
            str(flow.dport) == "443"
            and flow.proto.lower() == "tcp"
            and state == "Established"
            and (flow.sbytes + flow.dbytes) != 0
        )

    def is_ssl_proto_recognized_by_zeek(self, flow) -> bool:
        """
        if the conn was an ssl conn recognized by zeek, the 'service'
        field aka appproto should be 'ssl''
        """
        return flow.appproto and str(flow.appproto.lower()) == "ssl"

    def search_ssl_recognized_flows_for_ts_range(
        self, flow, start, end
    ) -> List[float]:
        """
        Searches for a flow that matches the given flow in
        self.ssl_recognized_flows.

        given the start and end time, returns the timestamps within that
        range.

        2 flows match if they share the src and dst IPs
        """

        # Handle the case where the key might not exist
        try:
            sorted_timestamps_of_past_ssl_flows = self.ssl_recognized_flows[
                (flow.saddr, flow.daddr)
            ]
        except KeyError:
            return []

        # Find the left and right boundaries
        left_idx = bisect.bisect_left(
            sorted_timestamps_of_past_ssl_flows, start
        )
        right_idx = bisect.bisect_right(
            sorted_timestamps_of_past_ssl_flows, end
        )

        return sorted_timestamps_of_past_ssl_flows[left_idx:right_idx]

    def keep_track_of_ssl_flow(self, flow, key) -> None:
        """keeps track of the given ssl flow in ssl_recognized_flows"""
        # we're using locks here because this is a part of an asyncio
        # function and there's another garbage collector that may be
        # modifying the dict at the same time.
        self.ssl_recognized_flows_lock.acquire()
        try:
            ts_list = self.ssl_recognized_flows[key]
            # to store the ts sorted for faster lookups
            bisect.insort(ts_list, float(flow.starttime))
        except KeyError:
            self.ssl_recognized_flows[key] = [float(flow.starttime)]

        self.ssl_recognized_flows_lock.release()

    async def check_non_ssl_port_443_conns(
        self, twid, flow, timeout_reached=False
    ):
        """
        alerts on established connections on port 443 that are not HTTPS (ssl)
        This is how we do the detection.
        for every detected non ssl flow, we check 5 mins back for
        matching flows that were detected as ssl by zeek. if found,
        we discard the
        evidence. if not found, we check for future 5 mins of matching zeek
        flows  that were detected as ssl by zeek. if found, we dont set an
        evidence, if not found, we set an evidence
        :kwarg timeout_reached: did we wait 5 mins in future and in the
        past for the ssl of the given flow to arrive or not?
        """
        if not self.is_tcp_established_443_non_empty_flow(flow):
            # we're not interested in that flow
            return False

        # key for looking up matching ssl flows in ssl_recognized_flows
        key = (flow.saddr, flow.daddr)

        if self.is_ssl_proto_recognized_by_zeek(flow):
            # not a fp, thats a recognized ssl flow
            self.keep_track_of_ssl_flow(flow, key)
            return False

        flow.starttime = float(flow.starttime)

        # in seconds
        five_mins = 5 * 60

        # timeout reached indicates that we did search in the past once,
        # we need to srch in the future now
        if timeout_reached:
            # look in the future
            matching_ssl_flows: List[float] = (
                self.search_ssl_recognized_flows_for_ts_range(
                    flow, flow.starttime, flow.starttime + five_mins
                )
            )
        else:
            # look in the past
            matching_ssl_flows: List[float] = (
                self.search_ssl_recognized_flows_for_ts_range(
                    flow, flow.starttime - five_mins, flow.starttime
                )
            )

        if matching_ssl_flows:
            # awesome! discard evidence. FP dodged.
            # clear these timestamps as we dont need them anymore?
            return False

        # reaching here means we looked in the past 5 mins and
        # found no timestamps, did we look in the future 5 mins?
        if timeout_reached:
            # yes we did. set an evidence
            self.set_evidence.non_ssl_port_443_conn(twid, flow)
            return True

        # ts not reached
        # wait 5 mins real-time (to give slips time to
        # read more flows) maybe the recognized ssl arrives
        # within that time?
        await self.wait_for_new_flows_or_timeout(five_mins)
        # we can safely await here without blocking the main thread because
        # once the timeout is reached, this function will never sleep again,
        # it'll either set the evidence or discard it
        await self.check_non_ssl_port_443_conns(
            twid, flow, timeout_reached=True
        )
        return False

    async def wait_for_new_flows_or_timeout(self, timeout: float):
        """
        waits for new incoming flows, but interrupts the wait if the
        profiler process stops sending new flows within the timeout period.

        :param timeout: the maximum time to wait before resuming execution.
        """

        # repeatedly check if slips is no longer receiving new flows
        async def will_slips_have_new_incoming_flows():
            """if slips will have no incoming flows, aka profiler stopped.
            this function will return False immediately"""
            while self.db.will_slips_have_new_incoming_flows():
                await asyncio.sleep(1)  # sleep to avoid busy looping
            return False

        try:
            # wait until either:
            # - will_slips_have_new_incoming_flows() returns False (no new flows)
            # - timeout is reached (5 minutes)
            await asyncio.wait_for(
                will_slips_have_new_incoming_flows(), timeout
            )

        except asyncio.TimeoutError:
            pass  # timeout reached

    def detect_doh(self, twid, flow):
        if not flow.is_DoH:
            return False
        self.set_evidence.doh(twid, flow)
        self.db.set_ip_info(flow.daddr, {"is_doh_server": True})

    @staticmethod
    def get_root_domain(domain):
        extracted = tldextract.extract(domain)
        return f"{extracted.domain}.{extracted.suffix}"

    def domains_belong_to_same_org(self, domain1, domain2) -> Optional[str]:
        """
        Checks if the 2 domains belong to the same org
        - by comparing the slds of both of them
        - by checking the whois registrant info from the
            db for both of them
        Raises ValueError when info for one of the domains isnt found in
        the db
        returns the common org if they belong to the same org
        """
        root1 = self.get_root_domain(domain1)
        root2 = self.get_root_domain(domain2)
        # same root domain e.g., example.com and www.example.com
        if root1 == root2:
            return root1

        domain1_info: dict = self.db.get_domain_data(domain1)
        if not (domain1_info and "Org" in domain1_info):
            raise ValueError

        domain2_info: dict = self.db.get_domain_data(domain2)
        if not (domain2_info and "Org" in domain2_info):
            raise ValueError

        domain1_org = domain1_info["Org"]
        domain2_org = domain2_info["Org"]

        if domain1_org.lower() == domain2_org.lower():
            return domain1_org

        domain2_org_list: List[str] = domain2_org.split(" ")
        # this way of matching ensures that we dont alert on
        # Yahoo Assets LLC and Yahoo Ad Tech LLC
        for word in domain1_org.split(" "):
            if word in ("LLC", "Corp", "Inc", "Ltd", "Org"):
                continue
            if word in domain2_org_list:
                return word

        return

    @staticmethod
    def extract_cn(certificate_string: str) -> Optional[str]:
        """
        extracts the CN (common name) from a given certificate string.

        :param certificate_string: the certificate string
        :return: the CN value or None if not found
        """
        match = re.search(r"CN=([^,]+)", certificate_string)
        if match:
            return match.group(1)
        return None

    def detect_cn_url_mismatch(self, twid, flow):
        """
        detected a hostname mismatch in the SSL certificate.
        This happens when the common name to which an SSL Certificate is
        issued (e.g., www.example.com) doesn't exactly match
        the name displayed in the URL bar.
        """
        if not flow.subject:
            return False

        # get the common name from the subject field
        cn = self.extract_cn(flow.subject)
        if not cn:
            return

        # use the cn as regex
        cn_regex = cn.replace(".", "\.").replace("*", ".*")

        # check if the server name matches the cn
        if re.match(cn_regex, flow.server_name):
            return

        # regex of the cn doesnt match, check orgs of the domains
        try:
            if self.domains_belong_to_same_org(cn, flow.server_name):
                return
        except ValueError:
            # we dont have info about one of the domains
            return
        self.set_evidence.cn_url_mismatch(twid, cn, flow)

    def remove_old_entries_from_ssl_recognized_flows(self) -> None:
        """
        the goal of this is to not have the ssl_recognized_flows dict
        growing forever, so here we remove all timestamps older than the last
        one-5 mins (zeek time)
        meaning, it ensures that all lists have max 5mins worth of timestamps
        changes the ssl_recognized_flows to the cleaned one
        """
        # Runs every 5 mins real time, to reduce unnecessary cleanups every
        # 1s
        now = time.time()
        time_since_last_cleanup = utils.get_time_diff(
            self.ts_of_last_ssl_recognized_flows_cleanup,
            now,
            "minutes",
        )

        if time_since_last_cleanup < 5:
            return

        clean_ssl_recognized_flows = {}
        for ips, timestamps in self.ssl_recognized_flows.items():
            ips: Tuple[str, str]
            timestamps: List[float]

            end: float = float(timestamps[-1])
            start = end - 5 * 60

            left = bisect.bisect_right(timestamps, start)
            right = bisect.bisect_left(timestamps, end)
            # thats the range we wanna remove from the list bc it's too old
            garbage = timestamps[left:right]
            clean_ssl_recognized_flows[ips] = [
                ts for ts in timestamps if ts not in garbage
            ]

        self.ssl_recognized_flows_lock.acquire()
        self.ssl_recognized_flows = clean_ssl_recognized_flows
        self.ssl_recognized_flows_lock.release()
        self.ts_of_last_ssl_recognized_flows_cleanup = now

    async def analyze(self, msg: dict):
        if utils.is_msg_intended_for(msg, "new_ssl"):
            msg = json.loads(msg["data"])
            twid = msg["twid"]
            flow = self.classifier.convert_to_flow_obj(msg["flow"])

            self.flowalerts.create_task(
                self.check_pastebin_download, twid, flow
            )
            self.check_self_signed_certs(twid, flow)
            self.detect_malicious_ja3(twid, flow)
            self.detect_incompatible_cn(twid, flow)
            self.detect_doh(twid, flow)
            self.detect_cn_url_mismatch(twid, flow)

        elif utils.is_msg_intended_for(msg, "new_flow"):
            msg = json.loads(msg["data"])
            twid = msg["twid"]
            flow = msg["flow"]
            flow = self.classifier.convert_to_flow_obj(flow)
            self.remove_old_entries_from_ssl_recognized_flows()
            self.flowalerts.create_task(
                self.check_non_ssl_port_443_conns, twid, flow
            )
