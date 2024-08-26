import json
import multiprocessing
import threading
import time

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class SSL(IFlowalertsAnalyzer):
    def init(self):
        self.classifier = FlowClassifier()
        # in pastebin download detection, we wait for each conn.log flow
        # of the seen ssl flow to appear
        # this is the dict of ssl flows we're waiting for
        self.pending_ssl_flows = multiprocessing.Queue()
        # thread that waits for ssl flows to appear in conn.log
        self.ssl_thread_started = False
        self.ssl_waiting_thread = threading.Thread(
            target=self.wait_for_ssl_flows_to_appear_in_connlog, daemon=True
        )

    def name(self) -> str:
        return "ssl_analyzer"

    def read_configuration(self):
        conf = ConfigParser()
        self.pastebin_downloads_threshold = (
            conf.get_pastebin_download_threshold()
        )

    def wait_for_ssl_flows_to_appear_in_connlog(self):
        """
        thread that waits forever for ssl flows to appear in conn.log
        whenever the conn.log of an ssl flow is found, thread calls
        check_pastebin_download
        ssl flows to wait for are stored in pending_ssl_flows
        """
        # this is the time we give ssl flows to appear in conn.log,
        # when this time is over, we check, then wait again, etc.
        wait_time = 60 * 2

        # this thread shouldn't run on interface only because in zeek dirs we
        # we should wait for the conn.log to be read too

        while not self.flowalerts.should_stop():
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
                conn_log_flow: str = self.db.get_flow(uid)
                if conn_log_flow := conn_log_flow.get(uid):
                    conn_log_flow: dict = json.loads(conn_log_flow)
                    if "starttime" in conn_log_flow:
                        # this means the flow is found in conn.log
                        self.check_pastebin_download(
                            ssl_flow, conn_log_flow, profileid, twid
                        )
                else:
                    # flow not found in conn.log yet,
                    # re-add it to the queue to check it later
                    self.pending_ssl_flows.put(ssl_flow)

            # give the ssl flows remaining in self.pending_ssl_flows
            # 2 more mins to appear
            time.sleep(wait_time)

    def check_pastebin_download(
        self, ssl_flow, conn_log_flow, profileid, twid
    ):
        """
        Alerts on downloads from pastebin.com with more than 12000 bytes
        This function waits for the ssl.log flow to appear
        in conn.log before alerting
        : param flow: this is the conn.log of the ssl flow
        we're currently checking
        """
        ssl_flow = self.classifier.convert_to_flow_obj(ssl_flow)
        conn_log_flow = self.classifier.convert_to_flow_obj(conn_log_flow)
        if "pastebin" not in ssl_flow.server_name:
            return False

        # orig_bytes is number of payload bytes downloaded
        downloaded_bytes = conn_log_flow.resp_bytes
        if downloaded_bytes >= self.pastebin_downloads_threshold:
            self.set_evidence.pastebin_download(
                twid, ssl_flow, downloaded_bytes
            )
            return True

        # reaching here means that the conn to pastebin did appear
        # in conn.log, but the downloaded bytes didnt reach the threshold.
        # maybe an empty file is downloaded
        return False

    def check_self_signed_certs(self, profileid, twid, flow):
        """
        checks the validation status of every a zeek ssl flow for self
        signed certs
        """
        if "self signed" not in flow.validation_status:
            return

        self.set_evidence.self_signed_certificates(profileid, twid, flow)

    def detect_malicious_ja3(self, profileid, twid, flow):
        if not (flow.ja3 or flow.ja3s):
            # we don't have info about this flow's ja3 or ja3s fingerprint
            return

        # get the dict of malicious ja3 stored in our db
        malicious_ja3_dict = self.db.get_all_blacklisted_ja3()

        if flow.ja3 in malicious_ja3_dict:
            self.set_evidence.malicious_ja3(
                profileid, twid, flow, malicious_ja3_dict
            )

        if flow.ja3s in malicious_ja3_dict:
            self.set_evidence.malicious_ja3s(profileid, twid, flow)

    def detect_incompatible_cn(self, profileid, twid, flow):
        """
        Detects if a certificate claims that it's CN (common name) belongs
        to an org that the domain doesn't belong to
        """
        if not flow.issuer:
            return False

        found_org_in_cn = ""
        for org in utils.supported_orgs:
            if org not in flow.issuer.lower():
                continue

            # save the org this domain/ip is claiming to belong to,
            # to use it to set evidence later
            found_org_in_cn = org

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

        if not found_org_in_cn:
            return False

        # found one of our supported orgs in the cn but
        # it doesn't belong to any of this org's
        # domains or ips
        self.set_evidence.incompatible_cn(
            profileid, twid, flow, found_org_in_cn
        )

    def check_non_ssl_port_443_conns(self, profileid, twid, flow):
        """
        alerts on established connections on port 443 that are not HTTPS (ssl)
        """
        flow.state = self.db.get_final_state_from_flags(flow.state, flow.pkts)
        # if it was a valid ssl conn, the 'service' field aka
        # appproto should be 'ssl'
        if (
            str(flow.dport) == "443"
            and flow.proto.lower() == "tcp"
            and flow.appproto.lower() != "ssl"
            and flow.state == "Established"
            and flow.allbytes != 0
        ):
            self.set_evidence.non_ssl_port_443_conn(profileid, twid, flow)

    def detect_doh(self, profileid, twid, flow):
        if not flow.is_doh:
            return False
        self.set_evidence.doh(twid, flow)
        self.db.set_ip_info(flow.daddr, {"is_doh_server": True})

    def analyze(self, msg: dict):
        if not self.ssl_thread_started:
            self.ssl_waiting_thread.start()
            self.ssl_thread_started = True

        if utils.is_msg_intended_for(msg, "new_ssl"):
            data = json.loads(msg["data"])
            profileid = data["profileid"]
            twid = data["twid"]
            flow = json.loads(data["flow"])
            flow = self.classifier.convert_to_flow_obj(flow)

            # we'll be checking pastebin downloads of this ssl flow
            # later
            # todo: can iput ssl flow obj in the queue??
            self.pending_ssl_flows.put(
                (
                    flow.daddr,
                    flow.server_name,
                    flow.uid,
                    flow.timestamp,
                    profileid,
                    twid,
                )
            )

            self.check_self_signed_certs(profileid, twid, flow)
            self.detect_malicious_ja3(twid, flow)
            self.detect_incompatible_cn(profileid, twid, flow)
            self.detect_doh(profileid, twid, flow)

        if utils.is_msg_intended_for(msg, "new_flow"):
            msg = json.loads(msg["data"])
            profileid = msg["profileid"]
            twid = msg["twid"]
            flow = msg["flow"]
            flow = self.classifier.convert_to_flow_obj(flow)
            self.check_non_ssl_port_443_conns(profileid, twid, flow)
