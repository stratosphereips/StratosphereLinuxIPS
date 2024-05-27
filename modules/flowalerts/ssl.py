import json
import multiprocessing
import threading
import time

from modules.flowalerts.set_evidence import SetEvidnceHelper
from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class SSL(IFlowalertsAnalyzer):
    def init(self, flowalerts=None):
        self.flowalerts = flowalerts
        self.set_evidence = SetEvidnceHelper(self.db)
        # thread that waits for ssl flows to appear in conn.log
        self.ssl_waiting_thread = threading.Thread(
            target=self.wait_for_ssl_flows_to_appear_in_connlog, daemon=True
        )
        self.ssl_waiting_thread.start()
        # in pastebin download detection, we wait for each conn.log flow
        # of the seen ssl flow to appear
        # this is the dict of ssl flows we're waiting for
        self.pending_ssl_flows = multiprocessing.Queue()
        self.channels = {"new_flow": self.db.subscribe("new_flow")}

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
        whenever the conn.log of an ssl flow is found, thread calls check_pastebin_download
        ssl flows to wait for are stored in pending_ssl_flows
        """
        # this is the time we give ssl flows to appear in conn.log,
        # when this time is over, we check, then wait again, etc.
        wait_time = 60 * 2

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
                    if "ts" in flow:
                        # this means the flow is found in conn.log
                        self.check_pastebin_download(*ssl_flow, flow)
                else:
                    # flow not found in conn.log yet,
                    # re-add it to the queue to check it later
                    self.pending_ssl_flows.put(ssl_flow)

            # give the ssl flows remaining in self.pending_ssl_flows
            # 2 more mins to appear
            time.sleep(wait_time)

    def check_pastebin_download(
        self, daddr, server_name, uid, ts, profileid, twid, flow
    ):
        """
        Alerts on downloads from pastebin.com with more than 12000 bytes
        This function waits for the ssl.log flow to appear
        in conn.log before alerting
        : param flow: this is the conn.log of the ssl flow
        we're currently checking
        """

        if "pastebin" not in server_name:
            return False

        # orig_bytes is number of payload bytes downloaded
        downloaded_bytes = flow.get("resp_bytes", 0)
        if downloaded_bytes >= self.pastebin_downloads_threshold:
            self.set_evidence.pastebin_download(
                downloaded_bytes, ts, profileid, twid, uid
            )
            return True

        else:
            # reaching this point means that the conn to pastebin did appear
            # in conn.log, but the downloaded bytes didnt reach the threshold.
            # maybe an empty file is downloaded
            return False

    def check_self_signed_certs(
        self,
        validation_status,
        daddr,
        server_name,
        profileid,
        twid,
        timestamp,
        uid,
    ):
        """
        checks the validation status of every a zeek ssl flow for self
        signed certs
        """
        if "self signed" not in validation_status:
            return

        self.set_evidence.self_signed_certificates(
            profileid, twid, daddr, uid, timestamp, server_name
        )

    def detect_malicious_ja3(
        self, saddr, daddr, ja3, ja3s, twid, uid, timestamp
    ):
        if not (ja3 or ja3s):
            # we don't have info about this flow's ja3 or ja3s fingerprint
            return

        # get the dict of malicious ja3 stored in our db
        malicious_ja3_dict = self.db.get_ja3_in_IoC()

        if ja3 in malicious_ja3_dict:
            self.set_evidence.malicious_ja3(
                malicious_ja3_dict,
                twid,
                uid,
                timestamp,
                saddr,
                daddr,
                ja3=ja3,
            )

        if ja3s in malicious_ja3_dict:
            self.set_evidence.malicious_ja3s(
                malicious_ja3_dict,
                twid,
                uid,
                timestamp,
                saddr,
                daddr,
                ja3=ja3s,
            )

    def detect_incompatible_cn(
        self, daddr, server_name, issuer, profileid, twid, uid, timestamp
    ):
        """
        Detects if a certificate claims that it's CN (common name) belongs
        to an org that the domain doesn't belong to
        """
        if not issuer:
            return False

        found_org_in_cn = ""
        for org in utils.supported_orgs:
            if org not in issuer.lower():
                continue

            # save the org this domain/ip is claiming to belong to,
            # to use it to set evidence later
            found_org_in_cn = org

            # check that the ip belongs to that same org
            if self.flowalerts.whitelist.is_ip_in_org(daddr, org):
                return False

            # check that the domain belongs to that same org
            if server_name and self.flowalerts.whitelist.is_domain_in_org(
                server_name, org
            ):
                return False

        if not found_org_in_cn:
            return False

        # found one of our supported orgs in the cn but
        # it doesn't belong to any of this org's
        # domains or ips
        self.set_evidence.incompatible_CN(
            found_org_in_cn, timestamp, daddr, profileid, twid, uid
        )

    def check_non_ssl_port_443_conns(self, msg):
        """
        alerts on established connections on port 443 that are not HTTPS (ssl)
        """
        profileid = msg["profileid"]
        twid = msg["twid"]
        timestamp = msg["stime"]
        flow = msg["flow"]

        flow = json.loads(flow)
        uid = next(iter(flow))
        flow_dict = json.loads(flow[uid])
        daddr = flow_dict["daddr"]
        state = flow_dict["state"]
        dport: int = flow_dict.get("dport", None)
        proto = flow_dict.get("proto")
        appproto = flow_dict.get("appproto", "")
        # if it was a valid ssl conn, the 'service' field aka
        # appproto should be 'ssl'
        if (
            str(dport) == "443"
            and proto.lower() == "tcp"
            and appproto.lower() != "ssl"
            and state == "Established"
        ):
            self.set_evidence.non_ssl_port_443_conn(
                daddr, profileid, timestamp, twid, uid
            )

    def analyze(self):
        if msg := self.flowalerts.get_msg("new_ssl"):
            data = msg["data"]
            data = json.loads(data)
            flow = data["flow"]
            flow = json.loads(flow)
            uid = flow["uid"]
            timestamp = flow["stime"]
            ja3 = flow.get("ja3", False)
            ja3s = flow.get("ja3s", False)
            issuer = flow.get("issuer", False)
            profileid = data["profileid"]
            twid = data["twid"]
            daddr = flow["daddr"]
            saddr = profileid.split("_")[1]
            server_name = flow.get("server_name")

            # we'll be checking pastebin downloads of this ssl flow
            # later
            self.pending_ssl_flows.put(
                (daddr, server_name, uid, timestamp, profileid, twid)
            )

            self.check_self_signed_certs(
                flow["validation_status"],
                daddr,
                server_name,
                profileid,
                twid,
                timestamp,
                uid,
            )

            self.detect_malicious_ja3(
                saddr, daddr, ja3, ja3s, twid, uid, timestamp
            )

            self.detect_incompatible_cn(
                daddr, server_name, issuer, profileid, twid, uid, timestamp
            )

        if msg := self.get_msg("new_flow"):
            new_flow = json.loads(msg["data"])
            self.check_non_ssl_port_443_conns(new_flow)
