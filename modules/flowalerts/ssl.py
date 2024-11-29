import asyncio
import json
from typing import (
    Union,
)

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
            await asyncio.sleep(40)
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
        self.set_evidence.incompatible_cn(twid, flow, found_org_in_cn)

    def check_non_ssl_port_443_conns(self, twid, flow):
        """
        alerts on established connections on port 443 that are not HTTPS (ssl)
        """
        flow.state = self.db.get_final_state_from_flags(flow.state, flow.pkts)
        # if it was a valid ssl conn, the 'service' field aka
        # appproto should be 'ssl'
        if (
            str(flow.dport) == "443"
            and flow.proto.lower() == "tcp"
            and str(flow.appproto).lower() != "ssl"
            and flow.state == "Established"
            and (flow.sbytes + flow.dbytes) != 0
        ):
            self.set_evidence.non_ssl_port_443_conn(twid, flow)

    def detect_doh(self, twid, flow):
        if not flow.is_DoH:
            return False
        self.set_evidence.doh(twid, flow)
        self.db.set_ip_info(flow.daddr, {"is_doh_server": True})

    async def analyze(self, msg: dict):
        if utils.is_msg_intended_for(msg, "new_ssl"):
            msg = json.loads(msg["data"])
            profileid = msg["profileid"]
            twid = msg["twid"]
            flow = self.classifier.convert_to_flow_obj(msg["flow"])

            task = asyncio.create_task(
                self.check_pastebin_download(twid, flow)
            )
            # to wait for these functions before flowalerts shuts down
            self.flowalerts.tasks.append(task)

            self.check_self_signed_certs(twid, flow)
            self.detect_malicious_ja3(twid, flow)
            self.detect_incompatible_cn(profileid, twid, flow)
            self.detect_doh(twid, flow)

        elif utils.is_msg_intended_for(msg, "new_flow"):
            msg = json.loads(msg["data"])
            twid = msg["twid"]
            flow = msg["flow"]
            flow = self.classifier.convert_to_flow_obj(flow)
            self.check_non_ssl_port_443_conns(twid, flow)
