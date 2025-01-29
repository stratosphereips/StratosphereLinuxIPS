# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import json
from typing import Union, Optional, List
import re
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

    def detect_incompatible_cn(self, twid, flow):
        """
        Detects if a certificate claims that it's CN (common name) belongs
        to an org that the domain doesn't belong to
        """
        if not flow.subject:
            return False

        found_org_in_cn = ""
        for org in utils.supported_orgs:
            if org not in flow.subject.lower():
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
            # the certificate doesn't claim to belong to any of slips known
            # orgs
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
            self.check_non_ssl_port_443_conns(twid, flow)
