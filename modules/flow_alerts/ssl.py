# SPDX-FileCopyrightText: 2021 Sebastian Garcia
# <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import json
from typing import Union, Optional, List
import re
from pathlib import Path
import tldextract
from slips_files.common.abstracts.iflowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.flows.suricata import SuricataTLS
from slips_files.core.flows.zeek import SSL


class SSL(IFlowalertsAnalyzer):
    def init(self) -> None:
        """Load provider domains once for certificate identity checks."""
        self.classifier = FlowClassifier()
        self.provider_domains: dict[str, tuple[str, ...]] = {}
        for org in utils.supported_orgs:
            path = Path("slips_files/organizations_info") / f"{org}_domains"
            if path.is_file():
                self.provider_domains[org] = tuple(
                    line.strip().lower().rstrip(".")
                    for line in path.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                )

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
        checks the validation status of every zeek ssl flow for self
        signed certs
        """
        if not hasattr(flow, "validation_status"):
            # must be a suricata TLS flow
            return

        if "self signed" not in flow.validation_status:
            return
        self.set_evidence.self_signed_certificates(twid, flow)

    def detect_malicious_ja3(self, twid, flow):
        if not (hasattr(flow, "ja3") and hasattr(flow, "ja3s")):
            # its a suricata flow
            return

        if not (flow.ja3 or flow.ja3s):
            # we don't have info about this flow's ja3 or ja3s fingerprint
            return

        # get the dict of malicious ja3 stored in our db
        malicious_ja3_dict = self.db.get_all_blacklisted_ja3()
        if flow.ja3 in malicious_ja3_dict:
            self.set_evidence.malicious_ja3(twid, flow, malicious_ja3_dict)

        if flow.ja3s in malicious_ja3_dict:
            self.set_evidence.malicious_ja3s(twid, flow, malicious_ja3_dict)

    def detect_tls_provider_impersonation(self, twid: str, flow: SSL) -> bool:
        """Flag a provider claim outside its known domains and networks.

        Parameters:
            twid: Detection time window.
            flow: TLS record containing the server name and certificate subject.

        Returns:
            Whether a suspected provider impersonation was recorded.
        """
        if not (flow.subject and flow.server_name):
            return False
        claims = " ".join(
            re.findall(
                r"(?:^|(?<!\\),)\s*(?:O|OU)\s*=\s*([^,]+)", flow.subject, re.I
            )
        ).lower()
        domain = flow.server_name.lower().rstrip(".")
        for org in utils.supported_orgs:
            if not re.search(rf"\b{re.escape(org)}\b", claims):
                continue
            domains = self.provider_domains.get(org, ())
            if not domains:
                continue
            if any(
                domain == known or domain.endswith(f".{known}")
                for known in domains
            ):
                return False
            if self.whitelist.org_analyzer.is_ip_in_org(flow.daddr, org):
                return False
            if self.whitelist.org_analyzer.is_domain_in_org(domain, org):
                return False
            self.set_evidence.tls_provider_impersonation(twid, flow, org)
            return True
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
        if not hasattr(flow, "is_DoH"):
            return False
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
            self.detect_tls_provider_impersonation(twid, flow)
            self.detect_doh(twid, flow)
            self.detect_cn_url_mismatch(twid, flow)
