import json

from modules.flowalerts.set_evidence import SetEvidnceHelper
from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.slips_utils import utils


class SSL(IFlowalertsAnalyzer):
    def init(self, flowalerts=None):
        self.flowalerts = flowalerts
        self.set_evidence = SetEvidnceHelper(self.db)

    def name(self) -> str:
        return "ssl_analyzer"

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

    def analyze(self):
        msg = self.flowalerts.get_msg("new_ssl")
        if not msg:
            return

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
        self.flowalerts.pending_ssl_flows.put(
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
