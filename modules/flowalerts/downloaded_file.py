import json

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.slips_utils import utils


class DownloadedFile(IFlowalertsAnalyzer):
    def init(self): ...

    def name(self) -> str:
        return "downloaded_files_analyzer"

    def check_malicious_ssl(self, ssl_info: dict):
        twid = ssl_info["timewindow"]
        profileid = ssl_info["profileid"]
        flow = utils.convert_to_flow_obj(ssl_info["flow"])

        if flow.type_ != "zeek":
            # this detection only supports zeek files.log flows
            return False

        if "SSL" not in flow.source or "SHA1" not in flow.analyzers:
            # not an ssl cert
            return False

        # check if we have this sha1 marked as malicious from one of our feeds
        if ssl_info_from_db := self.db.is_blacklisted_ssl(flow.sha1):
            self.set_evidence.malicious_ssl(
                profileid, twid, flow, ssl_info_from_db
            )
            return True
        return False

    def analyze(self, msg):
        if not utils.is_msg_intended_for(msg, "new_downloaded_file"):
            return

        ssl_info = json.loads(msg["data"])
        self.check_malicious_ssl(ssl_info)
