import json

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)


class DownloadedFile(IFlowalertsAnalyzer):
    def init(self): ...

    def name(self) -> str:
        return "downloaded_file_analyzer"

    def check_malicious_ssl(self, ssl_info):
        if ssl_info["type"] != "zeek":
            # this detection only supports zeek files.log flows
            return False

        flow: dict = ssl_info["flow"]

        source = flow.get("source", "")
        analyzers = flow.get("analyzers", "")
        sha1 = flow.get("sha1", "")

        if "SSL" not in source or "SHA1" not in analyzers:
            # not an ssl cert
            return False

        # check if we have this sha1 marked as malicious from one of our feeds
        ssl_info_from_db = self.db.get_ssl_info(sha1)
        if not ssl_info_from_db:
            return False

        self.set_evidence.malicious_ssl(ssl_info, ssl_info_from_db)

    def analyze(self):
        msg = self.flowalerts.get_msg("new_downloaded_file")
        if not msg:
            return

        ssl_info = json.loads(msg["data"])
        self.check_malicious_ssl(ssl_info)
