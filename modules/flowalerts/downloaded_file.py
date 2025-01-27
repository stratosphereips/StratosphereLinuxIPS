# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils


class DownloadedFile(IFlowalertsAnalyzer):
    def init(self):
        self.classifier = FlowClassifier()

    def name(self) -> str:
        return "downloaded_files_analyzer"

    def check_malicious_ssl(self, twid, flow):
        if flow.type_ != "files":
            # this detection only supports zeek files.log flows
            return False

        if "SSL" not in flow.source or "SHA1" not in flow.analyzers:
            # not an ssl cert
            return False

        # check if we have this sha1 marked as malicious from one of our feeds
        if ssl_info_from_db := self.db.is_blacklisted_ssl(flow.sha1):
            self.set_evidence.malicious_ssl(twid, flow, ssl_info_from_db)
            return True
        return False

    def analyze(self, msg):
        if not utils.is_msg_intended_for(msg, "new_downloaded_file"):
            return

        msg = json.loads(msg["data"])
        twid = msg["twid"]
        flow = self.classifier.convert_to_flow_obj(msg["flow"])
        self.check_malicious_ssl(twid, flow)
