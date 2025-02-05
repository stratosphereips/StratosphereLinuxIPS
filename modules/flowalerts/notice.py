# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils


class Notice(IFlowalertsAnalyzer):
    def init(self):
        self.classifier = FlowClassifier()

    def name(self) -> str:
        return "notice_analyzer"

    def check_vertical_portscan(self, twid, flow):
        if "Port_Scan" not in flow.note:
            return
        self.set_evidence.vertical_portscan(twid, flow)

    def check_horizontal_portscan(self, flow, profileid, twid):
        if "Address_Scan" not in flow.note:
            return
        self.set_evidence.horizontal_portscan(profileid, twid, flow)

    def check_password_guessing(self, twid, flow):
        if "Password_Guessing" not in flow.note:
            return False
        self.set_evidence.pw_guessing(twid, flow)

    def analyze(self, msg):
        if not utils.is_msg_intended_for(msg, "new_notice"):
            return False

        data = json.loads(msg["data"])
        profileid = data["profileid"]
        twid = data["twid"]
        flow = self.classifier.convert_to_flow_obj(data["flow"])

        self.check_vertical_portscan(twid, flow)
        self.check_horizontal_portscan(flow, profileid, twid)
        self.check_password_guessing(twid, flow)
        return True
