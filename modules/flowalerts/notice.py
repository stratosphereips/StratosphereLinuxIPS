import json

from modules.flowalerts.set_evidence import SetEvidnceHelper
from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)


class Notice(IFlowalertsAnalyzer):
    def init(self, flowalerts=None):
        self.flowalerts = flowalerts
        self.set_evidence = SetEvidnceHelper(self.db)

    def name(self) -> str:
        return "notice_analyzer"

    def check_vertical_portscan(self, flow, uid, twid):
        timestamp = flow["stime"]
        msg = flow["msg"]
        note = flow["note"]

        if "Port_Scan" not in note:
            return

        scanning_ip = flow.get("scanning_ip", "")
        self.set_evidence.vertical_portscan(
            msg,
            scanning_ip,
            timestamp,
            twid,
            uid,
        )

    def check_horizontal_portscan(self, flow, uid, profileid, twid):
        timestamp = flow["stime"]
        msg = flow["msg"]
        note = flow["note"]

        if "Address_Scan" not in note:
            return

        self.set_evidence.horizontal_portscan(
            msg,
            timestamp,
            profileid,
            twid,
            uid,
        )

    def check_password_guessing(self, flow, uid, twid):
        timestamp = flow["stime"]
        msg = flow["msg"]
        note = flow["note"]

        if "Password_Guessing" not in note:
            return False

        self.set_evidence.pw_guessing(msg, timestamp, twid, uid, by="Zeek")

    def analyze(self):
        msg = self.flowalerts.get_msg("new_notice")
        if not msg:
            return False

        data = msg["data"]
        data = json.loads(data)
        profileid = data["profileid"]
        twid = data["twid"]
        flow = data["flow"]
        flow = json.loads(flow)
        uid = data["uid"]

        self.check_vertical_portscan(flow, uid, twid)
        self.check_horizontal_portscan(flow, uid, profileid, twid)
        self.check_password_guessing(flow, uid, twid)
