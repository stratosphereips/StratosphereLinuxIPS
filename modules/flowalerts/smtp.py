# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json


from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.slips_utils import utils
from slips_files.common.flow_classifier import FlowClassifier


class SMTP(IFlowalertsAnalyzer):
    def init(self):
        # when the ctr reaches the threshold in 10 seconds,
        # we detect an smtp bruteforce
        self.smtp_bruteforce_threshold = 3
        self.classifier = FlowClassifier()
        # dict to keep track of bad smtp logins to check for bruteforce later
        # format {profileid: [ts,ts,...]}
        self.smtp_bruteforce_cache = {}

    def name(self) -> str:
        return "smtp_analyzer"

    def check_smtp_bruteforce(self, profileid, twid, flow):
        if "bad smtp-auth user" not in flow.last_reply:
            return False

        try:
            timestamps, uids = self.smtp_bruteforce_cache[profileid]
            timestamps.append(flow.starttime)
            uids.append(flow.uid)
            self.smtp_bruteforce_cache[profileid] = (timestamps, uids)
        except KeyError:
            # first time for this profileid to make bad smtp login
            self.smtp_bruteforce_cache.update(
                {profileid: ([flow.starttime], [flow.uid])}
            )

        self.set_evidence.bad_smtp_login(twid, flow)

        timestamps = self.smtp_bruteforce_cache[profileid][0]
        uids = self.smtp_bruteforce_cache[profileid][1]

        # check if 3 bad login attempts happened within 10 seconds or less
        if len(timestamps) != self.smtp_bruteforce_threshold:
            return

        # check if they happened within 10 seconds or less
        diff = utils.get_time_diff(timestamps[0], timestamps[-1])

        if diff > 10:
            # didnt happen within 10s!
            # remove the first login from cache so we
            # can check the next 3 logins
            self.smtp_bruteforce_cache[profileid][0].pop(0)
            self.smtp_bruteforce_cache[profileid][1].pop(0)
            return

        self.set_evidence.smtp_bruteforce(
            flow, twid, self.smtp_bruteforce_threshold, uids
        )

        # remove all 3 logins that caused this alert
        self.smtp_bruteforce_cache[profileid] = ([], [])

    def analyze(self, msg):
        if not utils.is_msg_intended_for(msg, "new_smtp"):
            return

        smtp_info: dict = json.loads(msg["data"])
        profileid = smtp_info["profileid"]
        twid = smtp_info["twid"]
        flow = self.classifier.convert_to_flow_obj(smtp_info["flow"])

        self.check_smtp_bruteforce(profileid, twid, flow)
