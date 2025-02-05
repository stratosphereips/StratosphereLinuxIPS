# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import json

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class SSH(IFlowalertsAnalyzer):
    def init(self):
        # after this number of failed ssh logins, we alert pw guessing
        self.pw_guessing_threshold = 20
        self.read_configuration()
        self.password_guessing_cache = {}
        self.classifier = FlowClassifier()

    def name(self) -> str:
        return "ssh_analyzer"

    def read_configuration(self):
        conf = ConfigParser()
        self.ssh_succesful_detection_threshold = (
            conf.ssh_succesful_detection_threshold()
        )

    def detect_successful_ssh_by_slips(
        self, twid, conn_log_flow: dict, ssh_flow
    ):
        """
        Try Slips method to detect if SSH was successful by
        comparing all bytes sent and received to our threshold
        """
        size = conn_log_flow["sbytes"] + conn_log_flow["dbytes"]
        if size <= self.ssh_succesful_detection_threshold:
            return

        daddr = conn_log_flow["daddr"]
        saddr = conn_log_flow["saddr"]
        # Set the evidence because there is no
        # easier way to show how Slips detected
        # the successful ssh and not Zeek
        self.set_evidence.ssh_successful(
            twid,
            saddr,
            daddr,
            size,
            ssh_flow.uid,
            ssh_flow.starttime,
            by="Slips",
        )
        return True

    def set_evidence_ssh_successful_by_zeek(
        self, twid, conn_log_flow, ssh_flow
    ):
        daddr = conn_log_flow["daddr"]
        saddr = conn_log_flow["saddr"]
        size = conn_log_flow["sbytes"] + conn_log_flow["dbytes"]
        self.set_evidence.ssh_successful(
            twid,
            saddr,
            daddr,
            size,
            ssh_flow.uid,
            ssh_flow.starttime,
            by="Zeek",
        )
        return True

    async def check_successful_ssh(self, twid, flow):
        """
        Function to check if an SSH connection logged in successfully
        """
        # this is the ssh flow read from conn.log not ssh.log
        conn_log_flow = utils.get_original_conn_flow(flow, self.db)

        if not conn_log_flow:
            await asyncio.sleep(15)
            conn_log_flow = utils.get_original_conn_flow(flow, self.db)
            if not conn_log_flow:
                return

        # it's true in zeek json files, T in zeke tab files
        if flow.auth_success in ["true", "T"]:
            self.set_evidence_ssh_successful_by_zeek(twid, conn_log_flow, flow)
        else:
            self.detect_successful_ssh_by_slips(twid, conn_log_flow, flow)

    def check_ssh_password_guessing(self, profileid, twid, flow):
        """
        This detection is only done when there's a failed ssh attempt
        alerts ssh pw bruteforce when there's more than
        20 failed attempts by the same ip to the same IP
        """
        if flow.auth_success in ("true", "T"):
            return False

        cache_key = f"{profileid}-{twid}-{flow.daddr}"
        # update the number of times this ip performed a failed ssh login
        if cache_key in self.password_guessing_cache:
            self.password_guessing_cache[cache_key].append(flow.uid)
        else:
            self.password_guessing_cache = {cache_key: [flow.uid]}

        conn_count = len(self.password_guessing_cache[cache_key])

        if conn_count >= self.pw_guessing_threshold:

            uids = self.password_guessing_cache[cache_key]
            self.set_evidence.pw_guessing(flow, twid, uids)
            # reset the counter
            del self.password_guessing_cache[cache_key]

    async def analyze(self, msg):
        if not utils.is_msg_intended_for(msg, "new_ssh"):
            return

        msg = json.loads(msg["data"])
        profileid = msg["profileid"]
        twid = msg["twid"]
        flow = self.classifier.convert_to_flow_obj(msg["flow"])

        self.flowalerts.create_task(self.check_successful_ssh, twid, flow)
        self.check_ssh_password_guessing(profileid, twid, flow)
