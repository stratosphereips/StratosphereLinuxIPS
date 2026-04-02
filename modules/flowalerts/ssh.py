# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import json

from slips_files.common.abstracts.iflowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class SSH(IFlowalertsAnalyzer):
    def init(self):
        self.read_configuration()
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

    async def analyze(self, msg):
        if not utils.is_msg_intended_for(msg, "new_ssh"):
            return

        msg = json.loads(msg["data"])
        twid = msg["twid"]
        flow = self.classifier.convert_to_flow_obj(msg["flow"])

        self.flowalerts.create_task(self.check_successful_ssh, twid, flow)
