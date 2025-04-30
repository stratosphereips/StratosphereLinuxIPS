# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils


class Software(IFlowalertsAnalyzer):
    def init(self):
        self.classifier = FlowClassifier()

    def name(self) -> str:
        return "software_analyzer"

    def check_multiple_ssh_versions(self, flow, twid, role="SSH::CLIENT"):
        """
        checks if this srcip was detected using a different
         ssh client or server versions before
        :param role: can be 'SSH::CLIENT' or 'SSH::SERVER'
        as seen in zeek software.log flows
        """
        if role not in flow.software:
            return

        profileid = f"profile_{flow.saddr}"
        # what software was used before for this profile?
        # returns a dict with
        # software:
        #   { 'version-major': ,'version-minor': ,'uid': }
        cached_used_sw: dict = self.db.get_software_from_profile(profileid)
        if not cached_used_sw:
            # we have no previous software info about this saddr in out db
            return False

        # these are the versions that this profile once used
        cached_ssh_versions: dict = cached_used_sw[flow.software]
        cached_versions = (
            f"{cached_ssh_versions['version-major']}_"
            f"{cached_ssh_versions['version-minor']}"
        )

        current_versions = f"{flow.version_major}_{flow.version_minor}"
        if cached_versions == current_versions:
            # they're using the same ssh client version
            return False

        # get the uid of the cached versions, and the uid
        # of the current used versions
        uids = [cached_ssh_versions["uid"], flow.uid]
        self.set_evidence.multiple_ssh_versions(
            flow,
            cached_versions,
            current_versions,
            twid,
            uids,
            role=role,
        )
        return True

    def analyze(self, msg):
        if not utils.is_msg_intended_for(msg, "new_software"):
            return

        msg = json.loads(msg["data"])
        twid = msg["twid"]
        flow = self.classifier.convert_to_flow_obj(msg["flow"])
        self.check_multiple_ssh_versions(flow, twid, role="SSH::CLIENT")
        self.check_multiple_ssh_versions(flow, twid, role="SSH::SERVER")
