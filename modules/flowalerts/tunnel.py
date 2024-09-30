import json

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.slips_utils import utils
from slips_files.common.flow_classifier import FlowClassifier


class Tunnel(IFlowalertsAnalyzer):
    def init(self):
        self.classifier = FlowClassifier()

    def name(self) -> str:
        return "tunnel_analyzer"

    def check_gre_tunnel(self, twid, flow):
        """
        Detects GRE tunnels
        :return: None
        """
        if flow.tunnel_type != "Tunnel::GRE":
            return
        self.set_evidence.gre_tunnel(twid, flow)

    def analyze(self, msg):
        if utils.is_msg_intended_for(msg, "new_tunnel"):
            msg = json.loads(msg["data"])
            twid = msg["twid"]
            flow = self.classifier.convert_to_flow_obj(msg["flow"])
            self.check_gre_tunnel(twid, flow)
