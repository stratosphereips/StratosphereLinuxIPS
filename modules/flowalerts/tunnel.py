import json

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.slips_utils import utils


class Tunnel(IFlowalertsAnalyzer):
    def init(self): ...
    def name(self) -> str:
        return "tunnel_analyzer"

    def check_gre_tunnel(self, profileid, twid, flow):
        """
        Detects GRE tunnels
        :return: None
        """
        if flow.tunnel_type != "Tunnel::GRE":
            return
        self.set_evidence.gre_tunnel(profileid, twid, flow)

    def analyze(self, msg):
        if utils.is_msg_intended_for(msg, "new_tunnel"):
            msg = json.loads(msg["data"])
            profileid = msg["profileid"]
            twid = msg["twid"]
            flow = utils.convert_to_flow_obj(profileid, twid, msg["flow"])
            self.check_gre_tunnel(flow)
