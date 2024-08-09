import json

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.slips_utils import utils


class Tunnel(IFlowalertsAnalyzer):
    def init(self): ...
    def name(self) -> str:
        return "tunnel_analyzer"

    def check_gre_tunnel(self, tunnel_info: dict):
        """
        Detects GRE tunnels
        :param tunnel_info: dict containing tunnel zeek flow
        :return: None
        """
        tunnel_flow = tunnel_info["flow"]
        tunnel_type = tunnel_flow["tunnel_type"]

        if tunnel_type != "Tunnel::GRE":
            return

        self.set_evidence.GRE_tunnel(tunnel_info)

    def analyze(self, msg):
        if utils.is_msg_intended_for(msg, "new_tunnel"):
            msg = json.loads(msg["data"])
            self.check_gre_tunnel(msg)
