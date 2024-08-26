from typing import Any, Dict, Type

from slips_files.core.flows.argus import ArgusConn
from slips_files.core.flows.nfdump import NfdumpConn
from slips_files.core.flows.suricata import (
    SuricataFlow,
    SuricataHTTP,
    SuricataDNS,
    SuricataTLS,
    SuricataFile,
    SuricataSSH,
)
from slips_files.core.flows.zeek import (
    Conn,
    DNS,
    HTTP,
    SSL,
    SSH,
    DHCP,
    FTP,
    SMTP,
    Tunnel,
    Notice,
    Files,
    ARP,
    Software,
    Weird,
)


class FlowClassifier:
    """
    when modules receive msgs in redis channels, they're received in dict
    format
    the goal of this class is to classify the flow type sent in the
    channel, and convert it back to the correct dataclass.
    """

    def __init__(self):
        self.flow_map: Dict[str, Type] = {
            "conn": Conn,
            "dns": DNS,
            "http": HTTP,
            "ssl": SSL,
            "ssh": SSH,
            "dhcp": DHCP,
            "ftp": FTP,
            "smtp": SMTP,
            "tunnel": Tunnel,
            "notice": Notice,
            "files": Files,
            "arp": ARP,
            "software": Software,
            "weird": Weird,
            "argus": ArgusConn,
            "nfdump": NfdumpConn,
            "suricata_flow": SuricataFlow,
            "suricata_http": SuricataHTTP,
            "suricata_dns": SuricataDNS,
            "suricata_tls": SuricataTLS,
            "suricata_file": SuricataFile,
            "suricata_ssh": SuricataSSH,
        }

    def classify(self, flow: Dict[str, Any]):
        # since suricata types are exactly the same as zeek types,
        # e.g. "conn", "files" etc.
        # i added a field for suricata flows called flow_source
        # the goal of this is to be able to map the flow.type_ to the
        # correct Suricata* class
        given_flow_type = flow.type_
        if hasattr(flow, "flow_source"):
            if flow.flow_source == "suricata":
                given_flow_type = f"suricata_{flow.type_}"

        try:
            return self.flow_map[given_flow_type]
        except KeyError:
            return

    def convert_to_flow_obj(self, flow: dict):
        """
        returns the given flow in one of the types defined in
         slips_files/core/flows/
        """
        flow_class = self.classify(flow)
        return flow_class(**flow)
