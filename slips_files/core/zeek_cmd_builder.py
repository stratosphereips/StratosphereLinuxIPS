import os
from typing import List


class ZeekCommandBuilder:
    """
    Builds Zeek (or Bro) command lines based on the given configuration.
    """

    def __init__(
        self,
        zeek_or_bro: str,
        input_type: str,
        rotation_period: str,
        enable_rotation: bool,
        tcp_inactivity_timeout: int,
    ):
        self.zeek_or_bro = zeek_or_bro
        self.input_type = input_type
        self.rotation_period = rotation_period
        self.enable_rotation = enable_rotation
        self.tcp_inactivity_timeout = tcp_inactivity_timeout

    def _get_input_parameter(self, pcap_or_interface: str) -> List[str]:
        if self.input_type == "interface":
            return ["-i", pcap_or_interface]

        elif self.input_type == "pcap":
            pcap = self._get_relative_pcap_path(pcap_or_interface)
            # using a list of params instead of a str for storing the cmd
            # becaus ethe given path may contain spaces
            return ["-r", pcap]

        raise ValueError(f"Unsupported input_type: {self.input_type}")

    def _get_rotation_args(self) -> List[str]:
        # rotation is disabled unless it's an interface
        if self.input_type == "interface" and self.enable_rotation:
            # how often to rotate zeek files? taken from slips.yaml
            return [
                "-e",
                f'"redef Log::default_rotation_interval ='
                f' {self.rotation_period} ;"',
            ]
        return []

    def _get_relative_pcap_path(self, pcap: str) -> str:
        """Resolve or normalize pcap paths.
        Extendable for relative/remote paths."""
        return os.path.abspath(pcap)

    def build(self, pcap_or_interface: str) -> List[str]:
        """
        constructs the zeek command based on the user given
        pcap/interface/packet filter/etc.
        """
        bro_parameter = self._get_input_parameter(pcap_or_interface)
        rotation = self._get_rotation_args()
        zeek_scripts_dir = os.path.join(os.getcwd(), "zeek-scripts")

        # 'local' is removed from the command because it
        # loads policy/protocols/ssl/expiring-certs and
        # and policy/protocols/ssl/validate-certs and they have conflicts
        # with our own
        # zeek-scripts/expiring-certs and validate-certs
        # we have our own copy pf local.zeek in __load__.zeek
        command = [
            self.zeek_or_bro,
            "-C",
            *bro_parameter,
            "-e",
            f"tcp_inactivity_timeout={self.tcp_inactivity_timeout}mins",
            "-e",
            "tcp_attempt_delay=1min",
            *rotation,
            zeek_scripts_dir,
        ]

        return command
