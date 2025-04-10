# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from datetime import timedelta
import sys
import ipaddress
from typing import (
    List,
    Union,
)
import yaml
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address

from slips_files.common.parsers.arg_parser import ArgumentParser
from slips_files.common.slips_utils import utils


class ConfigParser(object):
    name = "ConfigParser"
    description = "Parse and sanitize slips.yaml values. used by all modules"
    authors = ["Alya Gomaa"]

    def __init__(self):
        configfile: str = self.get_config_file()
        self.config = self.read_config_file(configfile)
        self.home_network_ranges = (
            "192.168.0.0/16",
            "172.16.0.0/12",
            "10.0.0.0/8",
        )
        self.home_network_ranges = list(
            map(ipaddress.ip_network, self.home_network_ranges)
        )

    def read_config_file(self, configfile: str) -> dict:
        """
        reads slips configuration file, slips.conf/slips.yaml is the default file
        """
        with open(configfile) as source:
            return yaml.safe_load(source)

    def get_config_file(self):
        """
        uses the arg parser to get the config file specified by -c or the
        path of the default one
        """
        parser = self.get_parser()
        return parser.get_configfile()

    def get_parser(self, help=False):
        return ArgumentParser(
            usage="./slips.py -c <configfile> [options] [file]", add_help=help
        )

    def get_args(self):
        """
        Returns the args given to slips parsed by ArgumentParser
        """
        parser = self.get_parser()
        return parser.parse_arguments()

    def read_configuration(self, section, name, default_value):
        """
        Read the configuration file for what slips.py needs.
         Other processes also access the configuration
        """
        try:
            section_data: dict = self.config.get(section, None)
            if section_data is None:
                return default_value
            return section_data.get(name, default_value)
        except (NameError, ValueError):
            # There is a conf, but there is no option,
            # or no section or no configuration file specified
            return default_value

    @property
    def web_interface_port(self) -> int:
        port = self.read_configuration("web_interface", "port", 55000)
        try:
            return int(port)
        except Exception:
            return 55000

    def get_entropy_threshold(self):
        """
        gets the shannon entropy used in detecting C&C over DNS TXT records from slips.conf/slips.yaml
        """
        threshold = self.read_configuration(
            "flowalerts", "entropy_threshold", 5
        )

        try:
            return float(threshold)
        except Exception:
            return 5

    def get_pastebin_download_threshold(self):
        threshold = self.read_configuration(
            "flowalerts", "pastebin_download_threshold", 700
        )

        try:
            return int(threshold)
        except Exception:
            return 700

    def get_all_homenet_ranges(self):
        return self.home_network_ranges

    def evidence_detection_threshold(self):
        default_value = 0.25
        threshold = self.read_configuration(
            "detection", "evidence_detection_threshold", default_value
        )
        try:
            threshold = float(threshold)
        except ValueError:
            threshold = default_value
        return threshold

    def packet_filter(self):
        return self.read_configuration("parameters", "pcapfilter", False)

    def online_whitelist(self):
        return self.read_configuration("whitelists", "online_whitelist", False)

    def tcp_inactivity_timeout(self):
        timeout = self.read_configuration(
            "parameters", "tcp_inactivity_timeout", "5"
        )
        try:
            timeout = int(timeout)
        except ValueError:
            timeout = 5
        return timeout

    def online_whitelist_update_period(self):
        update_period = self.read_configuration(
            "whitelists", "online_whitelist_update_period", 604800
        )
        try:
            update_period = int(update_period)
        except ValueError:
            update_period = 604800
        return update_period

    def popup_alerts(self):
        return self.read_configuration("detection", "popup_alerts", False)

    def export_labeled_flows(self):
        return self.read_configuration(
            "parameters", "export_labeled_flows", False
        )

    def export_labeled_flows_to(self):
        export = self.read_configuration(
            "parameters", "export_format", "None"
        ).lower()
        if "tsv" in export:
            return "tsv"
        if "json" in export:
            return "json"
        return False

    def rotation(self):
        return self.read_configuration("parameters", "rotation", True)

    def store_a_copy_of_zeek_files(self):
        return self.read_configuration(
            "parameters", "store_a_copy_of_zeek_files", False
        )

    def local_whitelist_path(self):
        return self.read_configuration(
            "whitelists", "local_whitelist_path", "config/whitelist.conf"
        )

    def enable_online_whitelist(self):
        return self.read_configuration(
            "whitelists", "enable_online_whitelist", True
        )

    def enable_local_whitelist(self):
        return self.read_configuration(
            "whitelists", "enable_local_whitelist", True
        )

    def logsfile(self):
        return self.read_configuration("modes", "logsfile", "slips.log")

    def stdout(self):
        return self.read_configuration("modes", "stdout", "slips.log")

    def stderr(self):
        return self.read_configuration("modes", "stderr", "errors.log")

    def create_p2p_logfile(self):
        return self.read_configuration(
            "local_p2p", "create_p2p_logfile", False
        )

    def ts_format(self):
        return self.read_configuration("timestamp", "format", None)

    def delete_zeek_files(self):
        return self.read_configuration(
            "parameters", "delete_zeek_files", False
        )

    def store_zeek_files_copy(self):
        return self.read_configuration(
            "parameters", "store_a_copy_of_zeek_files", True
        )

    def get_tw_width_as_float(self):
        try:
            twid_width = self.read_configuration(
                "parameters", "time_window_width", 3600
            )
        except (NameError, ValueError):
            # There is a conf, but there is no option,
            # or no section or no configuration file specified
            twid_width = 3600

        try:
            twid_width = float(twid_width)
        except ValueError:
            # Its not a float
            if "only_one_tw" in twid_width:
                # Only one tw. Width is 10 9s, wich is ~11,500 days, ~311 years
                twid_width = 9999999999
        return twid_width

    def disabled_detections(self) -> list:
        return self.read_configuration(
            "DisabledAlerts", "disabled_detections", []
        )

    def get_tw_width(self) -> str:
        twid_width = self.get_tw_width_as_float()
        # timedelta puts it in the form of X days, hours:minutes:seconds
        total_seconds = int(timedelta(seconds=twid_width).total_seconds())
        days, remainder = divmod(
            total_seconds, 86400
        )  # 86400 seconds in a day
        hrs, remainder = divmod(remainder, 3600)  # 3600 seconds in an hour
        mins, sec = divmod(remainder, 60)

        time_dict = {"day": days, "hr": hrs, "min": mins, "second": sec}

        # Build the result string, correctly handling singular/plural
        time_parts = [
            f"{value} {key}{'s' if value != 1 else ''}"
            for key, value in time_dict.items()
            if value > 0
        ]
        return " ".join(time_parts) if time_parts else "0 seconds"

    def enable_metadata(self):
        return self.read_configuration("parameters", "metadata_dir", False)

    def use_local_p2p(self):
        return self.read_configuration("local_p2p", "use_p2p", False)

    def use_global_p2p(self):
        return self.read_configuration("global_p2p", "use_global_p2p", False)

    def cesnet_conf_file(self):
        return self.read_configuration("CESNET", "configuration_file", False)

    def poll_delay(self):
        poll_delay = self.read_configuration("CESNET", "receive_delay", 86400)
        try:
            poll_delay = int(poll_delay)
        except ValueError:
            # By default push every 1 day
            poll_delay = 86400

        return poll_delay

    def send_to_warden(self):
        return self.read_configuration("CESNET", "send_alerts", False)

    def receive_from_warden(self):
        return self.read_configuration("CESNET", "receive_alerts", False)

    def verbose(self):
        verbose = self.read_configuration("parameters", "verbose", 1)
        try:
            verbose = int(verbose)
            return max(verbose, 1)
        except ValueError:
            return 1

    def debug(self):
        debug = self.read_configuration("parameters", "debug", 0)
        try:
            debug = int(debug)
            debug = max(debug, 0)
        except ValueError:
            debug = 0
        return debug

    def export_to(self):
        return self.read_configuration("exporting_alerts", "export_to", [])

    def export_strato_letters(self) -> bool:
        return self.read_configuration(
            "parameters", "export_strato_letters", False
        )

    def slack_token_filepath(self):
        return self.read_configuration(
            "exporting_alerts", "slack_api_path", False
        )

    def slack_channel_name(self):
        return self.read_configuration(
            "exporting_alerts", "slack_channel_name", False
        )

    def sensor_name(self):
        return self.read_configuration(
            "exporting_alerts", "sensor_name", False
        )

    def taxii_server(self):
        taxii_server = self.read_configuration(
            "exporting_alerts", "TAXII_server", False
        )
        return taxii_server.replace("www.", "")

    def taxii_port(self):
        return self.read_configuration("exporting_alerts", "port", False)

    def use_https(self):
        return self.read_configuration("exporting_alerts", "use_https", False)

    def discovery_path(self):
        return self.read_configuration(
            "exporting_alerts", "discovery_path", False
        )

    def inbox_path(self):
        return self.read_configuration("exporting_alerts", "inbox_path", False)

    def push_delay(self):
        # 3600 = 1h
        delay = self.read_configuration("exporting_alerts", "push_delay", 3600)
        try:
            delay = float(delay)
        except ValueError:
            delay = 3600
        return delay

    def collection_name(self):
        return self.read_configuration(
            "exporting_alerts", "collection_name", False
        )

    def taxii_username(self):
        return self.read_configuration(
            "exporting_alerts", "taxii_username", False
        )

    def taxii_password(self):
        return self.read_configuration(
            "exporting_alerts", "taxii_password", False
        )

    def jwt_auth_path(self):
        return self.read_configuration(
            "exporting_alerts", "jwt_auth_path", False
        )

    def long_connection_threshold(self):
        """
        returns threshold in seconds
        """
        # 1500 is in seconds, =25 mins
        threshold = self.read_configuration(
            "flowalerts", "long_connection_threshold", 1500
        )
        try:
            threshold = int(threshold)
        except ValueError:
            threshold = 1500
        return threshold

    def ssh_succesful_detection_threshold(self):
        """
        returns threshold in seconds
        """
        threshold = self.read_configuration(
            "flowalerts", "ssh_succesful_detection_threshold", 4290
        )
        try:
            threshold = int(threshold)
        except ValueError:
            threshold = 4290

        return threshold

    def data_exfiltration_threshold(self):
        """
        returns threshold in MBs
        """
        # threshold in MBs
        threshold = self.read_configuration(
            "flowalerts", "data_exfiltration_threshold", 500
        )
        try:
            threshold = int(threshold)
        except ValueError:
            threshold = 500
        return threshold

    def get_ml_mode(self):
        return self.read_configuration("flowmldetection", "mode", "test")

    def RiskIQ_credentials_path(self):
        return self.read_configuration(
            "threatintelligence", "RiskIQ_credentials_path", ""
        )

    def local_ti_data_path(self):
        return self.read_configuration(
            "threatintelligence",
            "local_threat_intelligence_files",
            "config/local_ti_files/",
        )

    def wait_for_TI_to_finish(self) -> bool:
        return self.read_configuration(
            "threatintelligence", "wait_for_TI_to_finish", False
        )

    def remote_ti_data_path(self):
        path = self.read_configuration(
            "threatintelligence",
            "download_path_for_remote_threat_intelligence",
            "modules/threat_intelligence/remote_data_files/",
        )
        return utils.sanitize(path)

    def ti_files(self):
        return self.read_configuration("threatintelligence", "ti_files", False)

    def ja3_feeds(self):
        return self.read_configuration(
            "threatintelligence", "ja3_feeds", False
        )

    def ssl_feeds(self):
        return self.read_configuration(
            "threatintelligence", "ssl_feeds", False
        )

    def timeline_human_timestamp(self):
        return self.read_configuration(
            "modules", "timeline_human_timestamp", False
        )

    def analysis_direction(self):
        """
        Controls which traffic flows are processed and analyzed by SLIPS.

        Determines whether SLIPS should focus on:
        - 'out' mode: Analyzes only outbound traffic (potential data exfiltration)
        - 'all' mode: Analyzes traffic in both directions (inbound and outbound)

        Returns:
            str or False: The value of the 'analysis_direction' parameter, or False if not found.
        """
        return self.read_configuration(
            "parameters", "analysis_direction", False
        )

    def update_period(self):
        update_period = self.read_configuration(
            "threatintelligence", "TI_files_update_period", 86400
        )
        try:
            update_period = float(update_period)
        except ValueError:
            update_period = 86400  # 1 day
        return update_period

    def vt_api_key_file(self):
        return self.read_configuration("virustotal", "api_key_file", None)

    def virustotal_update_period(self):
        update_period = self.read_configuration(
            "virustotal", "virustotal_update_period", 259200
        )
        try:
            update_period = int(update_period)
        except ValueError:
            update_period = 259200
        return update_period

    def riskiq_update_period(self):
        update_period = self.read_configuration(
            "threatintelligence", "riskiq_update_period", 604800
        )
        try:
            update_period = float(update_period)
        except ValueError:
            update_period = 604800  # 1 week
        return update_period

    def mac_db_update_period(self):
        update_period = self.read_configuration(
            "threatintelligence", "mac_db_update", 1209600
        )
        try:
            update_period = float(update_period)
        except ValueError:
            update_period = 1209600  # 2 weeks
        return update_period

    def delete_prev_db(self):
        return self.read_configuration("parameters", "deletePrevdb", True)

    def rotation_period(self):
        rotation_period = self.read_configuration(
            "parameters", "rotation_period", "1 day"
        )
        return utils.sanitize(rotation_period)

    def parse_ip(self, ip: str):
        """converts the given IP address or CIDR to an obj"""
        try:
            return (
                ipaddress.ip_network(ip, strict=False)
                if "/" in ip
                else ipaddress.ip_address(ip)
            )
        except ValueError:
            raise ValueError(f"Invalid IP or CIDR format: {ip}")

    def client_ips(
        self,
    ) -> List[Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]]:
        client_ips: str = self.read_configuration(
            "parameters", "client_ips", []
        )
        client_ips: str = utils.sanitize(str(client_ips))
        client_ips: List[str] = (
            client_ips.replace("[", "").replace("]", "").split(",")
        )
        client_ips: List[str] = [
            client_ip.strip().strip("'") for client_ip in client_ips
        ]
        # Remove empty strings if any
        client_ips: List[str] = [
            client_ip for client_ip in client_ips if client_ip
        ]
        # convert client ips to ip and network objs
        client_ips: List = [self.parse_ip(ip) for ip in client_ips]
        return client_ips

    def keep_rotated_files_for(self) -> int:
        """returns period in seconds"""
        keep_rotated_files_for = self.read_configuration(
            "parameters", "keep_rotated_files_for", "1 day"
        )
        try:
            period = utils.sanitize(keep_rotated_files_for)
            period = (
                period.replace("day", "").replace(" ", "").replace("s", "")
            )
            period = int(period)
        except ValueError:
            period = 1

        return period * 24 * 60 * 60

    def wait_for_modules_to_finish(self) -> int:
        """returns period in mins"""
        wait_for_modules_to_finish = self.read_configuration(
            "parameters", "wait_for_modules_to_finish", "15 mins"
        )
        try:
            period = utils.sanitize(wait_for_modules_to_finish)
            period = (
                period.replace("mins", "").replace(" ", "").replace("s", "")
            )
            period = float(period)
        except ValueError:
            period = 15

        return period

    def mac_db_link(self):
        return utils.sanitize(
            self.read_configuration("threatintelligence", "mac_db", "")
        )

    def store_zeek_files_in_the_output_dir(self):
        return self.read_configuration(
            "parameters", "store_zeek_files_in_the_output_dir", False
        )

    def label(self):
        return self.read_configuration("parameters", "label", "unknown")

    def get_UID(self):
        return int(self.read_configuration("Docker", "UID", 0))

    def get_GID(self):
        return int(self.read_configuration("Docker", "GID", 0))

    def reading_flows_from_cyst(self):
        custom_flows = "-im" in sys.argv or "--input-module" in sys.argv
        if not custom_flows:
            return False

        # are we reading custom flows from cyst module?
        for param in ("--input-module", "-im"):
            try:
                if "cyst" in sys.argv[sys.argv.index(param) + 1]:
                    return True
            except ValueError:
                # param isn't used
                pass

    def get_disabled_modules(self, input_type: str) -> list:
        """
        Uses input type to enable leak detector only on pcaps
        """
        to_ignore: List[str] = self.read_configuration(
            "modules", "disable", ["template"]
        )
        to_ignore = [mod.strip() for mod in to_ignore]

        # Ignore exporting alerts module if export_to is empty
        export_to = self.export_to()
        if "stix" not in export_to and "slack" not in export_to:
            to_ignore.append("exporting_alerts")

        use_p2p = self.use_local_p2p()
        if not (use_p2p and "-i" in sys.argv):
            to_ignore.append("p2ptrust")

        use_global_p2p = self.use_global_p2p()
        if not (use_global_p2p and ("-i" in sys.argv or "-g" in sys.argv)):
            to_ignore.append("fidesModule")
            to_ignore.append("irisModule")

        # ignore CESNET sharing module if send and receive are
        # disabled in slips.yaml
        send_to_warden = self.send_to_warden()
        receive_from_warden = self.receive_from_warden()

        if not send_to_warden and not receive_from_warden:
            to_ignore.append("cesnet")

        # don't run blocking module unless specified
        if not ("-cb" in sys.argv or "-p" in sys.argv):
            to_ignore.append("blocking")

        # leak detector only works on pcap files
        if input_type != "pcap":
            to_ignore.append("leak_detector")

        if not self.reading_flows_from_cyst():
            to_ignore.append("cyst")

        return to_ignore

    def get_cpu_profiler_enable(self):
        return self.read_configuration(
            "Profiling", "cpu_profiler_enable", False
        )

    def get_cpu_profiler_mode(self):
        return self.read_configuration("Profiling", "cpu_profiler_mode", "dev")

    def get_cpu_profiler_multiprocess(self):
        return self.read_configuration(
            "Profiling", "cpu_profiler_multiprocess", True
        )

    def get_cpu_profiler_output_limit(self) -> int:
        return int(
            self.read_configuration(
                "Profiling", "cpu_profiler_output_limit", 20
            )
        )

    def get_cpu_profiler_sampling_interval(self) -> int:
        return int(
            self.read_configuration(
                "Profiling", "cpu_profiler_sampling_interval", 5
            )
        )

    def get_cpu_profiler_dev_mode_entries(self) -> int:
        return int(
            self.read_configuration(
                "Profiling", "cpu_profiler_dev_mode_entries", 1000000
            )
        )

    def get_memory_profiler_enable(self):
        return self.read_configuration(
            "Profiling", "memory_profiler_enable", False
        )

    def get_memory_profiler_mode(self):
        return self.read_configuration(
            "Profiling", "memory_profiler_mode", "dev"
        )

    def get_memory_profiler_multiprocess(self):
        return self.read_configuration(
            "Profiling", "memory_profiler_multiprocess", True
        )

    def get_iris_config_location(self) -> str:
        return self.read_configuration(
            "global_p2p", "iris_conf", "config/iris_config.yaml"
        )

    def get_bootstrapping_setting(self) -> (bool, list):
        return (
            self.read_configuration("global_p2p", "bootstrapping_node", False)
            and self.read_configuration("global_p2p", "use_global_p2p", False)
            and ("-i" in sys.argv or "-g" in sys.argv),
            ["fidesModule", "irisModule"],
        )

    def is_bootstrapping_node(self) -> bool:
        return (
            self.read_configuration("global_p2p", "bootstrapping_node", False)
            and self.read_configuration("global_p2p", "use_global_p2p", False)
            and ("-i" in sys.argv or "-g" in sys.argv)
        )

    def get_bootstrapping_modules(self) -> list:
        return self.read_configuration(
            "global_p2p",
            "bootstrapping_modules",
            ["fidesModule", "irisModule"],
        )
