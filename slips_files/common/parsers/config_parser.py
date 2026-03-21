# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from datetime import timedelta
import sys
from slips_files.common.input_type import InputType
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
            usage="./slips.py -c <configfile> [options]", add_help=help
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

    def tranco_top_benign_limit(self):
        limit = self.read_configuration(
            "whitelists", "tranco_top_benign_limit", 1000
        )
        try:
            limit = int(limit)
        except ValueError:
            limit = 1000
        return max(0, limit)

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

    def get_tw_width_in_seconds(self):
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

    def evidence_signal_default(self) -> str:
        value = self.read_configuration(
            "EvidenceSignals", "default_signal", "PAMP"
        )
        if not isinstance(value, str):
            return "PAMP"
        value = value.strip().upper()
        if value not in ("PAMP", "DAMP"):
            return "PAMP"
        return value

    def evidence_signal_overrides(self) -> dict:
        overrides = self.read_configuration(
            "EvidenceSignals", "overrides", {}
        )
        if not isinstance(overrides, dict):
            return {}

        sanitized = {}
        for evidence_type, signal in overrides.items():
            if not isinstance(evidence_type, str):
                continue
            if not isinstance(signal, str):
                continue
            normalized_signal = signal.strip().upper()
            if normalized_signal not in ("PAMP", "DAMP"):
                continue
            sanitized[evidence_type.strip().upper()] = normalized_signal
        return sanitized

    def get_tw_width(self) -> str:
        twid_width = self.get_tw_width_in_seconds()
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

    def taxii_timeout(self):
        timeout = self.read_configuration(
            "exporting_alerts", "taxii_timeout", 10
        )
        try:
            timeout = float(timeout)
        except ValueError:
            timeout = 10
        return max(1.0, timeout)

    def taxii_version(self):
        return self.read_configuration("exporting_alerts", "taxii_version", 2)

    def taxii_direct_export(self):
        return self.read_configuration(
            "exporting_alerts", "direct_export", False
        )

    def taxii_direct_export_workers(self):
        workers = self.read_configuration(
            "exporting_alerts", "direct_export_workers", 2
        )
        try:
            workers = int(workers)
        except ValueError:
            workers = 2
        return max(1, workers)

    def taxii_direct_export_max_workers(self):
        workers = self.read_configuration(
            "exporting_alerts", "direct_export_max_workers", 8
        )
        try:
            workers = int(workers)
        except ValueError:
            workers = 8
        return max(1, workers)

    def taxii_direct_export_retry_max(self):
        retries = self.read_configuration(
            "exporting_alerts", "direct_export_retry_max", 0
        )
        try:
            retries = int(retries)
        except ValueError:
            retries = 0
        return max(0, retries)

    def taxii_direct_export_retry_backoff(self):
        backoff = self.read_configuration(
            "exporting_alerts", "direct_export_retry_backoff", 0.5
        )
        try:
            backoff = float(backoff)
        except ValueError:
            backoff = 0.5
        return max(0.0, backoff)

    def taxii_direct_export_retry_max_delay(self):
        delay = self.read_configuration(
            "exporting_alerts", "direct_export_retry_max_delay", 5.0
        )
        try:
            delay = float(delay)
        except ValueError:
            delay = 5.0
        return max(0.0, delay)

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

    def https_anomaly_training_hours(self) -> int:
        training_hours = self.read_configuration(
            "anomaly_detection_https", "training_hours", 24
        )
        try:
            training_hours = int(training_hours)
        except (TypeError, ValueError):
            training_hours = 24
        return max(0, training_hours)

    def https_anomaly_hourly_zscore_thr(self) -> float:
        threshold = self.read_configuration(
            "anomaly_detection_https", "hourly_zscore_threshold", 3.0
        )
        try:
            threshold = float(threshold)
        except (TypeError, ValueError):
            threshold = 3.0
        return max(0.5, threshold)

    def https_anomaly_flow_zscore_thr(self) -> float:
        threshold = self.read_configuration(
            "anomaly_detection_https", "flow_zscore_threshold", 3.5
        )
        try:
            threshold = float(threshold)
        except (TypeError, ValueError):
            threshold = 3.5
        return max(0.5, threshold)

    def https_anomaly_adapt_score_thr(self) -> float:
        threshold = self.read_configuration(
            "anomaly_detection_https", "adaptation_score_threshold", 2.0
        )
        try:
            threshold = float(threshold)
        except (TypeError, ValueError):
            threshold = 2.0
        return max(0.0, threshold)

    def https_anomaly_baseline_alpha(self) -> float:
        alpha = self.read_configuration(
            "anomaly_detection_https", "baseline_alpha", 0.1
        )
        try:
            alpha = float(alpha)
        except (TypeError, ValueError):
            alpha = 0.1
        return min(max(alpha, 0.001), 1.0)

    def https_anomaly_drift_alpha(self) -> float:
        alpha = self.read_configuration(
            "anomaly_detection_https", "drift_alpha", 0.05
        )
        try:
            alpha = float(alpha)
        except (TypeError, ValueError):
            alpha = 0.05
        return min(max(alpha, 0.001), 1.0)

    def https_anomaly_suspicious_alpha(self) -> float:
        alpha = self.read_configuration(
            "anomaly_detection_https", "suspicious_alpha", 0.005
        )
        try:
            alpha = float(alpha)
        except (TypeError, ValueError):
            alpha = 0.005
        return min(max(alpha, 0.0), 1.0)

    def https_anomaly_min_baseline_points(self) -> int:
        points = self.read_configuration(
            "anomaly_detection_https", "min_baseline_points", 6
        )
        try:
            points = int(points)
        except (TypeError, ValueError):
            points = 6
        return max(1, points)

    def https_anomaly_max_small_flow_anomalies(self) -> int:
        threshold = self.read_configuration(
            "anomaly_detection_https", "max_small_flow_anomalies", 1
        )
        try:
            threshold = int(threshold)
        except (TypeError, ValueError):
            threshold = 1
        return max(0, threshold)

    def https_anomaly_ja3_min_variants_per_server(self) -> int:
        threshold = self.read_configuration(
            "anomaly_detection_https", "ja3_min_variants_per_server", 3
        )
        try:
            threshold = int(threshold)
        except (TypeError, ValueError):
            threshold = 3
        return max(1, threshold)

    def https_anomaly_use_adwin_drift(self) -> bool:
        value = self.read_configuration(
            "anomaly_detection_https", "use_adwin_drift", True
        )
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def https_anomaly_adwin_delta(self) -> float:
        delta = self.read_configuration(
            "anomaly_detection_https", "adwin_delta", 0.002
        )
        try:
            delta = float(delta)
        except (TypeError, ValueError):
            delta = 0.002
        return min(max(delta, 0.000001), 1.0)

    def https_anomaly_adwin_clock(self) -> int:
        clock = self.read_configuration(
            "anomaly_detection_https", "adwin_clock", 32
        )
        try:
            clock = int(clock)
        except (TypeError, ValueError):
            clock = 32
        return max(1, clock)

    def https_anomaly_adwin_grace_period(self) -> int:
        grace = self.read_configuration(
            "anomaly_detection_https", "adwin_grace_period", 10
        )
        try:
            grace = int(grace)
        except (TypeError, ValueError):
            grace = 10
        return max(1, grace)

    def https_anomaly_adwin_min_window_length(self) -> int:
        min_win = self.read_configuration(
            "anomaly_detection_https", "adwin_min_window_length", 5
        )
        try:
            min_win = int(min_win)
        except (TypeError, ValueError):
            min_win = 5
        return max(1, min_win)

    def https_anomaly_log_verbosity(self) -> int:
        verbosity = self.read_configuration(
            "anomaly_detection_https", "log_verbosity", 3
        )
        try:
            verbosity = int(verbosity)
        except (TypeError, ValueError):
            verbosity = 3
        return min(max(verbosity, 0), 3)

    def https_anomaly_log_emojis(self) -> bool:
        value = self.read_configuration(
            "anomaly_detection_https", "log_emojis", True
        )
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def https_anomaly_log_colors(self) -> bool:
        value = self.read_configuration(
            "anomaly_detection_https", "log_colors", True
        )
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

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

    def llm_enabled(self) -> bool:
        value = self.read_configuration("llm", "enabled", False)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def llm_default_backend(self) -> str:
        value = self.read_configuration("llm", "default_backend", "")
        return str(value or "").strip()

    def llm_worker_threads(self) -> int:
        value = self.read_configuration("llm", "worker_threads", 2)
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 2
        return max(1, value)

    def llm_queue_size(self) -> int:
        value = self.read_configuration("llm", "queue_size", 100)
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 100
        return max(1, value)

    def llm_backends(self) -> dict:
        backends = self.read_configuration("llm", "backends", {})
        return backends if isinstance(backends, dict) else {}

    def regex_generator_enabled(self) -> bool:
        value = self.read_configuration("regex_generator", "enabled", False)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def regex_generator_generation_interval_seconds(self) -> float:
        value = self.read_configuration(
            "regex_generator", "generation_interval_seconds", 5
        )
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 5
        return max(0.0, value)

    def regex_generator_create_log_file(self) -> bool:
        value = self.read_configuration(
            "regex_generator", "create_log_file", False
        )
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def regex_generator_allowed_backends(self) -> list:
        value = self.read_configuration(
            "regex_generator", "allowed_backends", []
        )
        if not isinstance(value, list):
            return []
        return [
            str(backend).strip()
            for backend in value
            if str(backend).strip()
        ]

    def regex_generator_llm_temperature(self) -> float:
        value = self.read_configuration(
            "regex_generator", "llm_temperature", 1.2
        )
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 1.2
        return max(0.0, value)

    def regex_generator_llm_max_tokens(self) -> int:
        value = self.read_configuration(
            "regex_generator", "llm_max_tokens", 80
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 80
        return max(1, value)

    def regex_generator_llm_response_timeout_seconds(self) -> int:
        value = self.read_configuration(
            "regex_generator", "llm_response_timeout_seconds", 90
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 90
        return max(0, value)

    def regex_generator_recent_history_size(self) -> int:
        value = self.read_configuration(
            "regex_generator", "recent_history_size", 0
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 0
        return max(0, value)

    def regex_generator_max_regex_length(self) -> int:
        value = self.read_configuration(
            "regex_generator", "max_regex_length", 180
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 180
        return max(1, value)

    def regex_generator_regex_validation_timeout_seconds(self) -> float:
        value = self.read_configuration(
            "regex_generator", "regex_validation_timeout_seconds", 2
        )
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 2.0
        return max(0.0, value)

    def regex_generator_benign_match_strength_threshold(self) -> float:
        value = self.read_configuration(
            "regex_generator", "benign_match_strength_threshold", 75
        )
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 75.0
        return max(0.0, min(100.0, value))

    def regex_generator_type_weights(self) -> dict:
        default_weights = {
            "dns_domain": 1,
            "uri": 1,
            "filename": 1,
            "tls_sni": 1,
            "certificate_cn": 1,
        }
        value = self.read_configuration(
            "regex_generator", "type_weights", default_weights
        )
        if not isinstance(value, dict):
            return default_weights

        sanitized_weights = {}
        for regex_type, default_weight in default_weights.items():
            raw_weight = value.get(regex_type, default_weight)
            try:
                raw_weight = float(raw_weight)
            except (TypeError, ValueError):
                raw_weight = default_weight
            sanitized_weights[regex_type] = max(0.0, raw_weight)

        if not any(sanitized_weights.values()):
            return default_weights
        return sanitized_weights

    def regex_generator_store_dir(self) -> str:
        value = self.read_configuration(
            "regex_generator", "store_dir", "output/regex_generator"
        )
        if not isinstance(value, str) or not value.strip():
            return "output/regex_generator"
        return value.strip()

    def regex_generator_persistent_store_dir(self) -> str:
        value = self.read_configuration(
            "regex_generator", "persistent_store_dir", ""
        )
        if not isinstance(value, str) or not value.strip():
            return ""
        return value.strip()

    def regex_generator_store_rejected_regexes(self) -> bool:
        value = self.read_configuration(
            "regex_generator", "store_rejected_regexes", False
        )
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def regex_generator_max_stored_rejected_regexes(self) -> int:
        value = self.read_configuration(
            "regex_generator", "max_stored_rejected_regexes", 10000
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            return 10000
        return max(0, value)

    def regex_generator_seed_benign_samples(self) -> bool:
        value = self.read_configuration(
            "regex_generator", "seed_benign_samples", True
        )
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def t_cell_enabled(self) -> bool:
        value = self.read_configuration("t_cell", "enabled", True)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def t_cell_create_log_file(self) -> bool:
        value = self.read_configuration("t_cell", "create_log_file", True)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def t_cell_log_colors(self) -> bool:
        value = self.read_configuration("t_cell", "log_colors", True)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def t_cell_log_verbosity(self) -> int:
        value = self.read_configuration("t_cell", "log_verbosity", 1)
        if isinstance(value, bool):
            return 1
        if isinstance(value, (int, float)):
            value = int(value)
        else:
            normalized = str(value).strip().lower()
            named_levels = {
                "summary": 1,
                "decision": 2,
                "decisions": 2,
                "debug": 3,
            }
            if normalized in named_levels:
                value = named_levels[normalized]
            else:
                try:
                    value = int(normalized)
                except (TypeError, ValueError):
                    value = 1
        return max(1, min(3, int(value)))

    def t_cell_decision_trace_mode(self) -> int:
        value = self.read_configuration("t_cell", "decision_trace_mode", "off")
        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, (int, float)):
            return max(0, min(2, int(value)))

        normalized = str(value).strip().lower()
        named_levels = {
            "off": 0,
            "disabled": 0,
            "none": 0,
            "transitions": 1,
            "transition": 1,
            "state_changes": 1,
            "changes": 1,
            "all": 2,
            "full": 2,
            "debug": 2,
        }
        if normalized in named_levels:
            return named_levels[normalized]
        try:
            return max(0, min(2, int(normalized)))
        except (TypeError, ValueError):
            return 0

    def t_cell_decision_trace_file(self) -> str:
        value = self.read_configuration(
            "t_cell", "decision_trace_file", "t_cell_trace.jsonl"
        )
        if not isinstance(value, str) or not value.strip():
            return "t_cell_trace.jsonl"
        return value.strip()

    def t_cell_decision_trace_max_evidence(self) -> int:
        value = self.read_configuration(
            "t_cell", "decision_trace_max_evidence", 10
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 10
        return max(1, value)

    def t_cell_store_dir(self) -> str:
        value = self.read_configuration("t_cell", "store_dir", "output/t_cell")
        if not isinstance(value, str) or not value.strip():
            return "output/t_cell"
        return value.strip()

    def t_cell_persistent_store_dir(self) -> str:
        value = self.read_configuration(
            "t_cell", "persistent_store_dir", ""
        )
        if not isinstance(value, str) or not value.strip():
            return ""
        return value.strip()

    def t_cell_observation_retention_seconds(self) -> int:
        value = self.read_configuration(
            "t_cell", "observation_retention_seconds", 604800
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 604800
        return max(0, value)

    def t_cell_anergy_ttl_seconds(self) -> int:
        value = self.read_configuration("t_cell", "anergy_ttl_seconds", 21600)
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 21600
        return max(0, value)

    def t_cell_related_lookback_seconds(self) -> int:
        value = self.read_configuration(
            "t_cell", "related_lookback_seconds", 3600
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 3600
        return max(1, value)

    def t_cell_related_pamps_saturation(self) -> float:
        value = self.read_configuration(
            "t_cell", "related_pamps_saturation", 5
        )
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 5.0
        return max(0.01, value)

    def t_cell_danger_saturation(self) -> float:
        value = self.read_configuration("t_cell", "danger_saturation", 2.5)
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 2.5
        return max(0.01, value)

    def t_cell_damp_danger_weight(self) -> float:
        value = self.read_configuration("t_cell", "damp_danger_weight", 1.5)
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 1.5
        return max(0.0, value)

    def t_cell_co_stimulation_threshold(self) -> float:
        value = self.read_configuration(
            "t_cell", "co_stimulation_threshold", 0.65
        )
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0.65
        return max(0.0, min(1.0, value))

    def t_cell_co_stimulation_weights(self) -> dict:
        default_weights = {
            "confidence": 0.35,
            "related_pamps": 0.25,
            "danger": 0.40,
        }
        value = self.read_configuration(
            "t_cell", "co_stimulation_weights", default_weights
        )
        if not isinstance(value, dict):
            return default_weights

        sanitized_weights = {}
        for weight_name, default_weight in default_weights.items():
            raw_weight = value.get(weight_name, default_weight)
            try:
                raw_weight = float(raw_weight)
            except (TypeError, ValueError):
                raw_weight = default_weight
            sanitized_weights[weight_name] = max(0.0, raw_weight)

        if not any(sanitized_weights.values()):
            return default_weights
        return sanitized_weights

    def t_cell_novelty_window_seconds(self) -> int:
        value = self.read_configuration(
            "t_cell", "novelty_window_seconds", 86400
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 86400
        return max(1, value)

    def t_cell_context_recent_window_seconds(self) -> int:
        value = self.read_configuration(
            "t_cell", "context_recent_window_seconds", 1800
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 1800
        return max(1, value)

    def t_cell_effector_threshold(self) -> float:
        value = self.read_configuration("t_cell", "effector_threshold", 0.70)
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0.70
        return max(0.0, min(1.0, value))

    def t_cell_effector_min_related_count(self) -> int:
        value = self.read_configuration(
            "t_cell", "effector_min_related_count", 4
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 4
        return max(1, value)

    def t_cell_effector_cooldown_seconds(self) -> int:
        value = self.read_configuration(
            "t_cell", "effector_cooldown_seconds", 1800
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 1800
        return max(0, value)

    def t_cell_memory_threshold(self) -> float:
        value = self.read_configuration("t_cell", "memory_threshold", 0.60)
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0.60
        return max(0.0, min(1.0, value))

    def t_cell_memory_trend_ratio_max(self) -> float:
        value = self.read_configuration(
            "t_cell", "memory_trend_ratio_max", 0.60
        )
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0.60
        return max(0.0, value)

    def t_cell_memory_min_related_count(self) -> int:
        value = self.read_configuration(
            "t_cell", "memory_min_related_count", 3
        )
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 3
        return max(1, value)

    def t_cell_simulate_effector_without_blocking(self) -> bool:
        value = self.read_configuration(
            "t_cell", "simulate_effector_without_blocking", True
        )
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

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
        if not (use_global_p2p and ("-i" in sys.argv)):
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
            to_ignore.append("arp_poisoner")

        # leak detector only works on pcap files
        if input_type != InputType.PCAP:
            to_ignore.append("leak_detector")

        if not self.reading_flows_from_cyst():
            to_ignore.append("cyst")

        if not self.llm_enabled():
            to_ignore.append("llm")

        if not self.regex_generator_enabled():
            to_ignore.append("regex_generator")

        if not self.t_cell_enabled():
            to_ignore.append("t_cell")

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
