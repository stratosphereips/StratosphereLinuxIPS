# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Hardcoded runtime module names shared across Slips."""

from enum import Enum
from typing import Dict


class Modules(str, Enum):
    """Supported Slips runtime module names."""

    ALERT_SUMMARY = "alert_summary"
    ANOMALY_DETECTION_HTTPS = "anomaly_detection_https"
    ARP = "arp"
    ARP_POISONER = "arp_poisoner"
    BLOCKING = "blocking"
    BRUTE_FORCE_DETECTOR = "brute_force_detector"
    CESNET = "cesnet"
    CONN_ANALYZER = "conn_analyzer"
    CYST = "cyst"
    EVIDENCE_HANDLER = "evidence_handler"
    EXPORTING_ALERTS = "exporting_alerts"
    FEEDS_UPDATE_MANAGER = "feeds_update_manager"
    FIDES = "fides"
    FLOW_ALERTS = "flow_alerts"
    HTTP_ANALYZER = "http_analyzer"
    INPUT = "input"
    IP_INFO = "ip_info"
    IRIS = "iris"
    LEAK_DETECTOR = "leak_detector"
    LLM_PROXY = "llm_proxy"
    ML_LINEAR_MODEL = "ml_linear_model"
    ML_ONLINE_MODEL = "ml_online_model"
    MAIN = "main"
    NETWORK_DISCOVERY = "network_discovery"
    P2P_TRUST = "p2p_trust"
    REGEX_GENERATOR = "regex_generator"
    RISK_IQ = "risk_iq"
    RNN_CC_DETECTION = "rnn_cc_detection"
    PROFILER = "profiler"
    T_CELL = "t_cell"
    TEMPLATE = "template"
    THREAT_INTELLIGENCE = "threat_intelligence"
    TIMELINE = "timeline"
    VIRUSTOTAL = "virustotal"
    EVIDENCE_HANDLER_WORKER = "evidence_handler_worker"
    PROFILER_WORKER = "profiler_worker"


SUPPORTED_MODULE_NAME_BY_FILE: Dict[str, str] = {
    module: module for module in Modules
}

__all__ = ["Modules", "SUPPORTED_MODULE_NAME_BY_FILE"]
