# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch

import pytest

from modules.supported_module_names import Modules
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.input_type import InputType
from tests.module_factory import ModuleFactory


def test_evidence_signal_default_falls_back_to_pamp():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {"EvidenceSignals": {"default_signal": "invalid"}}

    assert parser.evidence_signal_default() == "PAMP"


def test_evidence_signal_overrides_sanitizes_values():
    parser = object.__new__(ConfigParser)
    parser.config = {
        "EvidenceSignals": {
            "overrides": {
                "anomalous_flow": "DAMP",
                "malicious_flow": "damp",
                "ssh_successful": "PAMP",
                "bad_type": "invalid",
                123: "DAMP",
            }
        }
    }

    assert parser.evidence_signal_overrides() == {
        "ANOMALOUS_FLOW": "DAMP",
        "MALICIOUS_FLOW": "DAMP",
        "SSH_SUCCESSFUL": "PAMP",
    }


def test_t_cell_config_defaults():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {}

    assert parser.t_cell_enabled() is True
    assert parser.t_cell_create_log_file() is True
    assert parser.t_cell_log_colors() is True
    assert parser.t_cell_log_verbosity() == 1
    assert parser.t_cell_decision_trace_mode() == 0
    assert parser.t_cell_decision_trace_file() == "t_cell_trace.jsonl"
    assert parser.t_cell_decision_trace_max_evidence() == 10
    assert parser.t_cell_store_dir() == "output/t_cell"
    assert parser.t_cell_persistent_store_dir() == ""
    assert parser.t_cell_observation_retention_seconds() == 604800
    assert parser.t_cell_anergy_ttl_seconds() == 21600
    assert parser.t_cell_related_lookback_seconds() == 3600
    assert parser.t_cell_related_pamps_saturation() == 5
    assert parser.t_cell_danger_saturation() == 2.5
    assert parser.t_cell_damp_danger_weight() == 1.5
    assert parser.t_cell_co_stimulation_threshold() == 0.65
    assert parser.t_cell_co_stimulation_weights() == {
        "confidence": 0.35,
        "related_pamps": 0.25,
        "danger": 0.40,
    }
    assert parser.t_cell_novelty_window_seconds() == 86400
    assert parser.t_cell_context_recent_window_seconds() == 1800
    assert parser.t_cell_effector_threshold() == 0.70
    assert parser.t_cell_effector_min_related_count() == 4
    assert parser.t_cell_effector_cooldown_seconds() == 1800
    assert parser.t_cell_memory_threshold() == 0.60
    assert parser.t_cell_memory_trend_ratio_max() == 0.60
    assert parser.t_cell_memory_min_related_count() == 3
    assert parser.t_cell_simulate_effector_without_blocking() is True


def test_t_cell_config_sanitization():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {
        "t_cell": {
            "enabled": "true",
            "create_log_file": "false",
            "log_colors": "false",
            "log_verbosity": "debug",
            "decision_trace_mode": "all",
            "decision_trace_file": " ",
            "decision_trace_max_evidence": "bad",
            "store_dir": "",
            "persistent_store_dir": " /tmp/tcell ",
            "observation_retention_seconds": "bad",
            "anergy_ttl_seconds": -2,
            "related_lookback_seconds": "bad",
            "related_pamps_saturation": "bad",
            "danger_saturation": 0,
            "damp_danger_weight": -5,
            "co_stimulation_threshold": "bad",
            "co_stimulation_weights": {
                "confidence": 0,
                "related_pamps": 0,
                "danger": 0,
            },
            "novelty_window_seconds": "bad",
            "context_recent_window_seconds": 0,
            "effector_threshold": 2,
            "effector_min_related_count": "bad",
            "effector_cooldown_seconds": "bad",
            "memory_threshold": "bad",
            "memory_trend_ratio_max": "bad",
            "memory_min_related_count": "bad",
            "simulate_effector_without_blocking": "false",
        }
    }

    assert parser.t_cell_enabled() is True
    assert parser.t_cell_create_log_file() is False
    assert parser.t_cell_log_colors() is False
    assert parser.t_cell_log_verbosity() == 3
    assert parser.t_cell_decision_trace_mode() == 2
    assert parser.t_cell_decision_trace_file() == "t_cell_trace.jsonl"
    assert parser.t_cell_decision_trace_max_evidence() == 10
    assert parser.t_cell_store_dir() == "output/t_cell"
    assert parser.t_cell_persistent_store_dir() == "/tmp/tcell"
    assert parser.t_cell_observation_retention_seconds() == 604800
    assert parser.t_cell_anergy_ttl_seconds() == 0
    assert parser.t_cell_related_lookback_seconds() == 3600
    assert parser.t_cell_related_pamps_saturation() == 5
    assert parser.t_cell_danger_saturation() == 0.01
    assert parser.t_cell_damp_danger_weight() == 0.0
    assert parser.t_cell_co_stimulation_threshold() == 0.65
    assert parser.t_cell_co_stimulation_weights() == {
        "confidence": 0.35,
        "related_pamps": 0.25,
        "danger": 0.40,
    }
    assert parser.t_cell_novelty_window_seconds() == 86400
    assert parser.t_cell_context_recent_window_seconds() == 1
    assert parser.t_cell_effector_threshold() == 1.0
    assert parser.t_cell_effector_min_related_count() == 4
    assert parser.t_cell_effector_cooldown_seconds() == 1800
    assert parser.t_cell_memory_threshold() == 0.60
    assert parser.t_cell_memory_trend_ratio_max() == 0.60
    assert parser.t_cell_memory_min_related_count() == 3
    assert parser.t_cell_simulate_effector_without_blocking() is False


def test_get_disabled_modules_tracks_t_cell_enablement():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {
        "modules": {"disable": ["template"]},
        "llm_proxy": {"enabled": True},
        "regex_generator": {"enabled": True},
        "t_cell": {"enabled": False},
    }

    disabled = parser.get_disabled_modules(InputType.PCAP)
    assert Modules.T_CELL in disabled

    parser.config["t_cell"]["enabled"] = True
    disabled = parser.get_disabled_modules(InputType.PCAP)
    assert Modules.T_CELL not in disabled


@patch(
    "slips_files.common.parsers.config_parser.sys.argv",
    ["slips.py", "-im", "cyst"],
)
def test_reading_flows_from_cyst_matches_supported_module_name() -> None:
    """Test CYST input detection uses the shared supported module name."""
    parser = ConfigParser.__new__(ConfigParser)

    assert parser.reading_flows_from_cyst() is True


@pytest.mark.parametrize("section", ["ml_linear_model", "ml_online_model"])
def test_ml_module_enable_logs_uses_configured_or_default_value(
    section: str,
) -> None:
    """Test ML log configuration accepts both explicit and default values."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {section: {"create_performance_metrics_log_files": "true"}}
    assert parser.ml_module_enable_logs(section) is True

    parser.config = {}
    assert parser.ml_module_enable_logs(section) is False


@pytest.mark.parametrize(
    "configured, expected",
    [
        (True, True),
        (False, False),
        ("yes", True),
        ("off", False),
    ],
)
def test_web_interface_enabled(configured: object, expected: bool) -> None:
    parser = object.__new__(ConfigParser)
    parser.read_configuration = Mock(return_value=configured)

    assert parser.web_interface_enabled() is expected
    parser.read_configuration.assert_called_once_with(
        "web_interface", "enabled", False
    )


@pytest.mark.parametrize(
    "configured, expected",
    [
        ("localhost", "localhost"),
        ("interface", "interface"),
        ("INTERFACE", "interface"),
        ("all", "localhost"),
        (None, "localhost"),
    ],
)
def test_web_interface_bind(configured: object, expected: str) -> None:
    """Accept only the two bounded web listen modes.

    Parameters:
        configured: Value read from the YAML file.
        expected: Normalized safe mode.
    """
    _module_factory = ModuleFactory()
    parser = object.__new__(ConfigParser)
    parser.read_configuration = Mock(return_value=configured)

    assert parser.web_interface_bind == expected
    parser.read_configuration.assert_called_once_with(
        "web_interface", "bind", "localhost"
    )


@pytest.mark.parametrize(
    "setting, value, expected",
    [
        ("listen_port", "7777", 7777),
        ("listen_port", "invalid", 6668),
        ("connection_ttl", "45", 45),
        ("connection_ttl", None, 30),
        ("handshake_pending_seconds", "1.5", 1.5),
        ("handshake_pending_seconds", "invalid", 2.0),
    ],
)
def test_local_p2p_connection_settings(setting: str, value, expected) -> None:
    """Parse dedicated P2P listener and bounded connection-state settings."""
    _module_factory = ModuleFactory()
    parser = object.__new__(ConfigParser)
    parser.config = {"local_p2p": {setting: value}}
    readers = {
        "listen_port": parser.p2p_listen_port,
        "connection_ttl": parser.p2p_connection_ttl,
        "handshake_pending_seconds": parser.p2p_handshake_pending_seconds,
    }

    assert readers[setting]() == expected
