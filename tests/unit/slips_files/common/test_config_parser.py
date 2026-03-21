# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.input_type import InputType


def test_evidence_signal_default_falls_back_to_pamp():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {"EvidenceSignals": {"default_signal": "invalid"}}

    assert parser.evidence_signal_default() == "PAMP"


def test_evidence_signal_overrides_sanitizes_values():
    parser = ConfigParser.__new__(ConfigParser)
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
        "llm": {"enabled": True},
        "regex_generator": {"enabled": True},
        "t_cell": {"enabled": False},
    }

    disabled = parser.get_disabled_modules(InputType.PCAP)
    assert "t_cell" in disabled

    parser.config["t_cell"]["enabled"] = True
    disabled = parser.get_disabled_modules(InputType.PCAP)
    assert "t_cell" not in disabled
