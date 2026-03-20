# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.parsers.config_parser import ConfigParser


def test_evidence_signal_default_falls_back_to_pamp():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {"EvidenceSignals": {"default_signal": "invalid"}}

    assert parser.evidence_signal_default() == "PAMP"


def test_evidence_signal_overrides_sanitizes_values():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {
        "EvidenceSignals": {
            "overrides": {
                "malicious_flow": "damp",
                "ssh_successful": "PAMP",
                "bad_type": "invalid",
                123: "DAMP",
            }
        }
    }

    assert parser.evidence_signal_overrides() == {
        "MALICIOUS_FLOW": "DAMP",
        "SSH_SUCCESSFUL": "PAMP",
    }
