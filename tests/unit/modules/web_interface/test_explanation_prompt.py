"""Behavior explanations from bounded evidence samples."""

from typing import Any

import pytest

from modules.web_interface.explanation_prompt import (
    build_explanation_prompt,
    explain_localnet_group,
)
from tests.module_factory import ModuleFactory


def test_repeated_localnet_group_explains_behavior_and_detection_reason() -> None:
    """Describe the dominant service sweep without listing destination IPs."""
    _factory = ModuleFactory()
    records: list[dict[str, Any]] = []
    for index in range(40):
        port = 23 if index < 31 else 20000 + index
        protocol = "tcp" if index < 31 else "udp"
        records.append({
            "evidence_type": "DIFFERENT_LOCALNET",
            "description": (
                "192.168.1.247 initiated a connection to 172.20.1.1 "
                "using TCP: the private destination address is outside "
                "the local network 192.168.1.0/24."
            ),
            "victim": {"value": f"172.20.1.{index + 1}"},
            "proto": protocol,
            "dst_port": port,
        })

    explanation = explain_localnet_group(22537, records)

    assert explanation is not None
    assert "40 sampled records" in explanation
    assert "22,537" in explanation
    assert "TCP/23 (telnet) on 31 distinct hosts" in explanation
    assert "outside the observed 192.168.1.0/24 subnet" in explanation
    assert "172.20.1.1" not in explanation
    assert "successful connection or login" in explanation


@pytest.mark.parametrize("evidence_type,ports", [
    ("UNKNOWN_PORT", [23, 23, 23]),
    ("DIFFERENT_LOCALNET", [23, 24, 25]),
])
def test_direct_explanation_requires_repeated_localnet_behavior(
    evidence_type: str, ports: list[int]
) -> None:
    """Keep other groups on the LLM explanation path.

    Parameters:
        evidence_type: Selected detector type.
        ports: Ports seen in the sample.
    """
    _factory = ModuleFactory()
    records = [
        {
            "evidence_type": evidence_type,
            "victim": {"value": f"172.20.1.{index + 1}"},
            "proto": "tcp", "dst_port": port,
        }
        for index, port in enumerate(ports)
    ]

    assert explain_localnet_group(100, records) is None


def test_group_prompt_summarizes_patterns_instead_of_event_lines() -> None:
    """Bound the prompt and keep the dominant service visible."""
    _factory = ModuleFactory()
    records = [
        {
            "evidence_type": "DIFFERENT_LOCALNET",
            "threat_level": "high", "profile_ip": "192.168.1.247",
            "victim": {"value": f"172.20.1.{index + 1}"},
            "proto": "tcp", "dst_port": 23,
            "timestamp": 1795624257 + index,
            "description": (
                f"192.168.1.247 connected to 172.20.1.{index + 1}: "
                "private destination outside local network 192.168.1.0/24"
            ),
        }
        for index in range(40)
    ]

    prompt = build_explanation_prompt("group", 22537, records)

    assert "40 contacts to 40 distinct hosts on TCP/23 (telnet)" in prompt
    assert "40 sampled from the newest and oldest records" in prompt
    assert "172.20.1.40" not in prompt
    assert prompt.count("private destination outside") == 1
    assert len(prompt) < 2500
