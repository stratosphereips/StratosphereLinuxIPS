"""Check TCP initiator evidence against Zeek's final logged endpoints."""

import pytest

from slips_files.common.flow_direction import (
    tcp_initiator_is_known,
    zeek_history_in_final_direction,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("history,normalized", [
    ("ShADadFf", "ShADadFf"),
    ("^ShADadFf", "^ShADadFf"),
    ("H^SADadFf", "h^SADadFf"),
    ("Hs^ADdFf", "hS^ADdFf"),
    ("ShA^Dd", "sHa^Dd"),
    ("S^A^h", "S^a^h"),
    ("AdDTafF", "AdDTafF"),
])
def test_history_uses_final_roles(history: str, normalized: str) -> None:
    """Interpret flags across flips without modifying the raw record.

    Parameters:
        history: Original Zeek history.
        normalized: Flags expressed relative to the final endpoints.
    """
    _factory = ModuleFactory()
    assert zeek_history_in_final_direction(history) == normalized


@pytest.mark.parametrize("proto,history,known", [
    ("tcp", "ShADadFf", True),
    ("TCP", "Sr", True),
    ("tcp", "^ShA", True),
    ("tcp", "H^ADadFf", True),
    ("tcp", "Hs^ADdFf", True),
    ("tcp", "hADadFf", True),
    ("tcp", "ShA^Dd", False),
    ("tcp", "AdDTafF", False),
    ("tcp", "^AdDTafF", False),
    ("tcp", "S^", False),
    ("tcp", "", False),
    ("tcp", "-", False),
    ("tcp", 123, False),
    ("tcp", None, True),
    ("udp", "Dd", True),
    ("icmp", "", True),
])
def test_tcp_initiator_evidence(proto: str, history: str | None, known: bool) -> None:
    """Distinguish a recorded handshake from ongoing traffic and guesses.

    Parameters:
        proto: Transport protocol.
        history: Zeek history, absent for other flow sources.
        known: Whether the final originator has supported client direction.
    """
    _factory = ModuleFactory()
    assert tcp_initiator_is_known(proto, history) is known
