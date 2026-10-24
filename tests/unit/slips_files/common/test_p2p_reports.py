"""Check peer finding labels without relabeling canonical report objects."""

import pytest

from slips_files.common.p2p_reports import (
    evidence_display_type,
    reported_detections,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "metadata", [None, {}, {"provenance": None}, {"provenance": "bad"}]
)
def test_legacy_reports_keep_their_transport_type(metadata: object) -> None:
    """Do not invent a detection type absent from a peer packet.

    Parameters:
        metadata: Missing or malformed historical peer metadata.
    """
    _factory = ModuleFactory()
    assert reported_detections(metadata) == []
    assert evidence_display_type("P2P_REPORT", metadata) == "P2P_REPORT"


def test_report_types_are_known_bounded_and_leave_local_evidence_unchanged() -> (
    None
):
    """Expose original types while preserving local and transport semantics."""
    _factory = ModuleFactory()
    metadata = {
        "provenance": [
            None,
            {"evidence_type": "invented"},
            {"evidence_type": "P2P_REPORT"},
            {
                "evidence_type": "UNKNOWN_PORT",
                "description": "Connection to TCP port 8123",
            },
            *[{"evidence_type": "ARP_SCAN"}] * 20,
        ]
    }
    detections = reported_detections(metadata)
    assert len(detections) == 13
    assert detections[0]["evidence_type"] == "UNKNOWN_PORT"
    assert evidence_display_type("P2P_REPORT", metadata) == "UNKNOWN_PORT"
    assert (
        evidence_display_type("DNS_WITHOUT_CONNECTION", metadata)
        == "DNS_WITHOUT_CONNECTION"
    )
