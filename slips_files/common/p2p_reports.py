"""Read reported detection details while preserving their peer origin."""

from typing import Any

from slips_files.core.structures.evidence import (
    EvidenceType,
    normalize_icmp_evidence,
)

MAX_DETECTIONS_PER_PEER_REPORT = 16

# evidence types that only describe "a peer told us something", not a real
# finding, so they are never shown as the peer's reported detection
PEER_WRAPPER_EVIDENCE_TYPES = frozenset(
    {"P2P_REPORT", "MALICIOUS_IP_FROM_P2P_NETWORK"}
)


def is_known_evidence_type(evidence_type_name: Any) -> bool:
    """Tell whether a reported type name is a real evidence type.

    Parameters:
        evidence_type_name: Value read from a peer's reported item.

    Returns:
        True only for strings naming a member of `EvidenceType`.
    """
    return (
        isinstance(evidence_type_name, str)
        and evidence_type_name in EvidenceType.__members__
    )


def extract_reported_detections(peer_report: Any) -> list[dict[str, Any]]:
    """Extract bounded detection details from a saved peer report.

    Parameters:
        peer_report: Saved peer metadata, possibly absent in older records.

    Returns:
        Known detection types and their supplied details, in reported order.
    """
    if not isinstance(peer_report, dict):
        return []

    reported_items = peer_report.get("provenance")
    if not isinstance(reported_items, list):
        return []

    detections = []
    for reported_item in reported_items[:MAX_DETECTIONS_PER_PEER_REPORT]:
        if not isinstance(reported_item, dict):
            continue

        evidence_type: EvidenceType = reported_item.get("evidence_type")

        is_known_type = (
            isinstance(evidence_type, str)
            and evidence_type in EvidenceType.__members__
        )
        if not is_known_type:
            continue

        if evidence_type in PEER_WRAPPER_EVIDENCE_TYPES:
            continue

        detection = {**reported_item, "evidence_type": evidence_type}
        normalize_icmp_evidence(detection)
        detections.append(detection)
    return detections


def resolve_evidence_display_type(
    original_evidence_type: str, peer_report: Any
) -> str:
    """Classify a peer report by its finding without changing its raw record.

    Parameters:
        original_evidence_type: Canonical type of the original evidence record.
        peer_report: Optional peer metadata containing reported detections.

    Returns:
        First reported detection type, or the original type when unavailable.
    """
    if original_evidence_type != "P2P_REPORT":
        return original_evidence_type

    reported_detections = extract_reported_detections(peer_report)
    if reported_detections:
        return reported_detections[0]["evidence_type"]
    return original_evidence_type
