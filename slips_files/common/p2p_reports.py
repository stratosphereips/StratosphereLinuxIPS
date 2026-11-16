"""Read reported detection details while preserving their peer origin."""

from typing import Any

from slips_files.core.structures.evidence import (
    EvidenceType,
    normalize_icmp_evidence,
)

MAX_EVIDENCE_PER_PEER_REPORT = 16

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


def extract_all_evidence_from_peer_report(
    peer_report: Any,
) -> list[dict[str, Any]]:
    """Extract evidence from the given peer report.

    Parameters:
        peer_report: Saved peer metadata, possibly absent in older records.

    Returns:
        Known detection types and their supplied details, in reported order.
    """
    if not isinstance(peer_report, dict):
        return []

    reported_evidence = peer_report.get("provenance")
    if not isinstance(reported_evidence, list):
        return []

    extracted_evidence = []
    for evidence in reported_evidence[:MAX_EVIDENCE_PER_PEER_REPORT]:
        if not isinstance(evidence, dict):
            continue

        evidence_type: EvidenceType = evidence.get("evidence_type")

        if not is_known_evidence_type(evidence_type):
            continue

        if evidence_type in PEER_WRAPPER_EVIDENCE_TYPES:
            continue

        detection = evidence.copy()
        normalize_icmp_evidence(detection)
        extracted_evidence.append(detection)
    return extracted_evidence


def get_first_evidence_in_peer_report(
    original_evidence_type: str, peer_report: Any
) -> str:
    """returns the first evidence from the provenvance of the given
    peer_report

    Parameters:
        original_evidence_type: Canonical type of the original evidence record.
        peer_report: Optional peer metadata containing reported detections.

    Returns:
        First reported detection type, or the original type when unavailable.
    """
    if original_evidence_type != "P2P_REPORT":
        return original_evidence_type

    evidence = extract_all_evidence_from_peer_report(peer_report)
    if evidence:
        # return the first one only, why? because the db and the web
        # interface are expecting 1 type per evidence.
        # so instead of putting "P2P_REPORT" as the type we choose the
        # first one because its more meaning
        return evidence[0]["evidence_type"]
    return original_evidence_type
