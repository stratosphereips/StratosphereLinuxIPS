"""Read reported detection details while preserving their peer origin."""

from typing import Any

from slips_files.core.structures.evidence import (
    EvidenceType,
    normalize_icmp_evidence,
)


def reported_detections(peer_report: Any) -> list[dict[str, Any]]:
    """Extract bounded detection details from a saved peer report.

    Parameters:
        peer_report: Saved peer metadata, possibly absent in older records.

    Returns:
        Known detection types and their supplied details, in reported order.
    """
    if not isinstance(peer_report, dict):
        return []
    provenance = peer_report.get("provenance")
    if not isinstance(provenance, list):
        return []
    result = []
    for item in provenance[:16]:
        if not isinstance(item, dict):
            continue
        kind = item.get("evidence_type")
        if not isinstance(kind, str) or kind not in EvidenceType.__members__:
            continue
        if kind in {"P2P_REPORT", "MALICIOUS_IP_FROM_P2P_NETWORK"}:
            continue
        detection = {**item, "evidence_type": kind}
        normalize_icmp_evidence(detection)
        result.append(detection)
    return result


def evidence_display_type(evidence_type: str, peer_report: Any) -> str:
    """Classify a peer report by its finding without changing its raw record.

    Parameters:
        evidence_type: Canonical type of the original evidence record.
        peer_report: Optional peer metadata containing reported detections.

    Returns:
        First reported detection type, or the original type when unavailable.
    """
    if evidence_type == "P2P_REPORT":
        detections = reported_detections(peer_report)
        if detections:
            return detections[0]["evidence_type"]
    return evidence_type
