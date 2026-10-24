# SPDX-License-Identifier: GPL-2.0-only
"""Validate report accuracy without treating detector agreement as ground truth."""

import hashlib
import ipaddress
import json
import math
import sqlite3
import time
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterator

from modules.supported_module_names import Modules
from slips_files.core.structures.evidence import (
    EvidenceType,
    is_icmp_protocol,
    normalize_icmp_evidence,
)
from slips_files.common.slips_utils import utils

DEFINITIVE = {"true_positive", "false_positive", "expected_behavior"}
NEGATIVE = {"false_positive", "expected_behavior"}
PEER_FINDINGS = {"P2P_REPORT", "MALICIOUS_IP_FROM_P2P_NETWORK"}
MAX_CREDIT = 0.20
HALF_LIFE = 30 * 86400
MATCH_WINDOW = 3600


def observation_record(
    record: dict[str, Any], network_id: str
) -> dict[str, Any]:
    """Build a local validation snapshot using the evidence's saved origin.

    Parameters:
        record: Durable evidence object as JSON-compatible data.
        network_id: Network at the time of observation, supplied by the receiver.

    Returns:
        Validation record, or {} for informational or malformed evidence.
    """
    kind = str(record.get("evidence_type", ""))
    peer = record.get("peer_report") or {}
    provenance = record.get("detection_provenance") or {}
    if not isinstance(peer, dict) or not isinstance(provenance, dict):
        return {}
    try:
        observed = float(
            record.get("observed_at")
            or utils.convert_ts_format(record["timestamp"], "unixtimestamp")
        )
        target = str(ipaddress.ip_address(record["attacker"]["value"]))
        identifier = str(record["id"])
        score = float(
            peer.get(
                "score",
                utils.threat_levels.get(
                    str(record.get("threat_level")).lower(), 0
                ),
            )
        )
        confidence = float(peer.get("confidence", record.get("confidence", 0)))
        if (
            not identifier
            or not math.isfinite(observed)
            or not math.isfinite(score)
            or not math.isfinite(confidence)
            or not 0 <= score <= 1
            or not 0 <= confidence <= 1
        ):
            return {}
    except (KeyError, TypeError, ValueError, OverflowError):
        return {}
    if not peer and (
        kind in PEER_FINDINGS
        or str(record.get("threat_level", "info")).lower() == "info"
    ):
        return {}
    if not provenance and not peer:
        provenance = {
            "evidence_type": kind,
            "module": str(record.get("source_module", "")),
            "rule_version": "legacy",
            "method": str(record.get("method", "HEURISTIC")).upper(),
        }
        provenance["family"] = dependency_family(kind, provenance["module"])
    network_id = str(
        peer.get("network_id") or provenance.get("network_id") or network_id
    )
    return {
        "id": identifier,
        "target": target,
        "target_key": f"{network_id}|{target}",
        "network_id": network_id,
        "evidence_type": kind,
        "observed_at": observed,
        "score": score,
        "confidence": confidence,
        "provenance": peer.get("provenance", []) if peer else provenance,
        "peer_id": str(peer.get("peer_id", "")),
        "message_type": str(peer.get("message_type", "")),
    }


def queue_review_event(
    connection: sqlite3.Connection,
    source: str,
    verdict: str,
    records: list[dict[str, Any]],
    withdrawn: list[str] | None = None,
) -> None:
    """Commit feedback to an outbox in the same transaction as the web review.

    Parameters:
        connection: Review database transaction.
        source: Stable alert/evidence review identity.
        verdict: Analyst verdict, or empty to withdraw an earlier decision.
        records: Durable detection snapshots used after data deletion.
        withdrawn: Deleted evidence IDs whose other feedback must be withdrawn.
    """
    connection.execute(
        "CREATE TABLE IF NOT EXISTS p2p_review_outbox (source TEXT PRIMARY KEY, revision INTEGER NOT NULL, payload TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS p2p_review_clock (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL)"
    )
    previous = connection.execute(
        "SELECT revision FROM p2p_review_clock WHERE id=1"
    ).fetchone()
    revision = max(time.time_ns(), previous[0] + 1 if previous else 0)
    connection.execute(
        "INSERT INTO p2p_review_clock VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision",
        (revision,),
    )
    event = {
        "source": source,
        "revision": revision,
        "verdict": verdict,
        "records": records,
        "withdrawn": withdrawn or [],
    }
    connection.execute(
        "INSERT INTO p2p_review_outbox VALUES (?, ?, ?) ON CONFLICT(source) DO UPDATE SET revision=excluded.revision, payload=excluded.payload",
        (source, revision, json.dumps(event)),
    )


@lru_cache(maxsize=128)
def detector_version(module: str, version: str) -> str:
    """Fingerprint detector code and release without transmitting source.

    Parameters:
        module: Canonical supported module name.
        version: Slips release.

    Returns:
        Stable digest identifying the detector implementation.
    """
    digest = hashlib.sha256(version.encode())
    if module in {item.value for item in Modules}:
        directory = Path("modules") / module
        for path in sorted(directory.glob("*.py")):
            digest.update(path.name.encode())
            try:
                digest.update(path.read_bytes())
            except OSError:
                return "legacy"
    return digest.hexdigest()[:24]


def dependency_family(evidence_type: str, module: str) -> str:
    """Conservatively identify detectors likely to share an error source.

    Parameters:
        evidence_type: Canonical evidence name.
        module: Canonical detector module.

    Returns:
        Dependency group; different versions do not establish independence.
    """
    if module in {
        Modules.THREAT_INTELLIGENCE,
        Modules.IP_INFO,
        Modules.VIRUSTOTAL,
    }:
        return "threat_intelligence"
    if any(token in evidence_type for token in ("DNS", "DGA", "NXDOMAIN")):
        return "dns_analysis"
    if any(token in evidence_type for token in ("SCAN", "ARP", "DHCP")):
        return "network_discovery"
    if module == Modules.CONN_ANALYZER:
        return "connection_policy"
    if "PASSWORD" in evidence_type or "SSH" in evidence_type:
        return "ssh_analysis"
    return module or "unknown"


def provenance_for_evidence(
    record: dict[str, Any], version: str
) -> dict[str, Any]:
    """Describe one local detection using bounded, non-secret metadata.

    Parameters:
        record: Serialized local evidence.
        version: Slips release identifier.

    Returns:
        Report provenance; informational and peer-derived findings return {}.
    """
    kind = str(record.get("evidence_type", ""))
    if (
        kind in PEER_FINDINGS
        or str(record.get("threat_level", "info")).lower() == "info"
    ):
        return {}
    module = str(record.get("source_module", ""))
    if module not in {item.value for item in Modules}:
        return {}
    provenance = {
        "evidence_type": kind,
        "module": module,
        "rule_version": detector_version(module, version),
        "family": dependency_family(kind, module),
        "method": str(record.get("method", "HEURISTIC")).upper(),
        "observed_at": record.get("observed_at", 0),
        "evidence_id": str(record.get("id", "")),
    }
    record = dict(record)
    normalize_icmp_evidence(record)
    description = record.get("description")
    if isinstance(description, str) and description:
        provenance["description"] = " ".join(description.split())[:1024]
    proto = str(record.get("proto") or "").lower()
    if proto == "icmpv6":
        proto = "icmp6"
    if proto in {"tcp", "udp", "icmp", "icmp6", "arp"}:
        provenance["proto"] = proto
    for key in ("src_port", "dst_port"):
        value = record.get(key)
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 < value <= 65535
        ):
            provenance[key] = value
    if is_icmp_protocol(proto):
        for key in ("icmp_type", "icmp_code"):
            value = record.get(key)
            if (
                isinstance(value, int)
                and not isinstance(value, bool)
                and 0 <= value <= 255
            ):
                provenance[key] = value
    return provenance


def validate_provenance(value: Any) -> list[dict[str, Any]]:
    """Validate optional peer metadata while deriving dependency groups locally.

    Parameters:
        value: Untrusted provenance list from an authenticated peer.

    Returns:
        Sanitized records. Legacy messages return an empty list.

    Raises:
        ValueError: Metadata is malformed or exceeds its bounds.
    """
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 16:
        raise ValueError(
            "Report provenance must contain at most 16 detections"
        )
    result = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("Invalid report provenance")
        fields = {}
        for key in (
            "evidence_type",
            "module",
            "rule_version",
            "method",
            "evidence_id",
        ):
            text = item.get(key, "")
            if (
                not isinstance(text, str)
                or len(text) > 160
                or any(ord(c) < 32 for c in text)
            ):
                raise ValueError("Invalid report provenance field")
            fields[key] = text
        if (
            fields["evidence_type"] not in EvidenceType.__members__
            or fields["evidence_type"] in PEER_FINDINGS
        ):
            raise ValueError("Invalid reported evidence type")
        if fields["module"] not in {module.value for module in Modules}:
            raise ValueError("Unknown reported detector module")
        observed = float(item.get("observed_at", 0))
        if (
            not math.isfinite(observed)
            or observed <= 0
            or observed > time.time() + 300
        ):
            raise ValueError("Invalid observation time")
        fields["observed_at"] = observed
        description = item.get("description", "")
        if (
            not isinstance(description, str)
            or len(description) > 1024
            or any(ord(char) < 32 for char in description)
        ):
            raise ValueError("Invalid reported detection description")
        if description:
            fields["description"] = description
        proto = item.get("proto", "")
        if not isinstance(proto, str) or proto not in {
            "",
            "tcp",
            "udp",
            "icmp",
            "icmp6",
            "arp",
        }:
            raise ValueError("Invalid reported detection protocol")
        if proto:
            fields["proto"] = proto
        for key in ("src_port", "dst_port"):
            if key not in item:
                continue
            port = item[key]
            if (
                not isinstance(port, int)
                or isinstance(port, bool)
                or not 0 < port <= 65535
            ):
                raise ValueError("Invalid reported detection port")
            fields[key] = port
        for key in ("icmp_type", "icmp_code"):
            if key not in item:
                continue
            value = item[key]
            if (
                not is_icmp_protocol(proto)
                or not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 255
            ):
                raise ValueError("Invalid reported ICMP type/code")
            fields[key] = value
        normalize_icmp_evidence(fields)
        fields["family"] = dependency_family(
            fields["evidence_type"], fields["module"]
        )
        result.append(fields)
    return result


def review_verdict(verdicts: list[str]) -> str:
    """Combine analyst decisions without allowing conflicting labels to train.

    Parameters:
        verdicts: Decisions about one evidence record.

    Returns:
        A definitive verdict, conflict, or an empty assessment.
    """
    if "conflict" in verdicts:
        return "conflict"
    positive = "true_positive" in verdicts
    negative = bool(NEGATIVE.intersection(verdicts))
    if positive and negative:
        return "conflict"
    return (
        "true_positive" if positive else "false_positive" if negative else ""
    )


class ReportValidator:
    """Store local report validation and reversible analyst feedback in SQLite."""

    def __init__(self, path: str | Path) -> None:
        """Initialize durable validation storage.

        Parameters:
            path: Database inside the configured permanent P2P directory.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            schemas = {
                "observations": "record_id TEXT PRIMARY KEY, target_key TEXT NOT NULL, data TEXT NOT NULL, observed_at REAL NOT NULL",
                "reviews": "source TEXT NOT NULL, record_id TEXT NOT NULL, verdict TEXT NOT NULL, PRIMARY KEY(source, record_id)",
                "review_events": "source TEXT PRIMARY KEY, revision INTEGER NOT NULL",
                "reports": "peer_id TEXT NOT NULL, target_key TEXT NOT NULL, evidence_type TEXT NOT NULL, rule_version TEXT NOT NULL, record_id TEXT NOT NULL, data TEXT NOT NULL, observed_at REAL NOT NULL, PRIMARY KEY(peer_id, target_key, evidence_type, rule_version)",
                "credits": "peer_id TEXT NOT NULL, target_key TEXT NOT NULL, evidence_type TEXT NOT NULL, rule_version TEXT NOT NULL, verdict TEXT NOT NULL, reason TEXT NOT NULL, report_data TEXT NOT NULL, earned_at REAL NOT NULL, changed_at REAL NOT NULL, PRIMARY KEY(peer_id, target_key)",
                "credit_sources": "peer_id TEXT NOT NULL, target_key TEXT NOT NULL, record_id TEXT NOT NULL, PRIMARY KEY(peer_id, target_key, record_id)",
                "rejections": "peer_id TEXT NOT NULL, target_key TEXT NOT NULL, evidence_type TEXT NOT NULL, rule_version TEXT NOT NULL, verdict TEXT NOT NULL, reason TEXT NOT NULL, report_data TEXT NOT NULL, earned_at REAL NOT NULL, changed_at REAL NOT NULL, PRIMARY KEY(peer_id, target_key, evidence_type, rule_version)",
                "review_imports": "run_path TEXT PRIMARY KEY, updated_at REAL NOT NULL, source TEXT NOT NULL",
                "feedback_state": "id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL",
            }
            for table, schema in schemas.items():
                connection.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} ({schema})"
                )
            connection.execute(
                "INSERT OR IGNORE INTO feedback_state VALUES (1, 0)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS observation_target ON observations(target_key)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS reviews_record ON reviews(record_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS reports_target ON reports(target_key)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS observation_time ON observations(observed_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS credit_detector ON credits(peer_id, evidence_type, rule_version)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS credit_target ON credits(target_key)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS rejection_target ON rejections(target_key)"
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Open a short transaction and close it on every exit.

        Returns:
            Connection with named rows and SQLite-managed write serialization.
        """
        connection = sqlite3.connect(str(self.path), timeout=2)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _put_observation(
        connection: sqlite3.Connection,
        record: dict[str, Any],
        compact: bool = True,
    ) -> None:
        """Retain the latest local observation without losing reviewed records.

        Parameters:
            connection: Active transaction.
            record: Canonical local observation or received report snapshot.
            compact: Keep only the latest unreviewed live observation; reviews retain all their records.
        """
        connection.execute(
            "INSERT INTO observations VALUES (?, ?, ?, ?) ON CONFLICT(record_id) "
            "DO UPDATE SET data=excluded.data",
            (
                record["id"],
                record["target_key"],
                json.dumps(record),
                record["observed_at"],
            ),
        )
        if compact and not record.get("peer_id"):
            connection.execute(
                "DELETE FROM observations WHERE target_key=? AND record_id<>? "
                "AND json_extract(data, '$.evidence_type')=? "
                "AND json_extract(data, '$.provenance.rule_version')=? "
                "AND json_extract(data, '$.peer_id')='' "
                "AND NOT EXISTS (SELECT 1 FROM reviews r WHERE r.record_id=observations.record_id) "
                "AND NOT EXISTS (SELECT 1 FROM credit_sources s WHERE s.record_id=observations.record_id)",
                (
                    record["target_key"],
                    record["id"],
                    record["evidence_type"],
                    record.get("provenance", {}).get("rule_version", ""),
                ),
            )

    def observe_local(self, record: dict[str, Any]) -> None:
        """Register traffic-derived evidence and reconsider earlier peer reports.

        Parameters:
            record: Observation containing provenance, target identity and time.
        """
        with self.connect() as connection:
            self._put_observation(connection, record)
            self._reconcile(connection, record["target_key"])

    def observe_report(
        self, record: dict[str, Any], reconcile: bool = True
    ) -> None:
        """Save latest typed reports independently of raw-report compaction.

        Parameters:
            record: Authenticated sender, score, confidence and provenance.
            reconcile: Apply validation after the current block evaluation.
        """
        with self.connect() as connection:
            provenance_items = record["provenance"] or [
                {
                    "evidence_type": "legacy",
                    "rule_version": "legacy",
                    "family": "unknown",
                    "method": "",
                    "observed_at": record["observed_at"],
                }
            ]
            for provenance in provenance_items:
                observed = (
                    provenance.get("observed_at") or record["observed_at"]
                )
                report = {
                    **record,
                    "detector": provenance,
                    "observed_at": observed,
                }
                previous = connection.execute(
                    "SELECT data FROM reports WHERE peer_id=? AND target_key=? AND evidence_type=? AND rule_version=?",
                    (
                        record["peer_id"],
                        record["target_key"],
                        provenance["evidence_type"],
                        provenance["rule_version"],
                    ),
                ).fetchone()
                if record.get("message_type") == "blame":
                    report["blame_at"] = observed
                elif (
                    previous
                    and record["score"] > 0
                    and record["confidence"] > 0
                ):
                    report["blame_at"] = json.loads(previous[0]).get(
                        "blame_at", 0
                    )
                connection.execute(
                    "INSERT INTO reports VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(peer_id, target_key, evidence_type, rule_version) "
                    "DO UPDATE SET record_id=excluded.record_id, data=excluded.data, "
                    "observed_at=excluded.observed_at WHERE excluded.observed_at >= reports.observed_at",
                    (
                        record["peer_id"],
                        record["target_key"],
                        provenance["evidence_type"],
                        provenance["rule_version"],
                        record["id"],
                        json.dumps(report),
                        observed,
                    ),
                )
            if reconcile:
                self._reconcile(connection, record["target_key"])

    def apply_review(self, event: dict[str, Any]) -> None:
        """Idempotently replace one web verdict and retract superseded credit.

        Parameters:
            event: Durable review outbox snapshot with revision and evidence.
        """
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT revision FROM review_events WHERE source=?",
                (event["source"],),
            ).fetchone()
            if previous and previous[0] >= event["revision"]:
                return
            targets = {
                row[0]
                for row in connection.execute(
                    "SELECT o.target_key FROM reviews r JOIN observations o ON o.record_id=r.record_id WHERE r.source=?",
                    (event["source"],),
                )
            }
            connection.execute(
                "DELETE FROM reviews WHERE source=?", (event["source"],)
            )
            for identifier in event.get("withdrawn", []):
                previous_record = connection.execute(
                    "SELECT target_key FROM observations WHERE record_id=?",
                    (identifier,),
                ).fetchone()
                if previous_record:
                    targets.add(previous_record[0])
                connection.execute(
                    "DELETE FROM reviews WHERE record_id=?", (identifier,)
                )
            for record in event["records"]:
                self._put_observation(connection, record, compact=False)
                targets.add(record["target_key"])
                if event["verdict"] in DEFINITIVE:
                    connection.execute(
                        "INSERT INTO reviews VALUES (?, ?, ?)",
                        (event["source"], record["id"], event["verdict"]),
                    )
                if record.get("peer_id") and record.get("provenance"):
                    for detector in record["provenance"]:
                        observed = (
                            detector.get("observed_at")
                            or record["observed_at"]
                        )
                        report = {
                            **record,
                            "detector": detector,
                            "observed_at": observed,
                        }
                        connection.execute(
                            "INSERT OR IGNORE INTO reports VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (
                                record["peer_id"],
                                record["target_key"],
                                detector["evidence_type"],
                                detector["rule_version"],
                                record["id"],
                                json.dumps(report),
                                observed,
                            ),
                        )
            connection.execute(
                "INSERT INTO review_events VALUES (?, ?) ON CONFLICT(source) DO UPDATE SET revision=excluded.revision",
                (event["source"], event["revision"]),
            )
            for target in targets:
                self._reconcile(connection, target)
            connection.execute(
                "UPDATE feedback_state SET revision=revision+1 WHERE id=1"
            )

    @staticmethod
    def _verdict(connection: sqlite3.Connection, identifier: str) -> str:
        """Read effective analyst feedback for one evidence record.

        Parameters:
            connection: Open validation database.
            identifier: Evidence ID.

        Returns:
            Definitive, conflicting, or missing verdict.
        """
        return review_verdict(
            [
                row[0]
                for row in connection.execute(
                    "SELECT verdict FROM reviews WHERE record_id=?",
                    (identifier,),
                )
            ]
        )

    def _validation(
        self, connection: sqlite3.Connection, report: dict[str, Any]
    ) -> tuple[str, str, list[str]]:
        """Require reviewed evidence or a distinct, concrete verification method.

        Parameters:
            connection: Current transaction.
            report: One typed authenticated report.

        Returns:
            Validation verdict and explanation suitable for the web.
        """
        direct = self._verdict(connection, report["id"])
        if (
            direct == "true_positive"
            and len(
                {
                    item["evidence_type"]
                    for item in report.get("provenance", [])
                }
            )
            > 1
        ):
            # An aggregate TP does not certify each component detector.
            direct = ""
        if direct == "conflict":
            return (
                direct,
                "Analyst review of this received report",
                [report["id"]],
            )
        detector = report["detector"]
        automatic = False
        judgments = [direct] if direct else []
        sources = [report["id"]] if direct else []
        for row in connection.execute(
            "SELECT data FROM observations WHERE target_key=? AND observed_at BETWEEN ? AND ?",
            (
                report["target_key"],
                report["observed_at"] - MATCH_WINDOW,
                report["observed_at"] + MATCH_WINDOW,
            ),
        ):
            local = json.loads(row[0])
            if (
                local.get("peer_id")
                or local.get("evidence_type") != detector["evidence_type"]
            ):
                continue
            reviewed = self._verdict(connection, local["id"])
            if reviewed == "conflict":
                return (
                    "conflict",
                    "Conflicting analyst verdicts",
                    [local["id"]],
                )
            if reviewed:
                judgments.append(reviewed)
                sources.append(local["id"])
            basis = local.get("provenance", {})
            if (
                basis.get("family")
                not in {None, "unknown", detector["family"]}
                and basis.get("method")
                in {"SIGNATURE", "INTEGRITY", "HONEYPOT"}
                and local.get("confidence", 0) >= 0.9
                and local.get("score", 0) >= 0.8
            ):
                automatic = True
                sources.append(local["id"])
        verdict = review_verdict(judgments)
        if verdict:
            return (
                verdict,
                (
                    "Analyst review of this received report"
                    if direct
                    else "Analyst review of matching local evidence"
                ),
                sources,
            )
        return (
            ("true_positive", "Independent local verification method", sources)
            if automatic
            else ("", "Awaiting independent validation or analyst verdict", [])
        )

    def _reconcile(self, connection: sqlite3.Connection, target: str) -> None:
        """Award at most one reversible credit per peer and target for its lifetime.

        Parameters:
            connection: Current write transaction.
            target: Network-scoped host identity.
        """
        rewarded = set()
        rejected = set()
        proof: dict[str, set[str]] = {}
        candidates = []
        for table in ("credits", "rejections"):
            for credit in connection.execute(
                f"SELECT * FROM {table} WHERE target_key=?", (target,)
            ).fetchall():
                peer_id = credit["peer_id"]
                report = json.loads(credit["report_data"])
                verdict, reason, sources = self._validation(connection, report)
                proof.setdefault(peer_id, set()).update(sources)
                parameters = [verdict, reason, time.time(), peer_id, target]
                condition = "peer_id=? AND target_key=?"
                if table == "credits":
                    rewarded.add(peer_id)
                else:
                    rejected.add(
                        (
                            peer_id,
                            credit["evidence_type"],
                            credit["rule_version"],
                        )
                    )
                    condition += " AND evidence_type=? AND rule_version=?"
                    parameters.extend(
                        [credit["evidence_type"], credit["rule_version"]]
                    )
                    candidates.append(report)
                if verdict != credit["verdict"] or reason != credit["reason"]:
                    connection.execute(
                        f"UPDATE {table} SET verdict=?, reason=?, changed_at=? WHERE {condition}",
                        parameters,
                    )
        candidates.extend(
            json.loads(row[0])
            for row in connection.execute(
                "SELECT data FROM reports WHERE target_key=? ORDER BY observed_at",
                (target,),
            )
        )
        for report in candidates:
            peer_id = report["peer_id"]
            detector = report["detector"]
            if detector["evidence_type"] == "legacy":
                continue
            verdict, reason, sources = self._validation(connection, report)
            rejection_key = (
                peer_id,
                detector["evidence_type"],
                detector["rule_version"],
            )
            if verdict == "true_positive" and peer_id not in rewarded:
                table = "credits"
                rewarded.add(peer_id)
            elif verdict == "false_positive" and rejection_key not in rejected:
                table = "rejections"
                rejected.add(rejection_key)
            else:
                continue
            now = time.time()
            connection.execute(
                f"INSERT OR IGNORE INTO {table} VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    peer_id,
                    target,
                    detector["evidence_type"],
                    detector["rule_version"],
                    verdict,
                    reason,
                    json.dumps(report),
                    now,
                    now,
                ),
            )
            proof.setdefault(peer_id, set()).update(sources)
        for peer_id, sources in proof.items():
            connection.execute(
                "DELETE FROM credit_sources WHERE peer_id=? AND target_key=?",
                (peer_id, target),
            )
            connection.executemany(
                "INSERT OR IGNORE INTO credit_sources VALUES (?, ?, ?)",
                [(peer_id, target, identifier) for identifier in sources],
            )

    def reconcile_target(self, target: str) -> None:
        """Apply validation after a received report's current block decision.

        Parameters:
            target: Receiver-derived network and host identity.
        """
        with self.connect() as connection:
            self._reconcile(connection, target)

    def report_adjustment(
        self, peer_id: str, evidence_type: str, rule_version: str
    ) -> dict[str, Any]:
        """Compute bounded, decaying report accuracy without altering reliability.

        Parameters:
            peer_id: Authenticated reporting identity.
            evidence_type: Type being evaluated.
            rule_version: Version of the reporting detector.

        Returns:
            Credit counts and trust adjustment, scoped to this detector/type.
        """
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT target_key, verdict, earned_at, 1 AS reward_allowed FROM credits WHERE peer_id=? AND evidence_type=? AND rule_version=? UNION ALL SELECT target_key, verdict, earned_at, 0 AS reward_allowed FROM rejections WHERE peer_id=? AND evidence_type=? AND rule_version=?",
                (
                    peer_id,
                    evidence_type,
                    rule_version,
                    peer_id,
                    evidence_type,
                    rule_version,
                ),
            ).fetchall()
        adjustment = 0.0
        positive = 0
        negative_cases: dict[str, float] = {}
        for row in rows:
            if row["verdict"] == "false_positive":
                negative_cases[row["target_key"]] = min(
                    negative_cases.get(row["target_key"], row["earned_at"]),
                    row["earned_at"],
                )
            elif row["verdict"] == "true_positive" and row["reward_allowed"]:
                positive += 1
                adjustment += 0.05 * 2 ** (
                    -max(0, time.time() - row["earned_at"]) / HALF_LIFE
                )
        for earned_at in negative_cases.values():
            adjustment -= 0.10 * 2 ** (
                -max(0, time.time() - earned_at) / HALF_LIFE
            )
        negative = len(negative_cases)
        return {
            "adjustment": max(-0.30, min(MAX_CREDIT, adjustment)),
            "confirmed": positive,
            "false_positive": negative,
        }

    def detector_weight(
        self, evidence_type: str, rule_version: str, target_prefix: str = ""
    ) -> float:
        """Discount detector confidence using reviewed, distinct target cases.

        Parameters:
            evidence_type: Canonical evidence name.
            rule_version: Detector implementation digest.
            target_prefix: Optional current-network scope.

        Returns:
            Weight in [0, 1], initially 1; this is not a calibrated probability.
        """
        cases: dict[str, list[str]] = {}
        records: dict[str, tuple[dict[str, Any], list[str]]] = {}
        with self.connect() as connection:
            for row in connection.execute(
                "SELECT o.record_id, o.target_key, o.data, r.verdict FROM observations o JOIN reviews r ON r.record_id=o.record_id"
            ):
                record = json.loads(row["data"])
                detector = record.get("provenance", {})
                if (
                    record.get("peer_id")
                    or not isinstance(detector, dict)
                    or record.get("evidence_type") != evidence_type
                    or detector.get("rule_version")
                    not in {rule_version, "legacy"}
                    or not row["target_key"].startswith(target_prefix)
                ):
                    continue
                records.setdefault(row["record_id"], (record, []))[1].append(
                    row["verdict"]
                )
        for record, labels in records.values():
            verdict = review_verdict(labels)
            if (
                record["provenance"].get("rule_version") == "legacy"
                and verdict == "true_positive"
            ):
                continue
            cases.setdefault(record["target_key"], []).append(verdict)
        verdicts = [review_verdict(values) for values in cases.values()]
        positive = verdicts.count("true_positive")
        negative = verdicts.count("false_positive")
        return (positive + 1) / (positive + negative + 1)

    def drain_reviews(self, run_path: str | Path, limit: int = 100) -> int:
        """Apply committed web feedback, retaining failed work for later retries.

        Parameters:
            run_path: Run flows.sqlite containing analyst reviews and the outbox.
            limit: Maximum feedback events applied in this pass.

        Returns:
            Number of successfully applied or already processed events.
        """
        applied = 0
        with sqlite3.connect(str(run_path), timeout=2) as connection:
            if not connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='p2p_review_outbox'"
            ).fetchone():
                return 0
            rows = connection.execute(
                "SELECT source, revision, payload FROM p2p_review_outbox ORDER BY revision LIMIT ?",
                (limit,),
            ).fetchall()
            for source, revision, payload in rows:
                self.apply_review(json.loads(payload))
                connection.execute(
                    "DELETE FROM p2p_review_outbox WHERE source=? AND revision=?",
                    (source, revision),
                )
                applied += 1
        return applied

    def reports_for_target(self, target_key: str) -> list[dict[str, Any]]:
        """Read latest typed opinions for one host in one network.

        Parameters:
            target_key: Receiver-derived network and host identity.

        Returns:
            Latest reports for dependency-aware decision processing.
        """
        with self.connect() as connection:
            return [
                json.loads(row[0])
                for row in connection.execute(
                    "SELECT data FROM reports WHERE target_key=? AND observed_at >= ?",
                    (target_key, time.time() - MATCH_WINDOW),
                )
            ]

    def feedback_revision(self) -> int:
        """Return the latest applied review revision for cache invalidation.

        Returns:
            Revision observed by both the web and P2P processes.
        """
        with self.connect() as connection:
            return int(
                connection.execute(
                    "SELECT revision FROM feedback_state WHERE id=1"
                ).fetchone()[0]
            )

    def import_reviews(
        self,
        run_path: str | Path,
        record_builder: Callable[[dict[str, Any]], dict[str, Any]],
        limit: int = 100,
    ) -> int:
        """Import existing web verdicts incrementally without scanning all flows.

        Parameters:
            run_path: Run SQLite database holding saved reviews.
            record_builder: Resolve one evidence snapshot and its historical network.
            limit: Maximum saved reviews processed during this pass.

        Returns:
            Number of reviews considered; repeated imports are idempotent.
        """
        with self.connect() as validation:
            cursor = validation.execute(
                "SELECT updated_at, source FROM review_imports WHERE run_path=?",
                (str(run_path),),
            ).fetchone()
        after, source = tuple(cursor) if cursor else (0.0, "")
        connection = sqlite3.connect(str(run_path), timeout=2)
        connection.row_factory = sqlite3.Row
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "evidence" not in tables or "data" not in {
                row[1]
                for row in connection.execute("PRAGMA table_info(evidence)")
            }:
                return 0
            queries = []
            if "evidence_reviews" in tables:
                queries.append(
                    "SELECT 'evidence:'||evidence_id AS source, evidence_id AS id, status AS verdict, updated_at FROM evidence_reviews"
                )
            if "alert_reviews" in tables and "verdict" in {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(alert_reviews)"
                )
            }:
                queries.append(
                    "SELECT 'alert:'||alert_id AS source, alert_id AS id, verdict, updated_at FROM alert_reviews"
                )
            if not queries:
                return 0
            rows = connection.execute(
                "SELECT * FROM ("
                + " UNION ALL ".join(queries)
                + ") WHERE updated_at>? OR (updated_at=? AND source>?) ORDER BY updated_at, source LIMIT ?",
                (after, after, source, limit),
            ).fetchall()
            for row in rows:
                alert = row["source"].startswith("alert:")
                condition = (
                    "evidence_id IN (SELECT evidence_id FROM alert_evidence WHERE alert_id=?)"
                    if alert
                    else "evidence_id=?"
                )
                records = []
                for evidence in connection.execute(
                    f"SELECT evidence_id, data FROM evidence WHERE {condition}",
                    (row["id"],),
                ):
                    raw = json.loads(evidence["data"])
                    raw.setdefault("id", evidence["evidence_id"])
                    record = record_builder(raw)
                    if record:
                        records.append(record)
                verdict = row["verdict"]
                if (
                    alert
                    and verdict == "true_positive"
                    and len({record["evidence_type"] for record in records})
                    > 1
                ):
                    verdict = "inconclusive"
                self.apply_review(
                    {
                        "source": row["source"],
                        "revision": int(row["updated_at"] * 1e9),
                        "verdict": verdict,
                        "records": records,
                    }
                )
                with self.connect() as validation:
                    validation.execute(
                        "INSERT INTO review_imports VALUES (?, ?, ?) ON CONFLICT(run_path) DO UPDATE SET updated_at=excluded.updated_at, source=excluded.source",
                        (str(run_path), row["updated_at"], row["source"]),
                    )
            return len(rows)
        finally:
            connection.close()

    def report_verdict(self, report: dict[str, Any]) -> str:
        """Read independent validation without awarding trust for the current report.

        Parameters:
            report: Stored authenticated report.

        Returns:
            Definitive, conflicting, or unknown assessment.
        """
        with self.connect() as connection:
            return self._validation(connection, report)[0]

    def local_report(
        self, target: str, max_age: float | None = MATCH_WINDOW
    ) -> tuple[float | None, float | None, list[dict[str, Any]]]:
        """Build an outgoing assessment from recent, unrejected local evidence.

        Parameters:
            target: Receiver-scoped network and host identity.
            max_age: Observation lifetime in seconds; None retains local peer history.

        Returns:
            Score, adjusted confidence and provenance, or an unknown assessment.
        """
        with self.connect() as connection:
            records = [
                json.loads(row[0])
                for row in connection.execute(
                    "SELECT data FROM observations WHERE target_key=? AND observed_at>=? ORDER BY observed_at DESC",
                    (
                        target,
                        time.time() - max_age if max_age is not None else 0,
                    ),
                )
            ]
            records = [
                record
                for record in records
                if not record.get("peer_id")
                and self._verdict(connection, record["id"])
                not in {"false_positive", "conflict"}
            ]
        if not records:
            return None, None, []
        assessments = [
            (
                record["score"],
                record["confidence"]
                * self.detector_weight(
                    record["evidence_type"],
                    record["provenance"]["rule_version"],
                    record["network_id"] + "|",
                ),
                record["provenance"],
            )
            for record in records
        ]
        score, confidence, provenance = max(
            assessments, key=lambda item: item[0] * item[1]
        )
        return (
            score,
            confidence,
            (
                [provenance]
                if provenance.get("module") in {item.value for item in Modules}
                else []
            ),
        )

    def peer_feedback(self, peer_id: str) -> list[dict[str, Any]]:
        """Expose separate, detector-specific accuracy records to the web.

        Parameters:
            peer_id: Authenticated reporter identity.

        Returns:
            Bounded list of detector adjustments and confirmed/false counts.
        """
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT evidence_type, rule_version FROM credits WHERE peer_id=? UNION SELECT evidence_type, rule_version FROM rejections WHERE peer_id=? LIMIT 100",
                (peer_id, peer_id),
            ).fetchall()
        return [
            {
                "evidence_type": row[0],
                "rule_version": row[1],
                **self.report_adjustment(peer_id, row[0], row[1]),
            }
            for row in rows
        ]

    def prune(self) -> None:
        """Bound unreviewed observation storage while preserving permanent credits."""
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM observations WHERE record_id IN (SELECT o.record_id FROM observations o WHERE o.observed_at < ? AND NOT EXISTS (SELECT 1 FROM reviews r WHERE r.record_id=o.record_id) AND NOT EXISTS (SELECT 1 FROM credit_sources c WHERE c.record_id=o.record_id) LIMIT 1000)",
                (time.time() - HALF_LIFE,),
            )
