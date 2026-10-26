"""Exercise durable, reversible validation using real SQLite databases."""

import json
import base64
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from modules.p2p_trust.trust.base_model import BaseModel
from modules.p2p_trust.p2p_trust import Trust
from modules.p2p_trust.trust.report_validation import (
    HALF_LIFE,
    ReportValidator,
    dependency_family,
    observation_record,
    provenance_for_evidence,
    queue_review_event,
    validate_provenance,
)
from modules.supported_module_names import Modules
from tests.module_factory import ModuleFactory


def observation(
    identifier: str = "local",
    target: str = "192.168.1.185",
    kind: str = "ARP_SCAN",
    module: str = Modules.ARP,
    version: str = "rule-v1",
    method: str = "HEURISTIC",
) -> dict:
    """Build a traffic-derived observation.

    Parameters:
        identifier: Unique evidence ID.
        target: Host being assessed.
        kind: Evidence type.
        module: Supported detection module.
        version: Detector implementation identity.
        method: Local detection method.

    Returns:
        Canonical observation with no peer-derived data.
    """
    now = time.time()
    return {
        "id": identifier,
        "target": target,
        "target_key": f"gateway:home|{target}",
        "network_id": "gateway:home",
        "evidence_type": kind,
        "observed_at": now,
        "score": 1.0,
        "confidence": 1.0,
        "peer_id": "",
        "message_type": "",
        "provenance": {
            "evidence_type": kind,
            "module": module.value if isinstance(module, Modules) else module,
            "rule_version": version,
            "family": dependency_family(kind, module),
            "method": method,
            "observed_at": now,
            "evidence_id": identifier,
        },
    }


def report(
    identifier: str = "peer-record", peer: str = "peer-A", **kwargs: str
) -> dict:
    """Build an authenticated typed blame.

    Parameters:
        identifier: Received evidence ID.
        peer: Authenticated sender identity.
        kwargs: Detection source overrides.

    Returns:
        Received report suitable for durable validation.
    """
    record = observation(identifier, **kwargs)
    return {
        **record,
        "peer_id": peer,
        "message_type": "blame",
        "raw_report_id": 10,
        "provenance": [record["provenance"]],
    }


def review(
    record: dict,
    verdict: str,
    revision: int = 1,
    source: str = "evidence:local",
) -> dict:
    """Create one analyst event.

    Parameters:
        record: Reviewed detection snapshot.
        verdict: Explicit analyst classification.
        revision: Monotonically increasing source revision.
        source: Alert or evidence review identity.

    Returns:
        Durable feedback event.
    """
    return {
        "source": source,
        "revision": revision,
        "verdict": verdict,
        "records": [record],
    }


@pytest.mark.parametrize("peers", [1, 2, 10])
def test_same_detector_agreement_never_earns_credit(
    tmp_path: Path, peers: int
) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    local = observation()
    validator.observe_local(local)
    for index in range(peers):
        validator.observe_report(report(peer=f"peer-{index}"))
    assert factory is not None
    with validator.connect() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM credits").fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    "verdict,positive,negative",
    [
        ("true_positive", 1, 0),
        ("false_positive", 0, 1),
        ("expected_behavior", 0, 1),
        ("in_review", 0, 0),
        ("resolved", 0, 0),
        ("inconclusive", 0, 0),
        ("unreviewed", 0, 0),
    ],
)
def test_only_explicit_verdicts_train(
    tmp_path: Path, verdict: str, positive: int, negative: int
) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    validator.observe_report(report())
    validator.apply_review(review(observation(), verdict))
    result = validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")
    assert (result["confirmed"], result["false_positive"]) == (
        positive,
        negative,
    )
    assert validator.detector_weight(
        "ARP_SCAN", "rule-v1", "gateway:home|"
    ) == (0.5 if negative else 1)
    assert factory is not None


def test_review_changes_conflicts_withdrawals_and_restarts(
    tmp_path: Path,
) -> None:
    factory = ModuleFactory()
    path = tmp_path / "validation.sqlite"
    validator = ReportValidator(path)
    peer_report, local = report(), observation()
    validator.observe_report(peer_report)
    validator.apply_review(review(local, "true_positive"))
    with validator.connect() as connection:
        earned = connection.execute(
            "SELECT earned_at FROM credits"
        ).fetchone()[0]
    validator = ReportValidator(path)
    validator.apply_review(review(local, "false_positive", 2, "alert:case"))
    assert (
        validator.report_verdict(
            {**peer_report, "detector": peer_report["provenance"][0]}
        )
        == "conflict"
    )
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "adjustment"
        ]
        == 0
    )
    validator.apply_review(review(local, "inconclusive", 3, "alert:case"))
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "confirmed"
        ]
        == 1
    )
    validator.apply_review(review(local, "false_positive", 4))
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "false_positive"
        ]
        == 1
    )
    validator.apply_review(
        review(local, "true_positive", 1)
    )  # replay is ignored
    validator.apply_review(review(local, "unreviewed", 5))
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "adjustment"
        ]
        == 0
    )
    with validator.connect() as connection:
        assert (
            connection.execute("SELECT earned_at FROM credits").fetchone()[0]
            == earned
        )
    assert validator.feedback_revision() == 5
    assert factory is not None


def test_credit_once_per_host_across_versions_and_types(
    tmp_path: Path,
) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    validator.observe_report(report())
    validator.apply_review(review(observation(), "true_positive"))
    for index in range(8):
        record = report(f"repeat-{index}", version=f"new-{index}")
        validator.observe_report(record)
        validator.apply_review(
            review(record, "true_positive", index + 2, f"evidence:{index}")
        )
    with validator.connect() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM credits").fetchone()[0]
            == 1
        )
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "confirmed"
        ]
        == 1
    )
    assert (
        validator.report_adjustment("peer-A", "UNKNOWN_PORT", "rule-v1")[
            "adjustment"
        ]
        == 0
    )
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "new-1")[
            "adjustment"
        ]
        == 0
    )
    assert factory is not None


@pytest.mark.parametrize(
    "method,family,expected",
    [
        ("HEURISTIC", "other", 0),
        ("SIGNATURE", "other", 1),
        ("SIGNATURE", "network_discovery", 0),
        ("INTEGRITY", "other", 1),
        ("HONEYPOT", "unknown", 0),
    ],
)
def test_independent_local_verification_is_conservative(
    tmp_path: Path, method: str, family: str, expected: int
) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    local = observation(method=method)
    local["provenance"]["family"] = family
    validator.observe_local(local)
    validator.observe_report(report())
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "confirmed"
        ]
        == expected
    )
    assert factory is not None


def test_peer_evidence_cannot_validate_peer_evidence(tmp_path: Path) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    first, second = report(), report("other", peer="peer-B")
    validator.observe_report(first)
    validator.apply_review(review(second, "true_positive"))
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "confirmed"
        ]
        == 0
    )
    assert (
        validator.report_adjustment("peer-B", "ARP_SCAN", "rule-v1")[
            "confirmed"
        ]
        == 1
    )
    assert factory is not None


def test_detector_weight_counts_distinct_hosts_and_keeps_context(
    tmp_path: Path,
) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    for index in range(20):
        validator.apply_review(
            review(
                observation(f"record-{index}"),
                "false_positive",
                index + 1,
                f"evidence:{index}",
            )
        )
    assert validator.detector_weight("ARP_SCAN", "rule-v1") == 0.5
    assert validator.detector_weight("ARP_SCAN", "other") == 1
    assert validator.detector_weight("UNKNOWN_PORT", "rule-v1") == 1
    assert (
        validator.detector_weight("ARP_SCAN", "rule-v1", "gateway:away|") == 1
    )
    assert factory is not None


def test_adjustment_is_bounded_decays_and_never_renews_on_repeat(
    tmp_path: Path,
) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    for index in range(10):
        item = report(str(index), target=f"192.168.1.{index + 10}")
        validator.observe_report(item)
        validator.apply_review(
            review(item, "true_positive", index + 1, f"evidence:{index}")
        )
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "adjustment"
        ]
        == 0.2
    )
    with validator.connect() as connection:
        connection.execute(
            "UPDATE credits SET earned_at=?", (time.time() - 4 * HALF_LIFE,)
        )
    assert validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
        "adjustment"
    ] == pytest.approx(0.03125, abs=0.0001)
    for index in range(10):
        item = report(str(index), target=f"192.168.1.{index + 10}")
        validator.apply_review(
            review(item, "false_positive", index + 100, f"evidence:{index}")
        )
    with validator.connect() as connection:
        connection.execute("UPDATE credits SET earned_at=?", (time.time(),))
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "adjustment"
        ]
        == -0.3
    )
    assert factory is not None


def test_outbox_retry_is_transactional_and_idempotent(tmp_path: Path) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    path = tmp_path / "flows.sqlite"
    with sqlite3.connect(path) as connection:
        queue_review_event(
            connection, "evidence:local", "false_positive", [observation()]
        )
    with patch.object(
        validator,
        "apply_review",
        side_effect=sqlite3.OperationalError("locked"),
    ):
        with pytest.raises(sqlite3.OperationalError):
            validator.drain_reviews(path)
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM p2p_review_outbox"
            ).fetchone()[0]
            == 1
        )
    assert validator.drain_reviews(path) == 1
    assert validator.drain_reviews(path) == 0
    assert validator.detector_weight("ARP_SCAN", "rule-v1") == 0.5
    assert factory is not None


def test_import_existing_web_reviews_in_pages(tmp_path: Path) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    path = tmp_path / "flows.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY,data TEXT); CREATE TABLE evidence_reviews(evidence_id TEXT PRIMARY KEY,status TEXT,updated_at REAL); CREATE TABLE alert_reviews(alert_id TEXT PRIMARY KEY,verdict TEXT,updated_at REAL); CREATE TABLE alert_evidence(alert_id TEXT,evidence_id TEXT);"
        )
        for index in range(3):
            raw = {
                "id": str(index),
                "attacker": {"value": f"192.168.1.{index + 10}"},
                "timestamp": time.time(),
                "threat_level": "low",
                "confidence": 1,
                "evidence_type": "ARP_SCAN",
                "source_module": Modules.ARP.value,
            }
            connection.execute(
                "INSERT INTO evidence VALUES (?,?)",
                (str(index), json.dumps(raw)),
            )
            connection.execute(
                "INSERT INTO evidence_reviews VALUES (?,?,?)",
                (str(index), "false_positive", index + 1),
            )
    def builder(raw: dict) -> dict:
        """Resolve an imported snapshot in the recorded test network.

        Parameters:
            raw: Stored evidence object.

        Returns:
            Canonical validation observation.
        """
        return observation_record(raw, "gateway:home")

    assert validator.import_reviews(path, builder, limit=2) == 2
    validator = ReportValidator(validator.path)
    assert validator.import_reviews(path, builder, limit=2) == 1
    assert validator.import_reviews(path, builder, limit=2) == 0
    assert (
        validator.detector_weight("ARP_SCAN", "rule-v1", "gateway:home|")
        == 0.25
    )
    assert factory is not None


@pytest.mark.parametrize(
    "field,value",
    [
        ("module", "unknown"),
        ("evidence_type", "P2P_REPORT"),
        ("rule_version", "a" * 161),
        ("observed_at", float("nan")),
    ],
)
def test_peer_provenance_is_bounded_and_validated(
    field: str, value: object
) -> None:
    factory = ModuleFactory()
    item = report()["provenance"][0]
    item[field] = value
    with pytest.raises(ValueError):
        validate_provenance([item])
    assert factory is not None


@pytest.mark.parametrize("proto", ["icmp", "icmp6", "icmpv6"])
@pytest.mark.parametrize("legacy", [False, True])
def test_peer_icmp_reports_preserve_type_and_zero_code(proto: str, legacy: bool) -> None:
    """Send type/code as ICMP metadata and accept older port-encoded reports.

    Parameters:
        proto: Local ICMP transport name.
        legacy: Whether to emulate an older sender's port fields.
    """
    _factory = ModuleFactory()
    record = {"evidence_type": "DIFFERENT_LOCALNET", "source_module": Modules.CONN_ANALYZER.value,
              "threat_level": "high", "id": "local-icmp", "observed_at": time.time(),
              "proto": proto, "src_port": 11, "dst_port": 0,
              "description": f"A connection on port 0/{proto} outside the network"}
    wire = provenance_for_evidence(record, "version")
    assert "src_port" not in wire and "dst_port" not in wire
    assert wire["icmp_type"] == 11 and wire["icmp_code"] == 0
    if legacy:
        wire.pop("icmp_type")
        wire.pop("icmp_code")
        wire["src_port"] = 11
    received = validate_provenance([wire])[0]
    assert received["icmp_type"] == 11
    assert received["icmp_code"] == (None if legacy else 0)
    assert not received["src_port"] and not received["dst_port"]
    assert "port" not in received["description"]
    invalid = {**wire, "icmp_code": 256}
    with pytest.raises(ValueError, match="ICMP type/code"):
        validate_provenance([invalid])


@pytest.mark.parametrize("direction", ["SRC", "DST"])
@pytest.mark.parametrize("addresses", [("192.0.2.10", "192.0.2.20"), ("2001:db8::10", "2001:db8::20")])
def test_peer_reports_keep_connection_roles(direction: str, addresses: tuple[str, str]) -> None:
    """Carry original endpoint roles without substituting the reporting peer.

    Parameters:
        direction: Direction of the host the detection concerns.
        addresses: Source and destination IPv4 or IPv6 addresses.
    """
    factory = ModuleFactory()
    source, destination = addresses
    attacker_ip, victim_ip = addresses if direction == "SRC" else tuple(reversed(addresses))
    record = {"evidence_type": "UNKNOWN_PORT", "source_module": Modules.CONN_ANALYZER.value,
              "threat_level": "high", "id": "original", "observed_at": time.time(),
              "proto": "tcp", "src_port": 6668, "dst_port": 6668,
              "attacker": {"direction": direction, "ioc_type": "IP", "value": attacker_ip},
              "victim": {"direction": "DST" if direction == "SRC" else "SRC", "ioc_type": "IP", "value": victim_ip}}
    wire = provenance_for_evidence(record, "version")
    assert wire["src_ip"] == source and wire["dst_ip"] == destination
    received = validate_provenance([wire])[0]
    assert received["src_ip"] == source and received["dst_ip"] == destination
    assert received["proto"] == "tcp"
    assert factory is not None


@pytest.mark.parametrize("value", [None, True, 123, "example.org", "192.0.2.999", "<img src=x>", "1" * 46])
@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
def test_peer_endpoint_metadata_rejects_invalid_addresses(field: str, value: object) -> None:
    """Reject malformed endpoint metadata while accepting older reports.

    Parameters:
        field: Source or destination address field.
        value: Invalid value received from a peer.
    """
    factory = ModuleFactory()
    item = report()["provenance"][0]
    assert validate_provenance([item])
    with pytest.raises(ValueError, match="address"):
        validate_provenance([{**item, field: value}])
    assert factory is not None


def test_shared_dependency_is_derived_locally_and_info_ignored() -> None:
    factory = ModuleFactory()
    item = report()["provenance"][0]
    item["family"] = "forged-independent-family"
    assert validate_provenance([item])[0]["family"] == "network_discovery"
    assert (
        provenance_for_evidence(
            {"evidence_type": "ARP_SCAN", "threat_level": "info"}, "version"
        )
        == {}
    )
    assert (
        observation_record(
            {
                "id": "info",
                "timestamp": time.time(),
                "attacker": {"value": "192.168.1.2"},
                "evidence_type": "CONNECTION_TO_PRIVATE_IP",
                "threat_level": "info",
            },
            "gateway:home",
        )
        == {}
    )
    assert factory is not None


@pytest.mark.parametrize(
    "families,expected_support",
    [
        (
            ["network_discovery", "network_discovery", "network_discovery"],
            0.35,
        ),
        (
            ["network_discovery", "connection_policy", "threat_intelligence"],
            1.05,
        ),
    ],
)
def test_correlated_reports_do_not_multiply_block_support(
    tmp_path: Path, families: list[str], expected_support: float
) -> None:
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    for index, family in enumerate(families):
        item = report(str(index), peer=f"peer-{index}")
        item["provenance"][0]["family"] = family
        validator.observe_report(item)
    trustdb = Mock()
    trustdb.get_ip_of_peer.side_effect = lambda peer: (
        time.time(),
        f"192.168.1.{int(peer[-1]) + 10}",
    )
    trustdb.get_reporter_reliability.return_value = 1
    trustdb.get_reporter_reputation.return_value = (None, None)
    model = BaseModel(
        Mock(), trustdb, Mock(), validator, lambda: "gateway:home"
    )
    score, confidence = model.get_opinion_on_ip("192.168.1.185")
    assert score == 1
    assert confidence == pytest.approx(0.35)
    assert model.last_corroboration["support"] == pytest.approx(
        expected_support
    )
    assert factory is not None


def test_later_false_reports_are_penalized_after_positive_credit(
    tmp_path: Path,
) -> None:
    """Rewarding one target must not exempt later false reports about it.

    Parameters:
        tmp_path: Isolated temporary directory.
    """
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    correct = report()
    validator.observe_report(correct)
    validator.apply_review(review(correct, "true_positive"))
    wrong = report("wrong", kind="UNKNOWN_PORT", module=Modules.CONN_ANALYZER)
    validator.observe_report(wrong)
    validator.apply_review(
        review(wrong, "false_positive", 2, "evidence:wrong")
    )
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "confirmed"
        ]
        == 1
    )
    assert (
        validator.report_adjustment("peer-A", "UNKNOWN_PORT", "rule-v1")[
            "false_positive"
        ]
        == 1
    )
    validator.apply_review(review(wrong, "true_positive", 3, "evidence:wrong"))
    assert (
        validator.report_adjustment("peer-A", "UNKNOWN_PORT", "rule-v1")[
            "adjustment"
        ]
        == 0
    )
    with validator.connect() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM credits").fetchone()[0]
            == 1
        )
    assert factory is not None


def test_review_clock_and_cache_revision_survive_clock_rollback(
    tmp_path: Path,
) -> None:
    """A later correction is applied even when the wall clock moves backward.

    Parameters:
        tmp_path: Isolated temporary directory.
    """
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    run = tmp_path / "flows.sqlite"
    with patch(
        "modules.p2p_trust.trust.report_validation.time.time_ns",
        return_value=100,
    ):
        with sqlite3.connect(run) as connection:
            queue_review_event(
                connection, "evidence:local", "false_positive", [observation()]
            )
    validator.drain_reviews(run)
    revision = validator.feedback_revision()
    with patch(
        "modules.p2p_trust.trust.report_validation.time.time_ns",
        return_value=10,
    ):
        with sqlite3.connect(run) as connection:
            queue_review_event(
                connection, "evidence:local", "true_positive", [observation()]
            )
    validator.drain_reviews(run)
    assert validator.feedback_revision() > revision
    assert validator.detector_weight("ARP_SCAN", "rule-v1") == 1
    assert factory is not None


def test_validated_wire_message_and_request_reply_use_provenance(
    tmp_path: Path,
) -> None:
    """Typed reports survive the Python/Pigeon envelope and feedback affects replies.

    Parameters:
        tmp_path: Isolated temporary directory.
    """
    director = ModuleFactory().create_go_director_obj()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    director.report_validation = validator
    director.network_identity = lambda: "gateway:home"
    local = observation()
    validator.observe_local(local)
    with patch(
        "modules.p2p_trust.utils.go_director.utils.get_own_ips",
        return_value=[],
    ):
        director.respond_to_message_request("192.168.1.185", "remote")
    envelope = json.loads(director.db.publish.call_args.args[1])
    message = json.loads(base64.b64decode(envelope["message"]))
    assert (
        validate_provenance(message["evaluation"]["provenance"])[0]["module"]
        == Modules.ARP.value
    )
    assert message["evaluation"]["score"] == 1
    assert envelope["recipient"] == "remote"
    director.trustdb.get_ip_of_peer.return_value = (
        time.time(),
        "192.168.1.10",
    )
    director.trustdb.get_latest_report_id.return_value = 20
    director.db.get_tw_of_ts.return_value = ["timewindow1"]
    director.process_message_report("remote", int(time.time()), message)
    received = validator.reports_for_target("gateway:home|192.168.1.185")
    assert received[0]["detector"]["evidence_type"] == "ARP_SCAN"
    assert received[0]["raw_report_id"] == 20
    assert (
        director.db.set_evidence.call_args.args[0].peer_report["peer_id"]
        == "remote"
    )
    validator.apply_review(review(local, "false_positive"))
    director.db.publish.reset_mock()
    with patch(
        "modules.p2p_trust.utils.go_director.utils.get_own_ips",
        return_value=[],
    ):
        director.respond_to_message_request("192.168.1.185", "remote")
    director.db.publish.assert_not_called()


def test_unrelated_accepted_detection_cannot_reuse_rejected_score(
    tmp_path: Path,
) -> None:
    """A rejected critical finding must not borrow another detector's confidence.

    Parameters:
        tmp_path: Isolated temporary directory.
    """
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    rejected = observation(
        "bad", kind="UNKNOWN_PORT", module=Modules.CONN_ANALYZER
    )
    accepted = observation("other")
    accepted["score"] = 0.2
    validator.observe_local(rejected)
    validator.observe_local(accepted)
    validator.apply_review(review(rejected, "false_positive"))
    assert validator.local_report(accepted["target_key"])[:2] == (0.2, 1)
    assert validator.local_report("gateway:another|192.168.1.185") == (
        None,
        None,
        [],
    )
    assert factory is not None


@pytest.mark.parametrize(
    "same_dependency,expected_block", [(True, False), (False, True)]
)
def test_local_and_remote_shared_error_does_not_supply_two_confirmations(
    tmp_path: Path, same_dependency: bool, expected_block: bool
) -> None:
    """An unreviewed shared heuristic cannot push the block decision over threshold.

    Parameters:
        tmp_path: Isolated temporary directory.
        same_dependency: Whether the local and remote detectors share a dependency.
        expected_block: Whether to forward the blame for blocking.
    """
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    local = observation()
    local["score"] = 0.8
    validator.observe_local(local)
    trust = Trust.__new__(Trust)
    trust.report_validation = validator
    trust._network_identity = lambda: "gateway:home"
    trust.db = Mock()
    trust.print = Mock()
    trust.reputation_model = Mock()
    trust.reputation_model.get_opinion_on_ip.return_value = (1, 0.35)
    family = "network_discovery" if same_dependency else "connection_policy"
    trust.reputation_model.last_corroboration = {
        "target": local["target_key"],
        "support": 0.35,
        "families": {
            family: {"score": 1, "confidence": 0.35, "validated": False}
        },
    }
    with patch(
        "modules.p2p_trust.p2p_trust.p2p_utils.get_ip_info_from_slips",
        return_value=(1, 1),
    ):
        trust.evaluate_blame_report(
            "peer-A",
            time.time(),
            {"message_type": "blame", "key": "192.168.1.185"},
        )
    assert trust.db.publish.called is expected_block
    assert factory is not None


@pytest.mark.parametrize(
    "target,support,expected",
    [
        ("192.168.1.185", 1.05, True),
        ("192.168.1.185", 0.35, False),
        ("192.168.1.99", 1.05, False),
    ],
)
def test_independent_blames_block_without_stale_target_support(
    tmp_path: Path, target: str, support: float, expected: bool
) -> None:
    """Corroboration belongs only to the exact host and receiver network.

    Parameters:
        tmp_path: Isolated temporary directory.
        target: Host associated with the stored corroboration.
        support: Independent blame support supplied to the decision.
        expected: Expected result.
    """
    factory = ModuleFactory()
    trust = Trust.__new__(Trust)
    trust.report_validation = ReportValidator(tmp_path / "validation.sqlite")
    trust._network_identity = lambda: "gateway:home"
    trust.db = Mock()
    trust.print = Mock()
    trust.reputation_model = Mock()
    trust.reputation_model.get_opinion_on_ip.return_value = (1, 0.35)
    trust.reputation_model.last_corroboration = {
        "target": f"gateway:home|{target}",
        "support": support,
    }
    with patch(
        "modules.p2p_trust.p2p_trust.p2p_utils.get_ip_info_from_slips",
        return_value=(None, None),
    ):
        trust.evaluate_blame_report(
            "peer-A",
            time.time(),
            {"message_type": "blame", "key": "192.168.1.185"},
        )
    assert trust.db.publish.called is expected
    assert factory is not None


def test_routine_report_retains_recent_blame_without_renewing_it(
    tmp_path: Path,
) -> None:
    """Routine report traffic cannot erase or extend an earlier blame's lifetime.

    Parameters:
        tmp_path: Isolated temporary directory.
    """
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    blame = report()
    validator.observe_report(blame)
    routine = report("later")
    routine["message_type"] = "report"
    validator.observe_report(routine)
    saved = validator.reports_for_target(blame["target_key"])[0]
    assert saved["blame_at"] == blame["provenance"][0]["observed_at"]
    routine["confidence"] = 0
    validator.observe_report(routine)
    assert not validator.reports_for_target(blame["target_key"])[0].get(
        "blame_at"
    )
    assert factory is not None


def test_positive_feedback_cannot_compensate_malicious_reporter(
    tmp_path: Path,
) -> None:
    """Strong local malicious evidence defeats previously earned reporting bonuses.

    Parameters:
        tmp_path: Isolated temporary directory.
    """
    factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    for index in range(5):
        item = report(str(index), target=f"192.168.1.{index + 20}")
        validator.observe_report(item)
        validator.apply_review(
            review(item, "true_positive", index + 1, f"evidence:{index}")
        )
    validator.observe_report(report())
    reporter_evidence = observation("compromised", target="192.168.1.10")
    validator.observe_local(reporter_evidence)
    trustdb = Mock()
    trustdb.get_ip_of_peer.return_value = (time.time(), "192.168.1.10")
    trustdb.get_reporter_reliability.return_value = 1
    model = BaseModel(
        Mock(), trustdb, Mock(), validator, lambda: "gateway:home"
    )
    assert model.get_opinion_on_ip("192.168.1.185")[1] == 0
    validator.apply_review(
        review(reporter_evidence, "false_positive", 10, "evidence:compromised")
    )
    assert model.get_opinion_on_ip("192.168.1.185")[1] == pytest.approx(
        (0.35 + 0.20) * 0.5, abs=0.001
    )
    model.main_slips_db.set_peer_trust.assert_called_with("192.168.1.10", 0.35)
    assert factory is not None


def test_feedback_consumed_by_web_still_invalidates_p2p_cache(
    tmp_path: Path,
) -> None:
    """P2P notices the durable feedback revision after the web empties the outbox.

    Parameters:
        tmp_path: Isolated temporary directory.
    """
    factory = ModuleFactory()
    trust = Trust.__new__(Trust)
    trust.report_validation = ReportValidator(tmp_path / "validation.sqlite")
    trust.parent_output_dir = "output/test"
    trust.args = SimpleNamespace(interface="en0")
    trust.db = Mock()
    trust.db.main_pid = 123
    trust.db.get_network_state.return_value = {"gateway_mac": "home"}
    run = tmp_path / "flows.sqlite"
    with sqlite3.connect(run) as connection:
        queue_review_event(
            connection, "evidence:local", "false_positive", [observation()]
        )
    trust.db.sqlite.get_db_path.return_value = run
    trust.trust_db = Mock()
    trust.print = Mock()
    trust._drain_review_feedback()
    assert trust._network_identity() == "gateway:home"
    trust.trust_db.execute.reset_mock()
    with sqlite3.connect(run) as connection:
        queue_review_event(
            connection, "evidence:local", "true_positive", [observation()]
        )
    trust.report_validation.drain_reviews(run)  # Web consumes the event first.
    trust.last_feedback_check = 0
    trust._drain_review_feedback()
    trust.trust_db.execute.assert_called_once_with("DELETE FROM opinion_cache")
    assert factory is not None
