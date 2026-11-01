"""Exercise peer agreement rewards and their permanent target deduplication."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modules.p2p_trust.trust.base_model import BaseModel, peer_trust_details
from modules.p2p_trust.trust.report_validation import AgreementPolicy, ReportValidator
from tests.module_factory import ModuleFactory
from tests.unit.modules.p2p_trust.trust.test_report_validation import observation, report, review


@pytest.mark.parametrize("condition,expected", [
    ("matching", 1), ("slight_skew", 1), ("no_local", 0), ("one_peer", 0),
    ("same_peer", 0), ("other_target", 0), ("other_type", 0),
    ("other_port", 0), ("missing_anchor_port", 0), ("other_network", 0), ("stale", 0),
    ("spread", 0), ("low_local_confidence", 0), ("low_peer_confidence", 0),
    ("low_reporter_confidence", 0), ("local_fp", 0), ("peer_fp", 0),
    ("disabled", 0), ("three_required", 0), ("lower_confidence", 1),
])
def test_agreement_requires_local_and_distinct_peers(
    tmp_path: Path, condition: str, expected: int,
) -> None:
    """Reward matching behavior only with a local witness and distinct senders.

    Parameters:
        tmp_path: Isolated persistent ledger.
        condition: Missing, mismatching, reviewed or qualifying witness case.
        expected: Whether each reporting peer earns one positive case.
    """
    _factory = ModuleFactory()
    settings = {"enabled": condition != "disabled"}
    if condition == "three_required":
        settings["min_peers"] = 3
    if condition == "lower_confidence":
        settings["min_confidence"] = 0.5
    validator = ReportValidator(tmp_path / "validation.sqlite", settings)
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793000000):
        local, first, second = observation(), report(), report("second", peer="peer-B")
        if condition == "slight_skew":
            first["provenance"][0]["observed_at"] += 1
            second["provenance"][0]["observed_at"] += 2
        if condition == "same_peer":
            second["peer_id"] = first["peer_id"]
            second["provenance"][0]["rule_version"] = "other-version"
        if condition == "other_target":
            second = report("second", peer="peer-B", target="192.168.1.186")
        if condition == "other_type":
            second["provenance"][0]["evidence_type"] = "UNKNOWN_PORT"
        if condition in {"other_port", "missing_anchor_port"}:
            local["provenance"]["dst_port"] = 445
            if condition == "other_port":
                first["provenance"][0]["dst_port"] = 445
            second["provenance"][0]["dst_port"] = 443
        if condition == "other_network":
            second["network_id"] = "gateway:office"
            second["target_key"] = "gateway:office|192.168.1.185"
        if condition in {"stale", "spread"}:
            second["provenance"][0]["observed_at"] -= 3601 if condition == "stale" else 3500
            if condition == "spread":
                local["observed_at"] += 3500
        if condition in {"low_local_confidence", "lower_confidence"}:
            local["confidence"] = 0.6
        if condition in {"low_peer_confidence", "lower_confidence"}:
            second["confidence"] = 0.6
        if condition == "low_reporter_confidence":
            first["confidence"] = 0.6
        if condition != "no_local":
            validator.observe_local(local)
        if condition == "local_fp":
            validator.apply_review(review(local, "false_positive"))
        validator.observe_report(first)
        if condition != "one_peer":
            validator.observe_report(second)
        if condition == "peer_fp":
            validator.apply_review(review(second, "false_positive"))
        learned = validator.peer_agreement("peer-A")
        assert learned["targets"] == expected
        assert learned["adjustment"] == pytest.approx(0.025 * expected)
        assert validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")["confirmed"] == 0


def test_agreement_survives_restart_versions_networks_and_repetition(tmp_path: Path) -> None:
    """Never renew a reward for the same peer ID and target IP.

    Parameters:
        tmp_path: Persistent ledger carried across restarts.
    """
    _factory = ModuleFactory()
    path = tmp_path / "validation.sqlite"
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793000000):
        validator = ReportValidator(path)
        local, first, second = observation(), report(), report("second", peer="peer-B")
        validator.observe_local(local)
        validator.observe_report(first)
        validator.observe_report(second)
        with validator.connect() as connection:
            earned = connection.execute("SELECT earned_at FROM credits WHERE peer_id='peer-A'").fetchone()[0]
        for _ in range(20):
            validator.observe_report(first)
            validator.observe_report(second)
        validator = ReportValidator(path)
        assert validator.peer_agreement("peer-A") == {"adjustment": 0.025, "targets": 1}
        local["id"] = "new-local"
        local["network_id"] = "gateway:office"
        local["target_key"] = "gateway:office|192.168.1.185"
        local["provenance"]["rule_version"] = "new-version"
        validator.observe_local(local)
        for item in (first, second):
            item["network_id"] = local["network_id"]
            item["target_key"] = local["target_key"]
            item["provenance"][0]["rule_version"] = "new-version"
            validator.observe_report(item)
        assert validator.peer_agreement("peer-A")["targets"] == 1
        with validator.connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM credits WHERE peer_id='peer-A'").fetchone()[0] == 1
            assert connection.execute("SELECT earned_at FROM credits WHERE peer_id='peer-A'").fetchone()[0] == earned
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793000000 + 30 * 86400):
        assert validator.peer_agreement("peer-A")["adjustment"] == pytest.approx(0.0125)


def test_agreement_review_retracts_and_restores_original_reward(tmp_path: Path) -> None:
    """FP and withdrawn verdicts update the original case without a second reward.

    Parameters:
        tmp_path: Isolated persistent ledger.
    """
    _factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793000000):
        local = observation()
        validator.observe_local(local)
        validator.observe_report(report())
        validator.observe_report(report("second", peer="peer-B"))
        validator.apply_review(review(local, "false_positive"))
        assert validator.peer_agreement("peer-A")["adjustment"] == 0
        validator.apply_review(review(local, "unreviewed", revision=2))
        assert validator.peer_agreement("peer-A") == {"adjustment": 0.025, "targets": 1}
        validator.apply_review(review(local, "true_positive", revision=3))
        assert validator.peer_agreement("peer-A")["adjustment"] == 0.025


def test_agreement_changes_actual_report_weight_and_is_capped(tmp_path: Path) -> None:
    """Apply learned trust to report weighting and cap rewards across targets.

    Parameters:
        tmp_path: Isolated persistent ledger.
    """
    _factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793000000):
        for index in range(10):
            target = f"192.168.1.{100 + index}"
            validator.observe_local(observation(f"local-{index}", target=target))
            validator.observe_report(report(f"first-{index}", target=target))
            validator.observe_report(report(f"second-{index}", peer="peer-B", target=target))
            if index == 0:
                trustdb = Mock()
                trustdb.get_ip_of_peer.return_value = (1793000000, "192.0.2.1")
                trustdb.get_reporter_reliability.return_value = 1
                model = BaseModel(Mock(), trustdb, Mock(), validator, lambda: "gateway:home")
                score, confidence = model.get_opinion_on_ip(target)
                assert score == 1
                assert confidence == pytest.approx(0.375)
                assert validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")["adjustment"] == 0
        assert validator.peer_agreement("peer-A") == {"adjustment": 0.2, "targets": 10}
        assert peer_trust_details(1, 0.5, 0, agreement_credit=0.2)["trust"] == pytest.approx(0.55)
        assert peer_trust_details(1, 1, 1, agreement_credit=0.2)["trust"] == pytest.approx(-0.15)


def test_original_agreement_proof_survives_latest_report_replacement(tmp_path: Path) -> None:
    """Retain the credited event when peers later send newer reports about it.

    Parameters:
        tmp_path: Persistent ledger holding the original supporting records.
    """
    _factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793000000):
        validator.observe_local(observation())
        validator.observe_report(report())
        validator.observe_report(report("second", peer="peer-B"))
        revision = validator.feedback_revision()
        validator.observe_report(report())
        assert validator.feedback_revision() == revision
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793007200):
        validator.observe_report(report("new-first"))
        validator.observe_report(report("new-second", peer="peer-B"))
        validator.reconcile_target("gateway:home|192.168.1.185")
        learned = validator.peer_agreement("peer-A")
        assert learned["targets"] == 1
        assert learned["adjustment"] == pytest.approx(0.025 * 2 ** (-7200 / (30 * 86400)))
        with validator.connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM observations WHERE json_extract(data, '$.peer_id')<>''").fetchone()[0] == 2


def test_old_duplicate_positive_cases_cannot_multiply_reward(tmp_path: Path) -> None:
    """Deduplicate pre-upgrade rewards for the same IP on multiple networks.

    Parameters:
        tmp_path: Ledger emulating older network-scoped credits.
    """
    _factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793000000):
        validator.observe_local(observation())
        validator.observe_report(report())
        validator.observe_report(report("second", peer="peer-B"))
        with validator.connect() as connection:
            connection.execute("DELETE FROM positive_targets")
            connection.execute("INSERT INTO credits SELECT peer_id, 'gateway:office|192.168.1.185', evidence_type, rule_version, verdict, reason, report_data, earned_at+1, changed_at FROM credits WHERE peer_id='peer-A'")
        assert validator.peer_agreement("peer-A")["targets"] == 1
        assert validator.peer_agreement("peer-A")["adjustment"] == 0.025


@pytest.mark.parametrize("offsets,expected", [((-3500, 3500), 0), ((-1700, 1700), 1), ((-3500, -3400), 1)])
def test_all_witnesses_fit_one_time_window(
    tmp_path: Path, offsets: tuple[int, int], expected: int,
) -> None:
    """Require the entire multi-peer group to fit one configured time span.

    Parameters:
        tmp_path: Isolated persistent ledger.
        offsets: Two witnesses' detection-time offsets from the local event.
        expected: Whether the claimant has the three-peer agreement required.
    """
    _factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite", {"min_peers": 3})
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793000000):
        validator.observe_local(observation())
        validator.observe_report(report())
        for index, offset in enumerate(offsets):
            witness = report(f"witness-{index}", peer=f"peer-{index}")
            witness["provenance"][0]["observed_at"] += offset
            validator.observe_report(witness)
        assert validator.peer_agreement("peer-A")["targets"] == expected


def test_equivalent_ipv6_targets_share_one_lifetime_reward(tmp_path: Path) -> None:
    """Treat expanded and compressed forms of one IP as the same reward target.

    Parameters:
        tmp_path: Isolated persistent ledger.
    """
    _factory = ModuleFactory()
    validator = ReportValidator(tmp_path / "validation.sqlite")
    with patch("modules.p2p_trust.trust.report_validation.time.time", return_value=1793000000):
        for target in ("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"):
            validator.observe_local(observation(f"local-{target}", target=target))
            validator.observe_report(report(f"first-{target}", target=target))
            validator.observe_report(report(f"second-{target}", peer="peer-B", target=target))
        assert validator.peer_agreement("peer-A") == {"adjustment": 0.025, "targets": 1}


@pytest.mark.parametrize("settings,expected", [
    (None, AgreementPolicy()),
    ({"enabled": False}, AgreementPolicy(enabled=False)),
    ({"min_peers": 3, "min_confidence": 0.9, "window_seconds": 60, "trust_credit": 0.01},
     AgreementPolicy(min_peers=3, min_confidence=0.9, window_seconds=60, trust_credit=0.01)),
    ({"min_peers": 1, "min_confidence": float("nan"), "window_seconds": -1, "trust_credit": 1}, AgreementPolicy()),
])
def test_agreement_policy(settings: object, expected: AgreementPolicy) -> None:
    """Validate configurable thresholds without disabling required local witnesses.

    Parameters:
        settings: YAML policy input.
        expected: Validated settings or safe defaults.
    """
    _factory = ModuleFactory()
    assert AgreementPolicy.from_config(settings) == expected
