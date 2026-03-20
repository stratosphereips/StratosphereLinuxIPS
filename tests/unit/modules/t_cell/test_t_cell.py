# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from unittest.mock import Mock, patch

from modules.t_cell.t_cell import (
    STATE_ACTIVATED,
    STATE_ANERGIC,
    STATE_ANTIGEN_RECOGNIZED,
    STATE_EFFECTOR,
    STATE_MATURE,
    STATE_MEMORY,
    AntigenCandidate,
    RegexMatch,
)
from slips_files.common.slips_utils import utils
from slips_files.core.database.sqlite_db.t_cell_db import TCellStorage
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceSignal,
    EvidenceType,
    IoCType,
    Method,
    ProfileID,
    Proto,
    ThreatLevel,
    TimeWindow,
    Victim,
)
from tests.module_factory import ModuleFactory

TEST_TS = utils.convert_ts_format(1700000000, utils.alerts_format)


def _build_storage(tmp_path):
    conf = Mock()
    conf.t_cell_store_dir = Mock(return_value="output/t_cell")
    conf.t_cell_persistent_store_dir = Mock(return_value="")
    return TCellStorage(Mock(), conf, str(tmp_path), 12345)


def _prepare_t_cell(tmp_path, log_verbosity: int = 3):
    t_cell = ModuleFactory().create_t_cell_obj()
    t_cell.output_dir = str(tmp_path)
    t_cell.log_file_path = str(tmp_path / "t_cell.log")
    storage = _build_storage(tmp_path)
    t_cell.db.get_t_cell_storage.return_value = storage
    with patch("modules.t_cell.t_cell.utils.drop_root_privs_permanently"):
        assert t_cell.pre_main() is False
    t_cell.log_verbosity = log_verbosity
    return t_cell, storage


def _build_evidence(
    evidence_id: str,
    signal: EvidenceSignal = EvidenceSignal.PAMP,
    attacker=None,
    victim=None,
    uids=None,
    profile_ip: str = "10.0.0.50",
    threat_level: ThreatLevel = ThreatLevel.HIGH,
    confidence: float = 1.0,
):
    attacker = attacker or Attacker(
        direction=Direction.SRC,
        ioc_type=IoCType.IP,
        value=profile_ip,
    )
    evidence = Evidence(
        evidence_type=EvidenceType.THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN,
        description="test evidence",
        attacker=attacker,
        victim=victim,
        threat_level=threat_level,
        profile=ProfileID(ip=profile_ip),
        timewindow=TimeWindow(number=1),
        uid=uids or ["uid-1"],
        timestamp=TEST_TS,
        proto=Proto.TCP,
        dst_port=443,
        method=Method.HEURISTIC,
        id=evidence_id,
        confidence=confidence,
    )
    evidence.evidence_signal = signal
    return evidence


def _message_for(evidence: Evidence) -> dict:
    return {"data": json.dumps(utils.to_dict(evidence))}


def _insert_observation(
    storage,
    evidence_id: str,
    profile_ip: str,
    antigens: list[dict],
    observed_at: float,
    confidence: float,
    threat_level_value: float,
    threat_level: str = "high",
    matched_regexes: list[dict] | None = None,
    evidence_signal: str = "PAMP",
):
    return storage.insert_observation(
        {
            "evidence_id": evidence_id,
            "evidence_type": "THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN",
            "evidence_signal": evidence_signal,
            "profile_ip": profile_ip,
            "timewindow_number": 1,
            "timestamp": TEST_TS,
            "observed_at": observed_at,
            "confidence": confidence,
            "threat_level": threat_level,
            "threat_level_value": threat_level_value,
            "interface": "default",
            "uids": [f"{evidence_id}-uid"],
            "antigen_count": len(antigens),
            "antigens": antigens,
            "matched_regexes": matched_regexes or [],
            "raw_evidence": {},
        }
    )


def _seed_recent_related_observations(
    storage,
    profile_ip: str,
    antigen: AntigenCandidate,
    fixed_now: float,
    count: int,
    confidence: float = 1.0,
    threat_level_value: float = 0.8,
    age_seconds: int = 300,
):
    for index in range(count):
        _insert_observation(
            storage=storage,
            evidence_id=f"hist-recent-{index}",
            profile_ip=profile_ip,
            antigens=[antigen.as_dict()],
            observed_at=fixed_now - age_seconds - index,
            confidence=confidence,
            threat_level_value=threat_level_value,
        )


def _accepted_domain_regex(regex_hash: str = "regex-hash") -> list[dict]:
    return [
        {
            "regex_type": "dns_domain",
            "regex": r"^bad\.example\.com$",
            "regex_hash": regex_hash,
            "created_at": 10,
        }
    ]


def test_extract_antigen_candidates_from_entities_and_altflows(tmp_path):
    t_cell, _ = _prepare_t_cell(tmp_path)
    attacker = Attacker(
        direction=Direction.SRC,
        ioc_type=IoCType.URL,
        value="https://download.bad.example.com/payload/run.exe?stage=2",
    )
    victim = Victim(
        direction=Direction.DST,
        ioc_type=IoCType.DOMAIN,
        value="victim.bad.example.com",
        SNI="sni.bad.example.com",
    )
    evidence = _build_evidence(
        "extract-1",
        attacker=attacker,
        victim=victim,
        uids=["dns-1", "http-1", "ssl-1"],
    )
    t_cell.db.get_altflow_from_uid.side_effect = lambda uid: {
        "dns-1": {"type_": "dns", "query": "dns.bad.example.com"},
        "http-1": {
            "type_": "http",
            "host": "http.bad.example.com",
            "uri": "/dropper/setup.exe",
        },
        "ssl-1": {
            "type_": "ssl",
            "server_name": "tls.bad.example.com",
            "subject": "C=US,O=Test,CN=cn.bad.example.com",
        },
    }[uid]

    extracted = {
        (item.regex_type, item.value)
        for item in t_cell._extract_antigen_candidates(evidence)
    }

    assert ("dns_domain", "download.bad.example.com") in extracted
    assert ("dns_domain", "victim.bad.example.com") in extracted
    assert ("dns_domain", "dns.bad.example.com") in extracted
    assert ("dns_domain", "http.bad.example.com") in extracted
    assert ("uri", "/payload/run.exe?stage=2") in extracted
    assert ("uri", "/dropper/setup.exe") in extracted
    assert ("filename", "run.exe") in extracted
    assert ("filename", "setup.exe") in extracted
    assert ("tls_sni", "sni.bad.example.com") in extracted
    assert ("tls_sni", "tls.bad.example.com") in extracted
    assert ("certificate_cn", "cn.bad.example.com") in extracted


def test_t_cell_ignores_damp_evidence(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path)
    evidence = _build_evidence("damp-1", signal=EvidenceSignal.DAMP)

    with patch("modules.t_cell.t_cell.time.time", return_value=2000.0):
        t_cell._process_evidence_message(_message_for(evidence))

    observations = storage.get_recent_observations(evidence.profile.ip, 0)
    assert len(observations) == 1
    assert observations[0]["evidence_signal"] == "DAMP"
    assert storage.get_all_cells() == []
    t_cell.db.publish.assert_not_called()
    with open(t_cell.log_file_path, encoding="utf-8") as log_file:
        assert "ignored_non_pamp" in log_file.read()


def test_t_cell_skips_pamp_without_antigens(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path)
    evidence = _build_evidence("no-antigen-1")

    with patch("modules.t_cell.t_cell.time.time", return_value=3000.0):
        t_cell._process_evidence_message(_message_for(evidence))

    assert storage.get_all_cells() == []
    assert t_cell.db.publish.call_count == 0
    with open(t_cell.log_file_path, encoding="utf-8") as log_file:
        assert "no_antigen_extracted" in log_file.read()


def test_t_cell_no_match_becomes_anergic_and_expires(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path)
    evidence = _build_evidence("anergy-1", uids=["http-1"])
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "http",
        "host": "bad.example.com",
        "uri": "/setup.exe",
    }
    t_cell.db.get_generated_regexes.return_value = []

    with patch("modules.t_cell.t_cell.time.time", return_value=4000.0):
        t_cell._process_evidence_message(_message_for(evidence))

    cell = storage.get_all_cells()[0]
    assert cell["state"] == STATE_ANERGIC
    assert cell["anergic_until"] == 4000.0 + t_cell.anergy_ttl_seconds

    evidence2 = _build_evidence("anergy-2", uids=["http-1"])
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex()
    with patch(
        "modules.t_cell.t_cell.time.time",
        return_value=4000.0 + t_cell.anergy_ttl_seconds + 1,
    ):
        t_cell._process_evidence_message(_message_for(evidence2))

    cell = storage.get_all_cells()[0]
    transitions = [
        transition["reason"]
        for transition in storage.get_transitions(cell["cell_key"])
    ]
    assert "anergy_expired" in transitions
    assert cell["state"] == STATE_ANTIGEN_RECOGNIZED


def test_t_cell_co_stimulation_times_out_after_one_tw(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path, log_verbosity=2)
    t_cell.state_wait_timeout_seconds = 100.0
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "dns",
        "query": "bad.example.com",
    }
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex(
        "timeout-regex"
    )

    first = _build_evidence(
        "costim-timeout-1",
        uids=["dns-1"],
        threat_level=ThreatLevel.LOW,
        confidence=0.1,
    )
    second = _build_evidence(
        "costim-timeout-2",
        uids=["dns-1"],
        threat_level=ThreatLevel.LOW,
        confidence=0.1,
    )

    with patch("modules.t_cell.t_cell.time.time", return_value=5_000.0):
        t_cell._process_evidence_message(_message_for(first))
    with patch("modules.t_cell.t_cell.time.time", return_value=5_101.0):
        t_cell._process_evidence_message(_message_for(second))

    cell = storage.get_all_cells()[0]
    transitions = [
        transition["reason"]
        for transition in storage.get_transitions(cell["cell_key"])
    ]
    assert "co_stimulation_timeout" in transitions
    assert cell["state"] == STATE_ANERGIC
    assert cell["anergic_until"] == 5_101.0 + t_cell.anergy_ttl_seconds


def test_find_best_regex_match_prefers_specificity_and_newest(tmp_path):
    t_cell, _ = _prepare_t_cell(tmp_path)
    t_cell.db.get_generated_regexes.return_value = [
        {
            "regex_type": "dns_domain",
            "regex": r"example\.com$",
            "regex_hash": "broad",
            "created_at": 1,
        },
        {
            "regex_type": "dns_domain",
            "regex": r"^bad\.example\.com$",
            "regex_hash": "specific-old",
            "created_at": 2,
        },
        {
            "regex_type": "dns_domain",
            "regex": r"^bad\.example\.com$",
            "regex_hash": "specific-new",
            "created_at": 3,
        },
    ]

    match = t_cell._find_best_regex_match(
        AntigenCandidate(regex_type="dns_domain", value="bad.example.com")
    )

    assert match.regex_hash == "specific-new"
    assert match.regex == r"^bad\.example\.com$"


def test_t_cell_effector_publishes_blocking_and_respects_cooldown(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path)
    fixed_now = 10_000.0
    profile_ip = "10.0.0.60"
    antigen = AntigenCandidate(regex_type="dns_domain", value="bad.example.com")
    evidence = _build_evidence("effector-1", profile_ip=profile_ip, uids=["dns-1"])
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "dns",
        "query": "bad.example.com",
    }
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex(
        "live-effector"
    )
    t_cell.db.get_pid_of.side_effect = lambda name: 123 if name == "Blocking" else None
    _seed_recent_related_observations(
        storage, profile_ip, antigen, fixed_now, count=4
    )

    with patch("modules.t_cell.t_cell.time.time", return_value=fixed_now):
        t_cell._process_evidence_message(_message_for(evidence))

    assert t_cell.db.publish.call_count == 1
    channel, payload = t_cell.db.publish.call_args.args
    assert channel == "new_blocking"
    assert json.loads(payload) == {
        "ip": profile_ip,
        "block": True,
        "tw": 1,
        "interface": None,
    }

    cell = storage.get_all_cells()[0]
    assert cell["state"] == STATE_EFFECTOR
    match = RegexMatch(
        regex_type="dns_domain",
        value="bad.example.com",
        regex_hash="live-effector",
        regex=r"^bad\.example\.com$",
        created_at=10,
        specificity=10.0,
    )
    with patch("modules.t_cell.t_cell.time.time", return_value=fixed_now + 1):
        t_cell._apply_effector(
            cell,
            evidence,
            match,
            {"effector_score": 0.95},
            fixed_now + 1,
        )

    assert t_cell.db.publish.call_count == 1
    with open(t_cell.log_file_path, encoding="utf-8") as log_file:
        assert "effector_cooldown" in log_file.read()


def test_t_cell_simulates_effector_without_blocking_modules(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path)
    fixed_now = 11_000.0
    profile_ip = "10.0.0.61"
    antigen = AntigenCandidate(regex_type="dns_domain", value="bad.example.com")
    evidence = _build_evidence("simulate-1", profile_ip=profile_ip, uids=["dns-1"])
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "dns",
        "query": "bad.example.com",
    }
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex(
        "sim-effector"
    )
    t_cell.db.get_pid_of.return_value = None
    _seed_recent_related_observations(
        storage, profile_ip, antigen, fixed_now, count=4
    )

    with patch("modules.t_cell.t_cell.time.time", return_value=fixed_now):
        t_cell._process_evidence_message(_message_for(evidence))

    assert t_cell.db.publish.call_count == 0
    assert storage.get_all_cells()[0]["state"] == STATE_EFFECTOR
    with open(t_cell.log_file_path, encoding="utf-8") as log_file:
        assert "effector_simulated" in log_file.read()


def test_t_cell_moves_to_memory_and_stores_context(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path)
    fixed_now = 12_000.0
    profile_ip = "10.0.0.62"
    antigen = AntigenCandidate(regex_type="dns_domain", value="bad.example.com")
    evidence = _build_evidence(
        "memory-1",
        profile_ip=profile_ip,
        uids=["dns-1"],
        threat_level=ThreatLevel.MEDIUM,
        confidence=0.5,
    )
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "dns",
        "query": "bad.example.com",
    }
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex(
        "memory-regex"
    )
    t_cell.db.get_pid_of.return_value = None

    for index in range(5):
        _insert_observation(
            storage=storage,
            evidence_id=f"hist-old-{index}",
            profile_ip=profile_ip,
            antigens=[antigen.as_dict()],
            observed_at=fixed_now - 2400 - index,
            confidence=1.0,
            threat_level_value=0.8,
        )
    for index in range(3):
        _insert_observation(
            storage=storage,
            evidence_id=f"hist-new-{index}",
            profile_ip=profile_ip,
            antigens=[antigen.as_dict()],
            observed_at=fixed_now - 300 - index,
            confidence=0.5,
            threat_level_value=0.5,
            threat_level="medium",
        )
    storage.upsert_memory(
        {
            "cell_key": "old-memory-cell",
            "profile_ip": "10.0.0.1",
            "regex_type": "dns_domain",
            "antigen_value": "bad.example.com",
            "regex_hash": "memory-regex",
            "regex": r"^bad\.example\.com$",
            "matched_value": "bad.example.com",
            "context": {"seeded": True},
            "created_at": fixed_now - 100,
            "updated_at": fixed_now - 100,
        }
    )

    with patch("modules.t_cell.t_cell.time.time", return_value=fixed_now):
        t_cell._process_evidence_message(_message_for(evidence))

    cell = storage.get_all_cells()[0]
    memories = storage.get_memories()
    assert cell["state"] == STATE_MEMORY
    assert any(memory["cell_key"] == cell["cell_key"] for memory in memories)


def test_t_cell_context_times_out_after_one_tw(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path, log_verbosity=2)
    t_cell.state_wait_timeout_seconds = 100.0
    profile_ip = "10.0.0.63"
    evidence_1 = _build_evidence("context-timeout-1", profile_ip=profile_ip, uids=["dns-1"])
    evidence_2 = _build_evidence("context-timeout-2", profile_ip=profile_ip, uids=["dns-1"])
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "dns",
        "query": "bad.example.com",
    }
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex(
        "context-timeout-regex"
    )
    for index in range(4):
        _insert_observation(
            storage=storage,
            evidence_id=f"danger-{index}",
            profile_ip=profile_ip,
            antigens=[
                {
                    "regex_type": "dns_domain",
                    "value": f"other-{index}.example.com",
                }
            ],
            observed_at=5_800.0 - index,
            confidence=1.0,
            threat_level_value=0.8,
        )

    with patch("modules.t_cell.t_cell.time.time", return_value=6_000.0):
        t_cell._process_evidence_message(_message_for(evidence_1))
    with patch("modules.t_cell.t_cell.time.time", return_value=6_101.0):
        t_cell._process_evidence_message(_message_for(evidence_2))

    cell = storage.get_all_cells()[0]
    transitions = [
        transition["reason"]
        for transition in storage.get_transitions(cell["cell_key"])
    ]
    assert "context_timeout" in transitions
    assert cell["state"] == STATE_MATURE


def test_t_cell_damp_observations_raise_co_stimulation(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path)
    fixed_now = 14_000.0
    profile_ip = "10.0.0.64"
    antigen = AntigenCandidate(regex_type="dns_domain", value="bad.example.com")
    evidence = _build_evidence(
        "damp-costim-1",
        profile_ip=profile_ip,
        uids=["dns-1"],
        threat_level=ThreatLevel.MEDIUM,
        confidence=0.7,
    )
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "dns",
        "query": "bad.example.com",
    }
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex(
        "damp-costim-regex"
    )
    t_cell.db.get_pid_of.return_value = None
    _seed_recent_related_observations(
        storage,
        profile_ip,
        antigen,
        fixed_now,
        count=2,
        confidence=0.5,
        threat_level_value=0.5,
    )
    _insert_observation(
        storage=storage,
        evidence_id="damp-pressure-1",
        profile_ip=profile_ip,
        antigens=[],
        observed_at=fixed_now - 30,
        confidence=1.0,
        threat_level_value=1.0,
        threat_level="critical",
        evidence_signal="DAMP",
    )

    with patch("modules.t_cell.t_cell.time.time", return_value=fixed_now):
        t_cell._process_evidence_message(_message_for(evidence))

    cell = storage.get_all_cells()[0]
    transitions = storage.get_transitions(cell["cell_key"])
    assert cell["state"] == STATE_ACTIVATED
    assert any(
        transition["reason"] == "co_stimulation_threshold_met"
        and transition["scores"]["damp_danger_score"] > 0
        for transition in transitions
    )
    assert t_cell.db.publish.call_count == 0


def test_t_cell_damp_observations_raise_context_pressure(tmp_path):
    t_cell, storage = _prepare_t_cell(tmp_path)
    fixed_now = 15_000.0
    profile_ip = "10.0.0.65"
    antigen = AntigenCandidate(regex_type="dns_domain", value="bad.example.com")
    evidence = _build_evidence(
        "damp-context-1",
        profile_ip=profile_ip,
        uids=["dns-1"],
        threat_level=ThreatLevel.LOW,
        confidence=1.0,
    )
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "dns",
        "query": "bad.example.com",
    }
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex(
        "damp-context-regex"
    )
    t_cell.db.get_pid_of.side_effect = (
        lambda name: 123 if name == "Blocking" else None
    )
    _seed_recent_related_observations(
        storage,
        profile_ip,
        antigen,
        fixed_now,
        count=4,
        confidence=1.0,
        threat_level_value=0.2,
        age_seconds=120,
    )
    _insert_observation(
        storage=storage,
        evidence_id="damp-pressure-2",
        profile_ip=profile_ip,
        antigens=[],
        observed_at=fixed_now - 20,
        confidence=1.0,
        threat_level_value=1.0,
        threat_level="critical",
        evidence_signal="DAMP",
    )

    with patch("modules.t_cell.t_cell.time.time", return_value=fixed_now):
        t_cell._process_evidence_message(_message_for(evidence))

    cell = storage.get_all_cells()[0]
    transitions = storage.get_transitions(cell["cell_key"])
    assert cell["state"] == STATE_EFFECTOR
    assert any(
        transition["reason"] == "context_effector"
        and transition["scores"]["recent_damp_pressure"] > 0
        for transition in transitions
    )
    assert t_cell.db.publish.call_count == 1


def test_t_cell_summary_log_hides_waiting_for_co_stimulation(tmp_path):
    t_cell, _ = _prepare_t_cell(tmp_path, log_verbosity=1)
    evidence = _build_evidence("pending-1", uids=["dns-1"])
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "dns",
        "query": "bad.example.com",
    }
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex(
        "pending-regex"
    )

    with patch("modules.t_cell.t_cell.time.time", return_value=13_000.0):
        t_cell._process_evidence_message(_message_for(evidence))

    with open(t_cell.log_file_path, encoding="utf-8") as log_file:
        log_contents = log_file.read()

    assert "action=antigen_recognized" in log_contents
    assert "waiting_for_co_stimulation" not in log_contents


def test_t_cell_decision_log_explains_waiting_for_co_stimulation(tmp_path):
    t_cell, _ = _prepare_t_cell(tmp_path, log_verbosity=2)
    evidence = _build_evidence("pending-2", uids=["dns-1"])
    t_cell.db.get_altflow_from_uid.return_value = {
        "type_": "dns",
        "query": "bad.example.com",
    }
    t_cell.db.get_generated_regexes.return_value = _accepted_domain_regex(
        "pending-regex"
    )

    with patch("modules.t_cell.t_cell.time.time", return_value=13_500.0):
        t_cell._process_evidence_message(_message_for(evidence))

    with open(t_cell.log_file_path, encoding="utf-8") as log_file:
        log_contents = log_file.read()

    assert "waiting_for_co_stimulation" in log_contents
    assert "score=" in log_contents
    assert "threshold=" in log_contents
    assert "related_pamps=" in log_contents


def test_t_cell_log_file_contains_color_codes(tmp_path):
    t_cell, _ = _prepare_t_cell(tmp_path)
    evidence = _build_evidence("log-1")

    t_cell._log_event(
        action="test_log",
        state=STATE_EFFECTOR,
        evidence=evidence,
        metrics={"score": 0.95},
        verbosity=3,
    )

    with open(t_cell.log_file_path, encoding="utf-8") as log_file:
        log_contents = log_file.read()

    assert "\033[" in log_contents
    assert "4 - effector" in log_contents
