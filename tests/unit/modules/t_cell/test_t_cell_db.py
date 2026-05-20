# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock

from slips_files.core.database.sqlite_db.t_cell_db import TCellStorage


def _build_storage(tmp_path, persistent_store_dir: str = ""):
    conf = Mock()
    conf.t_cell_store_dir = Mock(return_value="output/t_cell")
    conf.t_cell_persistent_store_dir = Mock(
        return_value=persistent_store_dir
    )
    return TCellStorage(Mock(), conf, str(tmp_path), 12345)


def test_t_cell_storage_uses_persistent_store_dir_when_configured(tmp_path):
    persistent_dir = tmp_path / "persistent-store"
    storage = _build_storage(tmp_path, persistent_store_dir=str(persistent_dir))

    assert storage.store_dir == str(persistent_dir)
    assert storage.db.db_path == str(persistent_dir / "t_cell.sqlite")
    storage.close()


def test_t_cell_storage_resolves_relative_persistent_store_dir_inside_permanent_dir(
    tmp_path, monkeypatch
):
    permanent_dir = tmp_path / "permanent"
    monkeypatch.setattr(
        "slips_files.core.database.sqlite_db.t_cell_db."
        "get_this_filepath_inside_permanent_dir",
        lambda filename: str(permanent_dir / filename),
    )
    storage = _build_storage(tmp_path, persistent_store_dir="t_cell")

    assert storage.store_dir == str(permanent_dir / "t_cell")
    assert storage.db.db_path == str(
        permanent_dir / "t_cell" / "t_cell.sqlite"
    )
    storage.close()


def test_t_cell_storage_crud_and_pruning(tmp_path):
    storage = _build_storage(tmp_path)
    observation_id = storage.insert_observation(
        {
            "evidence_id": "obs-1",
            "evidence_type": "THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN",
            "evidence_signal": "PAMP",
            "profile_ip": "10.0.0.50",
            "timewindow_number": 1,
            "timestamp": "2023/11/14 22:13:20.000000+0000",
            "observed_at": 100.0,
            "confidence": 0.9,
            "threat_level": "high",
            "threat_level_value": 0.8,
            "interface": "default",
            "uids": ["uid-1"],
            "antigen_count": 1,
            "antigens": [{"regex_type": "dns_domain", "value": "bad.example.com"}],
            "matched_regexes": [],
            "raw_evidence": {"id": "obs-1"},
        }
    )

    storage.update_observation_matches(
        observation_id,
        [
            {
                "regex_type": "dns_domain",
                "value": "bad.example.com",
                "regex_hash": "hash-1",
                "regex": r"^bad\.example\.com$",
            }
        ],
    )
    storage.upsert_cell(
        {
            "cell_key": "10.0.0.50|dns_domain|bad.example.com",
            "profile_ip": "10.0.0.50",
            "regex_type": "dns_domain",
            "antigen_value": "bad.example.com",
            "state": 4,
            "state_name": "4 - effector",
            "matched_regex_hash": "hash-1",
            "matched_regex": r"^bad\.example\.com$",
            "matched_value": "bad.example.com",
            "anergic_until": None,
            "effector_cooldown_until": 500.0,
            "last_observation_id": observation_id,
            "last_evidence_id": "obs-1",
            "last_transition_at": 100.0,
            "last_co_stimulation": 0.9,
            "last_effector_score": 0.95,
            "last_memory_score": 0.1,
            "context": {"state": "effector"},
            "created_at": 100.0,
            "updated_at": 100.0,
        }
    )
    storage.insert_transition(
        {
            "cell_key": "10.0.0.50|dns_domain|bad.example.com",
            "profile_ip": "10.0.0.50",
            "regex_type": "dns_domain",
            "antigen_value": "bad.example.com",
            "evidence_id": "obs-1",
            "observation_id": observation_id,
            "from_state": 3,
            "to_state": 4,
            "reason": "context_effector",
            "matched_regex_hash": "hash-1",
            "matched_regex": r"^bad\.example\.com$",
            "matched_value": "bad.example.com",
            "scores": {"effector_score": 0.95},
            "created_at": 100.0,
        }
    )
    storage.upsert_memory(
        {
            "cell_key": "10.0.0.50|dns_domain|bad.example.com",
            "profile_ip": "10.0.0.50",
            "regex_type": "dns_domain",
            "antigen_value": "bad.example.com",
            "regex_hash": "hash-1",
            "regex": r"^bad\.example\.com$",
            "matched_value": "bad.example.com",
            "context": {"memory_score": 0.7},
            "created_at": 100.0,
            "updated_at": 100.0,
        }
    )

    observation = storage.get_observation(observation_id)
    cells = storage.get_all_cells()
    transitions = storage.get_transitions()
    memories = storage.get_memories()

    assert observation["matched_regexes"][0]["regex_hash"] == "hash-1"
    assert cells[0]["state"] == 4
    assert transitions[0]["reason"] == "context_effector"
    assert memories[0]["regex_hash"] == "hash-1"
    assert storage.has_recent_regex_activity(
        "10.0.0.50", "hash-1", since_ts=50.0
    )
    assert storage.has_memory_for_regex("hash-1") is True

    storage.prune_observations(101.0)
    assert storage.get_recent_observations("10.0.0.50", 0) == []
