# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from pathlib import Path
from unittest.mock import Mock

from modules.t_cell.analyze_t_cell import build_report_payload, render_html
from slips_files.core.database.sqlite_db.t_cell_db import TCellStorage


def _build_storage(run_dir: Path) -> TCellStorage:
    conf = Mock()
    conf.t_cell_store_dir = Mock(return_value="output/t_cell")
    conf.t_cell_persistent_store_dir = Mock(return_value="")
    return TCellStorage(Mock(), conf, str(run_dir), 12345)


def _raw_evidence(
    evidence_id: str,
    evidence_type: str,
    signal: str,
    related_profile_ip: str,
    attacker_ip: str,
    victim_ip: str,
    description: str,
) -> dict:
    return {
        "evidence_type": evidence_type,
        "description": description,
        "attacker": {
            "direction": "SRC",
            "ioc_type": "IP",
            "value": attacker_ip,
        },
        "victim": {
            "direction": "DST",
            "ioc_type": "IP",
            "value": victim_ip,
        },
        "profile": {"ip": related_profile_ip},
        "timewindow": {"number": 1},
        "uid": [],
        "timestamp": "2026/03/21 09:22:37.000000+0000",
        "interface": "eno1",
        "id": evidence_id,
        "confidence": 1.0,
        "threat_level": "HIGH",
        "evidence_signal": signal,
    }


def test_build_report_payload_and_html(tmp_path):
    run_dir = tmp_path / "run-output"
    (run_dir / "metadata").mkdir(parents=True)
    storage = _build_storage(run_dir)

    damp_observation_id = storage.insert_observation(
        {
            "evidence_id": "damp-1",
            "evidence_type": "HTTP_TRAFFIC",
            "evidence_signal": "DAMP",
            "profile_ip": "2001:db8::5",
            "timewindow_number": 1,
            "timestamp": "2026/03/21 09:22:37.000000+0000",
            "observed_at": 1000.0,
            "confidence": 0.9,
            "threat_level": "medium",
            "threat_level_value": 0.5,
            "interface": "eno1",
            "uids": ["uid-damp-1"],
            "antigen_count": 2,
            "antigens": [
                {"regex_type": "dns_domain", "value": "rdap.db.ripe.net"},
                {"regex_type": "uri", "value": "/ip/5.161.194.92"},
            ],
            "matched_regexes": [],
            "raw_evidence": _raw_evidence(
                "damp-1",
                "HTTP_TRAFFIC",
                "DAMP",
                "2001:db8::5",
                "2001:db8::5",
                "2001:67c:2e8:22::c100:697",
                "RDAP lookup over HTTP",
            ),
        }
    )

    pamp_observation_id = storage.insert_observation(
        {
            "evidence_id": "pamp-1",
            "evidence_type": "THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN",
            "evidence_signal": "PAMP",
            "profile_ip": "203.0.113.90",
            "timewindow_number": 2,
            "timestamp": "2026/03/21 09:23:37.000000+0000",
            "observed_at": 2000.0,
            "confidence": 1.0,
            "threat_level": "high",
            "threat_level_value": 0.8,
            "interface": "eno1",
            "uids": ["uid-pamp-1"],
            "antigen_count": 1,
            "antigens": [
                {"regex_type": "dns_domain", "value": "bad.example.com"}
            ],
            "matched_regexes": [
                {
                    "regex_type": "dns_domain",
                    "value": "bad.example.com",
                    "regex_hash": "regex-hash-1",
                    "regex": r"^bad\.example\.com$",
                    "created_at": 1990.0,
                    "specificity": 1.0,
                }
            ],
            "raw_evidence": _raw_evidence(
                "pamp-1",
                "THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN",
                "PAMP",
                "147.32.80.37",
                "203.0.113.90",
                "147.32.80.37",
                "Known malicious domain",
            ),
        }
    )

    cell_key = "203.0.113.90|dns_domain|bad.example.com"
    storage.upsert_cell(
        {
            "cell_key": cell_key,
            "profile_ip": "203.0.113.90",
            "regex_type": "dns_domain",
            "antigen_value": "bad.example.com",
            "state": 5,
            "state_name": "5 - memory",
            "matched_regex_hash": "regex-hash-1",
            "matched_regex": r"^bad\.example\.com$",
            "matched_value": "bad.example.com",
            "anergic_until": None,
            "effector_cooldown_until": None,
            "last_observation_id": pamp_observation_id,
            "last_evidence_id": "pamp-1",
            "last_transition_at": 2000.3,
            "last_co_stimulation": 0.91,
            "last_effector_score": 0.33,
            "last_memory_score": 0.78,
            "context": {
                "novelty_score": 0,
                "recent_pressure": 0.42,
                "priming_signal": "PAMP",
                "priming_label": "pamp-primed",
                "priming_strength": 1.0,
                "priming_profile": {
                    "signal": "PAMP",
                    "label": "pamp-primed",
                    "strength": 1.0,
                    "co_stimulation_threshold": 0.65,
                    "effector_threshold": 0.70,
                    "memory_threshold": 0.60,
                    "state_wait_timeout_seconds": 3600.0,
                    "effector_min_related_count": 4,
                    "memory_min_related_count": 3,
                },
            },
            "created_at": 2000.0,
            "updated_at": 2000.3,
        }
    )
    storage.upsert_cell(
        {
            "cell_key": "192.168.1.121|tls_sni|arpanet-network.com",
            "profile_ip": "192.168.1.121",
            "regex_type": "tls_sni",
            "antigen_value": "arpanet-network.com",
            "state": 3,
            "state_name": "3 - activated",
            "matched_regex_hash": "regex-hash-2",
            "matched_regex": r"arpanet-network\.com$",
            "matched_value": "arpanet-network.com",
            "anergic_until": None,
            "effector_cooldown_until": None,
            "last_observation_id": pamp_observation_id,
            "last_evidence_id": "pamp-1",
            "last_transition_at": 2000.4,
            "last_co_stimulation": 1.0,
            "last_effector_score": 0.70,
            "last_memory_score": 0.40,
            "context": {
                "waiting_for": "context",
                "waiting_since": 2000.4,
                "wait_deadline": 2060.4,
            },
            "created_at": 2000.4,
            "updated_at": 2000.4,
        }
    )
    storage.insert_transition(
        {
            "cell_key": cell_key,
            "profile_ip": "203.0.113.90",
            "regex_type": "dns_domain",
            "antigen_value": "bad.example.com",
            "evidence_id": "pamp-1",
            "observation_id": pamp_observation_id,
            "from_state": 0,
            "to_state": 1,
            "reason": "antigen_recognized",
            "matched_regex_hash": "regex-hash-1",
            "matched_regex": r"^bad\.example\.com$",
            "matched_value": "bad.example.com",
            "scores": {
                "regex_specificity": 1.0,
                "priming_signal": "PAMP",
                "priming_label": "pamp-primed",
                "priming_strength": 1.0,
                "co_stimulation_threshold": 0.65,
                "effector_threshold": 0.70,
                "memory_threshold": 0.60,
                "state_wait_timeout_seconds": 3600.0,
                "effector_min_related_count": 4,
                "memory_min_related_count": 3,
            },
            "created_at": 2000.1,
        }
    )
    storage.insert_transition(
        {
            "cell_key": cell_key,
            "profile_ip": "203.0.113.90",
            "regex_type": "dns_domain",
            "antigen_value": "bad.example.com",
            "evidence_id": "pamp-1",
            "observation_id": pamp_observation_id,
            "from_state": 1,
            "to_state": 3,
            "reason": "co_stimulation_threshold_met",
            "matched_regex_hash": "regex-hash-1",
            "matched_regex": r"^bad\.example\.com$",
            "matched_value": "bad.example.com",
            "scores": {"value": 0.91, "threshold": 0.65},
            "created_at": 2000.2,
        }
    )
    storage.insert_transition(
        {
            "cell_key": cell_key,
            "profile_ip": "203.0.113.90",
            "regex_type": "dns_domain",
            "antigen_value": "bad.example.com",
            "evidence_id": "pamp-1",
            "observation_id": pamp_observation_id,
            "from_state": 3,
            "to_state": 5,
            "reason": "context_memory",
            "matched_regex_hash": "regex-hash-1",
            "matched_regex": r"^bad\.example\.com$",
            "matched_value": "bad.example.com",
            "scores": {"memory_score": 0.78, "memory_threshold": 0.60},
            "created_at": 2000.3,
        }
    )
    storage.upsert_memory(
        {
            "cell_key": cell_key,
            "profile_ip": "203.0.113.90",
            "regex_type": "dns_domain",
            "antigen_value": "bad.example.com",
            "regex_hash": "regex-hash-1",
            "regex": r"^bad\.example\.com$",
            "matched_value": "bad.example.com",
            "context": {"memory_score": 0.78, "recent_pressure": 0.42},
            "created_at": 2000.3,
            "updated_at": 2000.3,
        }
    )

    (run_dir / "metadata" / "slips.yaml").write_text(
        "\n".join(
            [
                "t_cell:",
                "  enabled: true",
                "  log_verbosity: 3",
                "  decision_trace_mode: transitions",
                "  co_stimulation_threshold: 0.65",
                "  effector_threshold: 0.70",
                "  memory_threshold: 0.60",
            ]
        ),
        encoding="utf-8",
    )
    (run_dir / "t_cell.log").write_text(
        "\n".join(
            [
                "T Cell module ready.",
                "2026/03/21 09:22:37.597262 | action=antigens_extracted | evidence=HTTP_TRAFFIC | eid=damp-1 | signal=DAMP | profile=2001:db8::5 | responsible=2001:db8::5 | target=2001:67c:2e8:22::c100:697 | antigens=dns_domain:rdap.db.ripe.net, uri:/ip/5.161.194.92",
                "2026/03/21 09:22:37.607926 | action=damp_reverification | evidence=HTTP_TRAFFIC | eid=damp-1 | signal=DAMP | profile=2001:db8::5 | responsible=2001:db8::5 | target=2001:67c:2e8:22::c100:697 | reevaluated_cells=0",
                "2026/03/21 09:23:37.607926 | action=memory_stored | state=5 - memory | evidence=THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN | eid=pamp-1 | signal=PAMP | profile=147.32.80.37 | responsible=203.0.113.90 | target=147.32.80.37 | cell=203.0.113.90|dns_domain|bad.example.com | regex=regex-hash-1 | value=bad.example.com",
            ]
        ),
        encoding="utf-8",
    )
    (run_dir / "t_cell_trace.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "ts": "2026/03/21 09:23:37.200000+0000",
                        "stage": "co_stimulation",
                        "action": "co_stimulation_threshold_met",
                        "cell_key": cell_key,
                        "from_state": "1 - antigen-recognized",
                        "to_state": "3 - activated",
                        "responsible_ip": "203.0.113.90",
                        "candidate": {
                            "regex_type": "dns_domain",
                            "value": "bad.example.com",
                        },
                        "current_evidence": {
                            "observation_id": pamp_observation_id,
                            "evidence_id": "pamp-1",
                            "evidence_type": "THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN",
                            "signal": "PAMP",
                            "confidence": 1.0,
                            "threat_level": "high",
                            "threat_level_value": 0.8,
                            "danger_contribution": 0.8,
                        },
                        "formula": {
                            "value": 0.91,
                            "threshold": 0.65,
                            "priming": {
                                "signal": "PAMP",
                                "label": "pamp-primed",
                                "strength": 1.0,
                                "co_stimulation_threshold": 0.65,
                                "effector_threshold": 0.70,
                                "memory_threshold": 0.60,
                                "state_wait_timeout_seconds": 3600.0,
                                "effector_min_related_count": 4,
                                "memory_min_related_count": 3,
                            },
                            "components": {
                                "confidence": {
                                    "value": 1.0,
                                    "weighted": 0.35,
                                },
                                "related_pamps": {
                                    "count": 1,
                                    "saturation": 5,
                                    "score": 0.2,
                                    "weighted": 0.05,
                                    "contributors": [
                                        {
                                            "observation_id": damp_observation_id,
                                            "evidence_id": "damp-1",
                                            "evidence_type": "HTTP_TRAFFIC",
                                            "signal": "DAMP",
                                            "confidence": 0.9,
                                            "threat_level": "medium",
                                            "threat_level_value": 0.5,
                                            "danger_contribution": 0.45,
                                            "relations": ["same_antigen"],
                                        }
                                    ],
                                },
                                "danger": {
                                    "score": 0.51,
                                    "weighted": 0.204,
                                    "pamp_score": 0.32,
                                    "damp_score": 0.18,
                                    "damp_weight": 1.5,
                                    "danger_saturation": 2.5,
                                    "pamp_contributors": [],
                                    "damp_contributors": [
                                        {
                                            "observation_id": damp_observation_id,
                                            "evidence_id": "damp-1",
                                            "evidence_type": "HTTP_TRAFFIC",
                                            "signal": "DAMP",
                                            "confidence": 0.9,
                                            "threat_level": "medium",
                                            "threat_level_value": 0.5,
                                            "danger_contribution": 0.45,
                                        }
                                    ],
                                },
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "ts": "2026/03/21 09:23:37.300000+0000",
                        "stage": "context",
                        "action": "context_memory",
                        "cell_key": cell_key,
                        "from_state": "3 - activated",
                        "to_state": "5 - memory",
                        "responsible_ip": "203.0.113.90",
                        "candidate": {
                            "regex_type": "dns_domain",
                            "value": "bad.example.com",
                        },
                        "current_evidence": {
                            "observation_id": pamp_observation_id,
                            "evidence_id": "pamp-1",
                            "evidence_type": "THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN",
                            "signal": "PAMP",
                            "confidence": 1.0,
                            "threat_level": "high",
                            "threat_level_value": 0.8,
                            "danger_contribution": 0.8,
                        },
                        "formula": {
                            "effector_score": 0.33,
                            "effector_threshold": 0.70,
                            "memory_score": 0.78,
                            "memory_threshold": 0.60,
                            "priming": {
                                "signal": "PAMP",
                                "label": "pamp-primed",
                                "strength": 1.0,
                                "co_stimulation_threshold": 0.65,
                                "effector_threshold": 0.70,
                                "memory_threshold": 0.60,
                                "state_wait_timeout_seconds": 3600.0,
                                "effector_min_related_count": 4,
                                "memory_min_related_count": 3,
                            },
                            "decision": {"effector": False, "memory": True},
                            "components": {
                                "novelty": {
                                    "score": 0,
                                    "has_memory_for_regex": True,
                                    "has_recent_regex_activity": True,
                                },
                                "recent_related": {
                                    "count": 1,
                                    "saturation": 5,
                                    "score": 0.2,
                                    "contributors": [],
                                },
                                "recent_pressure": {
                                    "combined_score": 0.42,
                                    "pamp_score": 0.32,
                                    "damp_score": 0.10,
                                    "pamp_total_raw": 0.8,
                                    "damp_total_raw": 0.25,
                                    "pamp_contributors": [],
                                    "damp_contributors": [],
                                },
                                "previous_pressure": {
                                    "combined_score": 0.70,
                                    "pamp_score": 0.52,
                                    "damp_score": 0.18,
                                    "pamp_total_raw": 1.3,
                                    "damp_total_raw": 0.45,
                                    "pamp_contributors": [],
                                    "damp_contributors": [],
                                },
                                "trend_ratio": 0.6,
                                "decrease_score": 0.4,
                                "familiarity_score": 1.0,
                                "stability_score": 0.33,
                            },
                        },
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    payload = build_report_payload(run_dir, max_observations=50, max_log_lines=50, max_trace_rows=50)

    assert payload["totals"]["observations"] == 2
    assert payload["totals"]["signals"] == {"DAMP": 1, "PAMP": 1}
    assert payload["totals"]["transitions"] == 3
    assert payload["totals"]["memories"] == 1
    assert payload["cell_states"]["5 - memory"] == 1
    assert payload["cell_states"]["3 - activated"] == 1
    assert payload["sources"]["trace_enabled"] is True
    assert payload["trace"]["total_rows"] == 2
    assert payload["recent_observations"][0]["category"] == "PAMP with regex match"
    assert any(
        row["waiting_label"] == "waiting for context"
        for row in payload["recent_cells"]
    )
    assert any(
        row["category"] == "DAMP with extracted antigens"
        for row in payload["recent_observations"]
    )
    assert payload["top_responsible_ips"][0]["label"] == "2001:db8::5"

    html = render_html(payload)

    assert "T Cell Report" in html
    assert "T Cell Run Report" in html
    assert "Run Findings" in html
    assert "Quick Summary" in html
    assert "Decision Trace" in html
    assert "Decision Reference" in html
    assert "T Cell Histories" in html
    assert "T Cell State Machine" in html
    assert "accepted regex match" in html
    assert "no accepted regex match" in html
    assert "weaker priming profile" in html
    assert "co-stimulation below threshold" in html
    assert "no co-stimulation timeout" in html
    assert "current cells:" in html
    assert "Module Log Tail" not in html
    assert "data-sortable-table='recent-observations'" in html
    assert "data-sortable-table='recent-transitions'" in html
    assert "data-sortable-table='recent-cells'" in html
    assert "data-default-sort-column='4'" in html
    assert "Default order groups rows by T cell" in html
    assert "Click a column header to sort." in html
    assert html.index("Recent Observations") < html.index("Run configuration snapshot")
    assert "co_stimulation_threshold_met" in html
    assert "context_memory" in html
    assert "bad.example.com" in html
    assert "DAMP with extracted antigens" in html
    assert "PAMP with regex match" in html
    assert "waiting for context" in html
    assert "clamp01(x) = max(0, min(1, x))" in html
    assert "Recognition &amp; Priming: 0 -&gt; 1 setup" in html
    assert "Co-Stimulation: 1 -&gt; 3 activation" in html
    assert "Context Effector: 3 -&gt; 4 containment" in html
    assert "Context Memory: 3 -&gt; 5 storage" in html
    assert "Hover or focus a node to see where that term comes from." in html
    assert "related_pamp_score" in html
    assert "novelty_score" in html
    assert "recent_pressure / max(previous_pressure, 0.01)" in html
    assert "Rule-Based Decisions" in html
    assert "signal_specific_priming" in html
    assert "effector = (novelty_score &gt; 0)" in html
    assert "priming=pamp-primed" in html
    assert "Effective profile:" in html
    assert "data-report-tab=\"histories\"" in html
    assert "History Index" in html
    assert "State transition" in html
    assert "Decision trace" in html
    assert "passed: 0.910 &gt;= 0.650" in html
    assert "effector=no (0.330 / 0.700) | memory=yes (0.780 / 0.600)" in html
    assert "Chronological lifecycle view for each cell" in html
    assert "3 - activated (waiting for context)" not in html

    storage.close()
