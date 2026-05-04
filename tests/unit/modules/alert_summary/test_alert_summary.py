# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import time

from modules.alert_summary.alert_summary import (
    PROMPT_VERSION,
    REDUCTION_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.alerts import Alert
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceType,
    IoCType,
    ProfileID,
    ThreatLevel,
    TimeWindow,
)
from tests.module_factory import ModuleFactory


def _build_evidence():
    return Evidence(
        evidence_type=EvidenceType.CONNECTION_WITHOUT_DNS,
        description="Connection to 203.0.113.10 without a preceding DNS lookup.",
        attacker=Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value="192.168.1.25",
        ),
        threat_level=ThreatLevel.MEDIUM,
        profile=ProfileID("192.168.1.25"),
        timewindow=TimeWindow(7),
        uid=["uid-1", "uid-2"],
        timestamp="2026/04/28 10:00:00.000000+0000",
        confidence=0.8,
        dst_port=443,
    )


def _build_alert(evidence):
    return Alert(
        profile=ProfileID("192.168.1.25"),
        timewindow=TimeWindow(
            7,
            start_time="2026-04-28T09:00:00+00:00",
            end_time="2026-04-28T10:00:00+00:00",
        ),
        last_evidence=evidence,
        accumulated_threat_level=1.2,
        last_flow_datetime="2026/04/28 10:00:00.000000+0000",
        correl_id=[evidence.id],
    )


def test_alert_summary_config_defaults():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {}

    assert parser.alert_summary_enabled() is False
    assert parser.alert_summary_allowed_backends() == []
    assert parser.alert_summary_log_verbosity() == 2
    assert parser.alert_summary_llm_temperature() == 0.2
    assert parser.alert_summary_llm_max_tokens() == 220
    assert parser.alert_summary_llm_response_timeout_seconds() == 120
    assert parser.alert_summary_history_enabled() is False
    assert parser.alert_summary_history_max_alerts() == 3
    assert parser.alert_summary_history_max_tokens() == 700
    assert parser.alert_summary_history_patterns_per_alert() == 2


def test_alert_summary_config_sanitization():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {
        "alert_summary": {
            "enabled": "true",
            "allowed_backends": "local_qwen",
            "log_verbosity": 99,
            "llm_temperature": "bad",
            "llm_max_tokens": "bad",
            "llm_response_timeout_seconds": -10,
            "history_enabled": "true",
            "history_max_alerts": "bad",
            "history_max_tokens": -10,
            "history_patterns_per_alert": "bad",
        }
    }

    assert parser.alert_summary_enabled() is True
    assert parser.alert_summary_allowed_backends() == []
    assert parser.alert_summary_log_verbosity() == 3
    assert parser.alert_summary_llm_temperature() == 0.2
    assert parser.alert_summary_llm_max_tokens() == 220
    assert parser.alert_summary_llm_response_timeout_seconds() == 0
    assert parser.alert_summary_history_enabled() is True
    assert parser.alert_summary_history_max_alerts() == 3
    assert parser.alert_summary_history_max_tokens() == 0
    assert parser.alert_summary_history_patterns_per_alert() == 2


def test_build_prompt_messages_uses_incident_metadata_and_digest():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    evidence = _build_evidence()
    alert = _build_alert(evidence)

    messages = alert_summary._build_prompt_messages(
        alert,
        ["10:00 | Connection to 203.0.113.10 without a preceding DNS lookup."],
        1,
        1,
        0,
    )

    assert messages[0]["content"] == SYSTEM_PROMPT
    assert "INCIDENT METADATA:" in messages[1]["content"]
    assert "CURRENT ALERT EVIDENCE DIGEST:" in messages[1]["content"]
    assert "Grouped Evidence Patterns: 1" in messages[1]["content"]
    assert "Prompt version: alert-summary-v2" in messages[1]["content"]
    assert "RECENT ALERT HISTORY" not in messages[1]["content"]


def test_build_prompt_messages_includes_recent_history_for_same_profile():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    prior_alert = _build_alert(_build_evidence())
    prior_alert.timewindow = TimeWindow(
        6,
        start_time="2026-04-28T08:00:00+00:00",
        end_time="2026-04-28T09:00:00+00:00",
    )
    alert_summary._remember_alert_summary(
        prior_alert,
        "Earlier scanning activity suggests reconnaissance.",
        [
            "08:10 | Horizontal port scan to port 443/TCP",
            "08:15 | Repeated unknown-port traffic to 198.51.100.10",
        ],
    )

    current_alert = _build_alert(_build_evidence())
    messages = alert_summary._build_prompt_messages(
        current_alert,
        ["10:00 | Connection to 203.0.113.10 without a preceding DNS lookup."],
        1,
        1,
        0,
    )

    assert "RECENT ALERT HISTORY" in messages[1]["content"]
    assert "HISTORICAL PROGRESSION" in messages[1]["content"]
    assert "Earlier scanning activity suggests reconnaissance." in messages[1]["content"]
    assert "Horizontal port scan to port 443/TCP" in messages[1]["content"]
    assert "continuation, escalation, repetition, diversification, or a different pattern" in messages[1]["content"]
    assert "recurrence raises, lowers, or does not materially change confidence and urgency" in messages[1]["content"]


def test_analyze_recent_history_counts_repeated_pattern_overlap():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    prior_alert = _build_alert(_build_evidence())
    prior_alert.timewindow = TimeWindow(6)
    alert_summary._remember_alert_summary(
        prior_alert,
        "Earlier scan summary.",
        [
            "09:15 | Connection to 203.0.113.10 without a preceding DNS lookup.",
            "09:20 | Horizontal port scan to port 443/TCP",
        ],
    )
    alert = _build_alert(_build_evidence())

    history_analysis = alert_summary._analyze_recent_history(
        alert,
        alert_summary._get_recent_alert_history(alert),
        [
            "10:00 | Connection to 203.0.113.10 without a preceding DNS lookup.",
            "10:05 | Connection to 203.0.113.11 without a preceding DNS lookup.",
        ],
    )

    assert history_analysis["prior_alert_count"] == 1
    assert history_analysis["matching_alert_count"] == 1
    assert history_analysis["repeated_pattern_count"] >= 1
    assert history_analysis["same_timewindow_alert_count"] == 0


def test_remember_alert_summary_keeps_only_recent_entries_per_profile():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.history_max_alerts = 2

    first_alert = _build_alert(_build_evidence())
    first_alert.timewindow = TimeWindow(5)
    second_alert = _build_alert(_build_evidence())
    second_alert.timewindow = TimeWindow(6)
    third_alert = _build_alert(_build_evidence())
    third_alert.timewindow = TimeWindow(7)

    alert_summary._remember_alert_summary(
        first_alert,
        "first summary",
        ["05:00 | first pattern"],
    )
    alert_summary._remember_alert_summary(
        second_alert,
        "second summary",
        ["06:00 | second pattern"],
    )
    alert_summary._remember_alert_summary(
        third_alert,
        "third summary",
        ["07:00 | third pattern"],
    )

    stored_history = list(
        alert_summary.alert_history_by_profile[str(third_alert.profile)]
    )

    assert len(stored_history) == 2
    assert stored_history[0]["summary_text"] == "second summary"
    assert stored_history[1]["summary_text"] == "third summary"


def test_build_grouped_evidence_items_merges_similar_descriptions():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    first_evidence = _build_evidence()
    second_evidence = _build_evidence()
    second_evidence.id = "evidence-2"
    second_evidence.description = (
        "Connection to 203.0.113.11 without a preceding DNS lookup."
    )
    second_evidence.timestamp = "2026/04/28 10:05:00.000000+0000"

    grouped_items = alert_summary._build_grouped_evidence_items(
        [first_evidence, second_evidence]
    )

    assert len(grouped_items) == 1
    assert "2x similar" in grouped_items[0]
    assert "203.0.113.10" in grouped_items[0]
    assert "203.0.113.11" in grouped_items[0]


def test_split_text_to_budget_preserves_content_without_truncation():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    text = " ".join(
        [
            "Repeated outbound HTTPS session to 203.0.113.10 after no DNS lookup."
            for _ in range(20)
        ]
    )

    parts = alert_summary._split_text_to_budget(text, 40)

    assert len(parts) > 1
    assert "..." not in " ".join(parts)
    assert "Repeated outbound HTTPS session" in parts[0]
    assert "no DNS lookup" in parts[-1]


def test_advance_active_job_starts_reduction_when_final_prompt_is_too_large(
    mocker,
):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    evidence = _build_evidence()
    alert = _build_alert(evidence)
    alert_summary.active_job = {
        "alert": alert,
        "evidences": [evidence],
        "backend": "local_qwen",
        "grouped_item_count": 2,
        "current_items": [
            "10:00 | repeated connection one",
            "10:05 | repeated connection two",
        ],
        "reduction_layer": 0,
        "current_chunks": [],
        "completed_chunk_summaries": [],
    }

    def _messages_fit(messages, _budget):
        return messages[0]["content"] == REDUCTION_SYSTEM_PROMPT

    mocker.patch.object(alert_summary, "_messages_fit", side_effect=_messages_fit)
    mocker.patch.object(
        alert_summary,
        "_chunk_items_for_reduction",
        return_value=[["10:00 | repeated connection one"], ["10:05 | repeated connection two"]],
    )

    alert_summary._advance_active_job()

    channel, payload = alert_summary.db.publish.call_args.args
    request = json.loads(payload)

    assert channel == "llm_request"
    assert request["metadata"]["chunk_index"] == 1
    assert request["metadata"]["chunk_count"] == 2
    assert alert_summary.pending_request["phase"] == "reduction"


def test_reduction_response_advances_to_final_summary(mocker):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    evidence = _build_evidence()
    alert = _build_alert(evidence)
    alert_summary.active_job = {
        "alert": alert,
        "evidences": [evidence],
        "backend": "local_qwen",
        "grouped_item_count": 2,
        "current_items": [
            "10:00 | repeated connection one",
            "10:05 | repeated connection two",
        ],
        "reduction_layer": 0,
        "current_chunks": [["10:00 | repeated connection one"], ["10:05 | repeated connection two"]],
        "completed_chunk_summaries": ["first digest"],
    }
    alert_summary.pending_request = {
        "request_id": "req-1",
        "backend": "local_qwen",
        "alert": alert,
        "evidences": [evidence],
        "phase": "reduction",
        "sent_at": time.time(),
        "metadata": {
            "reduction_layer": 1,
            "chunk_index": 2,
            "chunk_count": 2,
        },
    }
    mocker.patch.object(alert_summary, "_messages_fit", return_value=True)

    alert_summary._finalize_request(
        {
            "request_id": "req-1",
            "success": True,
            "text": "second digest",
        }
    )

    channel, payload = alert_summary.db.publish.call_args.args
    request = json.loads(payload)

    assert channel == "llm_request"
    assert request["metadata"]["reduction_layer"] == 1
    assert alert_summary.active_job["current_items"] == [
        "first digest",
        "second digest",
    ]
    assert alert_summary.active_job["reduction_layer"] == 1
    assert alert_summary.pending_request["phase"] == "final_summary"


def test_handle_pending_response_writes_one_paragraph_summary(tmp_path, mocker):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.parent_output_dir = str(tmp_path)
    alert_summary.summary_log_path = str(
        tmp_path / "alerts" / "alerts-summary.log"
    )
    alert_summary.operation_log_path = str(
        tmp_path / "llm-summary" / "alert_summary.log"
    )
    mocker.patch(
        "modules.alert_summary.alert_summary.utils.drop_root_privs_permanently"
    )
    alert_summary.pre_main()

    evidence = _build_evidence()
    alert = _build_alert(evidence)
    alert_summary.active_job = {
        "alert": alert,
        "evidences": [evidence],
        "backend": "local_qwen",
        "grouped_item_count": 1,
        "current_items": ["10:00 | Connection to 203.0.113.10 without a preceding DNS lookup."],
        "reduction_layer": 0,
        "current_chunks": [],
        "completed_chunk_summaries": [],
    }
    alert_summary.pending_request = {
        "request_id": "req-1",
        "backend": "local_qwen",
        "alert": alert,
        "evidences": [evidence],
        "phase": "final_summary",
        "sent_at": time.time(),
        "metadata": {"prompt_version": PROMPT_VERSION},
    }
    alert_summary.get_msg = lambda _channel: {
        "data": json.dumps(
            {
                "request_id": "req-1",
                "success": True,
                "text": "Likely true positive.\n\nRepeated outbound behavior suggests beaconing.",
            }
        )
    }

    alert_summary._handle_pending_response()

    with open(alert_summary.summary_log_path, "r", encoding="utf-8") as handle:
        content = handle.read()
    with open(alert_summary.operation_log_path, "r", encoding="utf-8") as handle:
        operation_content = handle.read()

    assert "Likely true positive. Repeated outbound behavior suggests beaconing." in content
    assert "\n\n" not in content
    assert "phase=final_summary" in operation_content
    assert alert_summary.pending_request is None
    assert alert_summary.active_job is None
    alert_summary.shutdown_gracefully()


def test_handle_pending_response_does_not_timeout_during_shutdown(
    tmp_path, mocker
):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.parent_output_dir = str(tmp_path)
    alert_summary.summary_log_path = str(
        tmp_path / "alerts" / "alerts-summary.log"
    )
    alert_summary.operation_log_path = str(
        tmp_path / "llm-summary" / "alert_summary.log"
    )
    mocker.patch(
        "modules.alert_summary.alert_summary.utils.drop_root_privs_permanently"
    )
    mocker.patch("modules.alert_summary.alert_summary.time.time", return_value=200)
    alert_summary.pre_main()

    evidence = _build_evidence()
    alert = _build_alert(evidence)
    alert_summary.active_job = {
        "alert": alert,
        "evidences": [evidence],
        "backend": "local_qwen",
        "grouped_item_count": 1,
        "current_items": ["10:00 | Connection to 203.0.113.10 without a preceding DNS lookup."],
        "reduction_layer": 0,
        "current_chunks": [],
        "completed_chunk_summaries": [],
    }
    alert_summary.pending_request = {
        "request_id": "req-shutdown",
        "backend": "local_qwen",
        "alert": alert,
        "evidences": [evidence],
        "phase": "final_summary",
        "sent_at": 0,
        "metadata": {"prompt_version": PROMPT_VERSION},
    }
    alert_summary.termination_event.is_set.return_value = True
    alert_summary.get_msg = lambda _channel: None

    alert_summary._handle_pending_response()

    with open(alert_summary.summary_log_path, "r", encoding="utf-8") as handle:
        content = handle.read()
    with open(alert_summary.operation_log_path, "r", encoding="utf-8") as handle:
        operation_content = handle.read()

    assert content == ""
    assert alert_summary.pending_request is not None
    assert "keeping alert_summary alive" in operation_content
    alert_summary.shutdown_gracefully()


def test_main_flushes_pending_alerts_without_backend_on_shutdown(
    tmp_path, mocker
):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.parent_output_dir = str(tmp_path)
    alert_summary.summary_log_path = str(
        tmp_path / "alerts" / "alerts-summary.log"
    )
    alert_summary.operation_log_path = str(
        tmp_path / "llm-summary" / "alert_summary.log"
    )
    mocker.patch(
        "modules.alert_summary.alert_summary.utils.drop_root_privs_permanently"
    )
    alert_summary.pre_main()

    evidence = _build_evidence()
    alert = _build_alert(evidence)
    alert_summary.pending_alerts.append(
        {"alert": alert, "evidences": [evidence]}
    )
    alert_summary.db.get_available_llm_backends.return_value = {
        "default_backend": "",
        "backends": {},
    }
    alert_summary.termination_event.is_set.return_value = True
    alert_summary._queue_new_alert = lambda: None

    alert_summary.main()

    with open(alert_summary.summary_log_path, "r", encoding="utf-8") as handle:
        content = handle.read()

    assert "LLM summary unavailable (No runtime-ready LLM backend available.)." in content
    assert "Local heuristic summary:" in content
    assert not alert_summary.pending_alerts
    alert_summary.shutdown_gracefully()


def test_should_stop_waits_for_pending_alerts_during_shutdown():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.pending_alerts.append({"alert": _build_alert(_build_evidence())})
    alert_summary.termination_event.is_set.return_value = True

    assert alert_summary.should_stop() is False


def test_should_stop_ignores_stale_llm_response_channel_after_work_finishes():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.channel_tracker = alert_summary.init_channel_tracker()
    alert_summary.termination_event.is_set.return_value = True
    alert_summary.channel_tracker["llm_response"]["msg_received"] = True
    alert_summary.channel_tracker["new_alert"]["msg_received"] = False

    assert alert_summary.should_stop() is True


def test_should_stop_waits_for_pending_shared_llm_request_count():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.channel_tracker = alert_summary.init_channel_tracker()
    alert_summary.termination_event.is_set.return_value = True
    alert_summary.channel_tracker["new_alert"]["msg_received"] = False
    alert_summary.db.get_pending_llm_request_count.return_value = 2

    assert alert_summary.should_stop() is False


def test_should_stop_waits_for_alive_evidence_handler_on_shutdown(mocker):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.channel_tracker = alert_summary.init_channel_tracker()
    alert_summary.termination_event.is_set.return_value = True
    alert_summary.channel_tracker["new_alert"]["msg_received"] = False
    alert_summary.db.get_pid_of.return_value = 43210
    mocker.patch.object(
        alert_summary,
        "_is_process_alive",
        return_value=True,
    )

    assert alert_summary.should_stop() is False


def test_get_alert_evidence_handles_mixed_timestamp_types_without_crashing():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    first_evidence = _build_evidence()
    second_evidence = _build_evidence()
    second_evidence.id = "evidence-2"
    second_evidence.timestamp = 1714299000.0
    alert = _build_alert(first_evidence)
    alert.correl_id = [first_evidence.id, second_evidence.id]

    first_payload = utils.to_dict(first_evidence)
    second_payload = utils.to_dict(second_evidence)
    second_payload["timestamp"] = 1714299000.0
    alert_summary.db.get_twid_evidence.return_value = {
        first_evidence.id: json.dumps(first_payload),
        second_evidence.id: json.dumps(second_payload),
    }

    evidences = alert_summary._get_alert_evidence(alert)

    assert len(evidences) == 2
    assert {evidence.id for evidence in evidences} == {
        first_evidence.id,
        second_evidence.id,
    }


def test_fallback_summary_contains_local_heuristic_context():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    evidence = _build_evidence()
    alert = _build_alert(evidence)

    summary = alert_summary._build_fallback_summary(
        alert,
        [evidence],
        "LLM request timed out.",
    )

    assert "LLM summary unavailable (LLM request timed out.)." in summary
    assert "Local heuristic summary:" in summary
    assert "Connection to 203.0.113.10 without a preceding DNS lookup." in summary


def test_fallback_summary_mentions_recent_history_when_available():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    prior_alert = _build_alert(_build_evidence())
    prior_alert.timewindow = TimeWindow(6)
    alert_summary._remember_alert_summary(
        prior_alert,
        "Earlier scan summary.",
        ["09:15 | Horizontal port scan to port 443/TCP"],
    )
    alert = _build_alert(_build_evidence())

    summary = alert_summary._build_fallback_summary(
        alert,
        [_build_evidence()],
        "LLM request timed out.",
    )

    assert "Recent related alert history for this source includes 1 prior summarized alerts" in summary
    assert "Horizontal port scan to port 443/TCP" in summary


def test_fallback_summary_raises_risk_when_same_pattern_repeats_across_history():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    prior_alert_one = _build_alert(_build_evidence())
    prior_alert_one.timewindow = TimeWindow(5)
    prior_alert_one.accumulated_threat_level = 6.0
    prior_alert_two = _build_alert(_build_evidence())
    prior_alert_two.timewindow = TimeWindow(6)
    prior_alert_two.accumulated_threat_level = 7.0
    current_evidence = _build_evidence()
    alert = _build_alert(current_evidence)
    alert.accumulated_threat_level = 6.5
    alert.confidence = 0.55

    alert_summary._remember_alert_summary(
        prior_alert_one,
        "Earlier repeated DNSless connection alert.",
        ["09:00 | Connection to 203.0.113.10 without a preceding DNS lookup."],
    )
    alert_summary._remember_alert_summary(
        prior_alert_two,
        "Another repeated DNSless connection alert.",
        ["09:30 | Connection to 203.0.113.11 without a preceding DNS lookup."],
    )

    summary = alert_summary._build_fallback_summary(
        alert,
        [current_evidence],
        "LLM request timed out.",
    )

    assert "repeated current-pattern matches" in summary
    assert "increasingly like a likely true positive" in summary
    assert "operational risk appears high" in summary


def test_operation_log_respects_configured_verbosity(tmp_path, mocker):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.log_verbosity = 1
    alert_summary.parent_output_dir = str(tmp_path)
    alert_summary.summary_log_path = str(
        tmp_path / "alerts" / "alerts-summary.log"
    )
    alert_summary.operation_log_path = str(
        tmp_path / "llm-summary" / "alert_summary.log"
    )
    mocker.patch(
        "modules.alert_summary.alert_summary.utils.drop_root_privs_permanently"
    )

    alert_summary.pre_main()
    alert_summary._log_operation("summary line", verbosity=1)
    alert_summary._log_operation("debug line", verbosity=3)

    with open(alert_summary.operation_log_path, "r", encoding="utf-8") as handle:
        content = handle.read()

    assert "summary line" in content
    assert "debug line" not in content
    alert_summary.shutdown_gracefully()


def test_shutdown_gracefully_logs_stop_message(tmp_path, mocker):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.parent_output_dir = str(tmp_path)
    alert_summary.summary_log_path = str(
        tmp_path / "alerts" / "alerts-summary.log"
    )
    alert_summary.operation_log_path = str(
        tmp_path / "llm-summary" / "alert_summary.log"
    )
    mocker.patch(
        "modules.alert_summary.alert_summary.utils.drop_root_privs_permanently"
    )

    alert_summary.pre_main()
    alert_summary.shutdown_gracefully()

    with open(alert_summary.operation_log_path, "r", encoding="utf-8") as handle:
        content = handle.read()

    assert "AlertSummary module stopped." in content
