# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import time

from modules.alert_summary.alert_summary import (
    PROMPT_VERSION,
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
    assert parser.alert_summary_llm_temperature() == 0.2
    assert parser.alert_summary_llm_max_tokens() == 220
    assert parser.alert_summary_llm_response_timeout_seconds() == 120


def test_alert_summary_config_sanitization():
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {
        "alert_summary": {
            "enabled": "true",
            "allowed_backends": "local_qwen",
            "llm_temperature": "bad",
            "llm_max_tokens": "bad",
            "llm_response_timeout_seconds": -10,
        }
    }

    assert parser.alert_summary_enabled() is True
    assert parser.alert_summary_allowed_backends() == []
    assert parser.alert_summary_llm_temperature() == 0.2
    assert parser.alert_summary_llm_max_tokens() == 220
    assert parser.alert_summary_llm_response_timeout_seconds() == 0


def test_dispatch_next_alert_publishes_expected_request_payload():
    alert_summary = ModuleFactory().create_alert_summary_obj()
    evidence = _build_evidence()
    alert = _build_alert(evidence)
    alert_summary.db.get_twid_evidence.return_value = {
        evidence.id: json.dumps(utils.to_dict(evidence))
    }
    alert_summary.pending_alerts.append({"alert": alert, "evidences": [evidence]})

    alert_summary._dispatch_next_alert("local_qwen")

    channel, payload = alert_summary.db.publish.call_args.args
    request = json.loads(payload)
    assert channel == "llm_request"
    assert request["requester"] == "alert_summary"
    assert request["backend"] == "local_qwen"
    assert request["temperature"] == 0.2
    assert request["max_tokens"] == 220
    assert request["metadata"]["alert_id"] == alert.id
    assert request["metadata"]["prompt_version"] == PROMPT_VERSION
    assert request["messages"][0]["content"] == SYSTEM_PROMPT
    assert "Connection to 203.0.113.10 without a preceding DNS lookup." in (
        request["messages"][1]["content"]
    )


def test_handle_pending_response_writes_one_paragraph_summary(tmp_path, mocker):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.parent_output_dir = str(tmp_path)
    alert_summary.summary_log_path = str(
        tmp_path / "alerts" / "alerts-summary.log"
    )
    mocker.patch(
        "modules.alert_summary.alert_summary.utils.drop_root_privs_permanently"
    )
    alert_summary.pre_main()

    evidence = _build_evidence()
    alert = _build_alert(evidence)
    alert_summary.pending_request = {
        "request_id": "req-1",
        "backend": "local_qwen",
        "alert": alert,
        "evidences": [evidence],
        "sent_at": time.time(),
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

    assert "Likely true positive. Repeated outbound behavior suggests beaconing." in content
    assert "\n\n" not in content
    assert alert_summary.pending_request is None
    alert_summary.shutdown_gracefully()


def test_main_flushes_pending_alerts_without_backend_on_shutdown(
    tmp_path, mocker
):
    alert_summary = ModuleFactory().create_alert_summary_obj()
    alert_summary.parent_output_dir = str(tmp_path)
    alert_summary.summary_log_path = str(
        tmp_path / "alerts" / "alerts-summary.log"
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

    assert "LLM summary unavailable: No runtime-ready LLM backend available." in content
    assert not alert_summary.pending_alerts
    alert_summary.shutdown_gracefully()
