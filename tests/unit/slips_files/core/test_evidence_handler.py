# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import pytest
from unittest.mock import Mock, MagicMock, patch, call
import json

from slips_files.core.structures.alerts import Alert
from slips_files.core.evidence_handler import DEFAULT_EVIDENCE_HANDLER_WORKERS
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    EvidenceSignal,
    EvidenceType,
    TimeWindow,
    Attacker,
    IoCType,
    Direction,
    ThreatLevel,
)
from tests.module_factory import ModuleFactory


def test_shutdown_gracefully():
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.stop_evidence_workers = Mock()
    handler.logger_stop_signal = Mock()
    handler.logger_thread = Mock()
    handler.evidence_worker_queue = Mock()
    handler.evidence_logger_q = Mock()

    handler.shutdown_gracefully()

    handler.stop_evidence_workers.assert_called_once()
    handler.logger_stop_signal.set.assert_called_once()
    handler.logger_thread.join.assert_called_once_with(timeout=5)
    handler.evidence_worker_queue.cancel_join_thread.assert_called_once()
    handler.evidence_worker_queue.close.assert_called_once()
    handler.evidence_logger_q.cancel_join_thread.assert_called_once()
    handler.evidence_logger_q.close.assert_called_once()


def test_stop_evidence_workers():
    handler = ModuleFactory().create_evidence_handler_obj()
    process_1 = Mock()
    process_2 = Mock()
    handler.evidence_worker_child_processes = [process_1, process_2]
    handler.evidence_worker_queue = Mock()

    handler.stop_evidence_workers()

    assert handler.evidence_worker_queue.put.call_args_list == [
        call("stop"),
        call("stop"),
    ]
    process_1.join.assert_called_once()
    process_2.join.assert_called_once()


@patch("slips_files.core.evidence_handler.EvidenceHandlerWorker")
def test_start_evidence_worker(mock_worker_cls):
    handler = ModuleFactory().create_evidence_handler_obj()
    worker = mock_worker_cls.return_value
    handler.evidence_worker_child_processes = []
    handler.evidence_worker_queue = Mock()
    handler.evidence_logger_q = Mock()

    handler.start_evidence_worker(7)

    mock_worker_cls.assert_called_once_with(
        logger=handler.logger,
        output_dir=handler.parent_output_dir,
        redis_port=handler.redis_port,
        termination_event=handler.termination_event,
        conf=handler.conf,
        ppid=handler.ppid,
        slips_args=handler.args,
        bloom_filters_manager=handler.bloom_filters,
        name="evidence_handler_worker_process_7",
        evidence_queue=handler.evidence_worker_queue,
        evidence_logger_q=handler.evidence_logger_q,
    )
    worker.start.assert_called_once()
    assert handler.evidence_worker_child_processes == [worker]


def test_should_stop_returns_false_if_termination_not_set():
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.termination_event.is_set.return_value = False

    assert handler.should_stop() is False


@patch("slips_files.core.evidence_handler.time.time", return_value=100.0)
def test_should_stop_waits_when_messages_are_still_arriving(_mock_time):
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.termination_event.is_set.return_value = True
    handler.is_msg_received_in_any_channel = Mock(return_value=True)
    handler.last_msg_received_time = 10.0

    assert handler.should_stop() is False
    assert handler.last_msg_received_time == 100.0


@patch("slips_files.core.evidence_handler.time.time", return_value=120.0)
def test_should_stop_waits_for_grace_period(_mock_time):
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.termination_event.is_set.return_value = True
    handler.is_msg_received_in_any_channel = Mock(return_value=False)
    handler.last_msg_received_time = 100.0

    assert handler.should_stop() is False


@patch("slips_files.core.evidence_handler.time.time", return_value=131.0)
def test_should_stop_after_grace_period(_mock_time):
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.termination_event.is_set.return_value = True
    handler.is_msg_received_in_any_channel = Mock(return_value=False)
    handler.last_msg_received_time = 100.0

    assert handler.should_stop() is True


def test_pre_main_starts_default_workers():
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.start_evidence_worker = Mock()

    handler.pre_main()

    assert handler.start_evidence_worker.call_count == (
        DEFAULT_EVIDENCE_HANDLER_WORKERS
    )
    handler.start_evidence_worker.assert_has_calls([call(0), call(1), call(2)])


def test_main_queues_received_messages():
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.should_stop = Mock(side_effect=[False, True])
    handler.evidence_worker_queue = Mock()

    def get_msg(channel):
        if channel == "evidence_added":
            return {"data": "evidence"}
        if channel == "new_blame":
            return {"data": "blame"}
        return None

    handler.get_msg = Mock(side_effect=get_msg)

    handler.main()

    assert handler.evidence_worker_queue.put.call_args_list == [
        call(
            {
                "channel": "evidence_added",
                "message": {"data": "evidence"},
            }
        ),
        call(
            {
                "channel": "new_blame",
                "message": {"data": "blame"},
            }
        ),
    ],
)
def test_add_alert_to_json_log_file(
    all_uids, timewindow, accumulated_threat_level
):
    mock_file = Mock()
    alert = Alert(
        profile=ProfileID("192.168.1.20"),
        timewindow=TimeWindow(
            timewindow,
            start_time="2024-10-04T18:46:50+03:00",
            end_time="2024-10-04T19:46:50+03:00",
        ),
        last_evidence=Evidence(
            evidence_type=EvidenceType.ARP_SCAN,
            description="ARP scan detected",
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value="192.168.1.20",
            ),
            threat_level=ThreatLevel.INFO,
            profile=ProfileID("192.168.1.20"),
            timewindow=TimeWindow(timewindow),
            uid=all_uids,
            timestamp="1728417813.8868346",
        ),
        accumulated_threat_level=accumulated_threat_level,
        last_flow_datetime="2024/10/04 15:45:30.123456+0000",
    )
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.jsonfile = mock_file
    evidence_handler.idmefv2.convert_to_idmef_alert = Mock(
        return_value="alert_in_idmef_format"
    )
    evidence_handler.evidence_logger_q.put = Mock()

    evidence_handler.add_alert_to_json_log_file(alert)
    evidence_handler.evidence_logger_q.put.assert_called_once_with(
        {
            "to_log": "alert_in_idmef_format",
            "where": "alerts.json",
        }
    )


def test_add_evidence_to_json_log_file_includes_evidence_signal():
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.idmefv2.convert_to_idmef_event = Mock(
        return_value={"Category": "Intrusion.Detection"}
    )
    evidence_handler.evidence_logger_q.put = Mock()

    evidence = Evidence(
        evidence_type=EvidenceType.MALICIOUS_FLOW,
        description="Anomalous HTTPS flow",
        attacker=Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value="192.168.1.20",
        ),
        threat_level=ThreatLevel.HIGH,
        profile=ProfileID("192.168.1.20"),
        timewindow=TimeWindow(1),
        uid=["uid-1"],
        timestamp="2024/10/04 15:45:30.123456+0000",
        evidence_signal=EvidenceSignal.DAMP,
    )

    evidence_handler.add_evidence_to_json_log_file(
        evidence, accumulated_threat_level=1.2
    )

    evidence_handler.evidence_logger_q.put.assert_called_once()
    logged_event = evidence_handler.evidence_logger_q.put.call_args.args[0]
    note = json.loads(logged_event["to_log"]["Note"])
    assert logged_event["where"] == "alerts.json"
    assert note["evidence_signal"] == "DAMP"
    assert note["threat_level"] == "high"
    assert note["timewindow"] == 1


def test_show_popup():
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.notify = Mock()
    alert = Mock(spec=Alert)
    evidence_handler.formatter.get_printable_alert = Mock(
        return_value="alert_time_desc"
    )

    evidence_handler.show_popup(alert)

    evidence_handler.notify.show_popup.assert_called_once_with(
        "alert_time_desc"
    )


def test_send_to_exporting_module():
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    tw_evidence = {
        "evidence1": Evidence(
            evidence_type=EvidenceType.ARP_SCAN,
            description="ARP scan detected",
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value="192.168.1.1",
            ),
            threat_level=ThreatLevel.MEDIUM,
            profile=ProfileID(ip="192.168.1.1"),
            timewindow=TimeWindow(number=1),
            uid=["uid1"],
            timestamp="2023/04/01 10:00:00.000000+0000",
        ),
        "evidence2": Evidence(
            evidence_type=EvidenceType.DNS_WITHOUT_CONNECTION,
            description="DNS query without connection",
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value="192.168.1.2",
            ),
            threat_level=ThreatLevel.LOW,
            profile=ProfileID(ip="192.168.1.2"),
            timewindow=TimeWindow(number=1),
            uid=["uid2"],
            timestamp="2023/04/01 10:01:00.000000+0000",
        ),
    }

    evidence_handler.db.publish = Mock()
    evidence_handler.send_to_exporting_module(tw_evidence)
    assert evidence_handler.db.publish.call_count == 2


@pytest.mark.parametrize(
    "sys_argv, running_non_stop, expected_result",
    [
        # testcase 1: running non stop with -p enabled
        (["-i", "-p"], True, True),
        # testcase 2: custom flows but the module is disabled
        (["-i", "-im"], False, False),
        # testcase 3: -i not in sys.argv and not running non stop
        ([], False, False),
    ],
)
def test_is_blocking_module_supported(
    sys_argv, running_non_stop, expected_result
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.is_running_non_stop = running_non_stop

    with patch("sys.argv", sys_argv):
        result = evidence_handler.is_blocking_modules_supported()
    assert result == expected_result


@pytest.mark.parametrize(
    "evidence, past_evidence_ids, expected_result",
    [
        # testcase1: Evidence not filtered
        (
            Evidence(
                evidence_type=EvidenceType.ARP_SCAN,
                description="",
                attacker=Attacker(
                    direction="SRC",
                    ioc_type=IoCType.IP,
                    value="192.168.1.1",
                ),
                threat_level=ThreatLevel.INFO,
                profile=ProfileID("192.168.1.1"),
                timewindow=TimeWindow(1),
                uid=[],
                timestamp=datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f%z"),
                id="1",
            ),
            [],
            False,
        ),
        # testcase2: Evidence filtered (part of past alert)
        (
            Evidence(
                evidence_type=EvidenceType.ARP_SCAN,
                description="",
                attacker=Attacker(
                    direction="SRC",
                    ioc_type=IoCType.IP,
                    value="192.168.1.1",
                ),
                threat_level=ThreatLevel.INFO,
                profile=ProfileID("192.168.1.1"),
                timewindow=TimeWindow(1),
                uid=[],
                timestamp=datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f%z"),
                id="2",
            ),
            ["2"],
            True,
        ),
        # testcase3: Evidence filtered (evidence that wasnt done by the given
        # profileid)
        (
            Evidence(
                evidence_type=EvidenceType.ARP_SCAN,
                description="",
                attacker=Attacker(
                    direction="DST",
                    ioc_type=IoCType.IP,
                    value="192.168.1.1",
                ),
                threat_level=ThreatLevel.INFO,
                profile=ProfileID("192.168.1.1"),
                timewindow=TimeWindow(1),
                uid=[],
                timestamp=datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f%z"),
                id="3",
            ),
            [],
            True,
        ),
    ],
)
def test_is_filtered_evidence(evidence, past_evidence_ids, expected_result):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    result = evidence_handler.is_filtered_evidence(evidence, past_evidence_ids)
    assert result == expected_result


@pytest.mark.parametrize(
    "evidence, expected_result",
    [  # Testcase1: Attacker direction is SRC
        (Mock(attacker=Mock(direction="SRC")), False),
        # Testcase2: Attacker direction is DST
        (Mock(attacker=Mock(direction="DST")), True),
    ],
)
def test_is_evidence_done_by_others(evidence, expected_result):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    result = evidence_handler.is_evidence_done_by_others(evidence)
    assert result == expected_result


@pytest.mark.parametrize(
    "confidence, threat_level, expected_output",
    [
        # Testcase 1: Low threat level, confidence 0.5
        (0.5, ThreatLevel.LOW, 0.1),
        # Testcase 2: Medium threat level, full confidence
        (1.0, ThreatLevel.MEDIUM, 0.5),
        # Testcase 3: High threat level, confidence 0.8
        (0.8, ThreatLevel.HIGH, 0.64),
        # Testcase 4: Critical threat level, confidence 0.3
        (0.3, ThreatLevel.CRITICAL, 0.3),
        # Testcase 5: Info threat level, zero confidence
        (0.0, ThreatLevel.INFO, 0.0),
    ],
)
def test_get_threat_level(confidence, threat_level, expected_output):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence = Mock(spec=Evidence)
    evidence.confidence = confidence
    evidence.threat_level = threat_level
    with patch.object(evidence_handler, "print") as mock_print:
        result = evidence_handler.get_threat_level(evidence)

    assert pytest.approx(result, abs=1e-6) == expected_output
    mock_print.assert_called_once_with(
        f"\t\tWeighted Threat Level: {result}", 3, 0
    )


@pytest.mark.parametrize(
    "ip, twid, flow_datetime, " "accumulated_threat_level, blocked",
    [
        # testcase1: IP blocked by blocking module
        (
            "192.168.1.100",
            1,
            "2023/10/26 10:10:10",
            0.8,
            True,
        ),
        # testcase2: IP not blocked by blocking module
        (
            "10.0.0.100",
            2,
            "2023/10/26 11:11:11",
            1.0,
            False,
        ),
    ],
)
def test_log_alert(
    ip,
    twid,
    flow_datetime,
    accumulated_threat_level,
    blocked,
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.width = 300
    evidence_handler.add_alert_to_json_log_file = Mock()
    evidence_handler.add_to_log_file = Mock()
    alert = Alert(
        profile=ProfileID(ip),
        timewindow=TimeWindow(twid),
        last_evidence=Mock(),
        accumulated_threat_level=accumulated_threat_level,
        last_flow_datetime=flow_datetime,
    )
    evidence_handler.log_alert(alert, blocked=blocked)

    evidence_handler.add_alert_to_json_log_file.assert_called_once()
    assert flow_datetime in evidence_handler.add_to_log_file.call_args[0][0]
    assert str(twid) in evidence_handler.add_to_log_file.call_args[0][0]
