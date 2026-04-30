# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import pytest

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


@pytest.mark.parametrize(
    "profileid, our_ips, expected_result, expected_publish_call_count",
    [
        ("192.168.1.100", ["10.0.0.1", "172.16.0.1"], True, 1),
        ("10.0.0.1", ["10.0.0.1", "172.16.0.1"], False, 0),
        ("8.8.8.8", [], True, 1),
    ],
)
def test_decide_blocking(
    mocker, profileid, our_ips, expected_result, expected_publish_call_count
):
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    worker.blocking_modules_supported = True
    worker.our_ips = our_ips
    with patch.object(worker.db, "publish") as mock_publish:
        tw = TimeWindow(
            2, "2025-05-09T13:27:45.123456", "2025-05-09T13:27:45.123456"
        )
        mocker.patch(
            "slips_files.common.slips_utils.Utils.get_interface_of_ip",
            return_value="eth0",
        )

        result = worker.decide_blocking(profileid, tw)

    assert result == expected_result
    assert mock_publish.call_count == expected_publish_call_count


@pytest.mark.parametrize(
    "profileid, twid, past_alerts, expected_output",
    [
        ("profile1_192.168.1.1", "timewindow1", {}, []),
        (
            "profile2_10.0.0.1",
            "timewindow2",
            {"alert1": '["evidence1", "evidence2"]'},
            ["evidence1", "evidence2"],
        ),
    ],
)
def test_get_evidence_that_were_part_of_a_past_alert(
    profileid, twid, past_alerts, expected_output
):
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    worker.db.get_profileid_twid_alerts.return_value = past_alerts

    result = worker.get_evidence_that_were_part_of_a_past_alert(
        profileid, twid
    )

    assert result == expected_output


def setup_worker(popup_enabled, blocked, mark_blocked=None):
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    worker.popup_alerts = popup_enabled

    alert = Alert(
        profile=ProfileID("1.2.3.4"),
        timewindow=TimeWindow(1),
        last_evidence=Mock(),
        accumulated_threat_level=12.2,
        last_flow_datetime="2024/10/04 15:45:30.123456+0000",
    )
    evidence = {"k": MagicMock(spec=Evidence)}

    worker.db.set_alert = MagicMock()
    worker.decide_blocking = MagicMock(side_effect=[False, mark_blocked])
    worker.db.is_blocked_profile_and_tw = MagicMock(return_value=blocked)
    worker.send_to_exporting_module = MagicMock()
    worker.formatter.format_evidence_for_printing = MagicMock(
        return_value="formatted_alert"
    )
    worker.print = MagicMock()
    worker.show_popup = MagicMock()
    worker.db.mark_profile_and_timewindow_as_blocked = MagicMock()
    worker.log_alert = MagicMock()

    return worker, alert, evidence


@pytest.mark.parametrize("popup_enabled", [True, False])
def test_handle_new_alert_already_blocked(popup_enabled):
    worker, alert, evidence = setup_worker(popup_enabled, blocked=True)

    worker.handle_new_alert(alert, evidence)

    worker.db.set_alert.assert_called_once_with(alert, evidence)
    worker.db.is_blocked_profile_and_tw.assert_called_once()
    worker.send_to_exporting_module.assert_not_called()
    worker.print.assert_not_called()
    worker.show_popup.assert_not_called()
    worker.db.mark_profile_and_timewindow_as_blocked.assert_not_called()
    worker.log_alert.assert_not_called()


@pytest.mark.parametrize(
    "popup_enabled, expect_popup",
    [
        (True, True),
        (False, False),
    ],
)
def test_handle_new_alert_not_blocked(popup_enabled, expect_popup):
    worker, alert, evidence = setup_worker(
        popup_enabled, blocked=False, mark_blocked=True
    )

    worker.handle_new_alert(alert, evidence)

    worker.send_to_exporting_module.assert_called_once_with(evidence)
    worker.print.assert_called_once_with("formatted_alert", 1, 0)
    if expect_popup:
        worker.show_popup.assert_called_once_with(alert)
    else:
        worker.show_popup.assert_not_called()
    worker.db.mark_profile_and_timewindow_as_blocked.assert_not_called()
    worker.log_alert.assert_called_once_with(alert, blocked=False)


@pytest.mark.parametrize("data", ["Test log entry", "Another log entry"])
def test_add_to_log_file(data):
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    worker.evidence_logger_q.put = Mock()

    worker.add_to_log_file(data)

    worker.evidence_logger_q.put.assert_called_once_with(
        {"to_log": data, "where": "alerts.log"}
    )


@pytest.mark.parametrize(
    "all_uids, timewindow, accumulated_threat_level",
    [
        (["uid1", "uid2"], 1, 0.5),
        ([], 10, 1.0),
    ],
)
def test_add_alert_to_json_log_file(
    all_uids, timewindow, accumulated_threat_level
):
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
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    worker.idmefv2.convert_to_idmef_alert = Mock(
        return_value="alert_in_idmef_format"
    )
    worker.evidence_logger_q.put = Mock()

    worker.add_alert_to_json_log_file(alert)

    worker.evidence_logger_q.put.assert_called_once_with(
        {
            "to_log": "alert_in_idmef_format",
            "where": "alerts.json",
        }
    )


@pytest.mark.parametrize(
    "confidence, expected_output",
    [
        (0.80, "High"),
        (0.55, "Medium"),
        (0.54, "low"),
    ],
)
def test_add_evidence_to_json_log_file_maps_confidence_to_string(
    confidence, expected_output
):
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    worker.idmefv2.convert_to_idmef_event = Mock(return_value={"ID": "e1"})
    worker.evidence_logger_q.put = Mock()
    worker.add_latency_to_csv = Mock()
    evidence = Evidence(
        evidence_type=EvidenceType.ARP_SCAN,
        description="ARP scan detected",
        attacker=Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value="192.168.1.20",
        ),
        threat_level=ThreatLevel.INFO,
        confidence=confidence,
        profile=ProfileID("192.168.1.20"),
        timewindow=TimeWindow(1),
        uid=["uid1"],
        timestamp="2024/10/04 15:45:30.123456+0000",
    )

    worker.add_evidence_to_json_log_file(evidence)

    logged_evidence = worker.evidence_logger_q.put.call_args[0][0]["to_log"]
    note = logged_evidence["Note"]
    assert '"confidence":' in note
    assert f'"confidence": "{expected_output}"' in note


def test_show_popup():
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    worker.notify = Mock()
    alert = Mock(spec=Alert)
    worker.formatter.get_printable_alert = Mock(return_value="alert_time_desc")

    worker.show_popup(alert)

    worker.notify.show_popup.assert_called_once_with("alert_time_desc")


def test_send_to_exporting_module():
    worker = ModuleFactory().create_evidence_handler_worker_obj()
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

    worker.exporting_modules_enabled = True
    worker.db.publish = Mock()

    worker.send_to_exporting_module(tw_evidence)

    assert worker.db.publish.call_count == 2


@pytest.mark.parametrize(
    "sys_argv, running_non_stop, expected_result",
    [
        (["-i", "-p"], True, True),
        (["-i", "-im"], False, False),
        ([], False, False),
    ],
)
def test_is_blocking_module_supported(
    sys_argv, running_non_stop, expected_result
):
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    worker.is_running_non_stop = running_non_stop

    with patch("sys.argv", sys_argv):
        result = worker.is_blocking_modules_supported()

    assert result == expected_result


@pytest.mark.parametrize(
    "evidence, past_evidence_ids, expected_result",
    [
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
    worker = ModuleFactory().create_evidence_handler_worker_obj()

    result = worker.is_filtered_evidence(evidence, past_evidence_ids)

    assert result == expected_result


@pytest.mark.parametrize(
    "evidence, expected_result",
    [
        (Mock(attacker=Mock(direction="SRC")), False),
        (Mock(attacker=Mock(direction="DST")), True),
    ],
)
def test_is_evidence_done_by_others(evidence, expected_result):
    worker = ModuleFactory().create_evidence_handler_worker_obj()

    result = worker.is_evidence_done_by_others(evidence)

    assert result == expected_result


@pytest.mark.parametrize(
    "confidence, threat_level, expected_output",
    [
        (0.5, ThreatLevel.LOW, 0.1),
        (1.0, ThreatLevel.MEDIUM, 0.5),
        (0.8, ThreatLevel.HIGH, 0.64),
        (0.3, ThreatLevel.CRITICAL, 0.3),
        (0.0, ThreatLevel.INFO, 0.0),
    ],
)
def test_get_threat_level(confidence, threat_level, expected_output):
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    evidence = Mock(spec=Evidence)
    evidence.confidence = confidence
    evidence.threat_level = threat_level

    with patch.object(worker, "print") as mock_print:
        result = worker.get_threat_level(evidence)

    assert pytest.approx(result, abs=1e-6) == expected_output
    mock_print.assert_called_once_with(
        f"\t\tWeighted Threat Level: {result}", 3, 0
    )


@pytest.mark.parametrize(
    "ip, twid, flow_datetime, accumulated_threat_level, blocked",
    [
        ("192.168.1.100", 1, "2023/10/26 10:10:10", 0.8, True),
        ("10.0.0.100", 2, "2023/10/26 11:11:11", 1.0, False),
    ],
)
def test_log_alert(
    ip,
    twid,
    flow_datetime,
    accumulated_threat_level,
    blocked,
):
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    worker.add_alert_to_json_log_file = Mock()
    worker.add_to_log_file = Mock()
    alert = Alert(
        profile=ProfileID(ip),
        timewindow=TimeWindow(twid),
        last_evidence=Mock(),
        accumulated_threat_level=accumulated_threat_level,
        last_flow_datetime=flow_datetime,
    )

    worker.log_alert(alert, blocked=blocked)

    worker.add_alert_to_json_log_file.assert_called_once()
    assert flow_datetime in worker.add_to_log_file.call_args[0][0]
    assert str(twid) in worker.add_to_log_file.call_args[0][0]
