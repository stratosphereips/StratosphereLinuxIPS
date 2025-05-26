# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import os
from unittest.mock import Mock, MagicMock, patch, call

from slips_files.core.structures.alerts import Alert
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    EvidenceType,
    Victim,
    TimeWindow,
    Attacker,
    IoCType,
    Direction,
    ThreatLevel,
)
from tests.module_factory import ModuleFactory
from datetime import datetime


@pytest.mark.parametrize(
    "profileid, our_ips, expected_result, expected_publish_call_count",
    [
        # testcase1: IP not in our_ips, should block
        ("192.168.1.100", ["10.0.0.1", "172.16.0.1"], True, 1),
        # testcase2: IP in our_ips, should not block
        ("10.0.0.1", ["10.0.0.1", "172.16.0.1"], False, 0),
        # testcase3: Empty our_ips, should block
        ("8.8.8.8", [], True, 1),
    ],
)
def test_decide_blocking(
    profileid, our_ips, expected_result, expected_publish_call_count
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.blocking_module_supported = True
    evidence_handler.our_ips = our_ips
    with patch.object(evidence_handler.db, "publish") as mock_publish:
        tw = TimeWindow(
            2, "2025-05-09T13:27:45.123456", "2025-05-09T13:27:45.123456"
        )
        result = evidence_handler.decide_blocking(profileid, tw)
        assert result == expected_result
        assert mock_publish.call_count == expected_publish_call_count


def test_shutdown_gracefully():
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.logfile = Mock()
    evidence_handler.jsonfile = Mock()

    evidence_handler.shutdown_gracefully()

    evidence_handler.logfile.close.assert_called_once()
    evidence_handler.jsonfile.close.assert_called_once()


@pytest.mark.parametrize(
    "profileid, twid, past_alerts, expected_output",
    [
        # testcase1: No past alerts
        ("profile1_192.168.1.1", "timewindow1", {}, []),
        # testcase2: One past alert
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
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.db.get_profileid_twid_alerts.return_value = past_alerts

    result = evidence_handler.get_evidence_that_were_part_of_a_past_alert(
        profileid, twid
    )
    assert result == expected_output


def setup_handler(popup_enabled, blocked, mark_blocked=None):
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.popup_alerts = popup_enabled

    alert = Alert(
        profile=ProfileID("1.2.3.4"),
        timewindow=TimeWindow(1),
        last_evidence=Mock(),
        accumulated_threat_level=12.2,
        last_flow_datetime="2024/10/04 15:45:30.123456+0000",
    )
    evidence = {"k": MagicMock(spec=Evidence)}

    handler.db.set_alert = MagicMock()
    handler.decide_blocking = MagicMock(side_effect=[None, mark_blocked])
    handler.db.is_blocked_profile_and_tw = MagicMock(return_value=blocked)
    handler.send_to_exporting_module = MagicMock()
    handler.formatter.format_evidence_for_printing = MagicMock(
        return_value="formatted_alert"
    )
    handler.print = MagicMock()
    handler.show_popup = MagicMock()
    handler.db.mark_profile_and_timewindow_as_blocked = MagicMock()
    handler.log_alert = MagicMock()

    return handler, alert, evidence


@pytest.mark.parametrize("popup_enabled", [True, False])
def test_handle_new_alert_already_blocked(popup_enabled):
    handler, alert, evidence = setup_handler(popup_enabled, blocked=True)
    handler.handle_new_alert(alert, evidence)

    handler.db.set_alert.assert_called_once_with(alert, evidence)
    handler.db.is_blocked_profile_and_tw.assert_called_once()
    handler.send_to_exporting_module.assert_not_called()
    handler.print.assert_not_called()
    handler.show_popup.assert_not_called()
    handler.db.mark_profile_and_timewindow_as_blocked.assert_not_called()
    handler.log_alert.assert_not_called()


@pytest.mark.parametrize(
    "popup_enabled, expect_popup",
    [
        (True, True),
        (False, False),
    ],
)
def test_handle_new_alert_not_blocked(popup_enabled, expect_popup):
    handler, alert, evidence = setup_handler(
        popup_enabled, blocked=False, mark_blocked=True
    )
    handler.handle_new_alert(alert, evidence)

    handler.send_to_exporting_module.assert_called_once_with(evidence)
    handler.print.assert_called_once_with("formatted_alert", 1, 0)

    if expect_popup:
        handler.show_popup.assert_called_once_with(alert)
    else:
        handler.show_popup.assert_not_called()

    handler.db.mark_profile_and_timewindow_as_blocked.assert_called_once()
    handler.log_alert.assert_called_once_with(alert, blocked=True)


@pytest.mark.parametrize(
    "output_dir, file_to_clean, file_exists",
    [
        # testcase1: File doesn't exist
        ("/tmp", "nonexistent.log", False),
        # testcase2: File exists
        ("/tmp", "existing.log", True),
    ],
)
def test_clean_file(output_dir, file_to_clean, file_exists):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    with patch("os.path.exists") as mock_exists, patch(
        "builtins.open"
    ) as mock_open:
        mock_exists.return_value = file_exists
        mock_file = Mock()
        mock_open.return_value = mock_file

        result = evidence_handler.clean_file(output_dir, file_to_clean)

        expected_path = os.path.join(output_dir, file_to_clean)
        mock_exists.assert_called_once_with(expected_path)
        mock_open.assert_called_with(expected_path, "a")

        assert result == mock_file


@pytest.mark.parametrize(
    "data",
    [
        # testcase1: Basic log entry
        "Test log entry",
        # testcase2: Another log entry
        "Another log entry",
    ],
)
def test_add_to_log_file(data):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    mock_file = Mock()
    evidence_handler.logfile = mock_file
    evidence_handler.add_to_log_file(data)
    assert mock_file.write.call_count == 2
    mock_file.write.assert_has_calls([call(data), call("\n")])
    mock_file.flush.assert_called_once()


@pytest.mark.parametrize(
    "all_uids, timewindow, accumulated_threat_level",
    [  # Testcase1: Basic alert with UIDs and threat level
        (
            ["uid1", "uid2"],
            1,
            0.5,
        ),
        # Testcase2: Alert without UIDs, high threat level
        (
            [],
            10,
            1.0,
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
    evidence_handler.idmefv2.convert_to_idmef_alert = Mock(return_value=True)
    with patch("json.dump") as mock_json_dump:
        evidence_handler.add_alert_to_json_log_file(alert)
        mock_json_dump.assert_called_once()
    mock_file.write.assert_any_call("\n")


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


@pytest.mark.parametrize(
    "attacker, victim, evidence_type",
    [
        # testcase1: Basic case
        (
            "192.168.1.100",
            Victim(direction="DST", ioc_type=IoCType.IP, value="10.0.0.1"),
            EvidenceType.ARP_SCAN,
        ),
        # testcase2: Different IP and evidence type
        (
            "10.0.0.100",
            Victim(
                direction="DST",
                ioc_type=IoCType.DOMAIN,
                value="example.com",
            ),
            EvidenceType.DNS_WITHOUT_CONNECTION,
        ),
    ],
)
def test_increment_attack_counter(attacker, victim, evidence_type):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    with patch.object(
        evidence_handler.db, "increment_attack_counter"
    ) as mock_increment:
        evidence_handler.increment_attack_counter(
            attacker, victim, evidence_type
        )
        mock_increment.assert_called_once_with(
            attacker, victim, evidence_type.name
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
