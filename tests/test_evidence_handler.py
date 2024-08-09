import pytest
import os
from unittest.mock import Mock, patch, call
import traceback
from slips_files.core.evidence_structure.evidence import (
    Evidence,
    ProfileID,
    EvidenceType,
    Victim,
    TimeWindow,
    Attacker,
    IoCType,
    Direction,
    IDEACategory,
    evidence_to_dict,
)
from slips_files.core.evidence_structure.evidence import ThreatLevel
import json
from tests.module_factory import ModuleFactory
from datetime import datetime


@pytest.mark.parametrize(
    "ip, detection_module, attacker, description, expected_output",
    [
        # testcase1: Basic evidence string formatting
        ("192.168.1.1", "TestModule", "10.0.0.1", "Malicious activity", ""),
        # testcase2: Evidence string with DNS resolution
        ("8.8.8.8", "DNSModule", "1.1.1.1", "Suspicious DNS query", ""),
        # testcase3: Evidence string without DNS resolution
        (
            "172.16.0.1",
            "FirewallModule",
            "192.168.0.1",
            "Blocked connection",
            "",
        ),
    ],
)
def test_format_evidence_string(
    ip, detection_module, attacker, description, expected_output
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.db.get_dns_resolution.return_value = {
        "domains": ["example.com"]
    }

    result = evidence_handler.format_evidence_string(
        ip, detection_module, attacker, description
    )
    assert result == expected_output


@pytest.mark.parametrize(
    "sys_argv, is_growing_zeek_dir, expected_result",
    [
        # testcase1: Running on interface
        (["-i"], False, True),
        # testcase2: Not running on interface, but growing Zeek dir
        ([], True, True),
        # testcase3: Not running on interface, not growing Zeek dir
        ([], False, False),
    ],
)
def test_is_running_on_interface(
    sys_argv, is_growing_zeek_dir, expected_result
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    with patch("sys.argv", sys_argv):
        evidence_handler.db.is_growing_zeek_dir.return_value = (
            is_growing_zeek_dir
        )
        result = evidence_handler.is_running_on_interface()
        assert result == expected_result


@pytest.mark.parametrize(
    "profileid, our_ips, expected_result, expected_publish_call_count",
    [
        # testcase1: IP not in our_ips, should block
        ("profile_192.168.1.100", ["10.0.0.1", "172.16.0.1"], True, 1),
        # testcase2: IP in our_ips, should not block
        ("profile_10.0.0.1", ["10.0.0.1", "172.16.0.1"], False, 0),
        # testcase3: Empty our_ips, should block
        ("profile_8.8.8.8", [], True, 1),
    ],
)
def test_decide_blocking(
    profileid, our_ips, expected_result, expected_publish_call_count
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.our_ips = our_ips
    with patch.object(evidence_handler.db, "publish") as mock_publish:
        result = evidence_handler.decide_blocking(profileid)
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


@pytest.mark.parametrize(
    "alert_id, tw_evidence",
    [
        # testcase1: Basic alert
        (
            "profile_192.168.1.1_timewindow1_evidence1",
            {"evidence1": Mock(spec=Evidence)},
        ),
        # testcase2: Multiple evidence
        (
            "profile_10.0.0.1_timewindow2_evidence2",
            {
                "evidence1": Mock(spec=Evidence),
                "evidence2": Mock(spec=Evidence),
            },
        ),
    ],
)
def test_handle_new_alert(alert_id, tw_evidence):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.IDs_causing_an_alert = ["evidence1", "evidence2"]

    with patch.object(
        evidence_handler.db, "set_evidence_causing_alert"
    ) as mock_set_evidence, patch.object(
        evidence_handler.db, "update_threat_level"
    ) as mock_update_threat, patch.object(
        evidence_handler.db, "publish"
    ) as mock_publish, patch.object(
        evidence_handler.db, "add_alert"
    ) as mock_add_alert, patch.object(
        evidence_handler.db, "label_flows_causing_alert"
    ) as mock_label_flows, patch.object(
        evidence_handler, "send_to_exporting_module"
    ) as mock_send_export, patch.object(
        evidence_handler.db, "set_accumulated_threat_level"
    ) as mock_set_threat:
        evidence_handler.handle_new_alert(alert_id, tw_evidence)

        profile, srcip, twid, _ = alert_id.split("_")
        profileid = f"{profile}_{srcip}"

        mock_set_evidence.assert_called_once_with(
            profileid, twid, alert_id, evidence_handler.IDs_causing_an_alert
        )
        mock_update_threat.assert_called_once_with(profileid, "critical", 1)
        mock_publish.assert_called_once()
        mock_add_alert.assert_called_once()
        mock_label_flows.assert_called_once_with(
            evidence_handler.IDs_causing_an_alert
        )
        mock_send_export.assert_called_once_with(tw_evidence)
        mock_set_threat.assert_called_once_with(profileid, twid, 0)


@pytest.mark.parametrize(
    "input_text, expected_output",
    [
        # testcase1: Short text (no wrapping needed)
        ("Short text", "Short text"),
        # testcase2: Text exactly 155 characters long
        ("A" * 155, "A" * 155),
        # testcase3: Text longer than 155 characters
        ("A" * 200, "A" * 155 + "\n          " + "A" * 45),
        # testcase4: Multiple line wraps
        (
            "A" * 400,
            "A" * 155 + "\n          " + "A" * 155 + "\n          " + "A" * 90,
        ),
    ],
)
def test_line_wrap(input_text, expected_output):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    result = evidence_handler.line_wrap(input_text)
    assert result == expected_output


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


def test_handle_unable_to_log_evidence():
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    with patch.object(evidence_handler, "print") as mock_print:
        evidence_handler.handle_unable_to_log_evidence()

        assert mock_print.call_count == 2
        mock_print.assert_has_calls(
            [
                call("Error in add_to_json_log_file()"),
                call(traceback.format_exc(), 0, 1),
            ]
        )


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
    "idea_dict, all_uids, timewindow, accumulated_threat_level",
    [  # Testcase1: Basic alert with UIDs and threat level
        (
            {"key": "value"},
            ["uid1", "uid2"],
            "timewindow1",
            0.5,
        ),
        # Testcase2: Alert without UIDs, high threat level
        (
            {"alert": "test"},
            [],
            "timewindow10",
            1.0,
        ),
    ],
)
def test_add_to_json_log_file(
    idea_dict, all_uids, timewindow, accumulated_threat_level
):
    mock_file = Mock()
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.jsonfile = mock_file

    with patch("json.dump") as mock_json_dump:
        evidence_handler.add_to_json_log_file(
            idea_dict, all_uids, timewindow, accumulated_threat_level
        )

    mock_json_dump.assert_called_once()

    called_idea_dict = mock_json_dump.call_args[0][0]
    assert "uids" in called_idea_dict
    assert called_idea_dict["uids"] == all_uids
    assert "accumulated_threat_level" in called_idea_dict
    assert (
        called_idea_dict["accumulated_threat_level"]
        == accumulated_threat_level
    )
    assert "timewindow" in called_idea_dict
    assert called_idea_dict["timewindow"] == int(
        timewindow.replace("timewindow", "")
    )

    mock_file.write.assert_any_call("\n")


def test_show_popup():
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.notify = Mock()

    colored_alert = "\033[31mRed Alert\033[0m \033[36mCyan Info\033[0m"
    expected_clean_alert = "Red Alert Cyan Info"

    evidence_handler.show_popup(colored_alert)

    evidence_handler.notify.show_popup.assert_called_once_with(
        expected_clean_alert
    )


@pytest.mark.parametrize(
    "threat_level, expected_description",
    [
        # Testcase 1: INFO threat level
        (ThreatLevel.INFO, "Original description threat level: info."),
        # Testcase 2: LOW threat level
        (ThreatLevel.LOW, "Original description threat level: low."),
        # Testcase 3: MEDIUM threat level
        (ThreatLevel.MEDIUM, "Original description threat level: medium."),
        # Testcase 4: HIGH threat level
        (ThreatLevel.HIGH, "Original description threat level: high."),
        # Testcase 5: CRITICAL threat level
        (ThreatLevel.CRITICAL, "Original description threat level: critical."),
    ],
)
def test_add_threat_level_to_evidence_description(
    threat_level, expected_description
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence = Mock(spec=Evidence)
    evidence.description = "Original description"
    evidence.threat_level = threat_level

    result = evidence_handler.add_threat_level_to_evidence_description(
        evidence
    )

    assert result.description == expected_description
    assert evidence.description == expected_description


@pytest.mark.parametrize(
    "profileid, twid, start_time, hostname, expected_output",
    [
        # testcase1: Basic case with hostname
        (
            ProfileID("192.168.1.1"),
            TimeWindow(1),
            1625097600,
            "example.com",
            "IP 192.168.1.1 (example.com) detected as malicious in timewindow 1 "
            "(start 2021/07/01 00:00:00, stop 2021/07/01 00:05:00) \n",
        ),
        # testcase2: No hostname
        (
            ProfileID("10.0.0.1"),
            TimeWindow(2),
            1625184000,
            None,
            "IP 10.0.0.1 detected as malicious in timewindow 2 "
            "(start 2021/07/02 00:00:00, stop 2021/07/02 00:05:00) \n",
        ),
        # testcase3: Different time window
        (
            ProfileID("172.16.0.1"),
            TimeWindow(3),
            1625270400,
            "test.local",
            "IP 172.16.0.1 (test.local) detected as malicious in timewindow 3 "
            "(start 2021/07/03 00:00:00, stop 2021/07/03 00:05:00) \n",
        ),
    ],
)
def test_get_alert_time_description(
    profileid, twid, start_time, hostname, expected_output
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.db.get_tw_start_time.return_value = start_time
    evidence_handler.db.get_hostname_from_profile.return_value = hostname
    evidence_handler.width = 300

    with patch(
        "slips_files.common.slips_utils.utils.convert_format"
    ) as mock_convert_format:

        def mock_convert(timestamp, format):
            print(f"Converting timestamp: {timestamp}")
            return datetime.utcfromtimestamp(timestamp).strftime(
                "%Y/%m/%d %H:%M:%S"
            )

        mock_convert_format.side_effect = mock_convert

        result = evidence_handler.get_alert_time_description(profileid, twid)

        print(f"Expected: {expected_output}")
        print(f"Actual: {result}")

        assert result == expected_output


@pytest.mark.parametrize(
    "evidence, flow_datetime, expected_output",
    [
        # testcase1: Basic case with hostname
        (
            Evidence(
                evidence_type=EvidenceType.ARP_SCAN,
                description="ARP scan detected",
                attacker=Attacker(
                    direction="SRC",
                    attacker_type="IP",
                    value="192.168.1.100",
                    profile=ProfileID("192.168.1.100"),
                ),
                threat_level=ThreatLevel.MEDIUM,
                category="Anomaly",
                profile=ProfileID("192.168.1.100"),
                timewindow=TimeWindow(1),
                uid=["1"],
                timestamp="2023/10/26 10:10:10.000000+0000",
                victim=None,
                proto="TCP",
                port=None,
                source_target_tag=None,
                id="1",
                conn_count=1,
                confidence=0.5,
            ),
            "2023/10/26 10:10:10",
            "2023/10/26 10:10:10 (TW 1): Src IP 192.168.1.100             . "
            "Detected ARP scan detected ",
        ),
        # testcase2: No hostname, different IP and timewindow
        (
            Evidence(
                evidence_type=EvidenceType.DNS_WITHOUT_CONNECTION,
                description="DNS query without connection",
                attacker=Attacker(
                    direction="SRC",
                    attacker_type="IP",
                    value="10.0.0.100",
                    profile=ProfileID("10.0.0.100"),
                ),
                threat_level=ThreatLevel.LOW,
                category="Anomaly",
                profile=ProfileID("10.0.0.100"),
                timewindow=TimeWindow(2),
                uid=["1"],
                timestamp="2023/10/26 11:11:11.000000+0000",
                victim=None,
                proto="UDP",
                port=None,
                source_target_tag=None,
                id="2",
                conn_count=1,
                confidence=0.5,
            ),
            "2023/10/26 11:11:11",
            "2023/10/26 11:11:11 (TW 2): Src IP 10.0.0.100                . "
            "Detected DNS query without connection ",
        ),
    ],
)
def test_get_evidence_to_log(evidence, flow_datetime, expected_output):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.db.get_hostname_from_profile.return_value = None
    result = evidence_handler.get_evidence_to_log(evidence, flow_datetime)
    assert result == expected_output


@pytest.mark.parametrize(
    "attacker, victim, evidence_type",
    [
        # testcase1: Basic case
        (
            "192.168.1.100",
            Victim(direction="DST", victim_type=IoCType.IP, value="10.0.0.1"),
            EvidenceType.ARP_SCAN,
        ),
        # testcase2: Different IP and evidence type
        (
            "10.0.0.100",
            Victim(
                direction="DST",
                victim_type=IoCType.DOMAIN,
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
                direction="SRC",
                attacker_type="IP",
                value="192.168.1.1",
            ),
            threat_level=ThreatLevel.MEDIUM,
            category="Anomaly.Traffic",
            profile=ProfileID(ip="192.168.1.1"),
            timewindow=TimeWindow(number=1),
            uid=["uid1"],
            timestamp="2023/04/01 10:00:00.000000+0000",
        ),
        "evidence2": Evidence(
            evidence_type=EvidenceType.DNS_WITHOUT_CONNECTION,
            description="DNS query without connection",
            attacker=Attacker(
                direction="SRC",
                attacker_type="IP",
                value="192.168.1.2",
            ),
            threat_level=ThreatLevel.LOW,
            category="Anomaly.Traffic",
            profile=ProfileID(ip="192.168.1.2"),
            timewindow=TimeWindow(number=1),
            uid=["uid2"],
            timestamp="2023/04/01 10:01:00.000000+0000",
        ),
    }

    with patch.object(evidence_handler.db, "publish") as mock_publish:
        evidence_handler.send_to_exporting_module(tw_evidence)

    assert mock_publish.call_count == 2
    expected_calls = [
        call("export_evidence", json.dumps(evidence_to_dict(evidence)))
        for evidence in tw_evidence.values()
    ]
    mock_publish.assert_has_calls(expected_calls, any_order=True)


@pytest.mark.parametrize(
    "sys_argv, is_running_on_interface_result, expected_result",
    [
        # Testcase 1: -i in sys.argv and
        # is_running_on_interface returns True
        (["-i"], True, True),
        # Testcase 2: -i not in sys.argv and
        # is_running_on_interface returns True
        ([], True, True),
        # Testcase 3: -i in sys.argv and
        # is_running_on_interface returns False, but -im is present
        (["-i", "-im"], False, True),
        # Testcase 4: -i not in sys.argv and
        # is_running_on_interface returns False
        ([], False, False),
    ],
)
def test_is_blocking_module_enabled(
    sys_argv, is_running_on_interface_result, expected_result
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    with patch("sys.argv", sys_argv):
        with patch.object(
            evidence_handler, "is_running_on_interface"
        ) as mock_is_running:
            mock_is_running.return_value = is_running_on_interface_result
            result = evidence_handler.is_blocking_module_enabled()
        assert result == expected_result


@pytest.mark.parametrize(
    "tw_evidence, expected_last_id",
    [
        # testcase 1: Single evidence
        ({"evidence1": {"id": "evidence1"}}, "evidence1"),
        # testcase 2: Multiple evidence
        (
            {
                "evidence1": {"id": "evidence1"},
                "evidence2": {"id": "evidence2"},
                "evidence3": {"id": "evidence3"},
            },
            "evidence3",
        ),
    ],
)
def test_get_last_evidence_ID(tw_evidence, expected_last_id):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    last_id = evidence_handler.get_last_evidence_ID(tw_evidence)
    assert last_id == expected_last_id


@pytest.mark.parametrize(
    "evidence, past_evidence_ids, expected_result",
    [
        # testcase1: Evidence not filtered
        (
            Evidence(
                evidence_type=EvidenceType.ARP_SCAN,
                description="",
                attacker=Attacker(
                    direction="SRC", attacker_type="IP", value="192.168.1.1"
                ),
                threat_level=ThreatLevel.INFO,
                category="INFO",
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
                    direction="SRC", attacker_type="IP", value="192.168.1.1"
                ),
                threat_level=ThreatLevel.INFO,
                category="INFO",
                profile=ProfileID("192.168.1.1"),
                timewindow=TimeWindow(1),
                uid=[],
                timestamp=datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f%z"),
                id="2",
            ),
            ["2"],
            True,
        ),
        # testcase3: Evidence filtered (attacker direction is DST)
        (
            Evidence(
                evidence_type=EvidenceType.ARP_SCAN,
                description="",
                attacker=Attacker(
                    direction="DST", attacker_type="IP", value="192.168.1.1"
                ),
                threat_level=ThreatLevel.INFO,
                category="INFO",
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
    "all_evidence, profileid, twid, flow_datetime, expected_output",
    [
        # testcase1: Single evidence
        (
            {
                "evidence1": Evidence(
                    evidence_type=EvidenceType.HORIZONTAL_PORT_SCAN,
                    description="Port scan detected",
                    attacker=Attacker(
                        Direction.SRC, IoCType.IP, "192.168.1.1"
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    category=IDEACategory.RECON_SCANNING,
                    profile=ProfileID("192.168.1.1"),
                    timewindow=TimeWindow(1),
                    uid=["uid1"],
                    timestamp="2023/07/01 12:00:00.000000+0000",
                )
            },
            ProfileID("192.168.1.1"),
            TimeWindow(1),
            "2023/07/01 12:00:00.000000+0000",
            "2023/07/01 12:00:00.000000+0000 IP 192.168.1.1 "
            "detected as malicious in timewindow 1 (start 2023/07/01 12:00:00, "
            "stop 2023/07/01 12:05:00) \n"
            "given the following evidence:\n"
            "\t- Detected Port scan detected threat level: medium.\n",
        ),
        # testcase2: Multiple evidence
        (
            {
                "evidence1": Evidence(
                    evidence_type=EvidenceType.HORIZONTAL_PORT_SCAN,
                    description="Port scan detected",
                    attacker=Attacker(
                        Direction.SRC, IoCType.IP, "192.168.1.1"
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    category=IDEACategory.RECON_SCANNING,
                    profile=ProfileID("192.168.1.1"),
                    timewindow=TimeWindow(1),
                    uid=["uid1"],
                    timestamp="2023/07/01 12:00:00.000000+0000",
                ),
                "evidence2": Evidence(
                    evidence_type=EvidenceType.MALICIOUS_JA3,
                    description="Malicious JA3 fingerprint",
                    attacker=Attacker(
                        Direction.SRC, IoCType.IP, "192.168.1.1"
                    ),
                    threat_level=ThreatLevel.HIGH,
                    category=IDEACategory.ANOMALY_CONNECTION,
                    profile=ProfileID("192.168.1.1"),
                    timewindow=TimeWindow(1),
                    uid=["uid2"],
                    timestamp="2023/07/01 12:01:00.000000+0000",
                ),
            },
            ProfileID("192.168.1.1"),
            TimeWindow(1),
            "2023/07/01 12:01:00.000000+0000",
            "2023/07/01 12:01:00.000000+0000 IP 192.168.1.1 "
            "detected as malicious in timewindow 1 (start 2023/07/01 12:00:00, "
            "stop 2023/07/01 12:05:00) \n"
            "given the following evidence:\n"
            "\t- Detected Port scan detected threat level: medium.\n"
            "\t- Detected Malicious JA3 fingerprint threat level: high.\n",
        ),
    ],
)
def test_format_evidence_causing_this_alert(
    all_evidence, profileid, twid, flow_datetime, expected_output
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    with patch.object(
        evidence_handler, "get_alert_time_description"
    ) as mock_get_alert_time:
        mock_get_alert_time.return_value = (
            f"IP {profileid.ip} detected as malicious "
            f"in timewindow {twid.number} (start 2023/07/01 12:00:00, "
            f"stop 2023/07/01 12:05:00) \n"
        )

        with patch.object(evidence_handler, "line_wrap") as mock_line_wrap:
            mock_line_wrap.side_effect = lambda x: x

            result = evidence_handler.format_evidence_causing_this_alert(
                all_evidence, profileid, twid, flow_datetime
            )

            result = (
                result.replace("\033[31m", "")
                .replace("\033[36m", "")
                .replace("\033[0m", "")
            )

            assert result == expected_output


@pytest.mark.parametrize(
    "flow, expected_dst, expected_src",
    [
        # testcase1: Basic flow with DNS resolutions
        (
            {"saddr": "192.168.1.1", "daddr": "8.8.8.8"},
            ["example.com"],
            ["example.com", "example.com"],
        ),
        # testcase2: Flow without DNS resolutions
        ({"saddr": "10.0.0.1", "daddr": "172.16.0.1"}, [None], [None, None]),
        # testcase3: Flow with SNI information
        (
            {"saddr": "192.168.1.2", "daddr": "1.1.1.1"},
            ["client.com"],
            ["client.com", "client.com"],
        ),
    ],
)
def test_get_domains_of_flow(flow, expected_dst, expected_src):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.db.get_ip_info.side_effect = [
        {"SNI": [{"server_name": expected_dst[0]}]} if expected_dst else {},
        {"SNI": [{"server_name": expected_src[0]}]} if expected_src else {},
    ]
    evidence_handler.db.get_dns_resolution.side_effect = [
        {"domains": expected_dst},
        {"domains": expected_src},
    ]

    result_dst, result_src = evidence_handler.get_domains_of_flow(
        {0: json.dumps(flow)}
    )

    assert result_dst == expected_dst
    assert result_src == expected_src


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
    "profileid, twid, flow_datetime, "
    "accumulated_threat_level, IDEA_dict, blocked",
    [
        # testcase1: IP blocked by blocking module
        (
            "profile_192.168.1.100",
            "timewindow1",
            "2023/10/26 10:10:10",
            0.8,
            {"Format": "IDEA0", "Category": "Evidence", "Attach": [{}]},
            True,
        ),
        # testcase2: IP not blocked by blocking module
        (
            "profile_10.0.0.100",
            "timewindow2",
            "2023/10/26 11:11:11",
            1.0,
            {"Format": "IDEA0", "Category": "Evidence", "Attach": [{}]},
            False,
        ),
    ],
)
def test_mark_as_blocked(
    profileid,
    twid,
    flow_datetime,
    accumulated_threat_level,
    IDEA_dict,
    blocked,
):
    evidence_handler = ModuleFactory().create_evidence_handler_obj()
    evidence_handler.width = 300
    with patch.object(
        evidence_handler.db, "mark_profile_as_malicious"
    ) as mock_mark_profile, patch.object(
        evidence_handler.db, "markProfileTWAsBlocked"
    ) as mock_mark_profile_tw, patch.object(
        evidence_handler, "add_to_log_file"
    ) as mock_add_to_log_file, patch.object(
        evidence_handler, "add_to_json_log_file"
    ) as mock_add_to_json_log_file:
        evidence_handler.mark_as_blocked(
            profileid,
            twid,
            flow_datetime,
            accumulated_threat_level,
            IDEA_dict,
            blocked,
        )

        mock_mark_profile.assert_called_once_with(profileid)

        block_actions = {
            True: lambda: mock_mark_profile_tw.assert_called_once_with(
                profileid, twid
            ),
            False: lambda: mock_mark_profile_tw.assert_not_called(),
        }
        block_actions[blocked]()

        ip = profileid.split("_")[-1].strip()
        action_text = {True: "Blocked", False: "Generated an alert"}
        expected_log_message = (
            f"{flow_datetime}: Src IP {ip:26}. "
            f"{action_text[blocked]} "
            f"given enough evidence on timewindow {twid.split('timewindow')[1]}. "
            f"(real time"
        )

        mock_add_to_log_file.assert_called_once()
        assert expected_log_message in mock_add_to_log_file.call_args[0][0]

        mock_add_to_json_log_file.assert_called_once()
        called_idea_dict = mock_add_to_json_log_file.call_args[0][0]
        assert called_idea_dict["Format"] == "Json"
        assert called_idea_dict["Category"] == "Alert"
        assert called_idea_dict["profileid"] == profileid
        assert called_idea_dict["threat_level"] == accumulated_threat_level
        assert expected_log_message in called_idea_dict["Attach"][0]["Content"]
