# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import Mock, patch

from slips_files.core.structures.alerts import Alert
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    EvidenceType,
    TimeWindow,
    Attacker,
    IoCType,
    Direction,
    ThreatLevel,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "all_evidence, profileid, twid, expected_output",
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
                    profile=ProfileID("192.168.1.1"),
                    timewindow=TimeWindow(1),
                    uid=["uid1"],
                    timestamp="2023/07/01 12:00:00.000000+0000",
                )
            },
            ProfileID("192.168.1.1"),
            TimeWindow(1),
            "IP 192.168.1.1 detected as malicious in timewindow 1"
            " (start 2023/07/01 12:00:00, stop 2023/07/01 12:05:00) \n"
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
                    profile=ProfileID("192.168.1.1"),
                    timewindow=TimeWindow(1),
                    uid=["uid2"],
                    timestamp="2023/07/01 12:01:00.000000+0000",
                ),
            },
            ProfileID("192.168.1.1"),
            TimeWindow(1),
            "IP 192.168.1.1 detected as malicious in timewindow 1"
            " (start 2023/07/01 12:00:00, stop 2023/07/01 12:05:00) \n"
            "given the following evidence:\n"
            "\t- Detected Port scan detected threat level: medium.\n"
            "\t- Detected Malicious JA3 fingerprint threat level: high.\n",
        ),
    ],
)
def test_format_evidence_for_printing(
    all_evidence, profileid, twid, expected_output
):
    formatter = ModuleFactory().create_evidence_formatter_obj()
    with patch.object(
        formatter, "get_printable_alert"
    ) as mock_get_alert_time, patch(
        "slips_files.common.slips_utils.utils.convert_format"
    ) as mock_convert_format:
        mock_convert_format.return_value = "converted_time"

        mock_get_alert_time.return_value = (
            f"IP {profileid.ip} detected as malicious "
            f"in timewindow {twid.number} (start 2023/07/01 12:00:00, "
            f"stop 2023/07/01 12:05:00) \n"
        )
        alert = Alert(
            profile=profileid,
            timewindow=twid,
            last_evidence=Mock(timestamp=1728412808.6257355),
            accumulated_threat_level=123,
            id="123",
            last_flow_datetime="",
        )
        formatter.line_wrap = Mock()
        formatter.line_wrap = lambda x: x
        result = formatter.format_evidence_for_printing(
            alert,
            all_evidence,
        )

        result = (
            result.replace("\033[31m", "")
            .replace("\033[36m", "")
            .replace("\033[0m", "")
        )
        assert expected_output in result
        assert "converted_time" in result


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
    formatter = ModuleFactory().create_evidence_formatter_obj()
    result = formatter.line_wrap(input_text)
    assert result == expected_output


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
    formatter = ModuleFactory().create_evidence_formatter_obj()
    evidence = Mock(spec=Evidence)
    evidence.description = "Original description"
    evidence.threat_level = threat_level

    result = formatter.add_threat_level_to_evidence_description(evidence)

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
            "IP 192.168.1.1 (example.com) detected as malicious in timewindow"
            " 1 (start converted_time, stop converted_time) \n",
        ),
        # testcase2: No hostname
        (
            ProfileID("10.0.0.1"),
            TimeWindow(2),
            1625184000,
            None,
            "IP 10.0.0.1 detected as malicious in timewindow 2 "
            "(start converted_time, stop converted_time) \n",
        ),
        # testcase3: Different time window
        (
            ProfileID("172.16.0.1"),
            TimeWindow(3),
            1625270400,
            "test.local",
            "IP 172.16.0.1 (test.local) detected as malicious in timewindow 3 "
            "(start converted_time, stop converted_time) \n",
        ),
    ],
)
def test_get_printable_alert(
    profileid, twid, start_time, hostname, expected_output
):
    formatter = ModuleFactory().create_evidence_formatter_obj()
    formatter.db.get_hostname_from_profile.return_value = hostname
    formatter.width = 300
    alert = Alert(
        profile=profileid,
        timewindow=twid,
        last_evidence=Mock(timestamp=1728412808.6257355),
        accumulated_threat_level=123,
        id="123",
        last_flow_datetime="",
    )
    with patch(
        "slips_files.common.slips_utils.utils.convert_format"
    ) as mock_convert_format:
        mock_convert_format.return_value = "converted_time"

        result = formatter.get_printable_alert(alert)

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
                    ioc_type="IP",
                    value="192.168.1.100",
                    profile=ProfileID("192.168.1.100"),
                ),
                threat_level=ThreatLevel.MEDIUM,
                profile=ProfileID("192.168.1.100"),
                timewindow=TimeWindow(1),
                uid=["1"],
                timestamp="2023/10/26 10:10:10.000000+0000",
                victim=None,
                proto="TCP",
                id="1",
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
                    ioc_type="IP",
                    value="10.0.0.100",
                    profile=ProfileID("10.0.0.100"),
                ),
                threat_level=ThreatLevel.LOW,
                profile=ProfileID("10.0.0.100"),
                timewindow=TimeWindow(2),
                uid=["1"],
                timestamp="2023/10/26 11:11:11.000000+0000",
                victim=None,
                proto="UDP",
                id="2",
                confidence=0.5,
            ),
            "2023/10/26 11:11:11",
            "2023/10/26 11:11:11 (TW 2): Src IP 10.0.0.100                . "
            "Detected DNS query without connection ",
        ),
    ],
)
def test_get_evidence_to_log(evidence, flow_datetime, expected_output):
    formatter = ModuleFactory().create_evidence_formatter_obj()
    formatter.db.get_hostname_from_profile.return_value = None
    result = formatter.get_evidence_to_log(evidence, flow_datetime)
    assert expected_output in result
