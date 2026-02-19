# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from slips_files.core.structures.evidence import (
    Evidence,
    IoCType,
    EvidenceType,
    ThreatLevel,
    Attacker,
    Victim,
    Direction,
    Proto,
    ProfileID,
    TimeWindow,
)
from slips_files.common.idea_format import (
    get_ip_version,
    extract_cc_server_ip,
    extract_cc_botnet_ip,
    idea_format,
    extract_role_type,
)
from datetime import datetime


@pytest.mark.parametrize(
    "ip, expected_version",
    [
        # testcase1: Valid IPv4 address
        ("192.168.1.1", "IP4"),
        # testcase2: Valid IPv6 address
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "IP6"),
    ],
)
def test_get_ip_version(ip, expected_version):
    assert get_ip_version(ip) == expected_version


@pytest.mark.parametrize(
    "evidence_description, expected_result",
    [
        # testcase1: IPv4 CC server
        (
            "Detected CC server IP: 192.168.1.1 on port 8080",
            ("192.168.1.1", "IP4"),
        ),
        # testcase2: IPv6 CC server
        (
            "Detected CC server IP: 2001:db8::1 on port 443",
            ("2001:db8::1", "IP6"),
        ),
        # testcase3: CC server with additional information
        (
            "Detected CC server IP: 10.0.0.1 on port 8888 using TCP",
            ("10.0.0.1", "IP4"),
        ),
    ],
)
def test_extract_cc_server_ip(evidence_description, expected_result):
    evidence = Evidence(
        evidence_type=EvidenceType.COMMAND_AND_CONTROL_CHANNEL,
        description=evidence_description,
        attacker=None,
        threat_level=None,
        profile=None,
        timewindow=None,
        uid=[],
        timestamp=datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f%z"),
    )
    assert extract_cc_server_ip(evidence) == expected_result


@pytest.mark.parametrize(
    "attacker_ip, expected_result",
    [
        # testcase1: IPv4 botnet IP
        ("192.168.1.100", ("192.168.1.100", "IP4")),
        # testcase2: IPv6 botnet IP
        ("2001:db8::2", ("2001:db8::2", "IP6")),
    ],
)
def test_extract_cc_botnet_ip(attacker_ip, expected_result):
    evidence = Evidence(
        evidence_type=EvidenceType.COMMAND_AND_CONTROL_CHANNEL,
        description="Some description",
        attacker=Attacker(
            value=attacker_ip,
            ioc_type=IoCType.IP,
            direction=Direction.SRC,
        ),
        threat_level=ThreatLevel.INFO,
        profile=ProfileID(ip=attacker_ip),
        timewindow=None,
        uid=[],
        timestamp=datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f%z"),
    )
    assert extract_cc_botnet_ip(evidence) == expected_result


def test_idea_format_command_and_control():
    evidence = Evidence(
        evidence_type=EvidenceType.COMMAND_AND_CONTROL_CHANNEL,
        description="Detected CC server IP: 192.168.1.1 on port 8080",
        attacker=Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value="10.0.0.1"
        ),
        threat_level=ThreatLevel.HIGH,
        profile=ProfileID(ip="10.0.0.1"),
        timewindow=TimeWindow(number=1),
        uid=["12345"],
        timestamp="2023/08/05 12:00:00.000000+0000",
        proto=Proto.TCP,
    )

    expected_output = {
        "Format": "IDEA0",
        "Source": [
            {"IP4": ["10.0.0.1"], "Type": ["Botnet"]},
            {
                "IP4": ["192.168.1.1"],
                "Type": ["CC"],
                "Proto": ["TCP"],
            },
        ],
        "Attach": [
            {
                "Content": "Detected CC server IP: 192.168.1.1 on port 8080",
                "ContentType": "text/plain",
            }
        ],
    }

    result = idea_format(evidence)

    assert result is not None, "idea_format returned None"

    required_keys = [
        "Format",
        "ID",
        "DetectTime",
        "EventTime",
        "Confidence",
        "Source",
        "Attach",
    ]
    for key in required_keys:
        assert key in result, f"Required key '{key}' not found in result"

    assert result["Format"] == "IDEA0"
    assert isinstance(result["ID"], str)
    assert isinstance(result["DetectTime"], str)
    assert isinstance(result["EventTime"], str)
    assert isinstance(result["Confidence"], (int, float))
    assert 0 <= result["Confidence"] <= 1

    assert len(result["Source"]) == len(expected_output["Source"])
    for expected_source, actual_source in zip(
        expected_output["Source"], result["Source"]
    ):
        for key, value in expected_source.items():
            assert (
                key in actual_source
            ), f"Expected key '{key}' not found in Source"
            assert (
                actual_source[key] == value
            ), f"Value mismatch for key '{key}' in Source"

    assert result["Attach"] == expected_output["Attach"]

    assert len(result["Source"]) == 2
    assert result["Source"][0]["Type"] == ["Botnet"]
    assert result["Source"][1]["Type"] == ["CC"]
    assert "Target" not in result

    for key in expected_output:
        assert key in result, f"Expected key '{key}' not found in result"
        assert (
            result[key] == expected_output[key]
        ), f"Value mismatch for key '{key}'"

    expected_keys = set(expected_output.keys()).union(
        {"ID", "DetectTime", "EventTime", "Confidence"}
    )
    unexpected_keys = set(result.keys()) - expected_keys
    assert (
        not unexpected_keys
    ), f"Unexpected keys found in result: {unexpected_keys}"


def test_idea_format_malicious_downloaded_file():
    evidence = Evidence(
        evidence_type=EvidenceType.MALICIOUS_DOWNLOADED_FILE,
        description="Malicious downloaded file abc123. "
        "size: 1024 bytes. "
        "File was downloaded from server: 5.5.5.5. "
        "Detected by: blacklist1. "
        "Confidence: 1. ",
        attacker=Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value="192.168.1.2",
        ),
        threat_level=ThreatLevel.HIGH,
        profile=ProfileID(ip="10.0.0.2"),
        timewindow=TimeWindow(number=2),
        uid=["67890"],
        timestamp="2023/08/05 13:00:00.000000+0000",
    )

    expected_output = {
        "Format": "IDEA0",
        "Source": [{"IP4": ["192.168.1.2"]}],
        "Attach": [{"Type": ["Malware"], "Hash": ["md5:abc123"]}],
        "Size": 1024,
    }

    result = idea_format(evidence)

    assert result is not None, "idea_format returned None"

    required_keys = [
        "Format",
        "ID",
        "DetectTime",
        "EventTime",
        "Confidence",
        "Source",
        "Attach",
    ]
    for key in required_keys:
        assert key in result, f"Required key '{key}' not found in result"

    assert result["Format"] == "IDEA0"
    assert isinstance(result["ID"], str)
    assert isinstance(result["DetectTime"], str)
    assert isinstance(result["EventTime"], str)
    assert isinstance(result["Confidence"], (int, float))
    assert 0 <= result["Confidence"] <= 1

    assert len(result["Source"]) == len(expected_output["Source"])
    for expected_source, actual_source in zip(
        expected_output["Source"], result["Source"]
    ):
        for key, value in expected_source.items():
            assert (
                key in actual_source
            ), f"Expected key '{key}' not found in Source"
            assert (
                actual_source[key] == value
            ), f"Value mismatch for key '{key}' in Source"

    assert result["Attach"] == expected_output["Attach"]
    assert "Size" in result
    assert result["Size"] == expected_output["Size"]

    for key in expected_output:
        assert key in result, f"Expected key '{key}' not found in result"
        assert (
            result[key] == expected_output[key]
        ), f"Value mismatch for key '{key}'"

    expected_keys = set(expected_output.keys()).union(
        {"ID", "DetectTime", "EventTime", "Confidence"}
    )
    unexpected_keys = set(result.keys()) - expected_keys
    assert (
        not unexpected_keys
    ), f"Unexpected keys found in result: {unexpected_keys}"


@pytest.mark.parametrize(
    "evidence_data, role, expected_result",
    [
        # Test case 1: Attacker with IPv4
        (
            {
                "attacker": Attacker(
                    direction=Direction.SRC,
                    ioc_type=IoCType.IP,
                    value="192.168.1.100",
                ),
                "victim": None,
            },
            "attacker",
            ("192.168.1.100", "IP4"),
        ),
        # Test case 2: Attacker with IPv6
        (
            {
                "attacker": Attacker(
                    direction=Direction.SRC,
                    ioc_type=IoCType.IP,
                    value="2001:db8::1",
                ),
                "victim": None,
            },
            "attacker",
            ("2001:db8::1", "IP6"),
        ),
        # Test case 3: Victim with IPv4
        (
            {
                "attacker": None,
                "victim": Victim(
                    direction=Direction.DST,
                    ioc_type=IoCType.IP,
                    value="10.0.0.1",
                ),
            },
            "victim",
            ("10.0.0.1", "IP4"),
        ),
        # Test case 4: Victim with IPv6
        (
            {
                "attacker": None,
                "victim": Victim(
                    direction=Direction.DST,
                    ioc_type=IoCType.IP,
                    value="2001:db8::2",
                ),
            },
            "victim",
            ("2001:db8::2", "IP6"),
        ),
        # Test case 5: Attacker with Domain
        (
            {
                "attacker": Attacker(
                    direction=Direction.SRC,
                    ioc_type=IoCType.DOMAIN,
                    value="example.com",
                ),
                "victim": None,
            },
            "attacker",
            ("example.com", "Hostname"),
        ),
        # Test case 6: Victim with URL
        (
            {
                "attacker": None,
                "victim": Victim(
                    direction=Direction.DST,
                    ioc_type=IoCType.URL,
                    value="https://example.com/page",
                ),
            },
            "victim",
            ("https://example.com/page", "URL"),
        ),
    ],
)
def test_extract_role_type(evidence_data, role, expected_result):
    evidence = Evidence(
        evidence_type=EvidenceType.MALICIOUS_FLOW,
        description="Test evidence",
        attacker=evidence_data["attacker"],
        threat_level=None,
        profile=None,
        timewindow=None,
        uid=[],
        timestamp="2023/08/05 12:00:00.000000+0000",
        victim=evidence_data["victim"],
    )

    result = extract_role_type(evidence, role)
    assert (
        result == expected_result
    ), f"Expected {expected_result}, but got {result}"
