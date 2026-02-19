# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/leak_detector/leak_detector.py"""

from tests.module_factory import ModuleFactory
from unittest import mock
import pytest
from unittest.mock import patch, mock_open
import json
from unittest.mock import MagicMock


@pytest.mark.parametrize(
    "return_code, expected_result",
    [  # Testcase1: Yara is installed
        (0, True),
        # Testcase2: Yara is not installed
        (1, False),
        # Testcase3: Yara returns an unexpected return code
        (32512, False),
    ],
)
@patch("os.system")
def test_is_yara_installed(
    mock_os_system, mock_db, return_code, expected_result
):
    """Test that the is_yara_installed method correctly identifies
    if Yara is installed."""

    mock_os_system.return_value = return_code
    leak_detector = ModuleFactory().create_leak_detector_obj()
    assert leak_detector.is_yara_installed() == expected_result


@patch("os.mkdir")
@patch("shutil.rmtree")
def test_delete_compiled_rules(mock_rmtree, mock_mkdir, mock_db):
    leak_detector = ModuleFactory().create_leak_detector_obj()
    leak_detector.delete_compiled_rules()
    mock_rmtree.assert_called_once_with(leak_detector.compiled_yara_rules_path)
    mock_mkdir.assert_called_once_with(leak_detector.compiled_yara_rules_path)


@pytest.mark.parametrize(
    "yara_installed, compile_rules_success, "
    "expected_return_value, expected_find_matches_call",
    [  # Testcase1:yara is not installed
        (False, False, 1, 0),
        # Testcase2:yara installed, compile success
        (True, True, None, 1),
        # Testcase3: yara installed, compile fails
        (True, False, None, 0),
    ],
)
@patch("subprocess.Popen")
def test_pre_main(
    mock_db,
    yara_installed,
    compile_rules_success,
    expected_return_value,
    expected_find_matches_call,
):
    """Tests the pre_main method."""
    leak_detector = ModuleFactory().create_leak_detector_obj()
    leak_detector.bin_found = yara_installed
    leak_detector.compile_and_save_rules = MagicMock(
        return_value=compile_rules_success
    )
    leak_detector.find_matches = MagicMock()

    assert leak_detector.pre_main() == expected_return_value
    assert leak_detector.find_matches.call_count == expected_find_matches_call


def test_main(mock_db):
    leak_detector = ModuleFactory().create_leak_detector_obj()
    result = leak_detector.main()
    assert result == 1


@pytest.mark.parametrize(
    "input_json, mock_json_loads_return, " "expected_output",
    [
        (
            # Testcase1: Valid JSON with extra characters
            '{"some": "data"}Killed',
            {"some": "data"},
            {"some": "data"},
        ),
        (
            # Testcase2: Valid JSON without extra characters
            '{"some": "data"}',
            {"some": "data"},
            {"some": "data"},
        ),
        (
            # Testcase3: Invalid JSON, JSONDecodeError raised
            "Invalid JSON",
            json.JSONDecodeError("Expecting ',' delimiter", "", 0),
            False,
        ),
    ],
)
@patch("json.loads")
def test_fix_json_packet(
    mock_json_loads,
    mock_db,
    input_json,
    mock_json_loads_return,
    expected_output,
):
    """Tests the fix_json_packet method of LeakDetector."""

    mock_json_loads.side_effect = (
        mock_json_loads_return
        if isinstance(mock_json_loads_return, Exception)
        else lambda x: mock_json_loads_return
    )

    leak_detector = ModuleFactory().create_leak_detector_obj()
    result = leak_detector.fix_json_packet(input_json)

    assert result == expected_output


@pytest.mark.parametrize(
    "listdir_return, popen_communicate_return, " "evidence_set_call_count",
    [
        (
            # Test case 1: Matches found, evidence set
            ["test_rule_compiled"],
            (b"test_rule\n0x4e15c:$rgx_gps_loc: 37.7749,-122.4194", None),
            True,
        ),
        (
            # Test case 2: No matches found, no evidence set
            ["test_rule_compiled"],
            (b"", None),
            False,
        ),
        (
            # Test case 3: Error during YARA execution, no action taken
            ["test_rule_compiled"],
            (b"", b"Error during YARA execution"),
            False,
        ),
    ],
)
@mock.patch("subprocess.Popen")
@mock.patch("os.listdir")
def test_find_matches(
    mock_listdir,
    mock_popen,
    listdir_return,
    popen_communicate_return,
    evidence_set_call_count,
    mock_db,
):
    """Tests the find_matches method of LeakDetector."""

    leak_detector = ModuleFactory().create_leak_detector_obj()

    mock_listdir.return_value = listdir_return
    mock_popen.return_value.communicate.return_value = popen_communicate_return
    leak_detector.set_evidence_yara_match = MagicMock()
    leak_detector.delete_compiled_rules = MagicMock()

    leak_detector.find_matches()

    mock_popen.assert_called_once()
    assert (
        leak_detector.set_evidence_yara_match.call_count
        == evidence_set_call_count
    )


@pytest.mark.parametrize(
    "pcap_data, offset, tshark_output, expected_result",
    [
        (
            # Testcase1: Packet found successfully
            b"\x00" * 24 + b"\x00" * 16 + b"\x00\x00\x00\x14" + b"\x00" * 20,
            25,
            json.dumps(
                [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.protocols": "ip:ipv4:ip:tcp",
                                    "frame.time_epoch": 1669852800,
                                },
                                "ip": {
                                    "ip.src": "10.0.0.1",
                                    "ip.dst": "10.0.0.2",
                                },
                                "tcp": {
                                    "tcp.srcport": "80",
                                    "tcp.dstport": "443",
                                },
                            }
                        }
                    }
                ]
            ).encode(),
            ("10.0.0.1", "10.0.0.2", "tcp", "80", "443", 1669852800),
        ),
        (
            # Testcase3: Error during tshark execution
            b"\x00" * 24 + b"\x00" * 16 + b"\x00\x00\x00\x14" + b"\x00" * 20,
            25,
            b"",
            None,
        ),
    ],
)
def test_get_packet_info(
    mock_db,
    pcap_data,
    offset,
    tshark_output,
    expected_result,
):
    """Tests the get_packet_info method of LeakDetector."""

    leak_detector = ModuleFactory().create_leak_detector_obj()
    leak_detector.fix_json_packet = MagicMock()
    with patch(
        "builtins.open", mock_open(read_data=pcap_data)
    ) as mock_file, patch("subprocess.Popen") as mock_popen:
        mock_file.return_value.tell.side_effect = [
            24,
            100,
        ]

        mock_popen.return_value.communicate.return_value = (
            tshark_output,
            None,
        )

        result = leak_detector.get_packet_info(offset)
        assert result == expected_result


@pytest.mark.parametrize(
    "get_packet_info_return, "
    "db_get_port_info_return, "
    "db_get_ip_identification_return, "
    "db_get_tw_of_ts_return, expected_call_count",
    [
        # Testcase 1: All data is available, evidence is set correctly
        (
            ("10.0.0.1", "10.0.0.2", "tcp", "80", "443", 1669852800),
            "HTTP",
            "(Example.com)",
            ["timewindow1"],
            2,
        ),
        # Testcase 2: get_packet_info returns None, evidence is not set
        (
            None,
            "HTTP",
            "(Example.com)",
            ["timewindow1"],
            0,
        ),
        # Testcase 3: db_get_port_info returns None, evidence is set with default info
        (
            ("10.0.0.1", "10.0.0.2", "tcp", "80", "443", 1669852800),
            None,
            "(Example.com)",
            ["timewindow1"],
            2,  # Expect two calls to 'set_evidence'
        ),
        # Testcase 4: db_get_ip_identification returns None, evidence is set with default info
        (
            ("10.0.0.1", "10.0.0.2", "tcp", "80", "443", 1669852800),
            "HTTP",
            None,
            ["timewindow1"],
            2,
        ),
        # Testcase 5: db_get_tw_of_ts returns None, evidence is not set
        (
            ("10.0.0.1", "10.0.0.2", "tcp", "80", "443", 1669852800),
            "HTTP",
            "(Example.com)",
            None,
            0,
        ),
    ],
)
def test_set_evidence_yara_match(
    mock_db,
    get_packet_info_return,
    db_get_port_info_return,
    db_get_ip_identification_return,
    db_get_tw_of_ts_return,
    expected_call_count,
):
    leak_detector = ModuleFactory().create_leak_detector_obj()
    leak_detector.get_packet_info = MagicMock(
        return_value=get_packet_info_return
    )
    leak_detector.db.get_port_info = MagicMock(
        return_value=db_get_port_info_return
    )
    leak_detector.db.get_ip_identification = MagicMock(
        return_value=db_get_ip_identification_return
    )
    leak_detector.db.get_tw_of_ts = MagicMock(
        return_value=db_get_tw_of_ts_return
    )
    mock_set_evidence = MagicMock()
    leak_detector.db.set_evidence = mock_set_evidence
    leak_detector.set_evidence_yara_match(
        {
            "rule": "GPS Leak",
            "offset": 25,
            "strings_matched": "37.7749,-122.4194",
        }
    )

    assert mock_set_evidence.call_count == expected_call_count
