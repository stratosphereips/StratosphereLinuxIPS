"""Unit test for modules/leak_detector/leak_detector.py"""

from module_factory import ModuleFactory
import os
from unittest import mock
import pytest
from unittest.mock import patch, mock_open
import json
from unittest.mock import MagicMock
from slips_files.common.imports import *


def test_compile_and_save_rules(mock_db):
    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)
    leak_detector.compile_and_save_rules()
    compiled_rules = os.listdir(leak_detector.compiled_yara_rules_path)
    assert "test_rule.yara_compiled" in compiled_rules
    compiled_test_rule = os.path.join(
        leak_detector.compiled_yara_rules_path, "test_rule.yara_compiled"
    )
    os.remove(compiled_test_rule)


@pytest.mark.parametrize(
    "return_code, expected_result, test_description",
    [
        (0, True, "Yara is installed (return code 0)"),
        (1, False, "Yara is not installed (return code 1)"),
        (32512, False, "Yara returns an unexpected return code"),
    ],
)
@patch("os.system")
def test_is_yara_installed(
    mock_os_system, mock_db, return_code, expected_result, test_description
):
    """Test that the is_yara_installed method correctly identifies if Yara is installed."""

    mock_os_system.return_value = return_code
    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)
    assert leak_detector.is_yara_installed() == expected_result


@patch("os.mkdir")
@patch("shutil.rmtree")
def test_delete_compiled_rules(mock_rmtree, mock_mkdir, mock_db):
    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)
    leak_detector.delete_compiled_rules()
    mock_rmtree.assert_called_once_with(leak_detector.compiled_yara_rules_path)
    mock_mkdir.assert_called_once_with(leak_detector.compiled_yara_rules_path)


@pytest.mark.parametrize(
    "yara_installed, compile_rules_success, expected_return_value, expected_find_matches_call, test_description",
    [
        (
            # Testcase1: yara is not installed
            False,
            False,
            1,
            0,
            "Returns 1 when YARA is not installed",
        ),
        (
            # Testcase2: yara is installed, compile rules success, find_matches called
            True,
            True,
            None,
            1,
            "Calls find_matches when YARA is installed and rules are compiled successfully",
        ),
        (
            # Testcase3: yara is installed, compile rules fails, find_matches not called
            True,
            False,
            None,
            0,
            "Doesn't call find_matches when YARA is installed but rules compilation fails",
        ),
    ],
)
@patch("subprocess.Popen")
def test_pre_main(
    mock_popen,
    mock_db,
    yara_installed,
    compile_rules_success,
    expected_return_value,
    expected_find_matches_call,
    test_description,
):
    """Tests the pre_main method of the LeakDetector class."""
    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)
    leak_detector.bin_found = yara_installed
    leak_detector.compile_and_save_rules = MagicMock(
        return_value=compile_rules_success
    )
    leak_detector.find_matches = MagicMock()
    assert leak_detector.pre_main() == expected_return_value
    assert leak_detector.find_matches.call_count == expected_find_matches_call


def test_main(mock_db):
    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)
    result = leak_detector.main()
    assert result == 1


@pytest.mark.parametrize(
    "listdir_return, system_return, expected_result, test_description",
    [
        (
            # Testcase1: Successful compilation
            ["test_rule.yara"],
            0,
            True,
            "Successfully compiles and saves rules when no errors occur",
        ),
        (
            # Testcase2: Compilation error
            ["test_rule.yara"],
            1,
            False,
            "Returns False when there is an error compiling a rule",
        ),
        (
            # Testcase3: No rules found
            [],
            0,
            True,
            "Successfully handles cases where no .yara rules are found",
        ),
    ],
)
@mock.patch("os.system")
@mock.patch("os.listdir")
@mock.patch("os.mkdir")
def test_compile_and_save_rules(
    mock_mkdir,
    mock_listdir,
    mock_system,
    listdir_return,
    system_return,
    expected_result,
    test_description,
    mock_db,
):
    """Tests the compile_and_save_rules method of LeakDetector."""

    mock_listdir.return_value = listdir_return
    mock_system.return_value = system_return

    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)
    result = leak_detector.compile_and_save_rules()

    assert result == expected_result


@pytest.mark.parametrize(
    "input_json, mock_json_loads_return, expected_output, test_description",
    [
        (
            # Testcase1: Valid JSON with extra characters
            '{"some": "data"}Killed',
            {"some": "data"},
            {"some": "data"},
            "Correctly fixes and loads JSON with extra characters",
        ),
        (
            # Testcase2: Valid JSON without extra characters
            '{"some": "data"}',
            {"some": "data"},
            {"some": "data"},
            "Correctly loads valid JSON without modifications",
        ),
        (
            # Testcase3: Invalid JSON, JSONDecodeError raised
            "Invalid JSON",
            json.JSONDecodeError(
                "Expecting ',' delimiter", "", 0
            ),  # Simulate the error
            False,
            "Handles JSONDecodeError gracefully and returns False",
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
    test_description,
):
    """Tests the fix_json_packet method of LeakDetector."""

    mock_json_loads.side_effect = (
        mock_json_loads_return
        if isinstance(mock_json_loads_return, Exception)
        else lambda x: mock_json_loads_return
    )

    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)
    result = leak_detector.fix_json_packet(input_json)

    assert result == expected_output


@pytest.mark.parametrize(
    "listdir_return, popen_communicate_return, evidence_set_called, delete_called, test_description",
    [
        (
            # Test case1: Matches found, evidence set
            ["test_rule_compiled"],
            (b"test_rule\n0x4e15c:$rgx_gps_loc: 37.7749,-122.4194", None),
            True,
            False,
            "Matches found, evidence should be set",
        ),
        (
            # Test case2: No matches found, no evidence set
            ["test_rule_compiled"],
            (b"", None),
            False,
            False,
            "No matches found, evidence should not be set",
        ),
        (
            # Test case3: Error during YARA execution, no action taken
            ["test_rule_compiled"],
            (b"", b"Error during YARA execution"),
            False,
            False,
            "Error during YARA execution, no action should be taken",
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
    evidence_set_called,
    delete_called,
    test_description,
    mock_db,
):
    """Tests the find_matches method of LeakDetector."""

    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)

    mock_listdir.return_value = listdir_return
    mock_popen.return_value.communicate.return_value = popen_communicate_return
    leak_detector.set_evidence_yara_match = MagicMock()
    leak_detector.delete_compiled_rules = MagicMock()

    leak_detector.find_matches()

    mock_popen.assert_called_once()

    if evidence_set_called:
        leak_detector.set_evidence_yara_match.assert_called_once()
    else:
        leak_detector.set_evidence_yara_match.assert_not_called()

    if delete_called:
        leak_detector.delete_compiled_rules.assert_called_once()
    else:
        leak_detector.delete_compiled_rules.assert_not_called()


@pytest.mark.parametrize(
    "pcap_data, offset, tshark_output, expected_result, test_description",
    [
        (
            # Testcase1: Packet found successfully
            b"\x00" * 24 + b"\x00" * 16 + b"\x00\x00\x00\x14" + b"\x00" * 20,
            25,
            b'[{"_source": {"layers": {"frame": {"frame.protocols": "eth:ethertype:ip:tcp", "frame.time_epoch": 1669852800}, "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"}, "tcp": {"tcp.srcport": "80", "tcp.dstport": "443"}}}}}]',
            False,
            "Packet found within range",
        ),
        (
            # Testcase2: Packet not found (offset out of range)
            b"\x00" * 24 + b"\x00" * 16 + b"\x00\x00\x00\x14" + b"\x00" * 20,
            100,
            None,
            False,
            "Packet not found, offset out of range",
        ),
        (
            # Testcase3: Error during tshark execution
            b"\x00" * 24 + b"\x00" * 16 + b"\x00\x00\x00\x14" + b"\x00" * 20,
            25,
            b"",
            False,
            "Error running tshark",
        ),
    ],
)
def test_get_packet_info(
    mock_db,
    pcap_data,
    offset,
    tshark_output,
    expected_result,
    test_description,
):
    """Tests the get_packet_info method of LeakDetector."""

    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)

    with patch(
        "builtins.open", mock_open(read_data=pcap_data)
    ) as mock_file, patch("subprocess.Popen") as mock_popen:
        mock_file.return_value.tell.return_value = 24

        if tshark_output is not None:
            mock_popen.return_value.communicate.return_value = (
                tshark_output,
                None,
            )

        result = leak_detector.get_packet_info(offset)
        assert result == expected_result


def test_set_evidence_yara_match(mock_db):
    leak_detector = ModuleFactory().create_leak_detector_obj(mock_db)
    leak_detector.get_packet_info = MagicMock(
        return_value=("10.0.0.1", "10.0.0.2", "tcp", "80", "443", 1669852800)
    )
    leak_detector.db.get_port_info = MagicMock(return_value="HTTP")
    leak_detector.db.get_ip_identification = MagicMock(
        return_value="(Example.com)"
    )
    leak_detector.db.get_tw_of_ts = MagicMock(return_value=["timewindow1"])
    mock_set_evidence = MagicMock()
    leak_detector.db.set_evidence = mock_set_evidence
    leak_detector.set_evidence_yara_match(
        {
            "rule": "GPS Leak",
            "offset": 25,
            "strings_matched": "37.7749,-122.4194",
        }
    )
    calls = mock_set_evidence.call_args_list
    assert len(calls) == 2
