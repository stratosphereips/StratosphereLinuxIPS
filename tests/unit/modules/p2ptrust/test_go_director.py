# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch
import pytest
from tests.module_factory import ModuleFactory
import tempfile
import os


@pytest.mark.parametrize(
    "data_dict, expected_method, expected_args",
    [
        # Test case 1: Handling a valid peer update message
        (
            {
                "message_type": "peer_update",
                "message_contents": {
                    "peerid": "test_peer",
                    "ip": "192.168.1.1",
                    "reliability": 0.8,
                },
            },
            "process_go_update",
            [{"peerid": "test_peer", "ip": "192.168.1.1", "reliability": 0.8}],
        ),
        # Test case 2: Handling a valid go_data message
        (
            {
                "message_type": "go_data",
                "message_contents": {
                    "reporter": "test_reporter",
                    "report_time": 1649445643,
                    "message": "eyJtZXNzYWdlX3R5cGUiOiJyZXBvcnQiLCJrZXkiOiIxOTIuMTY4LjE"
                    "uMSIsImtleV90eXBlIjoiaXAiLCJldmFsdWF0aW9uX3R5cGUiOiJzY29y"
                    "ZV9jb25maWRlbmNlIiwiZXZhbHVhdGlvbiI6eyJzY29yZSI6MC41LCJjb2"
                    "5maWRlbmNlIjowLjh9fQ==",
                },
            },
            "process_go_data",
            [
                {
                    "reporter": "test_reporter",
                    "report_time": 1649445643,
                    "message": "eyJtZXNzYWdlX3R5cGUiOiJyZXBvcnQiLCJrZXkiOiIxOTIuMTY4LjEuM"
                    "SIsImtleV90eXBlIjoiaXAiLCJldmFsdWF0aW9uX3R5cGUiOiJzY29yZV9jb"
                    "25maWRlbmNlIiwiZXZhbHVhdGlvbiI6eyJzY29yZSI6MC41LCJjb25maWRlbm"
                    "NlIjowLjh9fQ==",
                }
            ],
        ),
    ],
)
def test_handle_gopy_data(data_dict, expected_method, expected_args):
    go_director = ModuleFactory().create_go_director_obj()

    with patch.object(go_director, expected_method) as mock_method:
        go_director.handle_gopy_data(data_dict)
        mock_method.assert_called_once_with(*expected_args)


@pytest.mark.parametrize(
    "data_dict, expected_print_args",
    [
        # Test case 1: Handling missing keys in the message
        (
            {"invalid_key": "value"},
            (
                "Json from the pigeon: {'invalid_key': 'value'} doesn't contain expected values "
                "message_type or message_contents",
                0,
                1,
            ),
        ),
        # Test case 2: Handling an invalid message type
        (
            {"message_type": "invalid_type", "message_contents": {}},
            ("Invalid command: invalid_type", 0, 2),
        ),
    ],
)
def test_handle_gopy_data_error_cases(data_dict, expected_print_args):
    go_director = ModuleFactory().create_go_director_obj()

    go_director.handle_gopy_data(data_dict)
    go_director.print.assert_called_once_with(*expected_print_args)


@pytest.mark.parametrize(
    "report, expected_method, expected_args",
    [
        # Test case 1: Handling a valid report message
        (
            {
                "reporter": "test_reporter",
                "report_time": 1649445643,
                "message": "eyJtZXNzYWdlX3R5cGUiOiJyZXBvcnQiLCJrZXkiOiIxOTIuMT"
                "Y4LjEuMSIsImtleV90eXBlIjoiaXAiLCJldmFsdWF0aW9uX3R5cG"
                "UiOiJzY29yZV9jb25maWRlbmNlIiwiZXZhbHVhdGlvbiI6eyJzY29yZ"
                "SI6MC41LCJjb25maWRlbmNlIjowLjh9fQ==",
            },
            "process_message_report",
            [
                "test_reporter",
                1649445643,
                {
                    "message_type": "report",
                    "key": "192.168.1.1",
                    "key_type": "ip",
                    "evaluation_type": "score_confidence",
                    "evaluation": {"score": 0.5, "confidence": 0.8},
                },
            ],
        ),
        # Test case 2: Handling a valid request message
        (
            {
                "reporter": "test_reporter",
                "report_time": 1649445643,
                "message": "eyJtZXNzYWdlX3R5cGUiOiJyZXF1ZXN0IiwiZXZhbHVhdGl"
                "vbl90eXBlIjoic2NvcmVfY29uZmlkZW5jZSIsImtleV90eXBlIjoiaXA"
                "iLCJrZXkiOiIxOTIuMTY4LjEuMSJ9",
            },
            "process_message_request",
            [
                "test_reporter",
                1649445643,
                {
                    "message_type": "request",
                    "evaluation_type": "score_confidence",
                    "key_type": "ip",
                    "key": "192.168.1.1",
                },
            ],
        ),
    ],
)
def test_process_go_data(report, expected_method, expected_args):
    go_director = ModuleFactory().create_go_director_obj()

    with patch.object(go_director, expected_method) as mock_method:
        go_director.process_go_data(report)
        mock_method.assert_called_once_with(*expected_args)


@pytest.mark.parametrize(
    "message, expected_message_type, expected_data",
    [
        # Test case 1: Valid base64 encoded JSON message
        (
            "eyJtZXNzYWdlX3R5cGUiOiJyZXBvcnQiLCJrZXkiOiIxOTIuMTY4LjEuMSIsImtleV90eXBlIjoiaXAiLCJldmFsd"
            "WF0aW9uX3R5cGUiOiJzY29yZV9jb25maWRlbmNlIiwiZXZhbHVhdGlvbiI6ey"
            "JzY29yZSI6MC41LCJjb25maWRlbmNlIjowLjh9fQ==",
            "report",
            {
                "message_type": "report",
                "key": "192.168.1.1",
                "key_type": "ip",
                "evaluation_type": "score_confidence",
                "evaluation": {"score": 0.5, "confidence": 0.8},
            },
        ),
        # Test case 2: Invalid base64 encoded message
        ("invalid_base64_string", "", {}),
        # Test case 3: Valid base64 but invalid JSON message
        ("eyJpbmZvIjoiYmFkIGpzb24ifQ==", "", {}),
        # Test case 4: Valid base64 and JSON but missing 'message_type' key
        ("eyJrZXkiOiIxOTIuMTY4LjEuMSJ9", "", {}),
    ],
)
def test_validate_message(message, expected_message_type, expected_data):
    go_director = ModuleFactory().create_go_director_obj()
    message_type, data = go_director.validate_message(message)
    assert message_type == expected_message_type
    assert data == expected_data


@pytest.mark.parametrize(
    "data, expected_result",
    [
        # Test case 1: Valid request data
        (
            {
                "key": "192.168.1.1",
                "key_type": "ip",
                "evaluation_type": "score_confidence",
            },
            True,
        ),
        # Test case 2: Missing key
        ({"key_type": "ip", "evaluation_type": "score_confidence"}, False),
        # Test case 3: Invalid key type
        (
            {
                "key": "192.168.1.1",
                "key_type": "invalid_type",
                "evaluation_type": "score_confidence",
            },
            False,
        ),
        # Test case 4: Invalid IP address
        (
            {
                "key": "invalid_ip",
                "key_type": "ip",
                "evaluation_type": "score_confidence",
            },
            False,
        ),
        # Test case 5: Invalid evaluation type
        (
            {
                "key": "192.168.1.1",
                "key_type": "ip",
                "evaluation_type": "invalid_evaluation",
            },
            False,
        ),
    ],
)
def test_validate_message_request(
    data,
    expected_result,
):
    go_director = ModuleFactory().create_go_director_obj()
    result = go_director.validate_message_request(data)
    assert result == expected_result


@pytest.mark.parametrize(
    "ip, reporter, score, confidence, timestamp, "
    "profileid_of_attacker, "
    "expected_description, expected_threat_level",
    [
        # Test case 1: Basic test with valid data
        (
            "192.168.1.1",
            "test_reporter",
            0.5,
            0.8,
            1649445643,
            "profile_192.168.1.1",
            "attacking another peer:  (test_reporter).",
            "medium",
        ),
        # Test case 2: Test with a different score and confidence
        (
            "10.0.0.1",
            "another_reporter",
            0.9,
            0.6,
            1649445644,
            "profile_10.0.0.1",
            "attacking another peer:  (another_reporter).",
            "critical",
        ),
    ],
)
def test_set_evidence_p2p_report(
    ip,
    reporter,
    score,
    confidence,
    timestamp,
    profileid_of_attacker,
    expected_description,
    expected_threat_level,
):
    go_director = ModuleFactory().create_go_director_obj()
    go_director.trustdb.get_ip_of_peer.return_value = (timestamp, "")

    go_director.set_evidence_p2p_report(
        ip, reporter, score, confidence, timestamp, profileid_of_attacker
    )

    go_director.db.set_evidence.assert_called_once()
    call_args = go_director.db.set_evidence.call_args[0][0]
    assert call_args.attacker.value == ip
    assert expected_description in call_args.description
    assert call_args.threat_level == expected_threat_level


def test_read_configuration():
    with patch(
        "slips_files.common.parsers.config_parser.ConfigParser",
        return_value=3600.0,
    ):
        go_director = ModuleFactory().create_go_director_obj()
        go_director.read_configuration()
        assert go_director.width == 3600.0


@pytest.mark.parametrize(
    "text, expected_log_content",
    [  # Test case 1: Basic log message
        ("Test log message", " - Test log message\n"),
        # Test case 2: Another log message
        ("Another test message", " - Another test message\n"),
    ],
)
def test_log(
    text,
    expected_log_content,
):
    go_director = ModuleFactory().create_go_director_obj()

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
        temp_filename = temp_file.name

        with patch.object(go_director, "reports_logfile", temp_file):
            go_director.log(text)

    with open(temp_filename, "r") as f:
        log_content = f.read()
    os.unlink(temp_filename)
    assert expected_log_content in log_content


def test_process_message_request_valid_request():
    """Test handling of valid requests when override_p2p is False."""
    go_director = ModuleFactory().create_go_director_obj()
    go_director.override_p2p = False

    data = {
        "key": "192.168.1.1",
        "key_type": "ip",
        "evaluation_type": "score_confidence",
    }

    with patch.object(
        go_director, "respond_to_message_request"
    ) as mock_respond:
        go_director.process_message_request("test_reporter", 1649445643, data)

    mock_respond.assert_called_once_with("192.168.1.1", "test_reporter")
    go_director.print.assert_called_once_with(
        "[The Network -> Slips] request about "
        "192.168.1.1 from: test_reporter"
    )


@pytest.mark.parametrize(
    "data, expected_print_args",
    [
        # Test Case: Invalid Key Type
        (
            {
                "key": "192.168.1.1",
                "key_type": "invalid_type",
                "evaluation_type": "score_confidence",
            },
            ("Module can't process key " "type invalid_type", 0, 2),
        ),
        # Test Case: Invalid Key
        (
            {
                "key": "invalid_ip",
                "key_type": "ip",
                "evaluation_type": "score_confidence",
            },
            (
                "Provided key invalid_ip isn't a "
                "valid value for it's type ip",
                0,
                2,
            ),
        ),
        # Test Case: Invalid Evaluation Type
        (
            {
                "key": "192.168.1.1",
                "key_type": "ip",
                "evaluation_type": "invalid_evaluation",
            },
            (
                "Module can't process evaluation " "type invalid_evaluation",
                0,
                2,
            ),
        ),
    ],
)
def test_process_message_request_invalid_request(data, expected_print_args):
    """Test handling of invalid requests (regardless of override_p2p)."""
    go_director = ModuleFactory().create_go_director_obj()

    go_director.process_message_request("test_reporter", 1649445643, data)
    go_director.print.assert_called_once_with(*expected_print_args)


def test_process_message_request_override_p2p():
    """Test behavior when override_p2p is True."""
    go_director = ModuleFactory().create_go_director_obj()
    go_director.override_p2p = True
    go_director.request_func = Mock()
    data = {
        "key": "192.168.1.1",
        "key_type": "ip",
        "evaluation_type": "score_confidence",
    }

    go_director.process_message_request("test_reporter", 1649445643, data)

    go_director.request_func.assert_called_once_with(
        "192.168.1.1", "test_reporter"
    )


@pytest.mark.parametrize(
    "reporter, report_time, key_type, " "key, evaluation, expected_error",
    [
        (  # testcase1:Score value is out of bounds
            "test_reporter",
            1649445643,
            "ip",
            "192.168.1.1",
            {"score": 1.5, "confidence": 0.8},
            "Score value is out of bounds",
        ),
        (  # testcase2:Confidence value is out of bounds
            "test_reporter",
            1649445643,
            "ip",
            "192.168.1.1",
            {"score": 0.5, "confidence": 1.2},
            "Confidence value is out of bounds",
        ),
        (  # testcase3:Score or confidence are missing
            "test_reporter",
            1649445643,
            "ip",
            "192.168.1.1",
            {"score": 0.5},
            "Score or confidence are missing",
        ),
        (  # testcase4:Score or confidence have wrong data type
            "test_reporter",
            1649445643,
            "ip",
            "192.168.1.1",
            {"score": "invalid", "confidence": 0.8},
            "Score or confidence have wrong data type",
        ),
    ],
)
def test_process_evaluation_score_confidence_invalid(
    reporter, report_time, key_type, key, evaluation, expected_error
):
    go_director = ModuleFactory().create_go_director_obj()

    with patch.object(go_director, "print") as mock_print, patch.object(
        go_director.trustdb, "insert_new_go_report"
    ) as mock_insert, patch.object(
        go_director.db, "store_p2p_report"
    ) as mock_store, patch.object(
        go_director.db, "add_profile"
    ) as mock_add_profile, patch.object(
        go_director, "set_evidence_p2p_report"
    ) as mock_set_evidence:
        go_director.process_evaluation_score_confidence(
            reporter, report_time, key_type, key, evaluation
        )

        mock_print.assert_called_with(expected_error, 0, 2)
        mock_insert.assert_not_called()
        mock_store.assert_not_called()
        mock_add_profile.assert_not_called()
        mock_set_evidence.assert_not_called()


def test_process_evaluation_score_confidence_valid():
    go_director = ModuleFactory().create_go_director_obj()

    reporter = "test_reporter"
    report_time = 1649445643
    key_type = "ip"
    key = "192.168.1.1"
    evaluation = {"score": 0.5, "confidence": 0.8}
    expected_result = (
        "Data processing ok: reporter test_reporter, "
        "report time 1649445643, key 192.168.1.1 (ip), "
        "score 0.5, confidence 0.8"
    )

    with patch.object(go_director, "print") as mock_print, patch.object(
        go_director.trustdb, "insert_new_go_report"
    ) as mock_insert, patch.object(
        go_director.db, "store_p2p_report"
    ) as mock_store, patch.object(
        go_director.db, "add_profile"
    ) as mock_add_profile, patch.object(
        go_director, "set_evidence_p2p_report"
    ) as mock_set_evidence:
        go_director.process_evaluation_score_confidence(
            reporter, report_time, key_type, key, evaluation
        )

        mock_print.assert_called_with(expected_result, 2, 0)
        mock_insert.assert_called_once()
        mock_store.assert_called_once()
        mock_add_profile.assert_called_once()
        mock_set_evidence.assert_called_once()


@pytest.mark.parametrize(
    "data, expected_calls",
    [
        # Test case 1: Valid update with both IP and reliability
        (
            {
                "peerid": "test_peer",
                "ip": "192.168.1.1",
                "reliability": 0.8,
                "timestamp": 1649445643,
            },
            [
                ("insert_go_reliability", ("test_peer", 0.8)),
                ("insert_go_ip_pairing", ("test_peer", "192.168.1.1")),
            ],
        ),
        # Test case 2: Update with only reliability
        (
            {"peerid": "test_peer", "reliability": 0.7},
            [("insert_go_reliability", ("test_peer", 0.7))],
        ),
        # Test case 3: Update with only IP
        (
            {"peerid": "test_peer", "ip": "192.168.1.2"},
            [("insert_go_ip_pairing", ("test_peer", "192.168.1.2"))],
        ),
        # Test case 4: Invalid IP address
        ({"peerid": "test_peer", "ip": "invalid_ip"}, []),
    ],
)
def test_process_go_update(data, expected_calls):
    go_director = ModuleFactory().create_go_director_obj()

    with patch.object(
        go_director.trustdb, "insert_go_reliability"
    ) as mock_insert_reliability, patch.object(
        go_director.trustdb, "insert_go_ip_pairing"
    ) as mock_insert_ip:

        go_director.process_go_update(data)

        actual_calls = []
        for call in mock_insert_reliability.call_args_list:
            actual_calls.append(("insert_go_reliability", call[0]))
        for call in mock_insert_ip.call_args_list:
            actual_calls.append(("insert_go_ip_pairing", call[0]))

        assert actual_calls == expected_calls


def test_respond_to_message_request_with_info():
    go_director = ModuleFactory().create_go_director_obj()
    key = "192.168.1.1"
    reporter = "test_reporter"
    score = 0.5
    confidence = 0.8

    with patch(
        "modules.p2ptrust.utils." "go_director.get_ip_info_from_slips",
        return_value=(score, confidence),
    ) as mock_get_info:
        with patch(
            "modules.p2ptrust." "utils.go_director." "send_evaluation_to_go"
        ) as mock_send_evaluation:
            go_director.respond_to_message_request(key, reporter)

            mock_get_info.assert_called_once_with(key, go_director.db)

            expected_print = (
                f"[Slips -> The Network] Slips responded "
                f"with info score={score} confidence={confidence} "
                f"about IP: {key} to {reporter}."
            )
            go_director.print.assert_called_once_with(expected_print, 2, 0)

            mock_send_evaluation.assert_called_once_with(
                key,
                score,
                confidence,
                reporter,
                go_director.pygo_channel,
                go_director.db,
            )


def test_respond_to_message_request_without_info():
    go_director = ModuleFactory().create_go_director_obj()
    key = "10.0.0.1"
    reporter = "another_reporter"
    score = None
    confidence = None

    with patch(
        "modules.p2ptrust.utils." "go_director.get_ip_info_from_slips",
        return_value=(score, confidence),
    ) as mock_get_info:
        with patch(
            "modules.p2ptrust.utils." "go_director.send_evaluation_to_go"
        ) as mock_send_evaluation:
            go_director.respond_to_message_request(key, reporter)

            mock_get_info.assert_called_once_with(key, go_director.db)

            expected_print = (
                f"[Slips -> The Network] Slips has no info about IP: {key}. "
                f"Not responding to {reporter}"
            )
            go_director.print.assert_called_once_with(expected_print, 2, 0)

            mock_send_evaluation.assert_not_called()
