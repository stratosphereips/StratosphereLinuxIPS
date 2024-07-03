"""Unit test for modules/flowalerts/notice.py"""

from tests.module_factory import ModuleFactory
import json
import pytest


@pytest.mark.parametrize(
    "flow, expected_call_count",
    [
        # Test case 1: Vertical port scan
        (
            {
                "stime": 1234567890,
                "msg": "Scan message",
                "note": "Port_Scan",
                "scanning_ip": "192.168.1.1",
            },
            1,
        ),
        # Test case 2: Not a port scan
        (
            {
                "stime": 1234567890,
                "msg": "Other message",
                "note": "Other_Note",
            },
            0,
        ),
    ],
)
def test_check_vertical_portscan(mock_db, mocker, flow, expected_call_count):
    notice = ModuleFactory().create_notice_analyzer_obj(mock_db)
    mock_vertical_portscan = mocker.patch.object(
        notice.set_evidence, "vertical_portscan"
    )

    notice.check_vertical_portscan(flow, "test_uid", "test_twid")

    assert mock_vertical_portscan.call_count == expected_call_count
    expected_calls = [
        mocker.call(
            flow["msg"],
            flow.get("scanning_ip", ""),
            flow["stime"],
            "test_twid",
            "test_uid",
        )
    ] * expected_call_count
    mock_vertical_portscan.assert_has_calls(expected_calls)


@pytest.mark.parametrize(
    "flow, expected_call_count",
    [
        # Test case 1: Horizontal port scan
        (
            {
                "stime": 1234567890,
                "msg": "Scan message",
                "note": "Address_Scan",
            },
            1,
        ),
        # Test case 2: Not an address scan
        (
            {
                "stime": 1234567890,
                "msg": "Other message",
                "note": "Other_Note",
            },
            0,
        ),
    ],
)
def test_check_horizontal_portscan(mock_db, mocker, flow, expected_call_count):
    notice = ModuleFactory().create_notice_analyzer_obj(mock_db)
    mock_horizontal_portscan = mocker.patch.object(
        notice.set_evidence, "horizontal_portscan"
    )

    notice.check_horizontal_portscan(
        flow, "test_uid", "test_profileid", "test_twid"
    )

    assert mock_horizontal_portscan.call_count == expected_call_count
    expected_calls = [
        mocker.call(
            flow["msg"],
            flow["stime"],
            "test_profileid",
            "test_twid",
            "test_uid",
        )
    ] * expected_call_count
    mock_horizontal_portscan.assert_has_calls(expected_calls)


@pytest.mark.parametrize(
    "flow, expected_call_count",
    [
        # Test case 1: Password guessing
        (
            {
                "stime": 1234567890,
                "msg": "Guessing message",
                "note": "Password_Guessing",
            },
            1,
        ),
        # Test case 2: Not password guessing
        (
            {
                "stime": 1234567890,
                "msg": "Other message",
                "note": "Other_Note",
            },
            0,
        ),
    ],
)
def test_check_password_guessing(mock_db, mocker, flow, expected_call_count):
    notice = ModuleFactory().create_notice_analyzer_obj(mock_db)
    mock_pw_guessing = mocker.patch.object(notice.set_evidence, "pw_guessing")

    notice.check_password_guessing(flow, "test_uid", "test_twid")

    assert mock_pw_guessing.call_count == expected_call_count
    expected_calls = [
        mocker.call(
            flow["msg"], flow["stime"], "test_twid", "test_uid", by="Zeek"
        )
    ] * expected_call_count
    mock_pw_guessing.assert_has_calls(expected_calls)


@pytest.mark.parametrize(
    "msg, expected_result, expected_call_counts",
    [
        # Test case 1: Valid message
        (
            {
                "data": json.dumps(
                    {
                        "profileid": "test_profile",
                        "twid": "test_twid",
                        "flow": json.dumps(
                            {
                                "stime": 1234567890,
                                "msg": "Test message",
                                "note": "Port_Scan",
                                "scanning_ip": "192.168.1.1",
                            }
                        ),
                        "uid": "test_uid",
                    }
                )
            },
            True,
            {"vertical": 1, "horizontal": 1, "password": 1},
        ),
        # Test case 2: No message
        (None, False, {"vertical": 0, "horizontal": 0, "password": 0}),
    ],
)
def test_analyze(mock_db, mocker, msg, expected_result, expected_call_counts):
    notice = ModuleFactory().create_notice_analyzer_obj(mock_db)
    mock_get_msg = mocker.patch.object(
        notice.flowalerts, "get_msg", return_value=msg
    )
    mock_vertical = mocker.patch.object(notice, "check_vertical_portscan")
    mock_horizontal = mocker.patch.object(notice, "check_horizontal_portscan")
    mock_password = mocker.patch.object(notice, "check_password_guessing")

    result = notice.analyze()

    mock_get_msg.assert_called_once_with("new_notice")
    assert mock_vertical.call_count == expected_call_counts["vertical"]
    assert mock_horizontal.call_count == expected_call_counts["horizontal"]
    assert mock_password.call_count == expected_call_counts["password"]
    assert result == expected_result
