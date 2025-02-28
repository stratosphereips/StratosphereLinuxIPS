# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/flowalerts/notice.py"""

from dataclasses import asdict
from unittest.mock import Mock

from slips_files.core.flows.zeek import Notice
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
                "scanning_ip": "192.168.1.1",
            },
            0,
        ),
    ],
)
def test_check_vertical_portscan(flow, expected_call_count):
    notice = ModuleFactory().create_notice_analyzer_obj()
    notice.set_evidence.vertical_portscan = Mock()
    flow = Notice(
        starttime=flow["stime"],
        saddr="192.168.1.60",
        daddr="",
        sport="",
        dport="",
        note=flow["note"],
        msg="",
        scanned_port="",
        dst="",
        scanning_ip=flow["scanning_ip"],
        uid="1364",
    )
    notice.check_vertical_portscan("timewindow1", flow)

    assert (
        notice.set_evidence.vertical_portscan.call_count == expected_call_count
    )


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
def test_check_horizontal_portscan(mocker, flow, expected_call_count):
    notice = ModuleFactory().create_notice_analyzer_obj()
    mock_horizontal_portscan = mocker.patch.object(
        notice.set_evidence, "horizontal_portscan"
    )
    flow = Notice(
        starttime=flow["stime"],
        saddr="192.168.1.60",
        daddr="",
        sport="",
        dport="",
        note=flow["note"],
        msg=flow["msg"],
        scanned_port="",
        dst="",
        scanning_ip="",
        uid="1364",
    )
    notice.check_horizontal_portscan(flow, "test_profileid", "test_twid")

    assert mock_horizontal_portscan.call_count == expected_call_count
    expected_calls = [
        mocker.call("test_profileid", "test_twid", flow)
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
def test_check_password_guessing(mocker, flow, expected_call_count):
    notice = ModuleFactory().create_notice_analyzer_obj()
    mock_pw_guessing = mocker.patch.object(notice.set_evidence, "pw_guessing")
    flow = Notice(
        starttime=flow["stime"],
        saddr="192.168.1.60",
        daddr="",
        sport="",
        dport="",
        note=flow["note"],
        msg=flow["msg"],
        scanned_port="",
        dst="",
        scanning_ip="",
        uid="1364",
    )
    notice.check_password_guessing("test_twid", flow)

    assert mock_pw_guessing.call_count == expected_call_count
    expected_calls = [mocker.call("test_twid", flow)] * expected_call_count
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
                        "flow": asdict(
                            Notice(
                                starttime="1234567890",
                                saddr="192.168.1.1",
                                daddr="",
                                sport="",
                                dport="",
                                note="Port_Scan",
                                msg="Test message",
                                scanned_port="",
                                dst="",
                                scanning_ip="192.168.1.1",
                                uid="1234",
                            )
                        ),
                    }
                )
            },
            True,
            {"vertical": 1, "horizontal": 1, "password": 1},
        ),
    ],
)
def test_analyze(mocker, msg, expected_result, expected_call_counts):
    notice = ModuleFactory().create_notice_analyzer_obj()
    mock_vertical = mocker.patch.object(notice, "check_vertical_portscan")
    mock_horizontal = mocker.patch.object(notice, "check_horizontal_portscan")
    mock_password = mocker.patch.object(notice, "check_password_guessing")
    msg.update({"channel": "new_notice"})
    result = notice.analyze(msg)
    assert mock_vertical.call_count == expected_call_counts["vertical"]
    assert mock_horizontal.call_count == expected_call_counts["horizontal"]
    assert mock_password.call_count == expected_call_counts["password"]
    assert result == expected_result
