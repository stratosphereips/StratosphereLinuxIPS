# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/blocking/blocking.py"""
from tests.module_factory import ModuleFactory
from unittest.mock import patch
import pytest

from unittest.mock import MagicMock


@pytest.mark.parametrize(
    "ip, existing_requests, current_tw, expected_block_duration",
    [
        # ip being blocked for the first time
        ("1.2.3.4", {}, 100, 1),
        # test ip in self.requests
        ("5.6.7.8", {"5.6.7.8": {"block_this_ip_for": 2}}, 200, 3),
    ],
)
def test_unblock_request(
    ip, existing_requests, current_tw, expected_block_duration
):
    unblocker = ModuleFactory().create_unblocker_obj()
    unblocker.requests = existing_requests

    with patch.object(
        unblocker, "_get_tw_to_unblock_at"
    ) as mock_get_tw, patch.object(unblocker, "_add_req") as mock_add_req:
        mock_get_tw.return_value = "fake-tw"

        flags = {"reason": "test"}
        unblocker.unblock_request(ip, current_tw, flags=flags)

        mock_get_tw.assert_called_once_with(
            ip, current_tw, expected_block_duration
        )
        mock_add_req.assert_called_once_with(
            ip, "fake-tw", flags, expected_block_duration
        )


def test_check_if_time_to_unblock():
    unblocker = ModuleFactory().create_unblocker_obj()

    unblocker.requests = {
        "1.2.3.4": {
            "tw_to_unblock": MagicMock(end_time="2025-01-01T00:00:00"),
            "flags": {"src": "test"},
        }
    }
    # loop only once
    unblocker.should_stop = MagicMock(side_effect=[False, True])

    with patch("time.sleep"), patch(
        "time.time", return_value=1735689600.0
    ), patch(
        "modules.blocking.unblocker.utils.convert_ts_format",
        return_value=1735689600.0,
    ), patch.object(
        unblocker, "_unblock", return_value=True
    ) as mock_unblock, patch.object(
        unblocker, "_log_successful_unblock"
    ) as mock_log, patch.object(
        unblocker.db, "del_blocked_ip"
    ) as mock_del, patch.object(
        unblocker, "del_request"
    ) as mock_del_req:

        unblocker.check_if_time_to_unblock()

        mock_unblock.assert_called_once_with("1.2.3.4", {"src": "test"})
        mock_log.assert_called_once_with("1.2.3.4")
        mock_del.assert_called_once_with("1.2.3.4")
        mock_del_req.assert_called_once_with("1.2.3.4")


@pytest.mark.parametrize(
    "flags, expected_calls, unblock_success",
    [
        ({"from_": True}, 1, True),
        ({"to": True}, 1, True),
        ({"from_": True, "to": True}, 2, True),
        ({}, 2, True),  # defaults to both True
        ({"from_": True}, 1, False),
    ],
)
def test__unblock(flags, expected_calls, unblock_success):
    unblocker = ModuleFactory().create_unblocker_obj()
    unblocker.db.get_timewindow.return_value = "tw-1337"

    ip = "1.2.3.4"
    path = "modules.blocking.unblocker.exec_iptables_command"

    with patch(path, return_value=unblock_success) as mock_exec:
        result = unblocker._unblock(ip, flags)

        assert result == unblock_success
        assert mock_exec.call_count == expected_calls

        if unblock_success:
            unblocker.print.assert_called_once_with(
                f"IP {ip} is unblocked in tw-1337."
            )
            unblocker.log.assert_called_once_with(
                f"IP {ip} is unblocked in tw-1337."
            )
        else:
            unblocker.print.assert_called_once_with(
                f"An errror occured. Unable to unblock {ip}"
            )
            unblocker.log.assert_called_once_with(
                f"An errror occured. Unable to unblock {ip}"
            )
