# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/blocking/blocking.py"""
from tests.module_factory import ModuleFactory
from unittest.mock import patch
import pytest

from unittest.mock import MagicMock

from slips_files.core.structures.evidence import TimeWindow


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
        unblocker.db, "del_firewall_block_state"
    ) as mock_del_state:

        unblocker.check_if_time_to_unblock()

        mock_unblock.assert_called_once_with("1.2.3.4", {"src": "test"})
        mock_log.assert_called_once_with("1.2.3.4")
        mock_del.assert_called_once_with("1.2.3.4")
        mock_del_state.assert_called_once_with("1.2.3.4")
        assert "1.2.3.4" not in unblocker.requests


@pytest.mark.parametrize("remaining", [0, 1])
def test_update_requests_keeps_due_requests_until_unblocked(
    remaining: int,
) -> None:
    """A zero-window request must remain queued for firewall removal.

    Parameters:
        remaining: Number of time windows before the update.
    """
    unblocker = ModuleFactory().create_unblocker_obj()
    unblocker.requests = {
        "1.2.3.4": {
            "tw_to_unblock": TimeWindow(
                number=2,
                end_time="2026-08-26T18:38:10+02:00",
            ),
            "block_this_ip_for": remaining,
            "flags": {"from_": True, "to": True},
        }
    }

    with patch("time.time", return_value=1787758703.0):
        unblocker.update_requests()

    assert unblocker.requests["1.2.3.4"]["block_this_ip_for"] == 0
    unblocker.db.set_firewall_block_state.assert_called_once_with(
        "1.2.3.4",
        {
            "unblock_at": "2026-08-26T18:38:10+02:00",
            "remaining_timewindows": 0,
            "flags": {"from_": True, "to": True},
            "updated_at": 1787758703.0,
        },
    )


def test_add_request_persists_schedule_and_flags() -> None:
    """Persist every active unblock request for restart recovery."""
    unblocker = ModuleFactory().create_unblocker_obj()
    unblocker.db.get_blocking_timestamp.return_value = 1787757891.0
    timewindow = TimeWindow(
        number=2,
        end_time="2026-08-26T18:38:10+02:00",
    )
    flags = {"from_": True, "to": True}

    with patch("time.time", return_value=1787757900.0):
        unblocker._add_req("1.2.3.4", timewindow, flags, 1)

    unblocker.db.set_firewall_block_state.assert_called_once_with(
        "1.2.3.4",
        {
            "unblock_at": timewindow.end_time,
            "remaining_timewindows": 1,
            "flags": flags,
            "updated_at": 1787757900.0,
        },
    )


def test_restore_requests_recovers_persisted_schedule() -> None:
    """Recover pending firewall work after the blocker process restarts."""
    unblocker = ModuleFactory().create_unblocker_obj()
    unblocker.db.get_firewall_block_states.return_value = {
        "1.2.3.4": {
            "unblock_at": "2026-08-26T18:38:10+02:00",
            "remaining_timewindows": 0,
            "flags": {"from_": True, "to": True},
        }
    }

    unblocker._restore_requests()

    request = unblocker.requests["1.2.3.4"]
    assert request["tw_to_unblock"].end_time == "2026-08-26T18:38:10+02:00"
    assert request["block_this_ip_for"] == 0
    assert request["flags"] == {"from_": True, "to": True}


def test_successful_unblock_without_start_time_still_completes() -> None:
    """Do not let missing legacy metadata interrupt firewall cleanup."""
    unblocker = ModuleFactory().create_unblocker_obj()
    unblocker.db.get_blocking_timestamp.return_value = None

    unblocker._log_successful_unblock("1.2.3.4")

    unblocker.log.assert_called_once_with(
        "The blocking of 1.2.3.4 ended; its start time was unavailable."
    )


@pytest.mark.parametrize(
    "flags, unblock_success",
    [
        ({"from_": True}, True),
        ({"to": True}, True),
        ({"from_": True, "to": True}, True),
        ({}, True),
        ({"from_": True}, False),
    ],
)
def test__unblock(flags, unblock_success):
    unblocker = ModuleFactory().create_unblocker_obj()
    unblocker.db.get_timewindow.return_value = "tw-1337"

    ip = "1.2.3.4"
    path = "modules.blocking.unblocker.delete_slips_rules_for_ip"

    with patch(path, return_value=unblock_success) as mock_exec:
        result = unblocker._unblock(ip, flags)

        assert result == unblock_success
        mock_exec.assert_called_once_with(unblocker.sudo, ip, flags)

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
