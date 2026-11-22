# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for modules/ip_info/mac_vendor_info.py"""

import json
from queue import Queue
from unittest.mock import AsyncMock, Mock

import pytest
import requests

from tests.module_factory import ModuleFactory


def test_pending_mac_queries_stay_inside_ip_info_process() -> None:
    """Use a thread queue for MAC lookups to avoid named semaphores."""
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor

    assert isinstance(mac_vendor.pending_mac_queries, Queue)


async def test_get_vendor_from_database(mocker):
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mac_addr = "08:00:27:7f:09:e1"
    profileid = "profile_10.0.2.15"
    db_vendor = "Database Vendor"
    run_in_executor = AsyncMock()
    mac_vendor.get_vendor_offline = Mock()

    mac_vendor.db.get_mac_vendor_from_profile.return_value = db_vendor

    result = await mac_vendor.get_vendor_async(
        mac_addr, profileid, run_in_executor
    )
    assert result is True
    mac_vendor.db.get_mac_vendor_from_profile.assert_called_once_with(
        profileid
    )
    mac_vendor.get_vendor_offline.assert_not_called()
    run_in_executor.assert_not_awaited()


@pytest.mark.parametrize(
    "mac", ["A2:D7:7B:FA:6A:55", "02:00:00:00:00:01", "52:54:00:12:34:56"]
)
async def test_local_mac_classification_does_not_query_manufacturer(
    mac: str,
) -> None:
    """Local MAC prefixes cannot identify an IEEE hardware manufacturer.

    Parameters:
        mac: Private, manually assigned or virtual interface MAC.
    """
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mac_vendor.get_vendor_offline = Mock()
    run_in_executor = AsyncMock()
    result = await mac_vendor.get_vendor_async(
        mac, "profile_192.168.1.20", run_in_executor
    )
    assert result == {
        "MAC": mac,
        "Vendor": "Unknown",
        "mac_address_type": "locally_administered",
    }
    mac_vendor.db.get_mac_vendor_from_profile.assert_not_called()
    mac_vendor.get_vendor_offline.assert_not_called()
    run_in_executor.assert_not_awaited()
    mac_vendor.db.set_mac_vendor_to_profile.assert_not_called()


async def test_get_vendor_from_offline():
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mac_addr = "08:00:27:7f:09:e2"
    profileid = "profile_10.0.2.16"
    offline_vendor = "Offline Vendor"
    run_in_executor = AsyncMock()

    mac_vendor.db.get_mac_vendor_from_profile.return_value = None
    mac_vendor.get_vendor_offline = Mock(return_value=offline_vendor)

    result = await mac_vendor.get_vendor_async(
        mac_addr, profileid, run_in_executor
    )

    assert result == {"MAC": mac_addr, "Vendor": offline_vendor}
    mac_vendor.db.get_mac_vendor_from_profile.assert_called_once_with(
        profileid
    )
    mac_vendor.get_vendor_offline.assert_called_once_with(mac_addr, profileid)
    run_in_executor.assert_not_awaited()
    mac_vendor.db.set_mac_vendor_to_profile.assert_called_once_with(
        profileid, mac_addr, offline_vendor
    )


@pytest.mark.parametrize(
    "online_vendor, expected_vendor, expected_saves",
    [
        ("Online Vendor", "Online Vendor", 1),
        (None, "Unknown", 0),
    ],
)
async def test_get_vendor_falls_back_to_the_online_lookup(
    online_vendor: str | None, expected_vendor: str, expected_saves: int
) -> None:
    """Ask the online database only when the offline one has no answer.

    Parameters:
        online_vendor: Vendor returned by the online lookup, if any.
        expected_vendor: Vendor reported to the caller.
        expected_saves: How many times the vendor is saved to the profile.
    """
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mac_addr = "08:00:27:7f:09:e3"
    profileid = "profile_10.0.2.17"
    run_in_executor = AsyncMock(return_value=online_vendor)

    mac_vendor.db.get_mac_vendor_from_profile.return_value = None
    mac_vendor.get_vendor_offline = Mock(return_value=None)

    result = await mac_vendor.get_vendor_async(
        mac_addr, profileid, run_in_executor
    )

    assert result == {"MAC": mac_addr, "Vendor": expected_vendor}
    mac_vendor.get_vendor_offline.assert_called_once_with(mac_addr, profileid)
    run_in_executor.assert_awaited_once_with(
        mac_vendor.get_vendor_online, mac_addr
    )
    assert (
        mac_vendor.db.set_mac_vendor_to_profile.call_count == expected_saves
    )


async def test_get_vendor_broadcast_mac():
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mac_addr = "ff:ff:ff:ff:ff:ff"
    profileid = "profile_10.0.2.19"
    run_in_executor = AsyncMock()
    mac_vendor.get_vendor_offline = Mock()

    result = await mac_vendor.get_vendor_async(
        mac_addr, profileid, run_in_executor
    )

    assert result is False
    mac_vendor.db.get_mac_vendor_from_profile.assert_not_called()
    mac_vendor.get_vendor_offline.assert_not_called()
    run_in_executor.assert_not_awaited()
    mac_vendor.db.set_mac_vendor_to_profile.assert_not_called()


@pytest.mark.parametrize(
    "status_code, response_text, expected_vendor, mock_side_effect",
    [
        (200, "Valid Vendor", "Valid Vendor", None),
        (204, "", False, None),
        (None, None, False, requests.exceptions.ReadTimeout()),
        (None, None, False, requests.exceptions.ConnectionError()),
        (None, None, False, json.decoder.JSONDecodeError("Msg", "Doc", 0)),
    ],
)
def test_get_vendor_online(
    mocker,
    status_code,
    response_text,
    expected_vendor,
    mock_side_effect,
):
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mock_response = Mock(status_code=status_code, text=response_text)
    mock_requests = mocker.patch(
        "requests.get",
        return_value=mock_response,
        side_effect=mock_side_effect,
    )

    vendor = mac_vendor.get_vendor_online("00:11:22:33:44:55")

    assert vendor == expected_vendor
    mock_requests.assert_called_once_with(
        "https://api.macvendors.com/00:11:22:33:44:55", timeout=2
    )


def test_get_vendor_online_negative_cache_skips_second_lookup(mocker):
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mock_requests = mocker.patch(
        "requests.get",
        side_effect=requests.exceptions.ConnectionError(),
    )

    assert mac_vendor.get_vendor_online("00:11:22:33:44:55") is False
    assert mac_vendor.get_vendor_online("00:11:22:33:44:55") is False

    mock_requests.assert_called_once_with(
        "https://api.macvendors.com/00:11:22:33:44:55", timeout=2
    )


@pytest.mark.parametrize(
    "is_db_loaded, db_vendor, expected_vendor, expected_pending_queries",
    [
        (False, "Some Vendor", False, 1),
        (True, "Some Vendor", "Some Vendor", 0),
        (True, None, False, 0),
    ],
)
def test_get_vendor_offline_waits_for_the_mac_database(
    mocker,
    is_db_loaded: bool,
    db_vendor: str | None,
    expected_vendor: str | bool,
    expected_pending_queries: int,
) -> None:
    """Queue the lookup until the update manager has downloaded the db.

    Parameters:
        mocker: Pytest mock fixture.
        is_db_loaded: Whether the offline MAC database is ready.
        db_vendor: Vendor the offline database knows for the MAC.
        expected_vendor: Vendor returned to the caller.
        expected_pending_queries: Lookups left waiting for the database.
    """
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mac_vendor.mac_vendor_db_loaded = is_db_loaded
    mocker.patch(
        "modules.ip_info.mac_vendor_info.utils.get_mac_vendor_from_mac_addr",
        return_value=db_vendor,
    )

    vendor = mac_vendor.get_vendor_offline("00:11:22:33:44:55", "profile_1")

    assert vendor == expected_vendor
    assert mac_vendor.pending_mac_queries.qsize() == expected_pending_queries


def test_check_if_we_have_pending_mac_queries_with_mac_db(mocker):
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mac_vendor.mac_vendor_db_loaded = True
    mac_vendor.pending_mac_queries = Mock()
    mac_vendor.pending_mac_queries.empty.side_effect = [False, False, True]
    mac_vendor.pending_mac_queries.get.side_effect = [
        ("00:11:22:33:44:55", "profile_1"),
        ("AA:BB:CC:DD:EE:FF", "profile_2"),
        Exception("Empty queue"),
    ]
    mock_get_vendor_offline = mocker.patch.object(
        mac_vendor, "get_vendor_offline"
    )
    mac_vendor.check_if_we_have_pending_offline_mac_queries()
    assert mock_get_vendor_offline.call_count == 2
    mock_get_vendor_offline.assert_any_call("00:11:22:33:44:55", "profile_1")
    mock_get_vendor_offline.assert_any_call("AA:BB:CC:DD:EE:FF", "profile_2")


def test_check_if_we_have_pending_mac_queries_empty_queue(mocker):
    mac_vendor = ModuleFactory().create_ip_info_obj().mac_vendor
    mac_vendor.mac_vendor_db_loaded = True
    mac_vendor.pending_mac_queries = Mock()
    mac_vendor.pending_mac_queries.empty.return_value = True
    mock_get_vendor_offline = mocker.patch.object(
        mac_vendor, "get_vendor_offline"
    )
    mac_vendor.check_if_we_have_pending_offline_mac_queries()
    mock_get_vendor_offline.assert_not_called()
