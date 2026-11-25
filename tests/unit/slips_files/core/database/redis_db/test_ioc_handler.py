# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import json
from tests.module_factory import ModuleFactory


from unittest.mock import Mock


@pytest.mark.parametrize(
    "profileid, twid, ip_state, starttime, uid, daddr, proto, lookup, extra_info, expected_data",
    [
        # Testcase 1: Minimal required parameters
        (
            1,
            "tw1",
            "state1",
            1234,
            "uid1",
            "1.1.1.1",
            False,
            "lookup1",
            False,
            {
                "to_lookup": "lookup1",
                "profileid": "1",
                "twid": "tw1",
                "proto": "False",  # str(False)
                "ip_state": "state1",
                "stime": 1234,
                "uid": "uid1",
                "daddr": "1.1.1.1",
            },
        ),
        # Testcase 2: With extra information
        (
            2,
            "tw2",
            "state2",
            5678,
            "uid2",
            "2.2.2.2",
            "proto2",
            "lookup2",
            {"dns_query": "example.com"},
            {
                "to_lookup": "lookup2",
                "profileid": "2",
                "twid": "tw2",
                "proto": "proto2",
                "ip_state": "state2",
                "stime": 5678,
                "uid": "uid2",
                "daddr": "2.2.2.2",
                "dns_query": "example.com",
            },
        ),
    ],
)
def test_give_threat_intelligence(
    mocker,
    profileid,
    twid,
    ip_state,
    starttime,
    uid,
    daddr,
    proto,
    lookup,
    extra_info,
    expected_data,
):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler._should_ask_modules_about_ip = Mock(return_value=True)
    ioc_handler.publish = mocker.Mock()

    result = ioc_handler.give_threat_intelligence(
        profileid,
        twid,
        ip_state,
        starttime,
        uid,
        daddr,
        proto,
        lookup,
        extra_info,
    )

    ioc_handler.publish.assert_called_with(
        ioc_handler.channels.GIVE_TI, json.dumps(expected_data)
    )
    assert result == expected_data


@pytest.mark.parametrize(
    "file, expected_file_info",
    [
        # Testcase 1: File with info
        ("file1.txt", {"time": 1234.5, "etag": "abc123"}),
        # Testcase 2: File without info
        ("file2.txt", {}),
    ],
)
def test_get_ti_feed_info(mocker, file, expected_file_info):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.rcache.hget.return_value = json.dumps(expected_file_info)
    result = ioc_handler.get_ti_feed_info(file)
    assert result == expected_file_info


def test_set_ti_feed_info(mocker):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    data = {"time": 1234567890, "etag": "abc123"}
    ioc_handler.set_ti_feed_info("file1.txt", data)
    ioc_handler.rcache.hset.assert_called_with(
        "TI_files_info", "file1.txt", json.dumps(data)
    )


def test__store_new_url(mocker):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    url = "https://example.com"
    ioc_handler.is_cached_url_by_vt = mocker.Mock(return_value=False)
    ioc_handler._store_new_url(url)
    ioc_handler.rcache.hset.assert_called_with(
        ioc_handler.constants.VT_CACHED_URL_INFO, url, "{}"
    )


def test_set_new_domain(mocker):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.get_domain_data = mocker.Mock(return_value=False)
    ioc_handler._set_new_domain("example.com")
    ioc_handler.rcache.hset.assert_called_with(
        "DomainsInfo", "example.com", "{}"
    )


@pytest.mark.parametrize(
    "cached_info, expected_data",
    [
        # existing info keeps its other fields and only gets a new time
        (
            {"time": 100.0, "etag": "abc123"},
            {"time": 1234.56, "etag": "abc123"},
        ),
        # no cached info about this feed
        (None, {"time": 1234.56}),
    ],
)
def test_set_feed_last_update_time(mocker, cached_info, expected_data):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.rcache.hget.return_value = (
        json.dumps(cached_info) if cached_info else None
    )
    ioc_handler.set_feed_last_update_time("feed1.txt", 1234.56)
    ioc_handler.rcache.hset.assert_called_with(
        "TI_files_info", "feed1.txt", json.dumps(expected_data)
    )
