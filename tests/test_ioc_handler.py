# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import json
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "profileid, twid, ip_state, starttime, uid, daddr, "
    "proto, lookup, extra_info, expected_data",
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
                "proto": "False",
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
        "give_threat_intelligence", json.dumps(expected_data)
    )
    assert result == expected_data


@pytest.mark.parametrize(
    "sha1, expected_result",
    [
        # Testcase 1: SSL info found
        (
            "abc123",
            '{"source": "feed1", "tags": ["tag1", "tag2"], "threat_level": 3, '
            '"description": "Malicious SSL cert"}',
        ),
        # Testcase 2: SSL info not found
        ("xyz456", False),
    ],
)
def test_is_blacklisted_ssl(mocker, sha1, expected_result):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.rcache.hmget.return_value = [expected_result]
    result = ioc_handler.is_blacklisted_ssl(sha1)
    assert result == expected_result


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


def test_delete_ti_feed(mocker):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.delete_ti_feed("file1.txt")
    ioc_handler.rcache.hdel.assert_called_with(
        ioc_handler.constants.TI_FILES_INFO, "file1.txt"
    )


@pytest.mark.parametrize(
    "profileid, expected_result",
    [
        # Testcase 1: Profile is malicious
        ("profile1", "malicious"),
        # Testcase 2: Profile is not malicious
        ("profile2", False),
    ],
)
def test_is_profile_malicious(mocker, profileid, expected_result):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.r.hget.return_value = expected_result
    result = ioc_handler.is_profile_malicious(profileid)
    assert result == expected_result


@pytest.mark.parametrize(
    "file, data, expected_data",
    [
        # Testcase 1: Set new file info
        (
            "file1.txt",
            {"time": 1234567890, "etag": "abc123"},
            {"time": 1234567890, "etag": "abc123"},
        ),
        # Testcase 2: Update existing file info
        (
            "file2.txt",
            {"time": 1234567891, "etag": "def456"},
            {"time": 1234567891, "etag": "def456"},
        ),
    ],
)
def test_set_ti_feed_info(mocker, file, data, expected_data):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.set_ti_feed_info(file, data)
    ioc_handler.rcache.hset.assert_called_with(
        "TI_files_info", file, json.dumps(expected_data)
    )


@pytest.mark.parametrize(
    "domain, info_to_set, expected_data",
    [
        # Testcase 1: Add new information
        (
            "example.com",
            {"VirusTotal": [1, 2, 3], "Malicious": ""},
            {"VirusTotal": [1, 2, 3], "Malicious": ""},
        ),
        # Testcase 2: Overwrite existing information
        (
            "google.com",
            {"VirusTotal": [4, 5, 6], "Malicious": "yes"},
            {"VirusTotal": [4, 5, 6], "Malicious": "yes"},
        ),
    ],
)
def test_set_info_for_domains(mocker, domain, info_to_set, expected_data):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.get_domain_data = mocker.Mock(return_value={})
    ioc_handler.set_info_for_domains(domain, info_to_set, "add")
    expected_data_str = json.dumps(expected_data)
    ioc_handler.rcache.hset.assert_called_with(
        "DomainsInfo", domain, expected_data_str
    )
    ioc_handler.r.publish.assert_called_with("dns_info_change", domain)


def test__store_new_url(mocker):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    url = "https://example.com"
    ioc_handler.is_cached_url_by_vt = mocker.Mock(return_value=False)
    ioc_handler._store_new_url(url)
    ioc_handler.rcache.hset.assert_called_with(
        ioc_handler.constants.VT_CACHED_URL_INFO, url, "{}"
    )


def test_get_domain_data_with_data(mocker):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    test_domain = "example.com"
    expected_data = {"key1": "value1", "key2": "value2"}
    ioc_handler.rcache.hget.return_value = json.dumps(expected_data)
    result = ioc_handler.get_domain_data(test_domain)
    assert result == expected_data


def test_get_domain_data_without_data(mocker):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.rcache.hget.return_value = None
    result = ioc_handler.get_domain_data("google.com")
    assert result is False


@pytest.mark.parametrize(
    "domain",
    [
        # Testcase 1: New domain
        "example.com",
        # Testcase 2: Existing domain
        "google.com",
    ],
)
def test_set_new_domain(mocker, domain):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.get_domain_data = mocker.Mock(return_value=False)
    ioc_handler._set_new_domain(domain)
    ioc_handler.rcache.hset.assert_called_with("DomainsInfo", domain, "{}")


@pytest.mark.parametrize(
    "file, time, expected_data",
    [
        # Testcase 1: Set new last update time
        ("feed1.txt", 1234.56, {"time": 1234.56}),
        # Testcase 2: Update existing last update time
        ("feed2.txt", 5678.90, {"time": 5678.90}),
    ],
)
def test_set_feed_last_update_time(mocker, file, time, expected_data):
    ioc_handler = ModuleFactory().create_ioc_handler_obj()
    ioc_handler.rcache.hget.return_value = json.dumps({"time": 100.0})
    ioc_handler.set_feed_last_update_time(file, time)
    expected_data_json = json.dumps(expected_data)
    ioc_handler.rcache.hset.assert_called_with(
        "TI_files_info", file, expected_data_json
    )
