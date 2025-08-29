# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/ip_info/ip_info.py"""

import asyncio

import netifaces

from tests.module_factory import ModuleFactory
import maxminddb
import pytest
from unittest.mock import (
    Mock,
    patch,
)
import json
import requests
import socket
import subprocess
from slips_files.core.structures.evidence import (
    ThreatLevel,
    Evidence,
    Proto,
    EvidenceType,
    IoCType,
    Direction,
)


@pytest.mark.parametrize(
    "ip_address, expected_geocountry",
    [  # Testcase 1: Valid IP address
        ("153.107.41.230", {"geocountry": "Australia"}),
        # Testcase 2: Private IP address
        ("192.168.1.1", {"geocountry": "Private"}),
        # Testcase 3: Private IPv6 address
        ("2001:db8::1", {"geocountry": "Private"}),
        # Testcase 4: IP address not found in database
        ("23.188.195.255", {"geocountry": "Unknown"}),
    ],
)
def test_get_geocountry(ip_address, expected_geocountry):
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.country_db = maxminddb.open_database(
        "databases/GeoLite2-Country.mmdb"
    )
    assert ip_info.get_geocountry(ip_address) == expected_geocountry


def test_get_vendor_from_database(mocker):
    ip_info = ModuleFactory().create_ip_info_obj()
    mac_addr = "08:00:27:7f:09:e1"
    profileid = "profile_10.0.2.15"
    db_vendor = "Database Vendor"

    ip_info.db.get_mac_vendor_from_profile.return_value = db_vendor

    result = ip_info.get_vendor(mac_addr, profileid)
    expected_result = True
    assert result == expected_result
    (ip_info.db.get_mac_vendor_from_profile.assert_called_once_with(profileid))
    mocker.patch.object(ip_info, "get_vendor_offline").assert_not_called()
    mocker.patch.object(ip_info, "get_vendor_online").assert_not_called()


def test_get_vendor_from_offline(
    mocker,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    mac_addr = "08:00:27:7f:09:e2"
    profileid = "profile_10.0.2.16"
    offline_vendor = "Offline Vendor"

    ip_info.db.get_mac_vendor_from_profile.return_value = None
    mocker.patch.object(
        ip_info, "get_vendor_offline", return_value=offline_vendor
    )

    result = ip_info.get_vendor(mac_addr, profileid)

    assert result == {"MAC": mac_addr, "Vendor": offline_vendor}
    (ip_info.db.get_mac_vendor_from_profile.assert_called_once_with(profileid))
    (ip_info.get_vendor_offline.assert_called_once_with(mac_addr, profileid))
    mocker.patch.object(ip_info, "get_vendor_online").assert_not_called()
    ip_info.db.set_mac_vendor_to_profile.assert_called_once_with(
        profileid, mac_addr, offline_vendor
    )


def test_get_vendor_from_online(
    mocker,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    mac_addr = "08:00:27:7f:09:e3"
    profileid = "profile_10.0.2.17"
    online_vendor = "Online Vendor"

    ip_info.db.get_mac_vendor_from_profile.return_value = None
    mocker.patch.object(ip_info, "get_vendor_offline", return_value=None)
    mocker.patch.object(
        ip_info, "get_vendor_online", return_value=online_vendor
    )

    result = ip_info.get_vendor(mac_addr, profileid)

    assert result == {"MAC": mac_addr, "Vendor": online_vendor}
    (ip_info.db.get_mac_vendor_from_profile.assert_called_once_with(profileid))
    (ip_info.get_vendor_offline.assert_called_once_with(mac_addr, profileid))
    (ip_info.get_vendor_online.assert_called_once_with(mac_addr))
    ip_info.db.set_mac_vendor_to_profile.assert_called_once_with(
        profileid, mac_addr, online_vendor
    )


def test_get_vendor_not_found(
    mocker,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    mac_addr = "08:00:27:7f:09:e4"
    profileid = "profile_10.0.2.18"

    ip_info.db.get_mac_vendor_from_profile.return_value = None
    mocker.patch.object(ip_info, "get_vendor_offline", return_value=None)
    mocker.patch.object(ip_info, "get_vendor_online", return_value=None)

    result = ip_info.get_vendor(mac_addr, profileid)

    assert result == {"MAC": mac_addr, "Vendor": "Unknown"}
    (ip_info.db.get_mac_vendor_from_profile.assert_called_once_with(profileid))
    (ip_info.get_vendor_offline.assert_called_once_with(mac_addr, profileid))
    ip_info.get_vendor_online.assert_called_once_with(mac_addr)
    ip_info.db.set_mac_vendor_to_profile.assert_not_called()


def test_get_vendor_broadcast_mac(
    mocker,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    mac_addr = "ff:ff:ff:ff:ff:ff"
    profileid = "profile_10.0.2.19"

    result = ip_info.get_vendor(mac_addr, profileid)

    assert result is False
    ip_info.db.get_mac_vendor_from_profile.assert_not_called()
    mocker.patch.object(ip_info, "get_vendor_offline").assert_not_called()
    mocker.patch.object(ip_info, "get_vendor_online").assert_not_called()
    ip_info.db.set_mac_vendor_to_profile.assert_not_called()


def test_get_domain_info_no_creation_date():
    domain = "example.com"
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.db.get_domain_data.return_value = None
    ip_info.query_whois = Mock()
    ip_info.query_whois.return_value = Mock(
        creation_date=None, registrant=None
    )

    result = ip_info.get_domain_info(domain)

    assert result is None
    ip_info.db.set_info_for_domains.assert_not_called()


def test_get_domain_info_invalid_tld():
    domain = "example.invalid"
    ip_info = ModuleFactory().create_ip_info_obj()
    result = ip_info.get_domain_info(domain)

    assert result is None
    ip_info.db.get_domain_data.assert_not_called()
    ip_info.db.set_info_for_domains.assert_not_called()


def test_get_domain_info_cached_data():
    domain = "cached.com"
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.db.get_domain_data.return_value = {"Age": 100, "Org": "Cached LLC"}

    result = ip_info.get_domain_info(domain)

    assert result is None
    ip_info.db.set_info_for_domains.assert_not_called()


@pytest.mark.parametrize("domain", ["example.arpa", "example.local"])
def test_get_domain_info_special_domains(domain):
    ip_info = ModuleFactory().create_ip_info_obj()
    result = ip_info.get_domain_info(domain)

    assert result is None
    ip_info.db.get_domain_data.assert_not_called()
    ip_info.db.set_info_for_domains.assert_not_called()


def test_get_rdns_valid_ip():
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_address = "8.8.8.8"
    expected_rdns = {"reverse_dns": "dns.google"}

    with patch("socket.gethostbyaddr") as mock_gethostbyaddr, patch(
        "socket.inet_pton"
    ) as mock_inet_pton:

        mock_gethostbyaddr.return_value = ("dns.google", [], ["8.8.8.8"])
        mock_inet_pton.side_effect = socket.error

        result = ip_info.get_rdns(ip_address)
        assert result == expected_rdns

        mock_gethostbyaddr.assert_called_once_with(ip_address)
        mock_inet_pton.assert_called_once()
        ip_info.db.set_ip_info.assert_called_once_with(
            ip_address, expected_rdns
        )


def test_get_rdns_invalid_ip():
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_address = "invalid_ip"

    with patch("socket.gethostbyaddr") as mock_gethostbyaddr:
        mock_gethostbyaddr.side_effect = socket.gaierror

        result = ip_info.get_rdns(ip_address)
        assert result is False

        mock_gethostbyaddr.assert_called_once_with(ip_address)


def test_get_rdns_no_reverse_dns():
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_address = "1.1.1.1"

    with patch("socket.gethostbyaddr") as mock_gethostbyaddr, patch(
        "socket.inet_pton"
    ) as mock_inet_pton:

        mock_gethostbyaddr.return_value = ("1.1.1.1", [], ["1.1.1.1"])
        mock_inet_pton.return_value = b"\x01\x01\x01\x01"

        result = ip_info.get_rdns(ip_address)
        assert result is False

        mock_gethostbyaddr.assert_called_once_with(ip_address)
        mock_inet_pton.assert_called_once()


def test_get_rdns_localhost():
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_address = "127.0.0.1"
    expected_rdns = {"reverse_dns": "localhost.localdomain"}

    with patch("socket.gethostbyaddr") as mock_gethostbyaddr, patch(
        "socket.inet_pton"
    ) as mock_inet_pton:

        mock_gethostbyaddr.return_value = (
            "localhost.localdomain",
            [],
            ["127.0.0.1"],
        )
        mock_inet_pton.side_effect = socket.error

        result = ip_info.get_rdns(ip_address)
        assert result == expected_rdns

        mock_gethostbyaddr.assert_called_once_with(ip_address)
        mock_inet_pton.assert_called_once()
        ip_info.db.set_ip_info.assert_called_once_with(
            ip_address, expected_rdns
        )


def test_set_evidence_malicious_jarm_hash(mocker):
    ip_info = ModuleFactory().create_ip_info_obj()
    flow = {
        "dport": 443,
        "daddr": "192.168.1.100",
        "saddr": "192.168.1.10",
        "starttime": 1625097600,
        "proto": "tcp",
        "uid": "CuTCcR1Bbp9Je7LVqa",
    }
    twid = "timewindow1"
    ip_info.db.get_port_info.return_value = "https"
    ip_info.db.get_ip_identification.return_value = "Known malicious server"
    mock_set_evidence = mocker.patch.object(ip_info.db, "set_evidence")
    ip_info.set_evidence_malicious_jarm_hash(flow, twid)
    assert mock_set_evidence.call_count == 2
    dst_evidence = mock_set_evidence.call_args_list[0][0][0]
    assert isinstance(dst_evidence, Evidence)
    assert dst_evidence.evidence_type == EvidenceType.MALICIOUS_JARM
    assert dst_evidence.attacker.direction == Direction.DST
    assert dst_evidence.attacker.ioc_type == IoCType.IP
    assert dst_evidence.attacker.value == "192.168.1.100"
    assert dst_evidence.threat_level == ThreatLevel.MEDIUM
    assert dst_evidence.confidence == 0.7
    assert "192.168.1.100" in dst_evidence.description
    assert "port: 443/tcp (HTTPS)" in dst_evidence.description
    assert dst_evidence.profile.ip == "192.168.1.100"
    assert dst_evidence.timewindow.number == 1
    assert dst_evidence.uid == ["CuTCcR1Bbp9Je7LVqa"]
    assert dst_evidence.timestamp == 1625097600
    assert dst_evidence.proto == Proto.TCP
    src_evidence = mock_set_evidence.call_args_list[1][0][0]
    assert isinstance(src_evidence, Evidence)
    assert src_evidence.evidence_type == EvidenceType.MALICIOUS_JARM
    assert src_evidence.attacker.direction == Direction.SRC
    assert src_evidence.attacker.ioc_type == IoCType.IP
    assert src_evidence.attacker.value == "192.168.1.10"
    assert src_evidence.threat_level == ThreatLevel.LOW
    assert src_evidence.confidence == 0.7
    assert src_evidence.dst_port == 443
    assert "192.168.1.100" in src_evidence.description
    assert "port: 443/tcp (HTTPS)" in src_evidence.description
    assert src_evidence.profile.ip == "192.168.1.10"
    assert src_evidence.timewindow.number == 1
    assert src_evidence.uid == ["CuTCcR1Bbp9Je7LVqa"]
    assert src_evidence.timestamp == 1625097600
    assert src_evidence.proto == Proto.TCP


@pytest.mark.parametrize(
    "status_code, response_text, expected_vendor, " "mock_side_effect",
    [
        (
            200,
            "Valid Vendor",
            "Valid Vendor",
            None,
        ),
        (
            204,
            "",
            False,
            None,
        ),
        (
            None,
            None,
            False,
            requests.exceptions.ReadTimeout(),
        ),
        (
            None,
            None,
            False,
            requests.exceptions.ConnectionError(),
        ),
        (
            None,
            None,
            False,
            json.decoder.JSONDecodeError("Msg", "Doc", 0),
        ),
    ],
)
def test_get_vendor_online(
    mocker,
    status_code,
    response_text,
    expected_vendor,
    mock_side_effect,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    mock_response = Mock(status_code=status_code, text=response_text)
    mock_requests = mocker.patch(
        "requests.get",
        return_value=mock_response,
        side_effect=mock_side_effect,
    )

    vendor = ip_info.get_vendor_online("00:11:22:33:44:55")

    assert vendor == expected_vendor
    mock_requests.assert_called_once_with(
        "https://api.macvendors.com/00:11:22:33:44:55", timeout=2
    )


async def tmp_function():
    # Simulating some asynchronous work
    await asyncio.sleep(1)


async def test_shutdown_gracefully(
    mocker,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.reading_mac_db_task = tmp_function()

    mock_asn_db = mocker.Mock()
    mock_country_db = mocker.Mock()
    mock_mac_db = mocker.Mock()

    ip_info.asn_db = mock_asn_db
    ip_info.country_db = mock_country_db
    ip_info.mac_db = mock_mac_db

    await ip_info.shutdown_gracefully()

    mock_asn_db.close.assert_called_once()
    mock_country_db.close.assert_called_once()
    mock_mac_db.close.assert_called_once()


@pytest.mark.parametrize(
    "is_running_non_stop, is_running_in_ap_mode, ifaddresses_ret, get_gw_ret, expected",
    [
        # ap mode: returns own ip
        (True, True, {"addr": "10.0.0.1"}, None, "10.0.0.1"),
        (True, True, KeyError, None, None),
        # not ap mode: returns gw
        (True, False, None, "192.168.1.1", "192.168.1.1"),
        (True, False, None, None, None),
        # not running
        (False, True, {"addr": "10.0.0.1"}, None, None),
        (False, False, None, "192.168.1.1", None),
    ],
)
def test_get_gateway_ip_if_interface(
    mocker,
    is_running_non_stop,
    is_running_in_ap_mode,
    ifaddresses_ret,
    get_gw_ret,
    expected,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.is_running_non_stop = is_running_non_stop
    ip_info.is_running_in_ap_mode = is_running_in_ap_mode
    ip_info.args.interface = "wlan0"

    if is_running_non_stop:
        if is_running_in_ap_mode:
            if ifaddresses_ret is KeyError:
                mocker.patch("netifaces.ifaddresses", side_effect=KeyError)
            else:
                mocker.patch(
                    "netifaces.ifaddresses",
                    return_value={netifaces.AF_INET: [ifaddresses_ret]},
                )
        else:
            mocker.patch.object(
                ip_info, "get_gateway_for_iface", return_value=get_gw_ret
            )

    result = ip_info.get_gateway_ip_if_interface()
    assert result == expected


@pytest.mark.parametrize(
    "ip, is_multicast, cached_info, expected_calls",
    [
        # Testcase 1: Valid IP, not multicast, no cached info
        (
            "192.168.1.1",
            False,
            {},
            {"get_geocountry": 1, "get_asn": 1, "get_rdns": 1},
        ),
        # Testcase 2: Valid IP, multicast
        ("224.0.0.1", True, {}, {}),
        # Testcase 3: Valid IP, not multicast,
        # with cached geocountry
        (
            "10.0.0.1",
            False,
            {"geocountry": "USA"},
            {"get_asn": 1, "get_rdns": 1},
        ),
    ],
)
def test_handle_new_ip(mocker, ip, is_multicast, cached_info, expected_calls):
    ip_info = ModuleFactory().create_ip_info_obj()

    mock_ip_address = mocker.patch("ipaddress.ip_address")
    mock_ip_address.return_value.is_multicast = is_multicast

    ip_info.db.get_ip_info.return_value = cached_info

    mock_get_geocountry = mocker.patch.object(ip_info, "get_geocountry")
    mock_get_asn = mocker.patch.object(ip_info.asn, "get_asn")
    mock_get_rdns = mocker.patch.object(ip_info, "get_rdns")
    ip_info.asn.update_asn = Mock(return_value=True)
    ip_info.handle_new_ip(ip)
    assert mock_get_geocountry.call_count == expected_calls.get(
        "get_geocountry", 0
    )
    assert mock_get_asn.call_count == expected_calls.get("get_asn", 0)
    assert mock_get_rdns.call_count == expected_calls.get("get_rdns", 0)


def test_check_if_we_have_pending_mac_queries_with_mac_db(
    mocker,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.mac_db = Mock()
    ip_info.pending_mac_queries = Mock()
    ip_info.pending_mac_queries.empty.side_effect = [False, False, True]
    ip_info.pending_mac_queries.get.side_effect = [
        ("00:11:22:33:44:55", "profile_1"),
        ("AA:BB:CC:DD:EE:FF", "profile_2"),
        Exception("Empty queue"),
    ]
    mock_get_vendor_offline = mocker.patch.object(
        ip_info, "get_vendor_offline"
    )
    ip_info.check_if_we_have_pending_offline_mac_queries()
    assert mock_get_vendor_offline.call_count == 2
    mock_get_vendor_offline.assert_any_call("00:11:22:33:44:55", "profile_1")
    mock_get_vendor_offline.assert_any_call("AA:BB:CC:DD:EE:FF", "profile_2")


def test_check_if_we_have_pending_mac_queries_empty_queue(
    mocker,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.mac_db = Mock()
    ip_info.pending_mac_queries = Mock()
    ip_info.pending_mac_queries.empty.return_value = True
    mock_get_vendor = mocker.patch.object(ip_info, "get_vendor")
    ip_info.check_if_we_have_pending_offline_mac_queries()
    mock_get_vendor.assert_not_called()


@pytest.mark.parametrize(
    "gw_ip, cached_mac",
    [
        ("192.168.1.1", "00:11:22:33:44:55"),
    ],
)
def test_get_gateway_mac_cached(gw_ip, cached_mac):
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.db.get_mac_addr_from_profile.return_value = cached_mac

    result = ip_info.get_gateway_mac(gw_ip)

    assert result == cached_mac
    ip_info.db.get_mac_addr_from_profile.assert_called_once_with(
        f"profile_{gw_ip}"
    )


@pytest.mark.parametrize("gw_ip", ["192.168.0.1"])
def test_get_gateway_mac_not_found(mocker, gw_ip):
    ip_info = ModuleFactory().create_ip_info_obj()

    ip_info.db.get_mac_addr_from_profile.return_value = None
    ip_info.is_running_non_stop = True
    ip_info.is_running_in_ap_mode = False

    mocker.patch("sys.argv", ["-i", "eth0"])
    mock_subprocess_run = mocker.patch("subprocess.run")
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(
        1, "ip neigh"
    )

    mocker.patch(
        "slips_files.common.slips_utils.utils.get_mac_for_ip_using_cache",
        side_effect=subprocess.CalledProcessError(1, "arp"),
    )

    result = ip_info.get_gateway_mac(gw_ip)

    assert result is None
    assert mock_subprocess_run.call_count == 1  # only ip neigh is called
    ip_info.db.set_default_gateway.assert_not_called()


@pytest.mark.parametrize("gw_ip", ["172.16.0.1"])
def test_get_gateway_mac_ip_command_failure(mocker, gw_ip):
    ip_info = ModuleFactory().create_ip_info_obj()

    ip_info.db.get_mac_addr_from_profile.return_value = None
    ip_info.is_running_non_stop = True
    ip_info.is_running_in_ap_mode = False

    mocker.patch("sys.argv", ["-i", "eth0"])

    mock_subprocess_run = mocker.patch("subprocess.run")
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(
        1, "ip neigh"
    )

    mocker.patch(
        "slips_files.common.slips_utils.utils.get_mac_for_ip_using_cache",
        side_effect=subprocess.CalledProcessError(1, "arp"),
    )

    result = ip_info.get_gateway_mac(gw_ip)

    assert result is None
    assert mock_subprocess_run.call_count == 1
    mock_subprocess_run.assert_called_once_with(
        ["ip", "neigh", "show", gw_ip],
        capture_output=True,
        check=True,
        text=True,
    )
    ip_info.db.set_default_gateway.assert_not_called()


@pytest.mark.parametrize(
    "ip_address, expected_family",
    [
        # Testcase 1: IPv4 address
        ("192.168.1.1", socket.AF_INET),
        # Testcase 2: IPv6 address
        ("2001:db8::1", socket.AF_INET6),
        # Testcase 3: Another IPv4 address
        ("10.0.0.1", socket.AF_INET),
        # Testcase 4: Another IPv6 address
        ("::1", socket.AF_INET6),
        # Testcase 5: IPv4-mapped IPv6 address
        ("::ffff:192.0.2.1", socket.AF_INET6),
    ],
)
def test_get_ip_family(ip_address, expected_family):
    ip_info = ModuleFactory().create_ip_info_obj()
    assert ip_info.get_ip_family(ip_address) == expected_family
