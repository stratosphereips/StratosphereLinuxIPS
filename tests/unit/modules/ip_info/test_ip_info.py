# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/ip_info/ip_info.py"""

import asyncio
import threading

from tests.module_factory import ModuleFactory
import maxminddb
import pytest
from unittest.mock import (
    AsyncMock,
    Mock,
    call,
)
from slips_files.core.flows.zeek import DNS
from slips_files.core.structures.evidence import (
    ThreatLevel,
    Evidence,
    Proto,
    EvidenceType,
    IoCType,
    Direction,
)


def test_start_mac_db_reader_returns_without_running_loop() -> None:
    module_factory = ModuleFactory()
    ip_info = module_factory.create_ip_info_obj()
    ip_info.create_task = Mock()

    ip_info._start_mac_db_reader()

    ip_info.create_task.assert_not_called()


async def test_start_mac_db_reader_schedules_reader_in_running_loop() -> None:
    module_factory = ModuleFactory()
    ip_info = module_factory.create_ip_info_obj()
    created_task = Mock()
    ip_info.create_task = Mock(return_value=created_task)

    ip_info._start_mac_db_reader()

    ip_info.create_task.assert_called_once_with(ip_info.mac_vendor.read_mac_db)
    assert ip_info.reading_mac_db_task == created_task


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


async def test_rdns_is_not_skipped_when_asn_lookup_fails() -> None:
    """Resolve the name before an unrelated remote ASN lookup can fail."""
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.db.get_rdns_info.return_value = None
    ip_info.rdns.get_rdns_async = AsyncMock()
    ip_info.asn.get_asn_async = AsyncMock(side_effect=OSError("ASN offline"))
    with pytest.raises(OSError):
        await ip_info.handle_new_ip_async("8.8.8.8")
    ip_info.rdns.get_rdns_async.assert_awaited_once_with(
        "8.8.8.8", ip_info.run_lookup
    )
    assert ip_info.pending_ip_lookups == set()


async def test_duplicate_ip_enrichment_is_coalesced() -> None:
    """Keep repeated source and destination requests to one active lookup."""
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.pending_ip_lookups.add("8.8.8.8")
    ip_info.rdns.get_rdns_async = AsyncMock()
    await ip_info.handle_new_ip_async("8.8.8.8")
    ip_info.rdns.get_rdns_async.assert_not_awaited()


async def test_new_mac_is_enriched_using_the_lookup_executor() -> None:
    """Hand the bounded lookup runner to the MAC vendor helper."""
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.mac_vendor.get_vendor_async = AsyncMock()
    ip_info.mac_vendor.check_if_we_have_pending_offline_mac_queries = Mock()

    await ip_info.handle_new_mac_async("08:00:27:7f:09:e1", "profile_10.0.2.15")

    ip_info.mac_vendor.get_vendor_async.assert_awaited_once_with(
        "08:00:27:7f:09:e1", "profile_10.0.2.15", ip_info.run_lookup
    )
    pending_queries_check = (
        ip_info.mac_vendor.check_if_we_have_pending_offline_mac_queries
    )
    pending_queries_check.assert_called_once_with()


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


async def tmp_function():
    # Simulating some asynchronous work
    await asyncio.sleep(1)


async def test_shutdown_cancels_mac_database_retry_and_drains_lookups() -> None:
    """Do not wait for optional MAC data after all flows are processed."""
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.channels = {}
    ip_info.shutdown_gracefully = AsyncMock()
    reader = ip_info.create_task(asyncio.sleep, 600)
    ip_info.reading_mac_db_task = reader
    completed: list[bool] = []

    async def finish_lookup() -> None:
        """Mark a required lookup as finished."""
        completed.append(True)

    ip_info.create_task(finish_lookup)

    await asyncio.wait_for(
        ip_info.gather_tasks_and_shutdown_gracefully(), timeout=1
    )

    assert reader.cancelled()
    assert completed == [True]
    ip_info.shutdown_gracefully.assert_awaited_once()


async def test_shutdown_gracefully(
    mocker,
):
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.reading_mac_db_task = tmp_function()
    ip_info.host_info.flush_async = AsyncMock()

    mock_asn_db = mocker.Mock()
    mock_country_db = mocker.Mock()

    ip_info.asn_db = mock_asn_db
    ip_info.country_db = mock_country_db

    await ip_info.shutdown_gracefully()

    mock_asn_db.close.assert_called_once()
    mock_country_db.close.assert_called_once()
    ip_info.host_info.flush_async.assert_awaited_once_with(
        ip_info.run_host_archive_step
    )


async def test_shutdown_frees_resources_even_when_the_flush_fails() -> None:
    """A broken host store must not leave threads and databases open."""
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.host_info.flush_async = AsyncMock(
        side_effect=RuntimeError
    )
    ip_info.country_db = Mock()

    with pytest.raises(RuntimeError):
        await ip_info.shutdown_gracefully()

    ip_info.country_db.close.assert_called_once()
    with pytest.raises(RuntimeError):
        ip_info.host_archive_executor.submit(print)
    with pytest.raises(RuntimeError):
        ip_info.lookup_executor.submit(print)


async def test_host_archive_steps_run_off_the_event_loop() -> None:
    """Keep blocking SQLite work in the archive thread, not on the loop."""
    ip_info = ModuleFactory().create_ip_info_obj()

    def get_thread_name(prefix: str) -> str:
        return prefix + threading.current_thread().name

    thread_name = await ip_info.run_host_archive_step(get_thread_name, "in:")

    assert thread_name.startswith("in:host-archive")
    assert threading.current_thread().name != thread_name[3:]
    ip_info.host_archive_executor.shutdown()


@pytest.mark.parametrize(
    "is_batch_due, expected_batches",
    [
        (True, 1),
        (False, 0),
    ],
)
async def test_main_starts_a_host_archive_batch_only_when_due(
    is_batch_due: bool, expected_batches: int
) -> None:
    """Pace host archiving from main() without sleeping in it.

    Parameters:
        is_batch_due: Whether the helper rested enough for a new batch.
        expected_batches: Batches main() should start.
    """
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.get_msg = Mock(return_value=None)
    ip_info.create_task = Mock()
    ip_info.host_info.claim_due_batch = Mock(
        return_value=is_batch_due
    )

    await ip_info.main()

    start_batch = call(
        ip_info.host_info.archive_batch_async,
        ip_info.run_host_archive_step,
    )
    assert ip_info.create_task.call_args_list == (
        [start_batch] * expected_batches
    )


def test_pre_main_opens_the_host_store_before_dropping_root(mocker) -> None:
    """Root must create the permanent host store, later it's too late."""
    ip_info = ModuleFactory().create_ip_info_obj()
    startup_steps = Mock()
    ip_info.db.init_host_profile_store = startup_steps.init_host_profile_store
    mocker.patch(
        "modules.ip_info.ip_info.utils.drop_root_privs_permanently",
        startup_steps.drop_root_privs_permanently,
    )
    ip_info.wait_for_dbs = Mock()
    ip_info.gateway.get_gateway_ip_if_interface = Mock(return_value=None)

    ip_info.pre_main()

    assert [step[0] for step in startup_steps.mock_calls] == [
        "init_host_profile_store",
        "drop_root_privs_permanently",
    ]


def test_pre_main_stores_the_gateway_of_each_interface(mocker) -> None:
    """Save the gateway IP and MAC found by the gateway helper."""
    ip_info = ModuleFactory().create_ip_info_obj()
    mocker.patch("modules.ip_info.ip_info.utils.drop_root_privs_permanently")
    ip_info.wait_for_dbs = Mock()
    ip_info.gateway.get_gateway_ip_if_interface = Mock(
        return_value={"eth0": "192.168.1.1"}
    )
    ip_info.gateway.get_gateway_mac = Mock(
        return_value={"eth0": "AA:BB:CC:DD:EE:FF"}
    )

    ip_info.pre_main()

    assert ip_info.db.set_default_gateway.call_args_list == [
        call("IP", "192.168.1.1", "eth0"),
        call("MAC", "AA:BB:CC:DD:EE:FF", "eth0"),
    ]


@pytest.mark.parametrize(
    "ip, is_multicast, cached_info, cached_rdns, expected_calls",
    [
        # Testcase 1: Valid IP, not multicast, no cached info
        (
            "192.168.1.1",
            False,
            {},
            None,
            {"get_geocountry": 1, "get_asn": 1, "get_rdns": 1},
        ),
        # Testcase 2: Valid IP, multicast
        ("224.0.0.1", True, {}, None, {}),
        # Testcase 3: Valid IP, not multicast,
        # with cached geocountry
        (
            "10.0.0.1",
            False,
            {"geocountry": "USA"},
            None,
            {"get_asn": 1, "get_rdns": 1},
        ),
        # Testcase 4: Valid IP with cached rDNS
        (
            "10.0.0.2",
            False,
            {},
            "cached.example.com",
            {"get_geocountry": 1, "get_asn": 1},
        ),
    ],
)
def test_handle_new_ip(
    mocker, ip, is_multicast, cached_info, cached_rdns, expected_calls
):
    ip_info = ModuleFactory().create_ip_info_obj()

    mock_ip_address = mocker.patch("ipaddress.ip_address")
    mock_ip_address.return_value.is_multicast = is_multicast

    ip_info.db.get_ip_info.return_value = cached_info
    ip_info.db.get_rdns_info.return_value = cached_rdns

    mock_get_geocountry = mocker.patch.object(ip_info, "get_geocountry")
    mock_get_asn = mocker.patch.object(ip_info.asn, "get_asn")
    mock_get_rdns = mocker.patch.object(ip_info.rdns, "get_rdns")
    ip_info.asn.update_asn = Mock(return_value=True)
    ip_info.handle_new_ip(ip)
    assert mock_get_geocountry.call_count == expected_calls.get(
        "get_geocountry", 0
    )
    assert mock_get_asn.call_count == expected_calls.get("get_asn", 0)
    assert mock_get_rdns.call_count == expected_calls.get("get_rdns", 0)


def test_register_private_dns_server_stores_private_dns_server():
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.db.is_official_dns_server.return_value = False
    flow = DNS(
        starttime="1726568479.5997488",
        uid="1234",
        saddr="fd00:1::10",
        daddr="fd00:2::53",
        dport="53",
        sport="53000",
        proto="udp",
        query="example.com",
        qclass_name="",
        qtype_name="AAAA",
        rcode_name="NOERROR",
        answers=["2001:db8::1"],
        TTLs="",
    )

    assert ip_info.register_private_dns_server(flow) is True

    ip_info.db.store_official_dns_server.assert_called_once_with("fd00:2::53")
    ip_info.print.assert_called_once_with(
        "Detected DNS server by traffic heuristic: fd00:2::53"
    )


@pytest.mark.parametrize(
    "daddr, dport, proto",
    [
        ("8.8.8.8", "53", "udp"),
        ("fd00:2::53", "5353", "udp"),
        ("fd00:2::53", "53", "tcp"),
    ],
)
def test_register_private_dns_server_ignores_non_private_dns_server_flows(
    daddr, dport, proto
):
    ip_info = ModuleFactory().create_ip_info_obj()
    flow = DNS(
        starttime="1726568479.5997488",
        uid="1234",
        saddr="fd00:1::10",
        daddr=daddr,
        dport=dport,
        sport="53000",
        proto=proto,
        query="example.com",
        qclass_name="",
        qtype_name="A",
        rcode_name="NOERROR",
        answers=["8.8.4.4"],
        TTLs="",
    )

    assert ip_info.register_private_dns_server(flow) is False

    ip_info.db.store_official_dns_server.assert_not_called()
    ip_info.print.assert_not_called()
