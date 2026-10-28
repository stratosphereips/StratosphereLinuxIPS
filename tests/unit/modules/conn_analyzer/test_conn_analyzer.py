# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/conn_analyzer/conn_analyzer.py"""

from dataclasses import asdict
from typing import Any
from types import SimpleNamespace
from slips_files.core.flows.zeek import Conn
from slips_files.core.input_profilers.zeek import ZeekJSON
from tests.module_factory import ModuleFactory
import json
from unittest.mock import (
    Mock,
    MagicMock,
)
import pytest
from ipaddress import ip_address
from slips_files.common.input_type import InputType
from tests.unit.common_test_utils import get_mock_coro

# dummy params used for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
uid = "CAeDWs37BipkfP21u8"
timestamp = 1635765895.037696
saddr = "192.168.1.1"
daddr = "192.168.1.2"
dst_profileid = f"profile_{daddr}"


@pytest.mark.parametrize("history,expected", [
    ("AdDTafF", False),
    ("^AdDTafF", False),
    ("S^", False),
    ("ShA^Dd", False),
    ("ShADadFf", True),
    ("^ShADadFf", True),
    ("H^SADadFf", True),
    ("Hs^ADdFf", True),
])
def test_unknown_port_requires_supported_initiator(history: str, expected: bool) -> None:
    """Do not treat an ongoing SSH response as a new incoming connection.

    Parameters:
        history: Packet flags, including role changes before the final record.
        expected: Whether the final source has evidence of initiating TCP.
    """
    factory = ModuleFactory()
    conn = factory.create_conn_analyzer_obj()
    raw = {
        "ts": 1792947092.783236, "uid": "midstream-ssh",
        "id.orig_h": "147.32.80.37", "id.orig_p": 902,
        "id.resp_h": "192.168.1.163", "id.resp_p": 59148,
        "proto": "tcp", "duration": 1.781255, "orig_bytes": 5824,
        "resp_bytes": 10295264, "conn_state": "SF", "history": history,
        "orig_pkts": 1638, "resp_pkts": 7418,
    }
    flow, error = ZeekJSON(factory.logger).process_line(
        {"type": "conn.log", "interface": "en0", "data": raw}
    )
    assert error == ""
    conn.db.is_a_port_scanner.return_value = False
    conn.db.get_port_info.return_value = None
    conn.db.is_ftp_port.return_value = False
    conn.db.is_p2p_related_flow.return_value = False
    conn.port_belongs_to_an_org = Mock(return_value=False)
    conn.is_local_apple_peer_flow = Mock(return_value=False)
    conn.set_evidence.unknown_port = Mock()
    assert conn.check_unknown_port(f"profile_{flow.saddr}", twid, flow) is expected
    assert conn.set_evidence.unknown_port.call_count == int(expected)
    assert (flow.saddr, flow.sport, flow.daddr, flow.dport) == (
        raw["id.orig_h"], raw["id.orig_p"], raw["id.resp_h"], raw["id.resp_p"]
    )
    assert (flow.history, flow.sbytes, flow.dbytes) == (history, 5824, 10295264)


@pytest.mark.parametrize(
    "dport, proto, daddr, initial_p2p_daddrs, "
    "expected_result, expected_final_p2p_daddrs",
    [
        # Testcase 1: Protocol is not UDP
        (1234, "tcp", "192.168.1.0", {}, False, {}),
        # Testcase 2: Port number is less than 30000
        (8080, "udp", "192.168.1.0", {}, False, {}),
        # Testcase 3: First connection to an IP on port > 30000
        (30001, "udp", "192.168.1.1", {}, False, {"192.168.1.1": 1}),
        # Testcase 4: 5th connection to different IPs, becomes P2P
        (
            30001,
            "udp",
            "192.168.1.5",
            {
                "192.168.1.1": 1,
                "192.168.1.2": 1,
                "192.168.1.3": 1,
                "192.168.1.4": 1,
            },
            True,
            {
                "192.168.1.1": 1,
                "192.168.1.2": 1,
                "192.168.1.3": 1,
                "192.168.1.4": 1,
                "192.168.1.5": 1,
            },
        ),
        # Testcase 5: 6th connection to the same IP, different port > 30000
        (
            30002,
            "udp",
            "192.168.1.1",
            {"192.168.1.1": 5},
            False,
            {"192.168.1.1": 6},
        ),
        # Testcase 6: Connection to IP with 6+ previous connections
        (
            30003,
            "udp",
            "192.168.1.1",
            {"192.168.1.1": 6},
            True,
            {"192.168.1.1": 6},
        ),
    ],
)
def test_is_p2p(
    dport,
    proto,
    daddr,
    initial_p2p_daddrs,
    expected_result,
    expected_final_p2p_daddrs,
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.p2p_daddrs = initial_p2p_daddrs.copy()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.1.1",
        daddr=daddr,
        dur=1,
        proto=proto,
        appproto="",
        sport="0",
        dport=str(dport),
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )
    result = conn.is_p2p(flow)
    assert result == expected_result
    assert conn.p2p_daddrs == expected_final_p2p_daddrs


@pytest.mark.parametrize(
    (
        "dport",
        "proto",
        "mock_port_info",
        "mock_is_ftp_port",
        "mock_port_belongs_to_an_org",
        "mock_is_a_port_scanner",
        "expected_result",
    ),
    [
        # Successful connections are checked even after the source was a scanner.
        ("1337", "udp", None, False, False, True, True),
        # Case 2: unknown port, not scanner, not org-owned → True
        ("1337", "udp", None, False, False, False, True),
    ],
)
def test_check_unknown_port(
    mocker,
    dport,
    proto,
    mock_port_info,
    mock_is_ftp_port,
    mock_port_belongs_to_an_org,
    mock_is_a_port_scanner,
    expected_result,
):
    conn = ModuleFactory().create_conn_analyzer_obj()

    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.1.1",
        daddr="1.1.1.1",
        dur=1,
        proto=proto,
        appproto="",
        sport="12345",
        dport=str(dport),
        spkts=2,
        dpkts=1,
        sbytes=120,
        dbytes=60,
        smac="",
        dmac="",
        state="Established",
        history="S",
    )

    flow.interpreted_state = "Established"

    conn.db.is_a_port_scanner = Mock(return_value=mock_is_a_port_scanner)
    conn.db.get_port_info.return_value = mock_port_info
    conn.db.is_ftp_port.return_value = mock_is_ftp_port
    conn.db.is_p2p_related_flow.return_value = False

    port_belongs_mock = mocker.patch(
        "modules.conn_analyzer.conn_analyzer.ConnAnalyzer.port_belongs_to_an_org"
    )
    port_belongs_mock.return_value = mock_port_belongs_to_an_org

    profileid = f"profile_{flow.saddr}"

    assert conn.check_unknown_port(profileid, twid, flow) is expected_result


def test_check_unknown_port_true_case(mocker):
    conn = ModuleFactory().create_conn_analyzer_obj()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.1.1",
        daddr="1.1.1.1",
        dur=1,
        proto="tcp",
        appproto="",
        sport="0",
        dport="12345",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="ShADadFf",
    )
    conn.db.is_a_port_scanner = Mock(return_value=False)
    flow.interpreted_state = "Established"
    conn.db.get_port_info.return_value = None
    conn.db.is_ftp_port.return_value = False
    conn.db.is_p2p_related_flow.return_value = False
    mocker.patch.object(conn, "port_belongs_to_an_org", return_value=False)
    mocker.patch.object(conn, "is_p2p", return_value=False)
    mock_set_evidence = mocker.patch.object(conn.set_evidence, "unknown_port")

    assert conn.check_unknown_port(profileid, twid, flow)
    mock_set_evidence.assert_called_once_with(twid, flow)


@pytest.mark.parametrize(
    "saddr, daddr",
    [
        ("192.168.1.20", "224.0.0.251"),
        ("224.0.0.251", "192.168.1.20"),
        ("192.168.1.20", "ff02::1"),
        ("192.168.1.20", "255.255.255.255"),
        ("192.168.1.20", "192.168.1.255"),
    ],
)
def test_broadcast_and_multicast_flows_do_not_create_evidence(
    saddr: str, daddr: str
) -> None:
    """Skip unknown-port and private-IP evidence for broadcast traffic.

    Parameters:
        saddr: Flow source address.
        daddr: Flow destination address.
    """
    factory = ModuleFactory()
    conn = factory.create_conn_analyzer_obj()
    conn.db.get_local_network.return_value = "192.168.1.0/24"
    conn.set_evidence.unknown_port = Mock()
    conn.set_evidence.conn_to_private_ip = Mock()
    flow = Conn(
        starttime="1726249372.312124",
        uid="broadcast-flow",
        saddr=saddr,
        daddr=daddr,
        dur=1,
        proto="udp",
        appproto="",
        sport="12345",
        dport="12345",
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        smac="",
        dmac="",
        state="Established",
        history="S",
    )

    assert conn.check_unknown_port(f"profile_{saddr}", twid, flow) is None
    conn.check_connection_to_local_ip(twid, flow)

    conn.set_evidence.unknown_port.assert_not_called()
    conn.set_evidence.conn_to_private_ip.assert_not_called()


@pytest.mark.parametrize("dmac,interface", [
    ("ff:ff:ff:ff:ff:ff", "en0"),
    ("FF-FF-FF-FF-FF-FF", "default"),
    ("01:00:5e:00:00:fb", "en0"),
    ("33:33:00:00:00:01", ""),
])
def test_group_destination_mac_suppresses_private_and_unknown_port_evidence(
    dmac: str, interface: str,
) -> None:
    """Recognize broadcast discovery even when the current subnet differs.

    Parameters:
        dmac: Broadcast or multicast destination hardware address.
        interface: Live, offline or missing interface identifier.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.get_local_network.return_value = "192.168.160.0/24"
    conn.set_evidence.conn_to_private_ip = Mock()
    conn.set_evidence.unknown_port = Mock()
    flow = SimpleNamespace(
        saddr="192.168.1.116", daddr="192.168.1.255", sport=137,
        dport=137, proto="udp", history="D", dmac=dmac,
        interface=interface, starttime=1792502017.916054,
    )
    conn.check_connection_to_local_ip(twid, flow)
    conn.check_unknown_port(f"profile_{flow.saddr}", twid, flow)
    conn.set_evidence.conn_to_private_ip.assert_not_called()
    conn.set_evidence.unknown_port.assert_not_called()
    conn.db.get_network_state.assert_not_called()
    conn.db.get_local_network.assert_not_called()


@pytest.mark.parametrize("timestamp,destination,expected", [
    (150, "192.168.1.255", True),
    (150, "192.168.160.255", False),
    (250, "192.168.160.255", True),
    (250, "192.168.1.255", False),
    (50, "192.168.1.255", False),
])
def test_broadcast_uses_subnet_at_flow_time(
    timestamp: int, destination: str, expected: bool,
) -> None:
    """Choose the capture subnet for delayed flows after a network change.

    Parameters:
        timestamp: Capture time before or after the interface changed networks.
        destination: Address whose broadcast status depends on the subnet.
        expected: Whether the address was broadcast when captured.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.get_network_state.return_value = {
        "changed_at": 200, "local_network": "192.168.160.0/24",
        "history": [{"changed_at": 100, "local_network": "192.168.1.0/24"}],
    }
    conn.db.get_local_network.return_value = "192.168.160.0/24"
    flow = SimpleNamespace(saddr="192.168.1.116", daddr=destination,
        interface="en0", starttime=timestamp, dmac="")
    assert conn.is_broadcast_or_multicast_flow(flow) is expected
    flow.starttime = 250 if timestamp < 200 else 150
    assert conn.is_broadcast_or_multicast_flow(flow) is (not expected if timestamp >= 100 else False)
    conn.db.get_network_state.assert_called_once_with("en0")
    conn.db.get_local_network.assert_not_called()


@pytest.mark.parametrize("subnet,destination,expected", [
    ("192.168.1.0/24", "192.168.1.255", True),
    ("192.168.0.0/23", "192.168.0.255", False),
    ("192.168.0.0/23", "192.168.1.255", True),
    ("192.168.1.254/31", "192.168.1.255", False),
    ("192.168.1.255/32", "192.168.1.255", False),
    ("", "192.168.1.255", False),
    ("192.168.1.0/24", "192.168.1.116", False),
])
def test_broadcast_does_not_guess_from_last_octet(
    subnet: str, destination: str, expected: bool,
) -> None:
    """Retain valid unicast addresses ending in .255 and unknown subnets.

    Parameters:
        subnet: Known recording subnet, or empty when unavailable.
        destination: Destination IPv4 address.
        expected: Whether this is a broadcast under the specified prefix.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.get_network_state.return_value = None
    conn.db.get_local_network.return_value = subnet
    conn.set_evidence.conn_to_private_ip = Mock()
    flow = SimpleNamespace(saddr="192.168.1.20", daddr=destination,
        interface="default", starttime=150, dmac="02:00:00:00:00:01",
        proto="udp", sport=137, dport=137, history="D")
    assert conn.is_broadcast_or_multicast_flow(flow) is expected
    conn.check_connection_to_local_ip(twid, flow)
    assert conn.set_evidence.conn_to_private_ip.call_count == int(not expected)


@pytest.mark.parametrize(
    "daddr,dport,proto,dmac,dst_vendor,host_ip,gateway_mac,expected",
    [
        ("192.168.1.163", "57558", "udp", "aa:bb:cc:00:00:02", "Apple, Inc.", "192.168.1.247", "00:11:22:33:44:55", True),
        ("192.168.1.163", "57558", "udp", "aa:bb:cc:00:00:02", "Other", "192.168.1.247", "00:11:22:33:44:55", False),
        ("192.168.1.163", "57558", "udp", "", "Apple, Inc.", "192.168.1.247", "00:11:22:33:44:55", False),
        ("192.168.1.163", "57558", "udp", "00:11:22:33:44:55", "Apple, Inc.", "192.168.1.247", "00:11:22:33:44:55", False),
        ("192.168.2.163", "57558", "udp", "aa:bb:cc:00:00:02", "Apple, Inc.", "192.168.1.247", "00:11:22:33:44:55", False),
        ("192.168.1.163", "57558", "udp", "aa:bb:cc:00:00:02", "Apple, Inc.", "192.168.1.100", "00:11:22:33:44:55", False),
        ("192.168.1.163", "57558", "tcp", "aa:bb:cc:00:00:02", "Apple, Inc.", "192.168.1.247", "00:11:22:33:44:55", False),
        ("192.168.1.163", "5353", "udp", "aa:bb:cc:00:00:02", "Apple, Inc.", "192.168.1.247", "00:11:22:33:44:55", False),
    ],
)
def test_local_apple_peer_requires_direct_pair(
    mocker: Any,
    daddr: str,
    dport: str,
    proto: str,
    dmac: str,
    dst_vendor: str,
    host_ip: str,
    gateway_mac: str,
    expected: bool,
) -> None:
    """Skip only local high-port UDP flows with two identified Apple MACs.

    Parameters:
        mocker: Patches the offline MAC vendor lookup.
        daddr: Destination IP under test.
        dport: Destination port under test.
        proto: Transport protocol under test.
        dmac: Destination MAC from the flow.
        dst_vendor: Vendor associated with the destination MAC.
        host_ip: Computer IP in the network snapshot.
        gateway_mac: Router MAC in the network snapshot.
        expected: Whether the local Apple pair is recognized.
    """
    factory = ModuleFactory()
    conn = factory.create_conn_analyzer_obj()
    conn.db.get_network_state.return_value = {
        "host_ip": host_ip,
        "local_network": "192.168.1.0/24",
        "gateway_mac": gateway_mac,
        "changed_at": 0,
    }
    src_mac = "aa:bb:cc:00:00:01"
    mocker.patch(
        "modules.conn_analyzer.conn_analyzer.utils.get_mac_vendor_from_mac_addr",
        side_effect=lambda mac: "Apple, Inc." if mac == src_mac else dst_vendor,
    )
    flow = Conn(
        starttime="1726249372.312124",
        uid="apple-peer",
        saddr="192.168.1.247",
        daddr=daddr,
        dur=1,
        proto=proto,
        appproto="",
        sport="50000",
        dport=dport,
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        smac=src_mac,
        dmac=dmac,
        state="Established",
        history="Dd",
        interface="en0",
    )

    assert conn.is_local_apple_peer_flow(flow) is expected


def test_unknown_port_skips_identified_local_apple_peer(mocker: Any) -> None:
    """Suppress only unknown-port evidence for an identified Apple pair.

    Parameters:
        mocker: Replaces unrelated database checks and evidence output.
    """
    factory = ModuleFactory()
    conn = factory.create_conn_analyzer_obj()
    flow = Conn(
        starttime="1726249372.312124",
        uid="apple-peer",
        saddr="192.168.1.247",
        daddr="192.168.1.163",
        dur=1,
        proto="udp",
        appproto="",
        sport="50000",
        dport="57558",
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        smac="aa:bb:cc:00:00:01",
        dmac="aa:bb:cc:00:00:02",
        state="Established",
        history="Dd",
    )
    conn.db.is_a_port_scanner.return_value = False
    conn.db.get_port_info.return_value = None
    mocker.patch.object(conn, "port_belongs_to_an_org", return_value=False)
    mocker.patch.object(conn, "is_local_apple_peer_flow", return_value=True)
    evidence = mocker.patch.object(conn.set_evidence, "unknown_port")

    assert conn.check_unknown_port("profile_192.168.1.247", twid, flow) is False
    evidence.assert_not_called()


def test_check_unknown_port_uses_lowercase_protocol_for_known_ports(mocker):
    conn = ModuleFactory().create_conn_analyzer_obj()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.1.1",
        daddr="147.32.82.7",
        dur=1,
        proto="UDP",
        appproto="",
        sport="12345",
        dport="53",
        spkts=2,
        dpkts=1,
        sbytes=120,
        dbytes=60,
        smac="",
        dmac="",
        state="Established",
        history="S",
    )

    flow.interpreted_state = "Established"
    conn.db.is_a_port_scanner = Mock(return_value=False)
    conn.db.get_port_info = Mock(return_value="DNS")
    conn.db.is_ftp_port = Mock(return_value=False)
    mocker.patch.object(conn, "port_belongs_to_an_org", return_value=False)
    mocker.patch.object(conn, "is_p2p", return_value=False)
    mock_set_evidence = mocker.patch.object(conn.set_evidence, "unknown_port")

    profileid = f"profile_{flow.saddr}"

    assert conn.check_unknown_port(profileid, twid, flow) is False
    conn.db.get_port_info.assert_called_once_with("53/udp")
    mock_set_evidence.assert_not_called()


@pytest.mark.parametrize(
    "origstate, saddr, daddr, dport, uids, interpreted_state, expected_calls",
    [
        (  # Testcase1:5 rejections, evidence should be set
            "REJ",
            "192.168.1.1",
            "192.168.1.2",
            23,
            [f"uid_{i}" for i in range(4)],
            "Not Established",
            1,
        ),
        (  # Testcase2: Less than 5 rejections, no evidence
            "RST",
            "192.168.1.1",
            "192.168.1.2",
            2323,
            [f"uid_{i}" for i in range(4)],
            "Not Established",
            1,
        ),
        (  # Testcase3: Non-REJ state, no evidence
            "Established",
            "192.168.1.1",
            "192.168.1.2",
            23,
            ["uid_1"],
            "Established",
            0,
        ),
    ],
)
def test_check_multiple_telnet_reconnection_attempts(
    origstate, saddr, daddr, dport, uids, interpreted_state, expected_calls
):
    """
    Tests the check_multiple_telnet_reconnection_attempts function
    with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.set_evidence.multiple_telnet_reconnection_attempts = Mock()
    conn.db.get_reconnections_for_tw.return_value = {}

    for uid in uids:
        flow = Conn(
            starttime="1726249372.312124",
            uid=uid,
            saddr=saddr,
            daddr=daddr,
            dur=1,
            proto="tcp",
            appproto="",
            sport="0",
            dport=dport,
            spkts=0,
            dpkts=0,
            sbytes=0,
            dbytes=0,
            smac="",
            dmac="",
            state=origstate,
            history="Sr",
        )
        flow.interpreted_state = interpreted_state
        conn.check_multiple_telnet_reconnection_attempts(profileid, twid, flow)

    assert (
        conn.set_evidence.multiple_telnet_reconnection_attempts.call_count
        == expected_calls
    )


@pytest.mark.parametrize(
    "origstate, saddr, daddr, dport, uids, expected_calls",
    [
        (  # Testcase1:5 rejections, evidence should be set
            "REJ",
            "192.168.1.1",
            "192.168.1.2",
            80,
            [f"uid_{i}" for i in range(5)],
            1,
        ),
        (  # Testcase2: Less than 5 rejections, no evidence
            "REJ",
            "192.168.1.1",
            "192.168.1.2",
            80,
            [f"uid_{i}" for i in range(4)],
            0,
        ),
        (  # Testcase3: Non-REJ state, no evidence
            "Established",
            "192.168.1.1",
            "192.168.1.2",
            80,
            ["uid_1"],
            0,
        ),
    ],
)
def test_check_multiple_reconnection_attempts(
    mocker, origstate, saddr, daddr, dport, uids, expected_calls
):
    """
    Tests the check_multiple_reconnection_attempts function
    with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.conn_analyzer.set_evidence."
        "SetEvidenceHelper.multiple_reconnection_attempts"
    )
    conn.db.get_reconnections_for_tw.return_value = {}

    for uid in uids:
        flow = Conn(
            starttime="1726249372.312124",
            uid=uid,
            saddr=saddr,
            daddr=daddr,
            dur=1,
            proto="tcp",
            appproto="",
            sport="0",
            dport=str(dport),
            spkts=0,
            dpkts=0,
            sbytes=0,
            dbytes=0,
            smac="",
            dmac="",
            state=origstate,
            history="Sr",
        )
        flow.interpreted_state = "Established"
        conn.check_multiple_reconnection_attempts(profileid, twid, flow)

    assert mock_set_evidence.call_count == expected_calls


@pytest.mark.parametrize(
    "ip_address, expected_result",
    [  # Testcase1:Gateway
        ("192.168.1.1", True),
        # Testcase2:Multicast
        ("224.0.0.1", True),
        # Testcase3:Link-local
        ("169.254.1.1", True),
        # Testcase4:Reserved
        ("240.0.0.0", True),
        # Testcase5:Normal IP
        ("8.8.8.8", False),
    ],
)
def test_is_ignored_ip_data_upload(ip_address, expected_result):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.get_gateway_ip = Mock(return_value="192.168.1.1")

    assert (
        conn.is_ignored_ip_data_upload(ip_address, "eth0") is expected_result
    )


@pytest.mark.parametrize(
    "all_flows, expected_bytes_sent",
    [
        (  # Testcase 1: Normal flows with data
            {
                "uid1": {
                    "daddr": "8.8.8.8",
                    "sbytes": 1024,
                    "starttime": "2023-11-01 12:00:00",
                },
                "uid2": {
                    "daddr": "8.8.8.8",
                    "sbytes": 2048,
                    "starttime": "2023-11-01 12:02:00",
                },
            },
            {"8.8.8.8": (3072, ["uid1", "uid2"], "2023-11-01 12:02:00")},
        ),
        (  # Testcase 2: Flows with no 'sbytes'
            {
                "uid1": {
                    "daddr": "8.8.8.8",
                    "starttime": "2023-11-01 12:00:00",
                },
                "uid2": {
                    "daddr": "8.8.4.4",
                    "sbytes": 2048,
                    "starttime": "2023-11-01 12:02:00",
                },
            },
            {"8.8.4.4": (2048, ["uid2"], "2023-11-01 12:02:00")},
        ),
    ],
)
def test_get_sent_bytes(all_flows, expected_bytes_sent):
    conn = ModuleFactory().create_conn_analyzer_obj()
    bytes_sent = conn.get_sent_bytes(all_flows)
    assert bytes_sent == expected_bytes_sent


@pytest.mark.parametrize(
    "sbytes, ignored_ip, daddr, expected_result, expected_call_count",
    [  # Testcase1: Exceeds threshold
        (100 * 1024 * 1024 + 1, False, "192.168.1.2", True, 1),
        # Testcase2: Below threshold
        (10 * 1024 * 1024, False, "192.168.1.2", False, 0),
        # Testcase3: Ignored IP
        (100 * 1024 * 1024 + 1, True, "192.168.1.1", False, 0),
    ],
)
def test_check_data_upload(
    mocker, sbytes, daddr, ignored_ip, expected_result, expected_call_count
):
    """
    Tests the check_data_upload function with
    various scenarios for data upload.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.is_ignored_ip_data_upload = Mock(return_value=ignored_ip)
    mock_set_evidence = mocker.patch(
        "modules.conn_analyzer.set_evidence.SetEvidenceHelper.data_exfiltration"
    )
    conn.gateway = "192.168.1.1"
    flow = Conn(
        starttime="1726249372.312124",
        uid=uid,
        saddr="192.168.1.1",
        daddr=daddr,
        dur=1,
        proto="tcp",
        appproto="",
        sport="0",
        dport="0",
        spkts=0,
        dpkts=0,
        sbytes=sbytes,
        dbytes=0,
        smac="",
        dmac="",
        state="",
        history="",
        interface="eth0",
    )
    assert conn.check_data_upload(profileid, twid, flow) is expected_result
    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "is_tor_node, expected_result, expected_call_count",
    [
        (True, True, 1),
        (False, False, 0),
    ],
)
def test_check_tor_exit_node(
    mocker, is_tor_node, expected_result, expected_call_count
):
    """
    Tests the check_tor_exit_node function with Tor and non-Tor destinations.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.is_tor_node = Mock(return_value=is_tor_node)
    mock_set_evidence = mocker.patch.object(conn.set_evidence, "tor_exit_node")
    flow = Conn(
        starttime="1726249372.312124",
        uid=uid,
        saddr="192.168.1.1",
        daddr="185.220.101.1",
        dur=1,
        proto="tcp",
        appproto="",
        sport="12345",
        dport="443",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )

    assert conn.check_tor_exit_node(twid, flow) is expected_result
    conn.db.is_tor_node.assert_called_once_with(flow.daddr)
    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "flow_type, appproto, daddr, input_type, "
    "is_doh_server, is_dns_server, is_dhcp_server,"
    "client_ips, expected_result",
    [
        # Testcase 1: Not a 'conn' flow type
        (
            "dns",
            "dns",
            "8.8.8.8",
            InputType.PCAP,
            False,
            False,
            False,
            [],
            True,
        ),
        # Testcase 2: DNS application protocol
        (
            "conn",
            "dns",
            "8.8.8.8",
            InputType.PCAP,
            False,
            False,
            False,
            [],
            True,
        ),
        # Testcase 3: Ignored IP
        (
            "conn",
            "http",
            "192.168.1.1",
            InputType.PCAP,
            False,
            False,
            False,
            [],
            True,
        ),
        # Testcase 4: Client IP
        (
            "conn",
            "http",
            "10.0.0.1",
            InputType.PCAP,
            False,
            False,
            False,
            ["10.0.0.1"],
            True,
        ),
        # Testcase 5: DoH server
        (
            "conn",
            "http",
            "1.1.1.1",
            InputType.PCAP,
            True,
            False,
            False,
            [],
            True,
        ),
        # Testcase 6: DHCP server
        (
            "conn",
            "dhcp",
            "192.168.1.1",
            InputType.PCAP,
            True,
            False,
            True,
            [],
            True,
        ),
        # Testcase 7: Should not ignore
        (
            "conn",
            "http",
            "93.184.216.34",
            InputType.PCAP,
            False,
            False,
            False,
            [],
            False,
        ),
    ],
)
def test_should_ignore_conn_without_dns(
    mocker,
    flow_type,
    appproto,
    daddr,
    input_type,
    is_doh_server,
    is_dns_server,
    is_dhcp_server,
    client_ips,
    expected_result,
):
    """Tests the should_ignore_conn_without_dns
    function with various scenarios."""
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.is_running_non_stop = False
    flow = Conn(
        starttime="1726249372.312124",
        uid=uid,
        saddr="192.168.1.1",
        daddr=daddr,
        dur=1,
        proto="tcp",
        appproto=appproto,
        sport="0",
        dport="0",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="",
        history="ShADadFf",
        type_=flow_type,
    )

    conn.db.get_input_type.return_value = input_type
    conn.db.is_doh_server.return_value = is_doh_server
    conn.db.is_dhcp_server.return_value = is_dhcp_server
    conn.dns_analyzer = Mock()
    conn.client_ips = client_ips
    mocker.patch(
        "slips_files.common.slips_utils.utils.is_ignored_ip",
        side_effect=lambda ip: ip_address(ip).is_private,
    )

    assert conn.should_ignore_conn_without_dns(flow) is expected_result


@pytest.mark.parametrize(
    "rcode, port, proto, query, server, timestamp, expected",
    [
        ("NOERROR", 53, "udp", "example.org", "95.211.15.53", 100, True),
        ("NXDOMAIN", "53", "TCP", "absent.example.org", "95.211.15.53", 100, True),
        ("NOERROR", 53, "tcp", "example.org", "2606:4700:4700::1111", 100, True),
        ("-", 53, "udp", "example.org", "95.211.15.53", 100, False),
        ("SERVFAIL", 53, "udp", "example.org", "95.211.15.53", 100, False),
        ("REFUSED", 53, "udp", "example.org", "95.211.15.53", 100, False),
        ("NOERROR", 5353, "udp", "example.org", "95.211.15.53", 100, False),
        ("NOERROR", 53, "icmp", "example.org", "95.211.15.53", 100, False),
        ("NOERROR", 53, "udp", "-", "95.211.15.53", 100, True),
        ("NXDOMAIN", 53, "tcp", "", "95.211.15.53", 100, True),
        ("NOERROR", 53, "udp", "example.org", "224.0.0.251", 100, False),
        ("NOERROR", 53, "udp", "example.org", "invalid", 100, False),
        ("NOERROR", 53, "udp", "example.org", "95.211.15.53", float("nan"), False),
    ],
)
def test_remember_working_dns_server(
    rcode: str, port: int | str, proto: str, query: str,
    server: str, timestamp: float, expected: bool,
) -> None:
    """Learn actual resolver replies rather than trusting a destination port.

    Parameters:
        rcode: Observed DNS response code, or query-only marker.
        port: Destination service port.
        proto: Transport protocol.
        query: DNS question.
        server: Responder address.
        timestamp: Capture time of the DNS transaction.
        expected: Whether a working responder should be remembered.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    flow = SimpleNamespace(type_="dns", daddr=server, dport=port, proto=proto,
                           query=query, rcode_name=rcode, starttime=timestamp,
                           interface="eth0", answers=[])
    assert conn.remember_working_dns_server(flow) is expected
    assert len(conn.working_dns_servers) == int(expected)


@pytest.mark.parametrize(
    "port, proto, configured, learned, interface, age, expected",
    [
        (53, "udp", True, False, "eth0", 0, True),
        ("53", "TCP", True, False, "eth0", 0, True),
        (53, "udp", False, True, "eth0", 100, True),
        (53, "tcp", False, True, "eth0", -1, True),
        (53, "udp", False, True, "eth0", 86401, False),
        (53, "udp", False, True, "other-interface", 0, False),
        (53, "udp", False, False, "eth0", 0, False),
        (443, "tcp", True, True, "eth0", 0, False),
        (53, "icmp", True, True, "eth0", 0, False),
    ],
)
def test_working_dns_exemption_is_scoped(
    port: int | str, proto: str, configured: bool, learned: bool,
    interface: str, age: float, expected: bool,
) -> None:
    """Exempt resolver service traffic without exempting unrelated connections.

    Parameters:
        port: Connection destination port.
        proto: Connection transport.
        configured: Whether the address is a configured resolver.
        learned: Whether a valid DNS reply was observed.
        interface: Connection capture interface.
        age: Time difference from the observed DNS reply, in seconds.
        expected: Whether the connection should be excluded.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.is_official_dns_server.return_value = configured
    conn.db.get_network_state.return_value = None
    conn.db.is_doh_server.return_value = False
    conn.db.is_dhcp_server.return_value = False
    conn.is_running_non_stop = False
    conn.client_ips = []
    reply = SimpleNamespace(type_="dns", daddr="95.211.15.53", dport=53,
                            proto="udp", query="example.org", rcode_name="NOERROR",
                            starttime=100000, interface="eth0")
    if learned:
        assert conn.remember_working_dns_server(reply)
    flow = SimpleNamespace(type_="conn", saddr="10.0.2.111", daddr=reply.daddr,
                           sport=49284, dport=port, proto=proto.lower(), appproto="",
                           history="ShADadFf", starttime=100000 + age, interface=interface)
    assert conn.is_working_dns_connection(flow) is expected
    if proto != "icmp":
        assert conn.should_ignore_conn_without_dns(flow) is expected


def test_working_dns_cache_is_bounded() -> None:
    """Bound resolver state and ignore older updates from reordered logs."""
    conn = ModuleFactory().create_conn_analyzer_obj()
    flow = SimpleNamespace(type_="dns", daddr="95.211.15.53", dport=53,
                           proto="udp", query="example.org", rcode_name="NOERROR",
                           starttime=100, interface="eth0")
    for number in range(4097):
        flow.daddr = str(ip_address(int(ip_address("100.64.0.1")) + number))
        assert conn.remember_working_dns_server(flow)
    assert len(conn.working_dns_servers) == 4096
    assert ("eth0", "100.64.0.1") not in conn.working_dns_servers
    flow.starttime = 99
    assert conn.remember_working_dns_server(flow)
    assert conn.working_dns_servers[("eth0", flow.daddr)] == 100


@pytest.mark.parametrize("reply_arrives", [True, False])
async def test_without_dns_rechecks_responder_after_grace(
    mocker: Any, reply_arrives: bool,
) -> None:
    """Honor a DNS reply processed after the connection before reporting evidence.

    Parameters:
        mocker: Patch helper for the existing processing grace period.
        reply_arrives: Whether a valid DNS response arrives while waiting.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.is_official_dns_server.return_value = False
    conn.db.get_network_state.return_value = None
    conn.db.is_doh_server.return_value = False
    conn.db.is_dhcp_server.return_value = False
    conn.db.is_ip_resolved.return_value = False
    conn.is_running_non_stop = False
    conn.client_ips = []
    conn.input_type = InputType.PCAP
    conn.check_if_resolution_was_made_by_different_version = Mock(return_value=False)
    conn.is_well_known_org = Mock(return_value=False)
    conn.set_evidence.conn_without_dns = Mock()
    flow = SimpleNamespace(type_="conn", saddr="10.0.2.111", daddr="95.211.15.53",
                           sport=49284, dport=53, proto="udp", appproto="",
                           history="Dd", starttime=100000, interface="eth0")

    async def process_reply(delay: float) -> None:
        """Process a DNS response during the simulated log-order grace period.

        Parameters:
            delay: Existing wait requested by the detector.
        """
        assert delay == 15
        if reply_arrives:
            reply = SimpleNamespace(**{**vars(flow), "type_": "dns", "query": "example.org",
                                       "rcode_name": "NOERROR"})
            assert conn.remember_working_dns_server(reply)

    mocker.patch("modules.conn_analyzer.conn_analyzer.asyncio.sleep", side_effect=process_reply)
    assert await conn.check_connection_without_dns_resolution(profileid, twid, flow) is (not reply_arrives)
    assert conn.set_evidence.conn_without_dns.call_count == int(not reply_arrives)


async def test_conn_analyzer_consumes_dns_responder_messages(mocker: Any) -> None:
    """Route parsed DNS replies into resolver recognition in the module worker.

    Parameters:
        mocker: Patch helper for isolated channel messages.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    flow = SimpleNamespace(type_="dns", daddr="95.211.15.53", dport=53,
                           proto="udp", query="example.org", rcode_name="NOERROR",
                           starttime=100, interface="eth0")
    message = {"data": json.dumps({"flow": vars(flow)})}
    conn.classifier.convert_to_flow_obj = Mock(return_value=flow)
    mocker.patch.object(conn, "get_msg", side_effect=lambda channel: message if channel == "new_dns" else None)
    await conn.main()
    assert conn.working_dns_servers[("eth0", "95.211.15.53")] == 100
    conn.subscribe_to_channels()
    assert "new_dns" in conn.channels


@pytest.mark.parametrize(
    "profileid, daddr, mock_get_the_other_ip_version_return_value, "
    "mock_get_dns_resolution_return_value, expected_result",
    [
        (  # Test case 1: Resolution done by the other IP version
            profileid,
            daddr,
            json.dumps("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            {"resolved-by": ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]},
            True,
        ),
        (  # Test case 2: Resolution not done by another IP
            profileid,
            "2.3.4.5",
            json.dumps("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            {"resolved-by": []},
            False,
        ),
        (  # Test case 3: No other IP version found
            profileid,
            daddr,
            None,
            {"resolved-by": ["192.168.1.2"]},
            False,
        ),
        (  # Test case 4: 'resolved-by' is a string, not a list
            profileid,
            daddr,
            json.dumps("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            {"resolved-by": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
            True,
        ),
    ],
)
def test_check_if_resolution_was_made_by_different_version(
    profileid,
    daddr,
    mock_get_the_other_ip_version_return_value,
    mock_get_dns_resolution_return_value,
    expected_result,
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.get_the_other_ip_version.return_value = (
        mock_get_the_other_ip_version_return_value
    )
    conn.db.get_dns_resolution.return_value = (
        mock_get_dns_resolution_return_value
    )

    assert (
        conn.check_if_resolution_was_made_by_different_version(
            profileid, daddr
        )
        is expected_result
    )


@pytest.mark.parametrize(
    "sport, dport, proto, " "saddr, daddr, expected_calls",
    [
        (  # Testcase 1: Connection to port 0, evidence should be set
            0,
            80,
            "tcp",
            "192.168.1.1",
            "192.168.1.2",
            1,
        ),
        (  # Testcase 2: Connection from port 0, evidence should be set
            80,
            0,
            "tcp",
            "192.168.1.1",
            "192.168.1.2",
            1,
        ),
        (  # Testcase 3:  Both ports are non-zero, no evidence
            80,
            80,
            "tcp",
            "192.168.1.1",
            "192.168.1.2",
            0,
        ),
        (  # Testcase 4: IGMP protocol, no evidence
            0,
            0,
            "igmp",
            "192.168.1.1",
            "192.168.1.2",
            0,
        ),
    ],
)
def test_check_conn_to_port_0(
    sport, dport, proto, saddr, daddr, expected_calls
):
    """
    Tests the check_conn_to_port_0 function with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.set_evidence.port_0_connection = Mock()
    flow = Conn(
        starttime="1726249372.312124",
        uid=uid,
        saddr=saddr,
        daddr=daddr,
        dur=1,
        proto=proto,
        appproto="",
        sport=str(sport),
        dport=str(dport),
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="",
        history="",
    )

    conn.check_conn_to_port_0(profileid, twid, flow)
    assert conn.set_evidence.port_0_connection.call_count == expected_calls


@pytest.mark.parametrize(
    "dur, daddr, saddr, expected_result, expected_evidence_call",
    [
        (  # Test case 1: Duration above threshold
            2000,
            "192.168.1.2",
            "192.168.1.1",
            True,
            1,
        ),
        (  # Test case 2: Duration below threshold
            1000,
            "192.168.1.2",
            "192.168.1.1",
            False,
            0,
        ),
        (  # Test case 3: Duration as string
            "2000",
            "192.168.1.2",
            "192.168.1.1",
            True,
            1,
        ),
        (  # Test case 4: Multicast daddr
            2000,
            "224.0.0.1",
            "192.168.1.1",
            None,
            0,
        ),
        (  # Test case 5: Multicast saddr
            2000,
            "192.168.1.2",
            "224.0.0.1",
            None,
            0,
        ),
        (  # Test case 6: Both multicast
            2000,
            "224.0.0.2",
            "224.0.0.1",
            None,
            0,
        ),
    ],
)
def test_check_long_connection(
    dur, daddr, saddr, expected_result, expected_evidence_call
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.long_connection_threshold = 1500
    conn.set_evidence.long_connection = Mock()
    flow = Conn(
        starttime="1726249372.312124",
        uid=uid,
        saddr=saddr,
        daddr=daddr,
        dur=dur,
        proto="",
        appproto="",
        sport="0",
        dport="0",
        spkts=0,
        dpkts=0,
        sbytes=5,
        dbytes=5,
        smac="",
        dmac="",
        state="",
        history="",
    )
    assert conn.check_long_connection(twid, flow) == expected_result
    assert (
        conn.set_evidence.long_connection.call_count == expected_evidence_call
    )


@pytest.mark.parametrize(
    "daddr, portproto, org_info, mac_vendor, "
    "ip_identification, is_ip_in_org, expected_result",
    [
        # Test case 1: IP belongs to organization's range
        (
            "192.168.1.2",
            "80/tcp",
            json.dumps({"ip": ["192.168.1.0/24"], "org_name": ["TestOrg"]}),
            "",
            {},
            False,
            True,
        ),
        # Test case 2: MAC vendor matches organization
        (
            "10.0.0.1",
            "443/tcp",
            json.dumps({"ip": [], "org_name": ["AppleInc"]}),
            "Apple, Inc.",
            {},
            True,
            True,
        ),
        # Test case 3: IP identification matches organization
        (
            "172.16.0.1",
            "8080/tcp",
            json.dumps({"ip": [], "org_name": ["Google"]}),
            "",
            {"SNI": "dns.google.com"},
            False,
            True,
        ),
        # Test case 4: IP belongs to organization
        (
            "157.240.3.35",
            "443/tcp",
            json.dumps({"ip": [], "org_name": ["Facebook"]}),
            "",
            {},
            True,
            True,
        ),
        # Test case 5: IP doesn't belong to any organization
        (
            "203.0.113.1",
            "22/tcp",
            json.dumps({"ip": [], "org_name": []}),
            "",
            {},
            False,
            False,
        ),
    ],
)
def test_port_belongs_to_an_org(
    mocker,
    daddr,
    portproto,
    org_info,
    mac_vendor,
    ip_identification,
    is_ip_in_org,
    expected_result,
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.get_organization_of_port.return_value = org_info
    conn.db.get_mac_vendor_from_profile.return_value = mac_vendor
    conn.db.get_ip_identification.return_value = ip_identification
    mocker.patch.object(
        conn.whitelist.org_analyzer, "is_ip_in_org", return_value=is_ip_in_org
    )

    assert (
        conn.port_belongs_to_an_org(daddr, portproto, profileid)
        == expected_result
    )


@pytest.mark.parametrize(
    "src_vendor,dst_vendor,expected",
    [
        ("Apple, Inc.", "Apple, Inc.", True),
        ("Apple, Inc.", "", False),
        ("", "Apple, Inc.", False),
        ("Apple, Inc.", "Other vendor", False),
    ],
)
def test_org_port_requires_both_mac_vendors(
    mocker: Any, src_vendor: str, dst_vendor: str, expected: bool
) -> None:
    """Accept a MAC-only org match only when both endpoints match.

    Parameters:
        mocker: Patches the organization IP lookup.
        src_vendor: Source profile MAC vendor.
        dst_vendor: Destination profile MAC vendor.
        expected: Whether the vendor pair matches Apple's port entry.
    """
    factory = ModuleFactory()
    conn = factory.create_conn_analyzer_obj()
    conn.db.get_organization_of_port.return_value = json.dumps(
        {"ip": [], "org_name": ["Apple"]}
    )
    conn.db.get_mac_vendor_from_profile.side_effect = [
        src_vendor,
        dst_vendor,
    ]
    conn.db.get_ip_identification.return_value = {}
    mocker.patch.object(
        conn.whitelist.org_analyzer, "is_ip_in_org", return_value=False
    )

    assert (
        conn.port_belongs_to_an_org(
            "192.168.1.163", "57558/tcp", "profile_192.168.1.247"
        )
        is expected
    )


@pytest.mark.parametrize(
    "flow_type, smac, old_ip_list, saddr, expected_calls",
    [
        # Test case 1: New IP for existing MAC
        (
            "conn",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "192.168.1.3",
            1,
        ),
        # Test case 2: Same IP for existing MAC
        (
            "conn",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "192.168.1.2",
            0,
        ),
        # Test case 3: Non-conn flow type
        (
            "dns",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "192.168.1.3",
            0,
        ),
        # Test case 4: Public IP (should be ignored)
        (
            "conn",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "8.8.8.8",
            0,
        ),
        # Test case 5: IP already seen in connlog
        (
            "conn",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "192.168.1.3",
            0,
        ),
    ],
)
def test_check_device_changing_ips(
    flow_type, smac, old_ip_list, saddr, expected_calls
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.set_evidence.device_changing_ips = Mock()
    conn.db.was_ip_seen_in_connlog_before.return_value = expected_calls == 0
    conn.db.get_ip_of_mac.return_value = old_ip_list
    flow = Conn(
        starttime="1726249372.312124",
        uid=uid,
        saddr=saddr,
        daddr=daddr,
        dur=5,
        proto="",
        appproto="",
        sport="0",
        dport="0",
        spkts=0,
        dpkts=0,
        sbytes=5,
        dbytes=5,
        smac=smac,
        dmac="",
        state="",
        history="",
        type_=flow_type,
    )
    conn.check_device_changing_ips(twid, flow)
    assert conn.set_evidence.device_changing_ips.call_count == expected_calls


@pytest.mark.parametrize(
    "source,mac,old_ips,gateway_ip,gateway_mac,expected_old",
    [
        ("172.18.0.1", "b6:49:9f:96:b2:d4", ["147.32.82.228"], None, None, None),
        ("172.18.0.1", "b6:49:9f:96:b2:d4", ["172.18.0.9"], "172.18.0.1", "b6:49:9f:96:b2:d4", None),
        ("172.18.0.8", "b6:49:9f:96:b2:d4", ["172.18.0.9"], "172.18.0.1", "b6:49:9f:96:b2:d4", None),
        ("172.18.0.8", "ca:ef:de:b4:f3:fc", ["147.32.82.228", "172.18.0.9"], "172.18.0.1", "b6:49:9f:96:b2:d4", "172.18.0.9"),
        ("172.18.0.8", "ca:ef:de:b4:f3:fc", ["172.18.0.8"], None, None, None),
        ("172.18.0.8", "ff:ff:ff:ff:ff:ff", ["172.18.0.9"], None, None, None),
    ],
)
def test_device_ip_change_rejects_routed_mac_ownership(
    source: str, mac: str, old_ips: list[str], gateway_ip: str | None,
    gateway_mac: str | None, expected_old: str | None,
) -> None:
    """Ignore router hops and old public associations, retaining local changes."""
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.was_ip_seen_in_connlog_before.return_value = False
    conn.db.get_ip_of_mac.return_value = json.dumps(old_ips)
    conn.db.get_network_state.return_value = None
    conn.db.get_gateway_ip.return_value = gateway_ip
    conn.db.get_gateway_mac.return_value = gateway_mac
    conn.set_evidence.device_changing_ips = Mock()
    flow = SimpleNamespace(type_="conn", saddr=source, smac=mac, interface="eth0", starttime=1793026866.0)

    conn.check_device_changing_ips("timewindow2", flow)

    if expected_old:
        conn.set_evidence.device_changing_ips.assert_called_once_with("timewindow2", flow, expected_old)
    else:
        conn.set_evidence.device_changing_ips.assert_not_called()


def test_device_ip_change_uses_gateway_at_flow_time() -> None:
    """A delayed flow must use its previous network's gateway."""
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.was_ip_seen_in_connlog_before.return_value = False
    conn.db.get_ip_of_mac.return_value = json.dumps(["172.18.0.9"])
    conn.db.get_network_state.return_value = {
        "changed_at": 200.0, "gateway_mac": "00:11:22:33:44:55",
        "gateway_ip": "192.168.1.1", "history": [{
            "changed_at": 100.0, "gateway_mac": "b6:49:9f:96:b2:d4",
            "gateway_ip": "172.18.0.1",
        }],
    }
    conn.set_evidence.device_changing_ips = Mock()
    flow = SimpleNamespace(type_="conn", saddr="172.18.0.8", smac="b6:49:9f:96:b2:d4", interface="eth0", starttime=150.0)

    conn.check_device_changing_ips("timewindow2", flow)

    conn.set_evidence.device_changing_ips.assert_not_called()
    conn.db.get_gateway_mac.assert_not_called()


@pytest.mark.parametrize(
    "ip, ip_info, is_ip_asn_in_org_asn, "
    "is_domain_in_org, is_ip_in_org, expected_result",
    [
        # Test case 1: Well-known org by SNI
        (
            "8.8.8.8",
            {
                "SNI": {"server_name": "google.com"},
                "reverse_dns": "dns.google",
            },
            False,
            True,
            False,
            True,
        ),
        # Test case 2: Well-known org by reverse DNS
        (
            "157.240.3.35",
            {
                "SNI": None,
                "reverse_dns": "edge-star-mini-shv-01-amt2.facebook.com",
            },
            False,
            True,
            False,
            True,
        ),
        # Test case 3: Well-known org by ASN
        (
            "13.107.42.14",
            {"SNI": None, "reverse_dns": None},
            True,
            False,
            False,
            True,
        ),
        # Test case 4: Well-known org by IP range
        (
            "204.79.197.200",
            {"SNI": None, "reverse_dns": None},
            False,
            False,
            True,
            True,
        ),
        # Test case 5: Not a well-known org
        (
            "203.0.113.1",
            {"SNI": None, "reverse_dns": None},
            False,
            False,
            False,
            False,
        ),
    ],
)
def test_is_well_known_org(
    mocker,
    ip,
    ip_info,
    is_ip_asn_in_org_asn,
    is_domain_in_org,
    is_ip_in_org,
    expected_result,
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.db.get_ip_info.return_value = ip_info
    mock_is_ip_asn_in_org_asn = mocker.patch(
        "slips_files.core.helpers.whitelist.organization_whitelist."
        "OrgAnalyzer.is_ip_asn_in_org_asn"
    )
    mock_is_ip_asn_in_org_asn.return_value = is_ip_asn_in_org_asn

    mock_is_domain_in_org = mocker.patch(
        "slips_files.core.helpers.whitelist.organization_whitelist."
        "OrgAnalyzer.is_domain_in_org"
    )
    mock_is_domain_in_org.return_value = is_domain_in_org

    mock_is_ip_in_org = mocker.patch(
        "slips_files.core.helpers.whitelist."
        "organization_whitelist.OrgAnalyzer.is_ip_in_org"
    )
    mock_is_ip_in_org.return_value = is_ip_in_org
    assert conn.is_well_known_org(ip) == expected_result


@pytest.mark.parametrize(
    "saddr, daddr, dport, proto, expected_calls",
    [
        (  # Test case 1: Different local network usage (dstip),
            # evidence should be set
            "192.168.1.1",
            "10.0.0.1",
            80,
            "tcp",
            1,
        ),
        (  # Test case 2: Same local network usage, no evidence
            "192.168.1.1",
            "192.168.1.2",
            80,
            "tcp",
            0,
        ),
        (  # Test case 3: Different local network usage (srcip),
            # evidence should be set
            "10.0.0.1",
            "192.168.1.2",
            80,
            "tcp",
            1,
        ),
        (  # Test case 4:  Public IP used, no evidence
            "8.8.8.8",
            "192.168.1.2",
            80,
            "tcp",
            0,
        ),
        (  # Test case 5: Different IPv6 local network usage (dstip)
            "fd00:1::10",
            "fd00:2::20",
            80,
            "tcp",
            1,
        ),
        (  # Test case 6: Same IPv6 local network usage, no evidence
            "fd00:1::10",
            "fd00:1::20",
            80,
            "tcp",
            0,
        ),
    ],
)
def test_check_different_localnet_usage(
    saddr, daddr, dport, proto, expected_calls
):
    """
    Tests the check_different_localnet_usage function
    with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.set_evidence.different_localnet_usage = Mock()
    conn.db.get_local_network.return_value = (
        "fd00:1::/64" if ":" in saddr or ":" in daddr else "192.168.1.0/24"
    )
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr=saddr,
        daddr=daddr,
        dur=1,
        proto=proto,
        appproto="",
        sport="0",
        dport=str(dport),
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="ShADadFf",
    )
    conn.check_different_localnet_usage(
        twid,
        flow,
    )
    call_count = conn.set_evidence.different_localnet_usage.call_count
    assert call_count == expected_calls


@pytest.mark.parametrize(
    "saddr, daddr, sport, dport",
    [
        ("fd00:1::10", "fd00:2::53", "40000", "53"),
        ("fd00:2::53", "fd00:1::10", "53", "40000"),
    ],
)
def test_check_different_localnet_usage_ignores_official_dns_server(
    saddr, daddr, sport, dport
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.set_evidence.different_localnet_usage = Mock()
    conn.db.get_local_network.return_value = "fd00:1::/64"
    conn.db.is_official_dns_server.return_value = True
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr=saddr,
        daddr=daddr,
        dur=1,
        proto="tcp",
        appproto="",
        sport=sport,
        dport=dport,
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )

    conn.check_different_localnet_usage(
        twid,
        flow,
    )

    conn.set_evidence.different_localnet_usage.assert_not_called()


@pytest.mark.parametrize(
    "daddr, dport, proto, saddr, expected_calls",
    [
        (  # Test case 1: Both IPs are private,
            # not a DNS connection to the gateway
            "192.168.1.2",
            80,
            "tcp",
            "192.168.1.1",
            1,
        ),
        (  # Test case 2: Both IPs are private but
            # it's a DNS connection to the gateway
            "192.168.1.1",
            53,
            "udp",
            "192.168.1.2",
            0,
        ),
        (  # Test case 3: One IP is not private
            "8.8.8.8",
            80,
            "tcp",
            "192.168.1.1",
            0,
        ),
        ("192.168.1.2", 0, "icmp", "192.168.1.1", 0),
        ("fd00::2", 0, "icmp6", "fd00::1", 0),
        ("192.168.1.158", 5353, "udp", "192.168.1.163", 0),
        ("224.0.0.251", 5353, "udp", "192.168.1.163", 0),
    ],
)
def test_check_connection_to_local_ip(
    daddr, dport, proto, saddr, expected_calls
):
    """
    Tests the check_connection_to_local_ip function with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.set_evidence.conn_to_private_ip = Mock()
    conn.db.get_gateway_ip.return_value = "192.168.1.1"
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr=saddr,
        daddr=daddr,
        dur=1,
        proto=proto,
        appproto="",
        sport="0",
        dport=str(dport),
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="ShADadFf",
    )
    conn.check_connection_to_local_ip(twid, flow)
    assert conn.set_evidence.conn_to_private_ip.call_count == expected_calls


@pytest.mark.parametrize(
    "saddr, daddr, sport, dport, official_dns_ip",
    [
        ("192.168.1.20", "192.168.1.53", "40000", "53", ""),
        ("fd00::53", "fd00::10", "547", "546", ""),
        ("fd00::10", "fd00::53", "546", "547", ""),
    ],
)
def test_check_connection_to_local_ip_ignores_official_dns_server(
    saddr, daddr, sport, dport, official_dns_ip
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.set_evidence.conn_to_private_ip = Mock()
    conn.db.get_gateway_ip.return_value = "192.168.1.1"
    conn.db.is_official_dns_server.side_effect = (
        lambda ip: ip == official_dns_ip
    )
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr=saddr,
        daddr=daddr,
        dur=1,
        proto="udp",
        appproto="",
        sport=sport,
        dport=dport,
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )

    conn.check_connection_to_local_ip(twid, flow)

    conn.set_evidence.conn_to_private_ip.assert_not_called()


@pytest.mark.parametrize(
    "saddr, daddr, sport, dport",
    [
        ("fd00::10", "fd00::53", "40000", "53"),
        ("fd00::53", "fd00::10", "547", "546"),
        ("fd00::10", "fd00::53", "546", "547"),
    ],
)
def test_check_connection_to_local_ip_ignores_dns_and_dhcpv6_service_ports(
    saddr, daddr, sport, dport
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.set_evidence.conn_to_private_ip = Mock()
    conn.db.get_gateway_ip.return_value = "192.168.1.1"
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr=saddr,
        daddr=daddr,
        dur=1,
        proto="udp",
        appproto="",
        sport=sport,
        dport=dport,
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )

    conn.check_connection_to_local_ip(twid, flow)

    conn.set_evidence.conn_to_private_ip.assert_not_called()


@pytest.mark.parametrize(
    "msg, expected_result",
    [
        (
            {
                "channel": "tw_closed",
                "data": json.dumps(
                    {
                        "text": "profile_192.168.1.1_timewindow3",
                        "version": "test-version",
                    }
                ),
            },
            ("profile_192.168.1.1", "timewindow3"),
        ),
        (
            {
                "channel": "tw_closed",
                "data": json.dumps(
                    {
                        "text": json.dumps(
                            {
                                "text": "profile_192.168.1.1_timewindow3",
                                "version": "test-version",
                            }
                        ),
                        "version": "test-version",
                    }
                ),
            },
            ("profile_192.168.1.1", "timewindow3"),
        ),
        (
            {
                "channel": "tw_closed",
                "data": json.dumps(
                    {"text": "invalid_payload", "version": "test-version"}
                ),
            },
            None,
        ),
    ],
)
def test_parse_closed_tw_message(msg, expected_result):
    conn = ModuleFactory().create_conn_analyzer_obj()
    assert conn._parse_closed_tw_message(msg) == expected_result


async def test_check_non_ssl_port_443_conns_not_interested():
    """mock a flow that we're not interested in in that function, like a
    dns flow or something"""
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.is_tcp_established_443_non_empty_flow = Mock(return_value=False)
    result = await conn.check_non_ssl_port_443_conns(None, None)
    assert result is False


async def test_check_non_ssl_port_443_conns_is_ssl():
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    conn.is_ssl_proto_recognized_by_zeek = Mock(return_value=True)
    conn.keep_track_of_ssl_flow = Mock()
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await conn.check_non_ssl_port_443_conns(None, flow)
    assert result is False
    conn.keep_track_of_ssl_flow.assert_called_once()


async def test_check_non_ssl_port_443_conns_matching_ssl_past():
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    conn.is_ssl_proto_recognized_by_zeek = Mock(return_value=False)
    # Simulate a matching SSL flow
    conn.search_ssl_recognized_flows_for_ts_range = Mock(return_value=[1.0])
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await conn.check_non_ssl_port_443_conns(None, flow)
    assert result is False


async def test_check_non_ssl_port_443_conns_matching_ssl_future():
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    conn.is_ssl_proto_recognized_by_zeek = Mock(return_value=False)
    # Simulate a matching SSL flow
    conn.search_ssl_recognized_flows_for_ts_range = Mock(return_value=[1.0])
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await conn.check_non_ssl_port_443_conns(
        None, flow, timeout_reached=True
    )
    assert result is False


async def test_check_non_ssl_port_443_conns_no_matching_ssl_timeout():
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    conn.is_ssl_proto_recognized_by_zeek = Mock(return_value=False)

    # No matching SSL flows
    conn.search_ssl_recognized_flows_for_ts_range = Mock(return_value=[])
    conn.set_evidence = MagicMock()
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await conn.check_non_ssl_port_443_conns(
        None, flow, timeout_reached=True
    )
    assert result
    conn.set_evidence.non_ssl_port_443_conn.assert_called_once()


async def test_check_non_ssl_port_443_conns_no_matching_ssl_no_timeout():
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    conn.is_ssl_proto_recognized_by_zeek = Mock(return_value=False)
    conn.set_evidence.non_ssl_port_443_conn = Mock()
    conn.search_ssl_recognized_flows_for_ts_range = Mock(return_value=[])
    conn.wait_for_new_flows_or_timeout = get_mock_coro(True)
    # No matching SSL flows
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await conn.check_non_ssl_port_443_conns(None, flow)
    assert result is False
    conn.wait_for_new_flows_or_timeout.assert_called_once()
    conn.set_evidence.non_ssl_port_443_conn.assert_called_once()


@pytest.mark.parametrize(
    "dport, proto, sbytes, dbytes, final_state, expected",
    [
        ("443", "tcp", 0, 0, "Established", False),
    ],
)
def test_is_tcp_established_443_non_empty_flow(
    dport,
    proto,
    sbytes,
    dbytes,
    final_state,
    expected,
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    flow = Mock(
        dport=dport,
        cert_chain_fuids="",
        client_cert_chain_fuids="",
        pkts=80,
        proto=proto,
        sbytes=sbytes,
        dbytes=dbytes,
    )

    conn.db.get_final_state_from_flags.return_value = final_state

    result = conn.is_tcp_established_443_non_empty_flow(flow)
    assert result == expected


@pytest.mark.parametrize(
    "ssl_recognized_flows, flow, start, end, expected",
    [
        # case: matching timestamps within the range
        (
            {("192.168.1.1", "10.0.0.1"): [1.0, 2.0, 3.0, 4.0, 5.0]},
            {"saddr": "192.168.1.1", "daddr": "10.0.0.1"},
            2.0,
            4.0,
            [2.0, 3.0, 4.0],
        ),
        # case: no matching timestamps (empty result)
        (
            {("192.168.1.1", "10.0.0.1"): [1.0, 2.0, 3.0]},
            {"saddr": "192.168.1.1", "daddr": "10.0.0.1"},
            4.0,
            5.0,
            [],
        ),
        # case: flow does not exist in ssl_recognized_flows
        (
            {("192.168.1.2", "10.0.0.2"): [1.0, 2.0, 3.0]},
            {"saddr": "192.168.1.1", "daddr": "10.0.0.1"},
            1.0,
            3.0,
            [],
        ),
        # case: start and end cover all timestamps
        (
            {("192.168.1.1", "10.0.0.1"): [1.0, 2.0, 3.0, 4.0, 5.0]},
            {"saddr": "192.168.1.1", "daddr": "10.0.0.1"},
            1.0,
            5.0,
            [1.0, 2.0, 3.0, 4.0, 5.0],
        ),
    ],
)
def test_search_ssl_recognized_flows_for_ts_range(
    ssl_recognized_flows, flow, start, end, expected
):
    conn = ModuleFactory().create_conn_analyzer_obj()
    conn.ssl_recognized_flows = ssl_recognized_flows
    flow = Mock(saddr=flow["saddr"], daddr=flow["daddr"])
    result = conn.search_ssl_recognized_flows_for_ts_range(flow, start, end)
    assert result == expected


async def test_main_new_flow_msg_checks_non_ssl_port_443_conns(mocker):
    """
    the new_flow branch of main() should trigger the non-ssl-on-443
    check that used to live in ssl.py's analyze()
    """
    conn = ModuleFactory().create_conn_analyzer_obj()
    flow = Conn(
        starttime="1726249372.312124",
        uid=uid,
        saddr="192.168.1.87",
        daddr="1.1.1.1",
        dur=1,
        proto="",
        appproto="",
        sport="0",
        dport="",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="",
        history="",
    )
    msg = {
        "channel": "new_flow",
        "data": json.dumps(
            {
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
                "flow": asdict(flow),
            }
        ),
    }

    def fake_get_msg(channel):
        return msg if channel == "new_flow" else None

    mocker.patch.object(conn, "get_msg", side_effect=fake_get_msg)
    mock_create_task = mocker.patch.object(conn, "create_task")

    await conn.main()

    called_funcs = [call.args[0] for call in mock_create_task.call_args_list]
    assert conn.check_non_ssl_port_443_conns in called_funcs


def test_unknown_port_ignores_known_p2p_flow(mocker) -> None:
    """Suppress UNKNOWN_PORT for a flow matching a known P2P connection."""
    conn = ModuleFactory().create_conn_analyzer_obj()
    flow = Conn(
        starttime="1726249372.312124",
        uid="p2p-flow",
        saddr="192.168.1.1",
        daddr="198.51.100.20",
        dur=1,
        proto="tcp",
        appproto="",
        sport="51000",
        dport="6668",
        spkts=1,
        dpkts=1,
        sbytes=60,
        dbytes=60,
        state="Established",
        history="Sh",
    )
    conn.db.is_a_port_scanner.return_value = False
    conn.db.get_port_info.return_value = None
    conn.db.is_ftp_port.return_value = False
    conn.db.is_p2p_related_flow.return_value = True
    mocker.patch.object(conn, "port_belongs_to_an_org", return_value=False)
    evidence = mocker.patch.object(conn.set_evidence, "unknown_port")

    assert conn.check_unknown_port(profileid, twid, flow) is None
    evidence.assert_not_called()


@pytest.mark.parametrize("proto,state,history,known_service,expected", [
    ("tcp", "S1", "ShADadt", None, True),
    ("tcp", "SF", "ShADadfF", None, True),
    ("tcp", "S1", "ShADadt", "known-service", False),
    ("tcp", "S0", "S", None, False),
    ("tcp", "REJ", "Sr", None, False),
    ("udp", "SF", "Dd", None, True),
    ("udp", "S0", "D", None, False),
])
def test_scanner_keeps_established_unknown_service(proto: str, state: str, history: str, known_service: str | None, expected: bool) -> None:
    """Keep a scanner's successful services visible while suppressing failed probes.

    Parameters:
        proto: TCP or UDP transport.
        state: Zeek connection state.
        history: Recorded packet flags relative to the final endpoints.
        known_service: Existing service catalogue match, if any.
        expected: Whether Unknown Port evidence must be generated.
    """
    factory = ModuleFactory()
    conn = factory.create_conn_analyzer_obj()
    from modules.conn_analyzer.set_evidence import SetEvidenceHelper
    from slips_files.core.database.redis_db.scan_detections_db import ScanDetectionsHandler
    from slips_files.core.structures.evidence import EvidenceType, ThreatLevel

    raw = {"ts": 321.97754, "uid": "scanner-established-9001", "id.orig_h": "192.168.1.120",
           "id.orig_p": 49722, "id.resp_h": "212.129.49.59", "id.resp_p": 9001,
           "proto": proto, "service": "ssl" if proto == "tcp" and state == "S1" else "-",
           "duration": 10, "conn_state": state, "history": history,
           "orig_pkts": 357, "resp_pkts": 756, "orig_bytes": 207599, "resp_bytes": 902535}
    flow, error = ZeekJSON(factory.logger).process_line({"type": "conn.log", "interface": "default", "data": raw})
    assert error == ""
    flow.interpreted_state = ScanDetectionsHandler.get_final_state_from_flags(conn.db, flow.state, flow.pkts)
    conn.db.is_a_port_scanner.return_value = True
    conn.db.get_port_info.return_value = known_service
    conn.db.is_ftp_port.return_value = False
    conn.db.is_p2p_related_flow.return_value = False
    conn.port_belongs_to_an_org = Mock(return_value=False)
    conn.is_local_apple_peer_flow = Mock(return_value=False)
    conn.is_broadcast_or_multicast_flow = Mock(return_value=False)
    conn.set_evidence = SetEvidenceHelper(conn.db)

    assert conn.check_unknown_port(f"profile_{flow.saddr}", "timewindow1", flow) is expected
    assert conn.db.set_evidence.call_count == int(expected)
    if expected:
        evidence = conn.db.set_evidence.call_args.args[0]
        assert evidence.evidence_type == EvidenceType.UNKNOWN_PORT
        assert evidence.threat_level == ThreatLevel.HIGH
        assert evidence.profile.ip == "192.168.1.120"
        assert evidence.attacker.value == "192.168.1.120"
        assert evidence.victim.value == "212.129.49.59"
        assert str(evidence.dst_port) == "9001"
        assert evidence.uid == [flow.uid]
