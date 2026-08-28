# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import patch

import pytest
from slips_files.core.structures.evidence import (
    ThreatLevel,
    EvidenceType,
    Direction,
)
from slips_files.core.flows.zeek import Conn
from tests.module_factory import ModuleFactory


def test_device_changing_ips():
    """Testing the device_changing_ips method."""
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.0.1",
        daddr="10.0.0.60",
        dur=1,
        proto="tcp",
        appproto="",
        sport="0",
        dport="5",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )
    set_ev.device_changing_ips("timewindow4", flow, "10.0.0.1")

    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.DEVICE_CHANGING_IP
    assert evidence.attacker.value == flow.saddr
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.profile.ip == flow.saddr
    assert evidence.timewindow.number == 4
    assert evidence.uid == [flow.uid]


def test_non_ssl_port_443_conn():
    """Testing the non_ssl_port_443_conn method."""
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.0.1",
        daddr="192.168.0.60",
        dur=1,
        proto="tcp",
        appproto="",
        sport="0",
        dport="5",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )
    set_ev.non_ssl_port_443_conn(
        "timewindow6",
        flow,
    )

    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.NON_SSL_PORT_443_CONNECTION
    assert evidence.attacker.value == flow.saddr
    assert evidence.victim.value == flow.daddr
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.profile.ip == flow.saddr
    assert evidence.timewindow.number == 6
    assert evidence.uid == [flow.uid]


@pytest.mark.parametrize(
    "time_difference_hours, expected_confidence",
    [  # Testcase1:Within the 5 hours
        (4, 0.1),
        # Testcase2:Outside the 5-hour window
        (6, 0.8),
    ],
)
def test_conn_without_dns(time_difference_hours, expected_confidence):
    """Testing the conn_without_dns method, including time-based confidence
    adjustment."""
    flow = Conn(
        starttime="1726655400.0",
        uid="123",
        saddr="192.168.0.1",
        daddr="10.0.0.1",
        dur=1,
        proto="tcp",
        appproto="",
        sport="0",
        dport=50,
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    set_ev.db.is_running_non_stop.return_value = True
    with patch(
        "slips_files.common.slips_utils.utils.get_time_diff",
        return_value=time_difference_hours,
    ):
        set_ev.conn_without_dns("timewindow1", flow)
    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert evidence.confidence == expected_confidence
    assert (
        evidence.description
        == "A connection without DNS resolution to Destination IP: 10.0.0.1"
    )


def test_tor_exit_node():
    """Testing the tor_exit_node method."""
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    flow = Conn(
        starttime="1726655400.0",
        uid="123",
        saddr="192.168.0.1",
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

    set_ev.tor_exit_node("timewindow1", flow)
    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.TOR_EXIT_NODE
    assert evidence.attacker.direction == Direction.DST
    assert evidence.attacker.value == flow.daddr
    assert evidence.victim.direction == Direction.SRC
    assert evidence.victim.value == flow.saddr
    assert evidence.threat_level == ThreatLevel.INFO
    assert (
        evidence.description == "A connection to TOR exit node 185.220.101.1."
    )
    assert evidence.profile.ip == flow.saddr
    assert evidence.timewindow.number == 1
    assert evidence.uid == [flow.uid]
    assert evidence.confidence == 1.0


@pytest.mark.parametrize(
    "state, daddr, dport, proto, expected_threat_level, expected_description",
    [
        # Testcase 1: Standard TCP connection to an unknown port
        (
            "Established",
            "10.0.0.1",
            12345,
            "tcp",
            ThreatLevel.HIGH,
            "Connection to unknown destination port 12345/TCP "
            "destination IP 10.0.0.1.",
        ),
        # Testcase 2: UDP connection to an unknown port
        (
            "Established",
            "192.168.1.100",
            56789,
            "udp",
            ThreatLevel.HIGH,
            "Connection to unknown destination port 56789/UDP "
            "destination IP 192.168.1.100.",
        ),
        # Testcase 3:  Edge case with port 0
        (
            "not Established",
            "10.0.0.1",
            0,
            "tcp",
            ThreatLevel.MEDIUM,
            "Connection to unknown destination port 0/TCP "
            "destination IP 10.0.0.1.",
        ),
    ],
)
def test_unknown_port(
    state, daddr, dport, proto, expected_threat_level, expected_description
):
    """Testing the unknown_port method."""
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    set_ev.db.get_ip_identification.return_value = ""
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.0.1",
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
        state=state,
        history="",
    )
    flow.interpreted_state = flow.state
    set_ev.unknown_port("timewindow1", flow)
    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.UNKNOWN_PORT
    assert evidence.attacker.value == flow.saddr
    assert evidence.victim.value == daddr
    assert evidence.threat_level == expected_threat_level
    assert evidence.profile.ip == flow.saddr
    assert evidence.timewindow.number == 1
    assert evidence.uid == [flow.uid]
    assert evidence.description == expected_description


@pytest.mark.parametrize(
    "proto, daddr, dport, expected_description",
    [
        # Testcase 1: TCP connection to a private IP with a specific port
        (
            "tcp",
            "192.168.1.100",
            80,
            "Connecting to private IP: 192.168.1.100 on destination port: 80",
        ),
        # Testcase 2: UDP connection to a private IP with a specific port
        (
            "udp",
            "192.168.1.101",
            53,
            "Connecting to private IP: 192.168.1.101 on destination port: 53",
        ),
        # Testcase 3: ARP connection to a private IP
        (
            "arp",
            "192.168.1.103",
            "",
            "Connecting to private IP: 192.168.1.103 ",
        ),
    ],
)
def test_conn_to_private_ip(proto, daddr, dport, expected_description):
    """Testing the conn_to_private_ip method."""
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.0.1",
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
    set_ev.conn_to_private_ip("timewindow1", flow)
    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.CONNECTION_TO_PRIVATE_IP
    assert evidence.attacker.value == flow.saddr
    assert evidence.victim.value == daddr
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.profile.ip == flow.saddr
    assert evidence.timewindow.number == 1
    assert evidence.uid == [flow.uid]
    assert evidence.description == expected_description


def test_long_connection():
    """Testing the long_connection method."""
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.0.1",
        daddr="10.0.0.1",
        dur=7200,
        proto="tcp",
        appproto="",
        sport="0",
        dport="50",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )
    set_ev.long_connection("timewindow8", flow)
    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.LONG_CONNECTION
    assert evidence.attacker.value == flow.saddr
    assert evidence.victim.value == "10.0.0.1"
    assert evidence.threat_level == ThreatLevel.LOW
    assert evidence.confidence == 0.08
    assert evidence.profile.ip == flow.saddr
    assert evidence.timewindow.number == 8
    assert evidence.uid == [flow.uid]


def test_multiple_reconnection_attempts():
    """Testing the multiple_reconnection_attempts method."""
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.0.1",
        daddr="1.1.1.1",
        dur=1,
        proto="tcp",
        appproto="",
        sport="0",
        dport="60",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )
    set_ev.multiple_reconnection_attempts(
        "timewindow2",
        flow,
        reconnections=10,
        uids=["unique_id1", "unique_id2"],
    )

    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert (
        evidence.evidence_type == EvidenceType.MULTIPLE_RECONNECTION_ATTEMPTS
    )
    assert evidence.attacker.value == flow.saddr
    assert evidence.victim.value == flow.daddr
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert evidence.confidence == 0.5
    assert evidence.profile.ip == flow.saddr
    assert evidence.timewindow.number == 2
    assert sorted(evidence.uid) == sorted(["unique_id1", "unique_id2"])


@pytest.mark.parametrize(
    "profileid, attacker, "
    "victim, expected_attacker_direction, "
    "expected_victim_direction",
    [
        # Test case 1: profile_ip is attacker
        (
            "profile_192.168.0.1",
            "192.168.0.1",
            "192.168.0.2",
            Direction.SRC,
            Direction.DST,
        ),
        # Test case 2: profile_ip is victim
        (
            "profile_192.168.0.1",
            "192.168.0.2",
            "192.168.0.1",
            Direction.DST,
            Direction.SRC,
        ),
    ],
)
def test_connection_to_multiple_ports(
    profileid,
    attacker,
    victim,
    expected_attacker_direction,
    expected_victim_direction,
):
    """Testing the connection_to_multiple_ports method with parametrization.
    This test verifies the correct direction and profile_ip based on the
    input parameters.
    """
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr=attacker,
        daddr=victim,
        dur=1,
        proto="tcp",
        appproto="",
        sport="0",
        dport="80",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )
    set_ev.connection_to_multiple_ports(
        profileid=profileid,
        twid="timewindow3",
        flow=flow,
        victim=victim,
        attacker=attacker,
        dstports=[80, 8080, 8000],
        uids=["123"],
    )

    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.CONNECTION_TO_MULTIPLE_PORTS
    assert evidence.attacker.direction == expected_attacker_direction
    assert evidence.victim.direction == expected_victim_direction
    assert evidence.profile.ip == profileid.split("_")[-1]
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.confidence == 0.5
    assert evidence.timewindow.number == 3
    assert evidence.uid == [flow.uid]


@pytest.mark.parametrize(
    "profileid, attacker, victim, "
    "profile_ip, attacker_direction, victim_direction",
    [
        (  # Test case 1: profile_id is attacker
            "profile_192.168.0.1",
            "192.168.0.1",
            "10.0.0.1",
            "192.168.0.1",
            Direction.SRC,
            Direction.DST,
        ),
        (  # Test case 2: profile_id is victim
            "profile_10.0.0.1",
            "192.168.0.1",
            "10.0.0.1",
            "10.0.0.1",
            Direction.DST,
            Direction.SRC,
        ),
    ],
)
def test_for_port_0_connection(
    profileid,
    attacker,
    victim,
    profile_ip,
    attacker_direction,
    victim_direction,
):
    """Testing the for_port_0_connection method."""
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.0.1",
        daddr="1.1.1.1",
        dur=1,
        proto="tcp",
        appproto="",
        sport="12345",
        dport="0",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )
    set_ev.port_0_connection(
        profileid=profileid,
        twid="timewindow6",
        flow=flow,
        victim=victim,
        attacker=attacker,
    )

    assert set_ev.db.set_evidence.call_count == 1
    args, _ = set_ev.db.set_evidence.call_args
    evidence = args[0]
    assert evidence.evidence_type == EvidenceType.PORT_0_CONNECTION
    assert evidence.attacker.value == attacker
    assert evidence.victim.value == victim
    assert evidence.threat_level == ThreatLevel.HIGH
    assert evidence.confidence == 0.8
    assert evidence.profile.ip == profile_ip
    assert evidence.timewindow.number == 6
    assert evidence.uid == [flow.uid]
    assert evidence.attacker.direction == attacker_direction
    assert evidence.victim.direction == victim_direction


@pytest.mark.parametrize(
    "attacker_ip, threat_level, profile_ip",
    [
        # Testcase 1: Source IP as attacker
        ("192.168.0.1", ThreatLevel.INFO, "192.168.0.1"),
        # Testcase 2: Destination IP as attacker
        ("10.0.0.1", ThreatLevel.HIGH, "10.0.0.1"),
    ],
)
def test_data_exfiltration(attacker_ip, threat_level, profile_ip):
    """Testing the data_exfiltration method."""
    set_ev = ModuleFactory().create_conn_analyzer_set_evidence_helper()
    flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.0.1",
        daddr="10.0.0.1",
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
        state="Established",
        history="",
    )
    set_ev.data_exfiltration(
        daddr=flow.daddr,
        src_mbs=100.0,
        profileid="profile_192.168.0.1",
        twid="timewindow11",
        uids=["123"],
        timestamp=flow.starttime,
    )

    assert set_ev.db.set_evidence.call_count == 2

    call_args_1, _ = set_ev.db.set_evidence.call_args_list[0]
    evidence_1 = call_args_1[0]
    assert evidence_1.attacker.value == "192.168.0.1"
    assert evidence_1.threat_level == ThreatLevel.INFO
    assert evidence_1.profile.ip == "192.168.0.1"
    call_args_2, _ = set_ev.db.set_evidence.call_args_list[1]
    evidence_2 = call_args_2[0]
    assert evidence_2.attacker.value == "10.0.0.1"
    assert evidence_2.threat_level == ThreatLevel.HIGH
    assert evidence_2.profile.ip == "10.0.0.1"
