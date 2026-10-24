# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Regression tests for separate source and destination subnet findings."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from modules.web_interface.server import RunDataReader
from modules.supported_module_names import Modules
from slips_files.core.database.database_manager import DBManager
from slips_files.core.input_profilers.zeek import ZeekJSON
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.core.structures.evidence import (
    Direction,
    EvidenceType,
    ThreatLevel,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "saddr, daddr, subnet, outside",
    [
        (
            "10.0.2.2",
            "10.0.2.15",
            "192.168.0.0/16",
            "both private addresses are",
        ),
        (
            "10.0.2.2",
            "192.168.1.5",
            "192.168.0.0/16",
            "source address is",
        ),
        (
            "192.168.1.5",
            "10.0.2.2",
            "192.168.0.0/16",
            "destination address is",
        ),
        (
            "fd00:2::2",
            "fd00:2::15",
            "fd00:1::/64",
            "both private addresses are",
        ),
        (
            "fd00:1::5",
            "fd00:2::2",
            "fd00:1::/64",
            "destination address is",
        ),
    ],
)
@pytest.mark.parametrize(
    "proto, dport", [("tcp", 80), ("udp", 53), ("icmp", 0)]
)
def test_one_finding_per_host_across_connection_and_dns_analyzers(
    saddr: str,
    daddr: str,
    subnet: str,
    outside: str,
    proto: str,
    dport: int,
) -> None:
    """Keep source-high and destination-low findings on separate profiles.

    Parameters:
        saddr: Source address.
        daddr: Destination address.
        subnet: Monitored local subnet.
        outside: Expected explanation of the affected addresses.
        proto: Transport protocol.
        dport: Destination port or ICMP code.
    """
    module_factory = ModuleFactory()
    conn = module_factory.create_conn_analyzer_obj()
    dns = module_factory.create_dns_analyzer_obj()
    dns.db = conn.db
    dns.set_evidence.db = conn.db
    conn.db.get_network_state.return_value = None
    conn.db.get_local_network.return_value = subnet
    conn.db.is_official_dns_server.return_value = False
    flow = SimpleNamespace(
        saddr=saddr,
        daddr=daddr,
        proto=proto,
        sport=11,
        dport=dport,
        interface="default",
        starttime=147.026993,
        uid="C6VlUE4fyYvUJHu3ei",
    )

    conn.check_different_localnet_usage("timewindow1", flow)
    dns.check_different_localnet_usage("timewindow1", flow)

    findings = [call.args[0] for call in conn.db.set_evidence.call_args_list]
    assert len(findings) == 2
    assert {item.profile.ip for item in findings} == {saddr, daddr}
    source, destination = findings
    assert source.threat_level == ThreatLevel.HIGH
    assert source.profile.ip == source.attacker.value == saddr
    assert source.attacker.direction == Direction.SRC
    assert source.victim.value == daddr
    assert source.victim.direction == Direction.DST
    assert destination.threat_level == ThreatLevel.LOW
    assert destination.profile.ip == destination.attacker.value == daddr
    assert destination.attacker.direction == Direction.DST
    assert destination.victim.value == saddr
    assert destination.victim.direction == Direction.SRC
    assert source.rel_id == [destination.id]
    assert destination.rel_id == [source.id]
    assert source.description.startswith(
        f"{saddr} initiated a connection to {daddr}"
    )
    assert destination.description.startswith(
        f"{daddr} received a connection from {saddr}"
    )
    for evidence in findings:
        assert evidence.evidence_type == EvidenceType.DIFFERENT_LOCALNET
        assert evidence.uid == [flow.uid]
        assert outside in evidence.description
        assert subnet in evidence.description
        if proto == "icmp":
            assert "ICMP type: 11; code: 0" in evidence.description
            assert "port" not in evidence.description.lower()
        else:
            assert (
                f"Destination port: {dport}/{proto.upper()}"
                in evidence.description
            )


async def test_recorded_icmp_flow_produces_one_finding_per_host_in_main() -> (
    None
):
    """Replay the reported dataset flow through the connection message handler."""
    module_factory = ModuleFactory()
    conn = module_factory.create_conn_analyzer_obj()
    conn.db.get_network_state.return_value = None
    conn.db.get_local_network.return_value = "192.168.0.0/16"
    conn.db.is_official_dns_server.return_value = False
    record = json.loads(
        Path("dataset/test13-malicious-dhcpscan-zeek-dir/conn.log")
        .read_text()
        .splitlines()[0]
    )
    flow, error = ZeekJSON(module_factory.logger).process_line(
        {
            "type": "conn.log",
            "interface": "default",
            "data": record,
        }
    )
    assert not error
    conn.classifier.convert_to_flow_obj = Mock(return_value=flow)
    conn.get_msg = Mock(
        side_effect=lambda channel: (
            {
                "data": json.dumps(
                    {
                        "profileid": "profile_10.0.2.2",
                        "twid": "timewindow1",
                        "flow": {},
                    }
                )
            }
            if channel == "new_flow"
            else None
        )
    )
    for method in (
        "check_long_connection",
        "check_unknown_port",
        "check_multiple_reconnection_attempts",
        "check_multiple_telnet_reconnection_attempts",
        "check_conn_to_port_0",
        "detect_connection_to_multiple_ports",
        "check_data_upload",
        "check_tor_exit_node",
        "check_connection_to_local_ip",
        "check_device_changing_ips",
        "remove_old_entries_from_ssl_recognized_flows",
        "create_task",
    ):
        setattr(conn, method, Mock())

    await conn.main()

    findings = [call.args[0] for call in conn.db.set_evidence.call_args_list]
    assert len(findings) == 2
    assert [(item.profile.ip, item.threat_level) for item in findings] == [
        ("10.0.2.2", ThreatLevel.HIGH),
        ("10.0.2.15", ThreatLevel.LOW),
    ]
    for evidence in findings:
        assert evidence.uid == ["C6VlUE4fyYvUJHu3ei"]
        assert "both private addresses are outside" in evidence.description


def test_recorded_connections_store_one_severity_per_host_and_flow(
    tmp_path: Path,
) -> None:
    """Replay both dataset connections into an isolated evidence database.

    Parameters:
        tmp_path: Temporary output directory for the regression database.
    """
    module_factory = ModuleFactory()
    conn = module_factory.create_conn_analyzer_obj()
    dns = module_factory.create_dns_analyzer_obj()
    dns.db = conn.db
    dns.set_evidence.db = conn.db
    conn.db.get_network_state.return_value = None
    conn.db.get_local_network.return_value = "192.168.0.0/16"
    conn.db.is_official_dns_server.return_value = False
    database = SQLiteDB(module_factory.logger, str(tmp_path), os.getpid())
    conn.db.set_evidence.side_effect = database.add_evidence
    parser = ZeekJSON(module_factory.logger)
    try:
        for line in (
            Path("dataset/test13-malicious-dhcpscan-zeek-dir/conn.log")
            .read_text()
            .splitlines()
        ):
            flow, error = parser.process_line(
                {
                    "type": "conn.log",
                    "interface": "default",
                    "data": json.loads(line),
                }
            )
            assert not error
            conn.check_different_localnet_usage("timewindow1", flow)
            dns.check_different_localnet_usage("timewindow1", flow)

        rows = database.conn.execute(
            "SELECT f.uid,e.profile_ip,e.threat_level,e.data FROM evidence e "
            "JOIN evidence_flows f ON e.evidence_id=f.evidence_id "
            "WHERE e.evidence_type='DIFFERENT_LOCALNET' ORDER BY f.uid,e.profile_ip"
        ).fetchall()
        assert len(rows) == 4
        assert {row[:3] for row in rows} == {
            ("C6VlUE4fyYvUJHu3ei", "10.0.2.2", "high"),
            ("C6VlUE4fyYvUJHu3ei", "10.0.2.15", "low"),
            ("C6ce9q3xECAsonga21", "192.168.1.5", "high"),
            ("C6ce9q3xECAsonga21", "10.0.2.2", "low"),
        }
        assert len({row[:2] for row in rows}) == len(rows)
        for uid, host, level, raw in rows:
            evidence = json.loads(raw)
            assert (
                evidence["profile"]["ip"]
                == evidence["attacker"]["value"]
                == host
            )
            assert evidence["attacker"]["direction"] == (
                "SRC" if level == "high" else "DST"
            )
            assert evidence["uid"] == [uid]

        client = Mock()
        client.hgetall.return_value = {}
        client.hget.return_value = None
        client.get.return_value = None
        client.smembers.return_value = set()
        client.zrange.return_value = []
        with patch(
            "modules.web_interface.server.try_connect_with_and_without_password",
            return_value=client,
        ):
            reader = RunDataReader(
                6379, str(tmp_path), str(tmp_path / "hosts.sqlite")
            )
        for host, level, direction in (
            ("10.0.2.2", "high", "SRC"),
            ("10.0.2.15", "low", "DST"),
        ):
            page = reader.evidence(
                {
                    "profile": [host],
                    "range": ["all"],
                    "type": ["DIFFERENT_LOCALNET"],
                    "search": ["C6VlUE4fyYvUJHu3ei"],
                }
            )
            assert page["total"] == 1
            item = page["items"][0]
            assert item["profile_ip"] == host
            assert item["threat_level"] == level
            assert item["attacker"]["direction"] == direction
    finally:
        database.close()


@pytest.mark.parametrize("analyzer", ["conn", "dns"])
def test_delayed_flow_description_uses_the_original_subnet(
    analyzer: str,
) -> None:
    """Use the same historical subnet for both checking and explanation.

    Parameters:
        analyzer: Connection or DNS analyzer under test.
    """
    module_factory = ModuleFactory()
    module = (
        module_factory.create_conn_analyzer_obj()
        if analyzer == "conn"
        else module_factory.create_dns_analyzer_obj()
    )
    module.db.get_network_state.return_value = {
        "changed_at": 200,
        "local_network": "10.0.2.0/24",
        "dns_servers": [],
        "history": [
            {
                "changed_at": 100,
                "local_network": "192.168.0.0/16",
                "dns_servers": [],
            }
        ],
    }
    module.db.get_local_network.return_value = "10.0.2.0/24"
    module.db.is_official_dns_server.return_value = False
    flow = SimpleNamespace(
        saddr="10.0.2.2",
        daddr="10.0.2.15",
        proto="udp",
        sport=53000,
        dport=53 if analyzer == "dns" else 80,
        interface="eth0",
        starttime=150,
        uid="delayed-flow",
    )

    module.check_different_localnet_usage("timewindow1", flow)

    findings = [call.args[0] for call in module.db.set_evidence.call_args_list]
    assert len(findings) == 2
    for evidence in findings:
        assert "192.168.0.0/16" in evidence.description
        assert "10.0.2.0/24" not in evidence.description
    assert [item.threat_level for item in findings] == [
        ThreatLevel.HIGH,
        ThreatLevel.LOW,
    ]
    module.db.get_local_network.assert_not_called()


@pytest.mark.parametrize(
    "saddr, daddr",
    [
        ("10.0.2.2", "10.0.2.2"),
        ("fd00:2::a", "FD00:2:0:0:0:0:0:A"),
    ],
)
@pytest.mark.parametrize("proto, dport", [("tcp", 80), ("udp", 53)])
def test_same_host_cannot_receive_both_roles(
    saddr: str,
    daddr: str,
    proto: str,
    dport: int,
) -> None:
    """Ignore self-connections, including equivalent spellings of IPv6.

    Parameters:
        saddr: Source IP spelling.
        daddr: Equivalent destination IP spelling.
        proto: Transport protocol.
        dport: Destination port.
    """
    module_factory = ModuleFactory()
    conn = module_factory.create_conn_analyzer_obj()
    dns = module_factory.create_dns_analyzer_obj()
    dns.db = conn.db
    dns.set_evidence.db = conn.db
    conn.db.get_network_state.return_value = None
    conn.db.get_local_network.return_value = (
        "fd00:1::/64" if ":" in saddr else "192.168.0.0/16"
    )
    conn.db.is_official_dns_server.return_value = False
    flow = SimpleNamespace(
        saddr=saddr,
        daddr=daddr,
        proto=proto,
        sport=40000,
        dport=dport,
        interface="default",
        starttime=147.026993,
        uid="self-connection",
    )

    conn.check_different_localnet_usage("timewindow1", flow)
    dns.check_different_localnet_usage("timewindow1", flow)

    conn.db.set_evidence.assert_not_called()


def test_host_threat_updates_follow_the_source_and_destination_profiles() -> (
    None
):
    """Update each host once with its own severity through the real facade."""
    factory = ModuleFactory()
    helper = factory.create_conn_analyzer_set_evidence_helper()
    helper.different_localnet_usage(
        "timewindow1",
        SimpleNamespace(
            saddr="10.0.2.2",
            daddr="10.0.2.15",
            proto="tcp",
            sport=40000,
            dport=80,
            interface="default",
            starttime=147.026993,
            uid="scored-subnet-flow",
        ),
        "both",
        "192.168.0.0/16",
    )
    manager = SimpleNamespace(
        rdb=Mock(),
        sqlite=Mock(),
        conf=Mock(),
        trust_db=None,
        output_dir="output/unit-subnet-roles",
        source_module=Modules.CONN_ANALYZER.value,
        _get_evidence_interface=Mock(return_value="default"),
        update_threat_level=Mock(),
    )
    manager.conf.disabled_detections.return_value = []
    manager.sqlite.is_evidence_whitelisted.return_value = False
    manager.rdb.set_evidence.return_value = True

    for call in helper.db.set_evidence.call_args_list:
        assert DBManager.set_evidence(manager, call.args[0]) is True

    assert [
        call.args for call in manager.update_threat_level.call_args_list
    ] == [
        ("profile_10.0.2.2", "high", 1.0),
        ("profile_10.0.2.15", "low", 1.0),
    ]
    stored = [
        call.args[0] for call in manager.sqlite.add_evidence.call_args_list
    ]
    assert [item.profile.ip for item in stored] == ["10.0.2.2", "10.0.2.15"]
