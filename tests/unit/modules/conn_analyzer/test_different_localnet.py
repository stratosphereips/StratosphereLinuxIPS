# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Regression tests for one subnet finding per connection."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from slips_files.core.input_profilers.zeek import ZeekJSON
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.core.structures.evidence import EvidenceType, ThreatLevel
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "saddr, daddr, subnet, level, outside",
    [
        (
            "10.0.2.2",
            "10.0.2.15",
            "192.168.0.0/16",
            ThreatLevel.LOW,
            "both private addresses are",
        ),
        (
            "10.0.2.2",
            "192.168.1.5",
            "192.168.0.0/16",
            ThreatLevel.LOW,
            "source address is",
        ),
        (
            "192.168.1.5",
            "10.0.2.2",
            "192.168.0.0/16",
            ThreatLevel.HIGH,
            "destination address is",
        ),
        (
            "fd00:2::2",
            "fd00:2::15",
            "fd00:1::/64",
            ThreatLevel.LOW,
            "both private addresses are",
        ),
        (
            "fd00:1::5",
            "fd00:2::2",
            "fd00:1::/64",
            ThreatLevel.HIGH,
            "destination address is",
        ),
    ],
)
@pytest.mark.parametrize(
    "proto, dport", [("tcp", 80), ("udp", 53), ("icmp", 0)]
)
def test_one_finding_across_connection_and_dns_analyzers(
    saddr: str,
    daddr: str,
    subnet: str,
    level: ThreatLevel,
    outside: str,
    proto: str,
    dport: int,
) -> None:
    """Keep one severity and original flow identity across both analyzers.

    Parameters:
        saddr: Source address.
        daddr: Destination address.
        subnet: Monitored local subnet.
        level: Expected severity.
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

    conn.db.set_evidence.assert_called_once()
    evidence = conn.db.set_evidence.call_args.args[0]
    assert evidence.evidence_type == EvidenceType.DIFFERENT_LOCALNET
    assert evidence.threat_level == level
    assert evidence.uid == [flow.uid]
    assert evidence.profile.ip == saddr
    assert evidence.attacker.value == saddr
    assert evidence.victim.value == daddr
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


async def test_recorded_icmp_flow_produces_one_finding_in_main() -> None:
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

    conn.db.set_evidence.assert_called_once()
    evidence = conn.db.set_evidence.call_args.args[0]
    assert evidence.uid == ["C6VlUE4fyYvUJHu3ei"]
    assert evidence.threat_level == ThreatLevel.LOW
    assert "both private addresses are outside" in evidence.description


def test_recorded_connections_store_two_findings_instead_of_three(
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
            "SELECT f.uid,e.threat_level,e.description FROM evidence e "
            "JOIN evidence_flows f ON e.evidence_id=f.evidence_id "
            "WHERE e.evidence_type='DIFFERENT_LOCALNET' ORDER BY f.uid"
        ).fetchall()
        assert len(rows) == 2
        assert [(row[0], row[1]) for row in rows] == [
            ("C6VlUE4fyYvUJHu3ei", "low"),
            ("C6ce9q3xECAsonga21", "high"),
        ]
        assert "both private addresses are outside" in rows[0][2]
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

    module.db.set_evidence.assert_called_once()
    evidence = module.db.set_evidence.call_args.args[0]
    assert "192.168.0.0/16" in evidence.description
    assert "10.0.2.0/24" not in evidence.description
    assert evidence.threat_level == ThreatLevel.LOW
    module.db.get_local_network.assert_not_called()
