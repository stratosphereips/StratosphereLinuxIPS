"""Replay mDNS packets through Zeek, the Slips parser and permanent identity."""

import json
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from slips_files.core.input_profilers.zeek import ZeekJSON
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "reply,ttl,port,extra",
    [
        (True, 120, 5353, 0),
        (False, 120, 5353, 0),
        (True, 0, 5353, 0),
        (True, 120, 53, 0),
        (True, 120, 5353, 70),
    ],
)
def test_mdns_names_follow_address_record_owners(
    reply: bool, ttl: int, port: int, extra: int
) -> None:
    """A question about Storm must not name the router's unrelated answer records.

    Parameters:
        reply: Whether this is a reply or a query containing known answers.
        ttl: Address record lifetime; zero removes an mDNS record.
        port: Multicast DNS or ordinary DNS transport port.
        extra: Additional address records used to check the memory bound.
    """
    module_factory = ModuleFactory()
    zeek = shutil.which("zeek")
    if not zeek:
        pytest.skip("Zeek is not installed")
    scapy = pytest.importorskip("scapy.all")
    question = scapy.DNSQR(qname="storm.local", qtype="AAAA")
    records = [
        scapy.DNSRR(
            rrname="turris.local", type="A", ttl=ttl, rdata="192.168.1.1"
        ),
        scapy.DNSRR(
            rrname="turris.local",
            type="AAAA",
            ttl=ttl,
            rdata="fd9f:2ebd:5f8::1",
        ),
        scapy.DNSRR(
            rrname="storm.local", type="A", ttl=ttl, rdata="192.168.1.112"
        ),
        scapy.DNSRR(
            rrname="storm.local",
            type="AAAA",
            ttl=ttl,
            rdata="fd9f:2ebd:5f8::112",
        ),
    ]
    records.extend(
        scapy.DNSRR(
            rrname=f"other-{index}.local",
            type="A",
            ttl=ttl,
            rdata=f"192.168.2.{index + 1}",
        )
        for index in range(extra)
    )
    packet = (
        scapy.Ether()
        / scapy.IP(src="192.168.1.1", dst="224.0.0.251")
        / scapy.UDP(sport=port, dport=port)
        / scapy.DNS(
            id=0, qr=int(reply), aa=int(reply), qd=question, an=records
        )
    )
    packet.time = 1792132244.61987
    with tempfile.TemporaryDirectory(
        dir="output", prefix="mdns-identity-"
    ) as directory:
        root = Path(directory)
        scapy.wrpcap(str(root / "input.pcap"), [packet])
        result = subprocess.run(
            [
                zeek,
                "-C",
                "-r",
                str(root / "input.pcap"),
                "zeek-scripts/mdns-identity.zeek",
                "LogAscii::use_json=T",
                "-e",
                f'redef Log::default_logdir = "{root}";',
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        rows = [
            json.loads(line)
            for line in (root / "dns.log").read_text().splitlines()
        ]
        bindings = [
            value
            for row in rows
            for value in row.get("slips_mdns_bindings", [])
        ]
        expected = reply and ttl > 0 and port == 5353
        expected_bindings = (
            {
                "turris.local|192.168.1.1",
                "turris.local|fd9f:2ebd:5f8::1",
                "storm.local|192.168.1.112",
                "storm.local|fd9f:2ebd:5f8::112",
            }
            if expected
            else set()
        )
        if expected:
            expected_bindings.update(
                f"other-{index}.local|192.168.2.{index + 1}"
                for index in range(min(extra, 60))
            )
        assert set(bindings) == expected_bindings
        assert len(bindings) <= 64
        path = root / "hosts.sqlite"
        network = {
            "gateway_mac": "aa:bb:cc:dd:ee:01",
            "local_network": "192.168.1.0/24",
        }
        store = HostProfileStore(path, "old-run", lambda _: network, ["en0"])
        store.observe_flow(
            SimpleNamespace(
                type_="conn",
                interface="en0",
                starttime=100,
                saddr="192.168.1.112",
                daddr="8.8.8.8",
            )
        )
        with sqlite3.connect(path) as connection:
            connection.execute(
                "INSERT INTO facts VALUES (?,?,'mdns_name','storm.local',100,100,1)",
                ("gateway:aa:bb:cc:dd:ee:01", "192.168.1.112"),
            )
        HostProfileStore.set_host_annotation(
            path,
            "192.168.1.112",
            "gateway:aa:bb:cc:dd:ee:01",
            "iPad-Storm",
            "Tablet",
        )
        parser = ZeekJSON(module_factory.logger)
        for row in rows:
            flow, error = parser.process_line(
                {"type": "dns.log", "interface": "en0", "data": row}
            )
            assert not error
            store.observe_flow(flow)
        # A new network must establish ownership before inheriting the old name.
        network = {
            "gateway_mac": "aa:bb:cc:dd:ee:02",
            "local_network": "192.168.1.0/24",
        }
        current = HostProfileStore(path, "new-run", lambda _: network, ["en0"])
        for row in rows:
            flow, error = parser.process_line(
                {"type": "dns.log", "interface": "en0", "data": row}
            )
            assert not error
            current.observe_flow(flow)
        names = HostProfileStore.annotations_for_ips(
            path, ["192.168.1.1", "192.168.1.112", "fd9f:2ebd:5f8::112"]
        )
        assert names["192.168.1.1"] == {"name": "", "note": ""}
        if expected:
            assert names["192.168.1.112"]["name"] == "iPad-Storm"
            assert names["fd9f:2ebd:5f8::112"]["name"] == "iPad-Storm"
