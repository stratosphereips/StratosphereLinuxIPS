"""Check duration detection against actual Zeek ICMP and UDP records."""

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from slips_files.core.input_profilers.zeek import ZeekJSON
from tests.module_factory import ModuleFactory


def test_zeek_icmp_aggregation_does_not_trigger_long_connection(tmp_path: Path) -> None:
    """Replay long ICMP and neighbour-discovery exchanges beside a long UDP flow.

    Parameters:
        tmp_path: Isolated capture and Zeek logs.
    """
    factory = ModuleFactory()
    conn = factory.create_conn_analyzer_obj()
    zeek = shutil.which("zeek") or shutil.which("bro")
    if not zeek:
        pytest.skip("Zeek is required")
    scapy = pytest.importorskip("scapy.all")
    source, destination = "fe80::cb3:f31f:f5d6:209a", "fe80::44f:cfe7:e270:b19d"
    outgoing = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    incoming = scapy.Ether(src=outgoing.dst, dst=outgoing.src)
    packets = []
    for sequence, stamp in enumerate([index * 30 for index in range(63)] + [1865.942]):
        exchanges = [
            (outgoing / scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.ICMP(type=8, id=42, seq=sequence),
             incoming / scapy.IP(src="192.0.2.2", dst="192.0.2.1") / scapy.ICMP(type=0, id=42, seq=sequence)),
            (outgoing / scapy.IPv6(src=source, dst=destination, hlim=255) / scapy.ICMPv6ND_NS(tgt=destination),
             incoming / scapy.IPv6(src=destination, dst=source, hlim=255) / scapy.ICMPv6ND_NA(tgt=destination)),
            (outgoing / scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.UDP(sport=45000, dport=45001) / scapy.Raw(b"timing"),
             incoming / scapy.IP(src="192.0.2.2", dst="192.0.2.1") / scapy.UDP(sport=45001, dport=45000) / scapy.Raw(b"reply")),
        ]
        for request, response in exchanges:
            request.time = 1700000000 + stamp
            response.time = request.time + 0.001
            packets.extend((request, response))
    capture = tmp_path / "icmp-duration.pcap"
    scapy.wrpcap(str(capture), packets)
    result = subprocess.run(
        [zeek, "-C", "-r", str(capture), "LogAscii::use_json=T", "-e",
         f"redef Log::default_logdir={json.dumps(str(tmp_path))};"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    records = [json.loads(line) for line in (tmp_path / "conn.log").read_text().splitlines()]
    assert len(records) == 3, records
    conn.long_connection_threshold = 1500
    conn.set_evidence.long_connection = Mock()
    conn.db.get_network_state.return_value = None
    conn.db.get_local_network.return_value = "192.0.2.0/24"
    udp_uid = ""
    for record in records:
        assert record["duration"] > 1865
        flow, error = ZeekJSON(factory.logger).process_line({
            "type": "conn.log", "interface": "en0", "data": record,
        })
        assert not error
        detected = conn.check_long_connection("timewindow1", flow)
        assert detected is (True if record["proto"] == "udp" else None)
        if record["proto"] == "udp":
            udp_uid = flow.uid
    conn.set_evidence.long_connection.assert_called_once()
    assert conn.set_evidence.long_connection.call_args.args[1].uid == udp_uid
