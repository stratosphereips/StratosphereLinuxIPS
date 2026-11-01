"""Exercise the real optional collector using small generated PCAPs."""

import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from tests.module_factory import ModuleFactory


def packet(src: bytes, dst: bytes, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    """Build an Ethernet/IPv4/TCP frame for offline Zeek tests.

    Parameters:
        src: Source IPv4 bytes.
        dst: Destination IPv4 bytes.
        sport: Source TCP port.
        dport: Destination TCP port.
        seq: TCP sequence number.
        ack: TCP acknowledgement number.
        flags: TCP flags byte.
        payload: Synthetic application bytes.

    Returns:
        Frame with zero checksums, read using Zeek's -C switch.
    """
    ethernet = bytes.fromhex("0200000000020200000000010800")
    ip = struct.pack("!BBHHHBBH4s4s",0x45,0,40+len(payload),1,0,64,6,0,src,dst)
    tcp = struct.pack("!HHIIBBHHH",sport,dport,seq,ack,0x50,flags,65535,0,0)
    return ethernet+ip+tcp+payload


def write_capture(path: Path, callbacks: int = 24) -> None:
    """Write data callbacks, duplicate retransmissions and ACK responses.

    Parameters:
        path: Temporary PCAP destination.
        callbacks: Number of advancing data packets.
    """
    src,dst = bytes([10,0,0,1]),bytes([10,0,0,2])
    frames = [(1.0,packet(src,dst,50000,443,100,0,2)),
        (1.01,packet(dst,src,443,50000,200,101,18)),
        (1.02,packet(src,dst,50000,443,101,201,16)),
        (2.0,packet(dst,src,443,50000,201,101,24,b"r"*12))]
    for i in range(callbacks):
        stamp,seq = 10+i*10,101+i*8
        frames.extend([(stamp,packet(src,dst,50000,443,seq,213,24,b"x"*8)),
            (stamp+0.1,packet(dst,src,443,50000,213,seq+8,16)),
            (stamp+0.2,packet(src,dst,50000,443,seq,213,24,b"x"*8))])
    with path.open("wb") as target:
        target.write(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1))
        for stamp,frame in sorted(frames):
            target.write(struct.pack("<IIII",int(stamp),round((stamp-int(stamp))*1000000),len(frame),len(frame)))
            target.write(frame)


@pytest.mark.parametrize("acks", [False, True])
def test_native_packet_windows_exclude_retransmissions_and_keep_bounded_sizes(tmp_path: Path, acks: bool) -> None:
    """Validate real packet times, ring ordering and optional ACK collection.

    Parameters:
        tmp_path: Isolated capture and logs.
        acks: Whether pure ACK windows should be included.
    """
    module = ModuleFactory().create_beaconing_obj(packet_timing={"enabled":True,"include_acks":acks,"min_events":8,"window_events":12,"emit_every":4,"min_connection_age_seconds":0})
    zeek = shutil.which("zeek")
    if not zeek:
        pytest.skip("Zeek is not installed")
    capture = tmp_path / "callbacks.pcap"
    write_capture(capture)
    result = subprocess.run([zeek,"-C","-r",str(capture),"zeek-scripts/packet-timing.zeek","LogAscii::use_json=T","-e",
        module.packet_settings.zeek_overrides()+f' redef Log::default_logdir="{tmp_path}";'],capture_output=True,text=True,timeout=20)
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in (tmp_path/"packet_timing.log").read_text().splitlines()]
    data = [row for row in rows if row["kind"] == "data"]
    assert [row["event_count"] for row in data] == [8,12,16,20,24]
    assert all(len(row["times"]) <= 12 for row in rows)
    assert all(row["times"] == sorted(set(row["times"])) for row in rows)
    assert data[-1]["times"] == [10+i*10 for i in range(12,24)]
    assert all(row["lengths"] == [8]*len(row["times"]) for row in data)
    assert any(row["kind"] == "ack" for row in rows) is acks
    assert all("payload" not in row for row in rows)
