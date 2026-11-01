"""Replay HTTP exchanges through Zeek without letting Slips read body bytes."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from slips_files.core.input_profilers.zeek import ZeekJSON
from slips_files.core.structures.evidence import EvidenceType
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("interim", [False, True])
def test_http_transaction_header_metadata(interim: bool) -> None:
    """Keep final, top-level headers and MIME signatures separate on keep-alive.

    :param interim: Whether the first transaction includes a 100 Continue reply.
    """
    analyzer = ModuleFactory().create_http_analyzer_obj()
    zeek = shutil.which("zeek")
    if not zeek:
        pytest.skip("Zeek is not installed")
    scapy = pytest.importorskip("scapy.all")
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    )
    payloads = [
        (
            True,
            b"POST /first HTTP/1.1\r\nHost: 195.219.57.34:8080\r\nContent-Length: "
            + str(len(png)).encode()
            + b"\r\n\r\n"
            + png,
        ),
    ]
    if interim:
        payloads.append(
            (
                False,
                b"HTTP/1.1 100 Continue\r\nContent-Type: text/plain\r\n\r\n",
            )
        )
    payloads.extend(
        [
            (
                False,
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "
                + str(len(png)).encode()
                + b"\r\n\r\n"
                + png,
            ),
            (
                True,
                b"POST /second HTTP/1.1\r\nHost: example.test\r\nContent-Type: image/png\r\nContent-Length: "
                + str(len(png)).encode()
                + b"\r\n\r\n"
                + png,
            ),
            (
                False,
                b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: "
                + str(len(png)).encode()
                + b"\r\n\r\n"
                + png,
            ),
            (True, b"GET /third HTTP/1.1\r\nHost: example.test\r\n\r\n"),
            (
                False,
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
            ),
        ]
    )
    # Include a multipart upload: its inner Content-Type must not replace the outer header.
    multipart = (
        b"--boundary\r\nContent-Type: image/png\r\nContent-Disposition: form-data; name=file\r\n\r\n"
        + png
        + b"\r\n--boundary--\r\n"
    )
    payloads.extend(
        [
            (
                True,
                b"POST /multipart HTTP/1.1\r\nHost: example.test\r\nContent-Type: multipart/form-data; boundary=boundary\r\nContent-Length: "
                + str(len(multipart)).encode()
                + b"\r\n\r\n"
                + multipart,
            ),
            (
                False,
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK",
            ),
        ]
    )
    client, server = "10.0.2.102", "195.219.57.34"
    packets = [
        scapy.IP(src=client, dst=server)
        / scapy.TCP(sport=49167, dport=8080, flags="S", seq=100),
        scapy.IP(src=server, dst=client)
        / scapy.TCP(sport=8080, dport=49167, flags="SA", seq=200, ack=101),
        scapy.IP(src=client, dst=server)
        / scapy.TCP(sport=49167, dport=8080, flags="A", seq=101, ack=201),
    ]
    client_seq, server_seq = 101, 201
    for outgoing, data in payloads:
        packets.append(
            scapy.IP(
                src=client if outgoing else server,
                dst=server if outgoing else client,
            )
            / scapy.TCP(
                sport=49167 if outgoing else 8080,
                dport=8080 if outgoing else 49167,
                flags="PA",
                seq=client_seq if outgoing else server_seq,
                ack=server_seq if outgoing else client_seq,
            )
            / data
        )
        if outgoing:
            client_seq += len(data)
        else:
            server_seq += len(data)
    packets.append(
        scapy.IP(src=client, dst=server)
        / scapy.TCP(
            sport=49167, dport=8080, flags="FA", seq=client_seq, ack=server_seq
        )
    )
    for index, packet in enumerate(packets):
        packet.time = 1635765895 + index * 0.1
    with tempfile.TemporaryDirectory(
        dir="output", prefix="http-headers-"
    ) as directory:
        root = Path(directory)
        scapy.wrpcap(str(root / "input.pcap"), packets)
        result = subprocess.run(
            [
                zeek,
                "-C",
                "-r",
                str(root / "input.pcap"),
                "zeek-scripts/http-content-metadata.zeek",
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
            for line in (root / "http.log").read_text().splitlines()
        ]
    assert len(rows) == 4
    assert len({row["uid"] for row in rows}) == 1
    assert [row["trans_depth"] for row in rows] == [1, 2, 3, 4]
    assert rows[0]["slips_request_content_type"] == ""
    assert rows[0]["slips_response_content_type"] == "text/html; charset=utf-8"
    assert rows[0]["orig_mime_types"] == ["image/png"]
    assert rows[0]["resp_mime_types"] == ["image/png"]
    assert rows[1]["slips_request_content_type"] == "image/png"
    assert rows[1]["slips_response_content_type"] == "image/png"
    assert rows[2]["slips_response_content_encoding"] == "gzip"
    assert (
        rows[3]["slips_request_content_type"]
        == "multipart/form-data; boundary=boundary"
    )
    parser = ZeekJSON(analyzer.db)
    for row in rows:
        flow, error = parser.process_line(
            {"type": "http.log", "interface": "test", "data": row}
        )
        assert not error
        analyzer.check_http_header_anomalies("timewindow1", flow)
    records = [
        call.args[0] for call in analyzer.db.set_evidence.call_args_list
    ]
    assert [record.evidence_type for record in records] == [
        EvidenceType.HTTP_IP_HOST,
        EvidenceType.HTTP_BINARY_POST_WITHOUT_CONTENT_TYPE,
        EvidenceType.HTTP_BINARY_RESPONSE_AS_HTML,
    ]
    assert all(
        record.detection_details["http_transaction"] == 1 for record in records
    )
