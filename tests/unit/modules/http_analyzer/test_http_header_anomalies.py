"""Independent HTTP header findings use only positively observed Zeek metadata."""

from dataclasses import asdict

import pytest

from slips_files.common.flow_classifier import FlowClassifier
from slips_files.core.flows.zeek import HTTP
from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs
from slips_files.core.structures.evidence import (
    EvidenceType,
    Direction,
    ThreatLevel,
)
from tests.module_factory import ModuleFactory


def http_flow(**changes: object) -> HTTP:
    """Build an HTTP transaction with optional field overrides.

    :param changes: Fields to replace in the transaction.
    :return: A Zeek HTTP flow.
    """
    values = dict(
        starttime=1635765895.037696,
        uid="Cheader1",
        saddr="10.0.2.102",
        daddr="195.219.57.34",
        sport=49167,
        dport=8080,
        trans_depth=1,
        method="POST",
        host="example.test",
        uri="/upload",
        version="1.1",
        user_agent="test",
        request_body_len=197,
        response_body_len=7434,
        status_code="200",
        status_msg="OK",
        resp_mime_types="",
        resp_fuids="",
    )
    values.update(changes)
    return HTTP(**values)


@pytest.mark.parametrize(
    "host,expected",
    [
        ("195.219.57.34:8080", True),
        ("195.219.57.34", True),
        ("[2001:db8::1]:8080", True),
        ("[2001:db8::1]", True),
        ("example.test:8080", False),
        ("195.219.57.34.example.test", False),
        ("", False),
        ("example.test@195.219.57.34", False),
        ("195.219.57.34/path", False),
        ("195.219.57.34:bad", False),
        ("195.219.57.34:99999", False),
        ("999.219.57.34", False),
    ],
)
def test_literal_ip_host(host: str, expected: bool) -> None:
    """Recognize only literal IP authorities, including bracketed IPv6.

    :param host: Host header to check.
    :param expected: Whether informational evidence should be produced.
    """
    analyzer = ModuleFactory().create_http_analyzer_obj()
    analyzer.check_http_header_anomalies("timewindow1", http_flow(host=host))
    assert analyzer.db.set_evidence.call_count == int(expected)
    if expected:
        evidence = analyzer.db.set_evidence.call_args.args[0]
        assert evidence.evidence_type == EvidenceType.HTTP_IP_HOST
        assert evidence.threat_level == ThreatLevel.INFO
        assert evidence.profile.ip == "10.0.2.102"
        assert host in evidence.description


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({}, True),
        ({"request_headers_complete": "T"}, True),
        ({"orig_mime_types": "application/x-dosexec,image/png"}, True),
        ({"request_headers_complete": False}, False),
        ({"request_headers_complete": "F"}, False),
        ({"request_headers_complete": ""}, False),
        ({"orig_mime_types": ""}, False),
        ({"orig_mime_types": ["text/plain"]}, False),
        ({"orig_mime_types": ["image/svg+xml"]}, False),
        ({"request_content_type": "application/octet-stream"}, False),
        ({"request_content_encoding": "gzip"}, False),
        ({"request_body_len": 0}, False),
        ({"method": "GET"}, False),
    ],
)
def test_binary_post_requires_positive_metadata(
    changes: dict, expected: bool
) -> None:
    """Unknown MIME, missing headers, normal text and encoded bodies are insufficient.

    :param changes: Overrides for the otherwise matching transaction.
    :param expected: Whether the binary POST check should match.
    """
    analyzer = ModuleFactory().create_http_analyzer_obj()
    values = dict(
        request_headers_complete=True,
        orig_mime_types=["application/x-dosexec"],
    )
    values.update(changes)
    analyzer.check_http_header_anomalies("timewindow1", http_flow(**values))
    assert analyzer.db.set_evidence.call_count == int(expected)
    if expected:
        evidence = analyzer.db.set_evidence.call_args.args[0]
        assert (
            evidence.evidence_type
            == EvidenceType.HTTP_BINARY_POST_WITHOUT_CONTENT_TYPE
        )
        assert evidence.profile.ip == "10.0.2.102"
        assert evidence.attacker.direction == Direction.SRC
        assert evidence.victim.value == "195.219.57.34"
        assert evidence.src_port == 49167 and evidence.dst_port == 8080


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({}, True),
        ({"response_content_type": "Text/HTML; charset=utf-8"}, True),
        ({"response_headers_complete": "T"}, True),
        ({"response_headers_complete": "F"}, False),
        ({"response_headers_complete": False}, False),
        ({"response_content_type": "image/png"}, False),
        ({"response_content_type": ""}, False),
        ({"resp_mime_types": []}, False),
        ({"resp_mime_types": ["text/html"]}, False),
        ({"response_content_encoding": "br"}, False),
        ({"response_content_encoding": "gzip"}, False),
        ({"response_body_len": 0}, False),
    ],
)
def test_binary_html_response_scores_server(
    changes: dict, expected: bool
) -> None:
    """A response mismatch belongs to the server, rather than its client.

    :param changes: Overrides for the otherwise matching response.
    :param expected: Whether the response check should match.
    """
    analyzer = ModuleFactory().create_http_analyzer_obj()
    values = dict(
        response_headers_complete=True,
        response_content_type="text/html",
        resp_mime_types=["image/png"],
    )
    values.update(changes)
    analyzer.check_http_header_anomalies("timewindow1", http_flow(**values))
    assert analyzer.db.set_evidence.call_count == int(expected)
    if expected:
        evidence = analyzer.db.set_evidence.call_args.args[0]
        assert (
            evidence.evidence_type == EvidenceType.HTTP_BINARY_RESPONSE_AS_HTML
        )
        assert evidence.profile.ip == "195.219.57.34"
        assert evidence.attacker.direction == Direction.DST
        assert evidence.victim.direction == Direction.SRC
        assert evidence.victim.value == "10.0.2.102"
        assert evidence.threat_level == ThreatLevel.MEDIUM


def test_checks_are_independent_and_keep_transaction_identity() -> None:
    """All three findings can describe one transaction without losing its ports."""
    analyzer = ModuleFactory().create_http_analyzer_obj()
    flow = http_flow(
        host="195.219.57.34:8080",
        orig_mime_types=["image/png"],
        resp_mime_types=["image/png"],
        request_headers_complete=True,
        response_headers_complete=True,
        response_content_type="text/html",
        trans_depth=3,
    )
    analyzer.check_http_header_anomalies("timewindow1", flow)
    records = [
        call.args[0] for call in analyzer.db.set_evidence.call_args_list
    ]
    assert {record.evidence_type for record in records} == {
        EvidenceType.HTTP_IP_HOST,
        EvidenceType.HTTP_BINARY_POST_WITHOUT_CONTENT_TYPE,
        EvidenceType.HTTP_BINARY_RESPONSE_AS_HTML,
    }
    assert all(
        record.detection_details["http_transaction"] == 3 for record in records
    )
    assert all(record.uid == [flow.uid] for record in records)
    assert all(
        record.src_port == 49167 and record.dst_port == 8080
        for record in records
    )


@pytest.mark.parametrize("enriched", [False, True])
def test_zeek_parser_and_flow_roundtrip(enriched: bool) -> None:
    """New HTTP fields survive ingestion; older logs never imply missing headers.

    :param enriched: Whether the Zeek script supplied header metadata.
    """
    analyzer = ModuleFactory().create_http_analyzer_obj()
    parser = ZeekJSON(analyzer.db)
    row = {
        "ts": 1635765895.037696,
        "uid": "Cheader1",
        "id.orig_h": "10.0.2.102",
        "id.orig_p": 49167,
        "id.resp_h": "195.219.57.34",
        "id.resp_p": 8080,
        "method": "POST",
        "host": "example.test",
        "uri": "/upload",
        "request_body_len": 197,
        "response_body_len": 7434,
        "trans_depth": 2,
        "orig_mime_types": ["image/png"],
        "resp_mime_types": ["image/png"],
    }
    if enriched:
        row.update(
            slips_request_headers_complete=True,
            slips_request_content_type="",
            slips_response_headers_complete=True,
            slips_response_content_type="text/html",
        )
    flow, error = parser.process_line(
        {"type": "http.log", "interface": "test", "data": row}
    )
    assert not error
    recovered = FlowClassifier().convert_to_flow_obj(asdict(flow))
    assert recovered.trans_depth == 2
    assert recovered.orig_mime_types == ["image/png"]
    assert recovered.sport == 49167 and recovered.dport == 8080
    analyzer.check_http_header_anomalies("timewindow1", recovered)
    assert analyzer.db.set_evidence.call_count == (2 if enriched else 0)


def test_tsv_empty_header_is_not_a_content_type() -> None:
    """Zeek TSV empty markers and boolean flags retain their header meaning."""
    analyzer = ModuleFactory().create_http_analyzer_obj()
    parser = ZeekTabs(analyzer.db)
    row = {
        "ts": "1635765895.037696",
        "uid": "Cheader1",
        "id.orig_h": "10.0.2.102",
        "id.orig_p": "49167",
        "id.resp_h": "195.219.57.34",
        "id.resp_p": "8080",
        "method": "POST",
        "host": "example.test",
        "uri": "/upload",
        "request_body_len": "197",
        "response_body_len": "7434",
        "trans_depth": "2",
        "orig_mime_types": "image/png",
        "resp_mime_types": "image/png",
        "slips_request_headers_complete": "T",
        "slips_request_content_type": "(empty)",
        "slips_request_content_encoding": "(empty)",
        "slips_response_headers_complete": "T",
        "slips_response_content_type": "text/html",
        "slips_response_content_encoding": "(empty)",
    }
    fields = {
        "type": "http.log",
        "interface": "test",
        "data": "#fields\t" + "\t".join(row),
    }
    parser.process_line(fields)
    # The mocked DB cannot return the field index mapping published by the parser.
    analyzer.db.get_lines_processors.return_value = parser.line_processor_cache
    flow, error = parser.process_line(
        {
            "type": "http.log",
            "interface": "test",
            "data": "\t".join(row.values()),
        }
    )
    assert not error
    assert flow.request_content_type == ""
    analyzer.check_http_header_anomalies("timewindow1", flow)
    assert analyzer.db.set_evidence.call_count == 2
