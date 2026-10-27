"""Packet timing decisions, metadata routing and conservative scoring."""

import json
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modules.web_interface.server import RunDataReader
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils
from slips_files.common.input_type import InputType
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.core.flows.packet_timing import PacketTiming
from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs
from tests.module_factory import ModuleFactory
from modules.supported_module_names import Modules
from tests.unit.modules.smb_analyzer.test_ingestion import connection


def summary(**changes: object) -> dict:
    """Build a generic small-data callback window.

    Parameters:
        changes: Summary fields to replace.

    Returns:
        Connection metadata without payload content or malware indicators.
    """
    result = dict(type_="packet_timing", uid="Cpacket", record_id="Cpacket:packet:sample",
        starttime=4300, saddr="10.0.0.1", daddr="8.8.8.8", sport=50000, dport=443,
        proto="tcp", history="ShADad", service=[], is_orig=True, kind="data",
        times=[1000+i*300 for i in range(12)], lengths=[8]*12,
        event_count=12, orig_bytes=135, resp_bytes=12)
    result.update(changes)
    return result


@pytest.mark.parametrize("changes,expected", [
    ({}, "SUSPICIOUS_PACKET_HEARTBEAT"),
    ({"service":["ssl"]}, "PERIODIC_PACKETS"),
    ({"service":"http"}, "PERIODIC_PACKETS"),
    ({"dport":22}, "PERIODIC_PACKETS"),
    ({"history":"Dd"}, "PERIODIC_PACKETS"),
    ({"is_orig":False}, "PERIODIC_PACKETS"),
    ({"kind":"ack","lengths":[0]*12}, "PERIODIC_PACKETS"),
    ({"kind":"keepalive","lengths":[1]*12}, "PERIODIC_PACKETS"),
    ({"lengths":[200]*12}, "PERIODIC_PACKETS"),
    ({"resp_bytes":0}, "PERIODIC_PACKETS"),
])
def test_periodic_packets_require_context_for_suspicion(changes: dict, expected: str) -> None:
    """Keep ordinary application and transport timing out of scored heartbeat evidence.

    Parameters:
        changes: Protocol, direction or traffic context.
        expected: Evidence type supported by that context.
    """
    module = ModuleFactory().create_beaconing_obj(packet_timing={"enabled":True,"include_acks":True})
    finding = module.packet_detector.process(summary(**changes), "network")
    assert finding["evidence_type"] == expected
    assert finding["details"]["period"] == pytest.approx(300)
    assert finding["threat"] == ("medium" if expected.startswith("SUSPICIOUS") else "info")


@pytest.mark.parametrize("changes", [
    {"times":[0,1,7,19,20,150,500,700,701,900,1000,1001]},
    {"times":[1000]*12}, {"times":[float("nan")]*12},
    {"times":[1,2]}, {"lengths":[8]}, {"lengths":[8]*11+[10000]},
    {"daddr":"224.0.0.1"}, {"event_count":1}, {"kind":"bogus"},
])
def test_invalid_or_nonperiodic_summaries_are_ignored(changes: dict) -> None:
    """Reject malformed records and irregular packet sequences.

    Parameters:
        changes: Invalid observation fields.
    """
    module = ModuleFactory().create_beaconing_obj(packet_timing={"enabled":True})
    assert module.packet_detector.process(summary(**changes), "network") is None


def test_packet_progress_suppresses_repeats_and_downgrades() -> None:
    """Keep count-spaced reporting independent of the rolling window size."""
    module = ModuleFactory().create_beaconing_obj(packet_timing={"enabled":True})
    assert module.packet_detector.process(summary(), "network")
    assert module.packet_detector.process(summary(), "network") is None
    assert module.packet_detector.process(summary(times=[4000+i*300 for i in range(12)], event_count=20), "network") is None
    continuation = module.packet_detector.process(summary(times=[40000+i*300 for i in range(12)], event_count=100), "network")
    assert continuation["details"]["continuation"]
    assert continuation["details"]["next_report_events"] == 1000
    assert module.packet_detector.process(summary(service=["ssl"], times=[50000+i*300 for i in range(12)], event_count=110), "network") is None


def test_packet_evidence_uses_original_flow_and_worker_scoring() -> None:
    """Publish evidence with source attribution and a direct link to its summary."""
    module = ModuleFactory().create_beaconing_obj(packet_timing={"enabled":True})
    module.live = False
    module.handle_packet_timing({"profileid":"profile_10.0.0.1","twid":"timewindow1","flow":summary()})
    evidence = module.db.set_evidence.call_args.args[0]
    assert evidence.profile.ip == "10.0.0.1"
    assert evidence.uid == ["Cpacket:packet:sample"]
    assert evidence.dst_port == 443
    worker = ModuleFactory().create_evidence_handler_worker_obj()
    assert worker.get_threat_level(evidence) == pytest.approx(0.425)
    assert "300.000s" in evidence.description
    disabled = ModuleFactory().create_beaconing_obj()
    disabled.handle_packet_timing({"profileid":"profile_10.0.0.1","twid":"timewindow1","flow":summary()})
    disabled.db.set_evidence.assert_not_called()


def test_packet_rule_configuration_changes_ports_and_scoring() -> None:
    """Apply packet-specific escalation and severity controls independently."""
    module = ModuleFactory().create_beaconing_obj(packet_timing={"enabled":True,
        "expected_tls_ports":[8443], "suspicious_threat_level":"low", "suspicious_confidence":0.4})
    ordinary = module.packet_detector.process(summary(), "network")
    assert ordinary["threat"] == "info"
    configured = module.packet_detector.process(summary(uid="C8443",dport=8443), "network")
    assert configured["threat"] == "low"
    assert configured["confidence"] == 0.4


@pytest.mark.parametrize("changes", [{"enabled":"yes"},{"min_events":1},{"window_events":8},
    {"max_connections":float("inf")},{"min_support":0.1},{"expected_tls_ports":[0]},
    {"small_payload_bytes":10000},{"unknown_option":1}])
def test_invalid_packet_options_fail_at_startup(changes: dict) -> None:
    """Reject unsafe collection limits and misspelled options.

    Parameters:
        changes: Invalid nested packet settings.
    """
    factory = ModuleFactory()
    with pytest.raises((ValueError, TypeError)):
        factory.create_beaconing_obj(packet_timing=changes)


@pytest.mark.parametrize("format_", ["json", "tsv"])
def test_packet_summary_parser_and_channel_roundtrip(format_: str) -> None:
    """Route summary records without publishing individual packets.

    Parameters:
        format_: Zeek JSON or TSV representation.
    """
    factory = ModuleFactory()
    row = {"ts":4300,"uid":"Cpacket","id.orig_h":"10.0.0.1","id.orig_p":50000,
        "id.resp_h":"8.8.8.8","id.resp_p":443,"is_orig":True,"kind":"data",
        "history":"ShADad","times":[1000+i*300 for i in range(12)],"lengths":[8]*12,
        "event_count":12,"orig_bytes":135,"resp_bytes":12}
    parser = ZeekJSON(Mock()) if format_ == "json" else ZeekTabs(Mock())
    data = row
    if format_ == "tsv":
        parser.process_line({"type":"packet_timing.log","interface":"eth0","data":"#fields\t"+"\t".join(row)})
        parser.db.get_lines_processors.return_value = parser.line_processor_cache
        data = "\t".join(",".join(map(str,value)) if isinstance(value,list) else "T" if value is True else str(value) for value in row.values())
    flow, error = parser.process_line({"type":"packet_timing.log","interface":"eth0","data":data})
    assert not error
    assert flow.type_ == "packet_timing"
    assert not utils.is_ignored_zeek_log_file("packet_timing.log")
    assert flow.record_id.startswith("Cpacket:packet:")
    assert asdict(FlowClassifier().convert_to_flow_obj(asdict(flow))) == asdict(flow)
    handler = factory.create_flow_handler_obj(flow)
    handler.handle_packet_timing()
    assert handler.db.publish.call_args.args[0] == "new_packet_timing"
    assert handler.db.add_altflow.call_count == 1


def test_packet_summaries_are_distinct_and_linked_in_web(tmp_path: Path) -> None:
    """Retain successive windows without overwriting each other or the conn row.

    Parameters:
        tmp_path: Isolated run database.
    """
    factory = ModuleFactory()
    database = SQLiteDB(factory.logger, str(tmp_path), 12345)
    first = PacketTiming(**summary(record_id=""))
    second = PacketTiming(**summary(record_id="",starttime=4600,event_count=20))
    for flow in (first,second):
        database.add_altflow(flow,"profile_10.0.0.1","timewindow1")
    database.execute("INSERT INTO flows(uid,flow,profileid,twid) VALUES(?,?,?,?)", ("Cpacket",json.dumps({"uid":"Cpacket","saddr":"10.0.0.1","daddr":"8.8.8.8","type_":"conn"}),"profile_10.0.0.1","timewindow1"))
    reader = object.__new__(RunDataReader)
    reader.sqlite_path = Path(database._flows_db)
    reader.output_dir = tmp_path
    reader._columns_cache, reader._tables_cache = {}, {}
    reader._connect_sqlite = lambda: connection(reader.sqlite_path)
    group = reader.flow_details("Cpacket",{})
    assert group["network_flow"]["uid"] == "Cpacket"
    assert group["protocol_flow_total"] == 2
    assert {row["uid"] for row in group["protocol_flows"]} == {first.record_id,second.record_id}
    database.execute("INSERT INTO evidence_flows(evidence_id,uid) VALUES(?,?)",("Epacket", first.record_id))
    linked = reader.flows_for_evidence("Epacket",{})
    assert len(linked["items"]) == 1
    assert linked["items"][0]["network_flow"]["uid"] == "Cpacket"
    assert linked["items"][0]["protocol_flows"][0]["uid"] == first.record_id
    database.conn.close()


@pytest.mark.parametrize("packet_enabled,beacon_enabled,module_disabled", [(False,True,False),(True,True,False),(True,False,False),(True,True,True)])
def test_packet_collector_is_loaded_only_when_explicitly_enabled(packet_enabled: bool, beacon_enabled: bool, module_disabled: bool) -> None:
    """Keep packet events out of the default capture path.

    Parameters:
        packet_enabled: Nested collector switch.
        beacon_enabled: Parent module switch.
        module_disabled: Whether the module is explicitly disabled by name.
    """
    factory = ModuleFactory()
    module = factory.create_beaconing_obj(packet_timing={"enabled":packet_enabled})
    input_process = factory.create_input_obj("", InputType.PCAP)
    input_process.conf = module.conf
    input_process.conf.beaconing_enabled.return_value = beacon_enabled
    read = module.conf.read_configuration.side_effect
    module.conf.read_configuration.side_effect = lambda section,key,default: [Modules.BEACONING.value] if section == "modules" and key == "disable" and module_disabled else read(section,key,default)
    input_process.tcp_inactivity_timeout = 60
    with patch("slips_files.core.input.zeek.utils.zeek_input_utils.ZeekCommandBuilder") as builder:
        builder.return_value.build.return_value = ["zeek"]
        command = input_process.zeek_utils._construct_zeek_cmd("test.pcap")
    loaded = any(argument.endswith("packet-timing.zeek") for argument in command)
    assert loaded is (packet_enabled and beacon_enabled and not module_disabled)
