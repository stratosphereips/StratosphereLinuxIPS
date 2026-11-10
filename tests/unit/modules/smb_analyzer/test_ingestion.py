"""SMB ingestion, durable event identities and evidence detail linking."""

import json
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock

import pytest
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "kind", ["smb_mapping", "smb_files", "smb_cmd", "ntlm", "dce_rpc"]
)
@pytest.mark.parametrize("format_", ["json", "tsv"])
def test_smb_protocols_survive_parser_and_channel_roundtrip(
    kind: str, format_: str
) -> None:
    """Retain each protocol's status, time, endpoints and original connection UID.

    :param kind: Related Zeek log type.
    :param format_: JSON or TSV representation.
    """
    factory = ModuleFactory()
    row = {
        "ts": 1700000000.0,
        "uid": "Csmb",
        "id.orig_h": "192.168.1.120",
        "id.resp_h": "8.8.8.8",
        "id.orig_p": 50000,
        "id.resp_p": 445,
        "path": r"\\server\IPC$",
        "name": "document.txt",
        "action": "SMB::FILE_WRITE",
        "status": "LOGON_FAILURE",
        "success": False,
        "username": "alice",
        "slips_event_ts": 1700000010.0,
    }
    parser = ZeekJSON(Mock()) if format_ == "json" else ZeekTabs(Mock())
    if format_ == "tsv":
        fields = {
            "type": kind + ".log",
            "interface": "eth0",
            "data": "#fields\t" + "\t".join(row),
        }
        parser.process_line(fields)
        parser.db.get_lines_processors.return_value = (
            parser.line_processor_cache
        )
        data = "\t".join(
            "F" if value is False else str(value) for value in row.values()
        )
    else:
        data = row
    flow, error = parser.process_line(
        {"type": kind + ".log", "interface": "eth0", "data": data}
    )
    assert not error
    assert flow.type_ == kind and flow.uid == "Csmb"
    assert float(flow.starttime) == 1700000010
    assert flow.record_id.startswith("Csmb:smb:")
    recovered = FlowClassifier().convert_to_flow_obj(asdict(flow))
    assert asdict(recovered) == asdict(flow)
    handler = factory.create_flow_handler_obj(flow)
    handler.handle_smb()
    payload = json.loads(handler.db.publish.call_args.args[1])
    assert handler.db.publish.call_args.args[0] == "new_smb"
    assert payload["flow"]["record_id"] == flow.record_id
    assert handler.db.add_altflow.called


def connection(path: Path) -> object:
    """Open a test-only SQLite reader with the web's row representation.

    :param path: Isolated database path.
    :return: SQLite connection that can be used as a context manager.
    """
    import sqlite3

    result = sqlite3.connect(path)
    result.row_factory = sqlite3.Row
    return result


def test_module_attribution_and_configured_confidence() -> None:
    """The initiating client receives the finding with explicit uncertainty."""
    module = ModuleFactory().create_smb_analyzer_obj(
        rules={"SMB_SCAN": {"threat_level": "low", "confidence": 0.6}}
    )
    for i in range(20):
        module.handle(
            {
                "profileid": "profile_192.168.1.120",
                "twid": "timewindow1",
                "flow": {
                    "type_": "conn",
                    "uid": f"C{i}",
                    "starttime": 1700000000 + i / 10,
                    "saddr": "192.168.1.120",
                    "daddr": f"10.0.0.{i+1}",
                    "dport": 445,
                    "proto": "tcp",
                    "history": "S",
                    "state": "S0",
                },
            }
        )
    records = [call.args[0] for call in module.db.set_evidence.call_args_list]
    assert records
    assert all(
        record.profile.ip == "192.168.1.120"
        and record.confidence == 0.6
        and record.threat_level.name == "LOW"
        for record in records
    )
    assert (
        "not the probability"
        in records[0].detection_details["confidence_meaning"]
    )


def test_sparse_protocol_queue_is_merged_with_dense_connections() -> None:
    """One pending event per channel prevents SMB metadata running far ahead."""
    module = ModuleFactory().create_smb_analyzer_obj()
    rows = {
        "new_flow": iter(
            {"data": json.dumps({"flow": {"starttime": i}})}
            for i in range(100)
        ),
        "new_smb": iter(
            {"data": json.dumps({"flow": {"starttime": i}})}
            for i in (30.5, 60.5, 90.5)
        ),
    }
    module.get_msg = Mock(
        side_effect=lambda channel: next(rows[channel], None)
    )
    processed = []
    module.handle = lambda payload: processed.append(
        payload["flow"]["starttime"]
    )
    module.main()
    assert len(processed) == 64
    assert processed == sorted(processed)
    assert 30.5 in processed and 60.5 in processed and 90.5 not in processed
    assert len(module.pending) <= 2
    module.main()
    assert len(processed) == 103
    assert processed == sorted(processed)
    module.pending = {"new_smb": (105, {"flow": {"starttime": 105}})}
    module.shutdown_gracefully()
    assert processed[-1] == 105
    assert not module.pending


def test_unrelated_connections_skip_network_and_detection_work() -> None:
    """Common web traffic needs no SMB state, network lookup or IP parsing."""
    module = ModuleFactory().create_smb_analyzer_obj()
    module.scope = Mock(
        side_effect=AssertionError("Unrelated traffic reached SMB analysis")
    )
    module.handle(
        {
            "profileid": "profile_192.168.1.120",
            "flow": {
                "type_": "conn",
                "saddr": "192.168.1.120",
                "daddr": "8.8.8.8",
                "dport": 443,
                "proto": "tcp",
            },
        }
    )
    module.scope.assert_not_called()
    module.db.set_evidence.assert_not_called()
