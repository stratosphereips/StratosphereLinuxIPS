from unittest.mock import MagicMock, Mock

from slips_files.core.structures.flow_attributes import Protocol, Role
from slips_files.core.structures.evidence import ProfileID, TimeWindow
from tests.module_factory import ModuleFactory
import pytest


@pytest.mark.parametrize(
    "scan_kind, expected_key",
    [
        (
            "vertical",
            "profile_10.0.0.1_timewindow2:tcp:not_estab:8.8.8.8:uids",
        ),
        (
            "horizontal",
            "profile_10.0.0.1_timewindow2:tcp:not_estab:dstport:443:uids",
        ),
    ],
)
def test_get_portscan_uids(scan_kind, expected_key):
    """Read contributing scan UIDs in chronological order."""
    module_factory = ModuleFactory()
    handler = module_factory.create_scan_detections_db()
    profileid = ProfileID(ip="10.0.0.1")
    twid = TimeWindow(number=2)
    handler.r.zrange.return_value = ["uid-early", "uid-late"]

    if scan_kind == "vertical":
        result = handler.get_uids_for_vertical_portscan(
            profileid, twid, Protocol.TCP, "8.8.8.8"
        )
    else:
        result = handler.get_uids_for_horizontal_portscan(
            profileid, twid, Protocol.TCP, 443
        )

    assert result == ["uid-early", "uid-late"]
    handler.r.zrange.assert_called_once_with(expected_key, 0, -1)


@pytest.mark.parametrize("scan_kind", ["vertical", "horizontal"])
def test_store_portscan_flow_uid(scan_kind):
    """Store every contributing connection UID in the scan index."""
    module_factory = ModuleFactory()
    handler = module_factory.create_scan_detections_db()
    pipe = MagicMock()
    flow = Mock(
        uid="scan-flow",
        starttime=123.5,
        daddr="8.8.8.8",
        dport=443,
        pkts=1,
        spkts=1,
        state_hist="",
    )
    profileid = ProfileID(ip="10.0.0.1")
    twid = TimeWindow(number=2)
    handler._update_portscan_index_hash = Mock(return_value=pipe)

    if scan_kind == "vertical":
        handler._store_vertical_portscan_info(
            pipe, profileid, twid, Protocol.TCP, "8.8.8.8", flow
        )
        expected_key = "profile_10.0.0.1_timewindow2:tcp:not_estab:8.8.8.8:uids"
    else:
        handler._store_horizontal_portscan_info(
            pipe, profileid, twid, Protocol.TCP, flow
        )
        expected_key = "profile_10.0.0.1_timewindow2:tcp:not_estab:dstport:443:uids"

    pipe.zadd.assert_any_call(expected_key, {"scan-flow": 123.5}, nx=True)


def test_add_ips():
    handler = ModuleFactory().create_scan_detections_db()

    profileid = Mock()
    twid = Mock()
    flow = Mock()
    pipe = MagicMock()

    flow.saddr = "10.0.0.1"
    flow.daddr = "8.8.8.8"
    flow.starttime = 123.456

    handler.r.pipeline = MagicMock()
    handler.r.pipeline.return_value.__enter__.return_value = pipe

    handler._ask_modules_about_all_ips_in_flow = Mock()
    handler._store_flow_info_if_needed_by_detection_modules = Mock(return_value=pipe)
    handler.mark_profile_tw_as_modified = Mock(return_value=pipe)

    role = Role.CLIENT
    handler.add_ips(profileid, twid, flow, role)

    handler._ask_modules_about_all_ips_in_flow.assert_called_once_with(
        profileid, twid, flow
    )

    handler._store_flow_info_if_needed_by_detection_modules.assert_called_once_with(
        profileid, twid, flow, role, flow.daddr, pipe
    )

    handler.mark_profile_tw_as_modified.assert_not_called()

    pipe.execute.assert_called_once()


@pytest.mark.parametrize(
    "flags, packet_count, expected_state",
    [
        # Testcase1: Established states
        ("SA_SA", 10, "Established"),
        ("PA_PA", 10, "Established"),
        ("S1", 10, "Established"),
        ("EST", 10, "Established"),
        ("RST", 10, "Established"),
        ("FIN", 10, "Established"),
        # Testcase2: Not Established states
        ("S_RA", 10, "Not Established"),
        ("S0", 10, "Not Established"),
        ("INT", 10, "Not Established"),
        ("RST", 3, "Not Established"),
        ("FIN", 3, "Not Established"),
        # Testcase3: ICMP states
        ("ECO", 10, "Established"),
        ("UNK", 10, "Established"),
        # Testcase4: Other states
        ("CON", 10, "Established"),
        ("ECO", 10, "Established"),
        ("ECR", 10, "Not Established"),
        ("URH", 10, "Not Established"),
        ("URP", 10, "Not Established"),
    ],
)
def test_get_final_state_from_flags(flags, packet_count, expected_state):
    handler = ModuleFactory().create_scan_detections_db()

    final_state = handler.get_final_state_from_flags(flags, packet_count)
    assert final_state == expected_state
