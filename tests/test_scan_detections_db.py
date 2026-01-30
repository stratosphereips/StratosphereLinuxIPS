from unittest.mock import MagicMock, Mock

from slips_files.core.structures.flow_attributes import Role
from tests.module_factory import ModuleFactory
import pytest


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
    handler._store_flow_info_if_needed_by_detection_modules = Mock(
        return_value=pipe
    )
    handler.mark_profile_tw_as_modified = Mock(return_value=pipe)

    role = Role.CLIENT
    handler.add_ips(profileid, twid, flow, role)

    handler._ask_modules_about_all_ips_in_flow.assert_called_once_with(
        profileid, twid, flow
    )

    handler._store_flow_info_if_needed_by_detection_modules.assert_called_once_with(
        profileid, twid, flow, role, flow.daddr, pipe
    )

    handler.mark_profile_tw_as_modified.assert_called_once_with(
        str(profileid), str(twid), flow.starttime, pipe=pipe
    )

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
