# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import MagicMock
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "evidence_in_idea, expected_output",
    [
        # testcase1: Remove private IPv4
        (
            {"Source": [{"IP4": ["192.168.1.100"]}, {"IP4": ["8.8.8.8"]}]},
            {"Source": [{"IP4": ["8.8.8.8"]}]},
        ),
        # testcase2: Remove private IPv6
        (
            {"Target": [{"IP6": ["fd00::1"]}, {"IP6": ["2001:db8::1"]}]},
            {"Target": [{"IP6": ["2001:db8::1"]}]},
        ),
        # testcase3: Keep public IPs
        (
            {"Source": [{"IP4": ["1.1.1.1"]}]},
            {"Source": [{"IP4": ["1.1.1.1"]}]},
        ),
        # testcase4: Remove all IPs (should result in empty dict)
        (
            {
                "Source": [{"IP4": ["10.0.0.1"]}],
                "Target": [{"IP6": ["fc00::1"]}],
            },
            {},
        ),
    ],
)
def test_remove_private_ips(evidence_in_idea, expected_output):
    cesnet = ModuleFactory().create_cesnet_obj()
    result = cesnet.remove_private_ips(evidence_in_idea)
    assert result == expected_output


@pytest.mark.parametrize(
    "evidence_in_idea, expected_output",
    [
        # testcase1: Valid alert with Source
        ({"Source": [{"IP4": ["8.8.8.8"]}]}, True),
        # testcase2: Valid alert with Target
        ({"Target": [{"IP6": ["2001:db8::1"]}]}, True),
        # testcase3: Invalid alert (no Source or Target)
        ({}, False),
    ],
)
def test_is_valid_alert(evidence_in_idea, expected_output):
    cesnet = ModuleFactory().create_cesnet_obj()
    result = cesnet.is_valid_alert(evidence_in_idea)
    assert result == expected_output


@pytest.mark.parametrize(
    "events, expected_output",
    [
        # testcase1: Single valid event
        (
            [
                {
                    "Source": [{"IP4": ["8.8.8.8"]}],
                    "Category": ["Malware"],
                    "Description": "Test",
                    "Node": [{"Name": "Test", "SW": ["TestSW"]}],
                }
            ],
            1,
        ),
        # testcase2: Multiple events, one invalid
        (
            [
                {
                    "Source": [{"IP4": ["8.8.8.8"]}],
                    "Category": ["Malware"],
                    "Description": "Test1",
                    "Node": [{"Name": "Test1", "SW": ["TestSW1"]}],
                },
                {},  # Invalid event
                {
                    "Source": [{"IP6": ["2001:db8::1"]}],
                    "Category": ["Intrusion"],
                    "Description": "Test2",
                    "Node": [{"Name": "Test2", "SW": ["TestSW2"]}],
                },
            ],
            2,
        ),
        # testcase3: All invalid events
        ([{}, {}, {}], 0),
        # testcase4: Events with multiple source IPs
        (
            [
                {
                    "Source": [
                        {"IP4": ["192.168.1.100", "8.8.8.8"]},
                        {"IP6": ["2001:db8::1"]},
                    ],
                    "Category": ["Malware"],
                    "Description": "Test",
                    "Node": [{"Name": "Test", "SW": ["TestSW"]}],
                },
            ],
            2,
        ),
    ],
)
def test_import_alerts(events, expected_output):
    cesnet = ModuleFactory().create_cesnet_obj()

    cesnet.wclient = MagicMock()
    cesnet.wclient.getEvents = MagicMock(return_value=events)
    cesnet.db = MagicMock()
    cesnet.db.add_ips_to_ioc = MagicMock()
    cesnet.print = MagicMock()

    cesnet.import_alerts()

    assert cesnet.db.add_ips_to_ioc.call_count == 1

    src_ips = cesnet.db.add_ips_to_ioc.call_args[0][0]

    assert len(src_ips) == expected_output
