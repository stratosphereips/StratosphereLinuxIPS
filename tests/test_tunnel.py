# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/flowalerts/tunnel.py"""

from dataclasses import asdict
from unittest.mock import Mock

from slips_files.core.flows.zeek import Tunnel
from tests.module_factory import ModuleFactory
import json
import pytest


@pytest.mark.parametrize(
    "tunnel_type, expected_call_count",
    [
        # testcase 1: Check if GRE tunnel is detected
        # and evidence is set
        ("Tunnel::GRE", 1),
        # testcase 2: Check if non-GRE tunnel is ignored
        ("Tunnel::IP", 0),
        # testcase 3: Check if invalid tunnel type is ignored
        ("Invalid", 0),
    ],
)
def test_check_gre_tunnel(mocker, tunnel_type, expected_call_count):
    """
    Tests the check_gre_tunnel function for various
    tunnel types and checks if the evidence is set correctly.
    """
    tunnel = ModuleFactory().create_tunnel_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidenceHelper.gre_tunnel"
    )
    flow = Tunnel(
        starttime="1726655400.0",
        uid="1234",
        saddr="192.168.0.1",
        daddr="10.0.0.1",
        sport="",
        dport="",
        tunnel_type=tunnel_type,
        action="TUNNEL",
    )
    tunnel.check_gre_tunnel("timewindow1", flow)
    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "tunnel_type, expected_call_count",
    [
        # testcase 1: Check if GRE tunnel is detected
        # and evidence is set
        ("Tunnel::GRE", 1),
        # testcase 2: Check if non-GRE tunnel is ignored
        ("Tunnel::IP", 0),
        # testcase 3: Check if invalid tunnel type is ignored
        ("Invalid", 0),
    ],
)
def test_check_gre_scan(mocker, tunnel_type, expected_call_count):
    tunnel = ModuleFactory().create_tunnel_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidenceHelper.gre_scan"
    )
    flow = Tunnel(
        starttime="1726655400.0",
        uid="1234",
        saddr="192.168.0.1",
        daddr="10.0.0.1",
        sport="",
        dport="",
        tunnel_type=tunnel_type,
        action="Tunnel::DISCOVER",
    )
    tunnel.check_gre_scan("timewindow1", flow)
    assert mock_set_evidence.call_count == expected_call_count


def test_analyze_with_message(mocker):
    """Tests analyze when flowalerts.get_msg returns data."""
    flow = Tunnel(
        starttime="1726655400.0",
        uid="1234",
        saddr="192.168.0.1",
        daddr="10.0.0.1",
        sport="",
        dport="",
        tunnel_type="Tunnel::GRE",
        action="TUNNEL",
    )
    msg = {
        "channel": "new_tunnel",
        "data": json.dumps({"twid": "timewindow1", "flow": asdict(flow)}),
    }
    tunnel = ModuleFactory().create_tunnel_analyzer_obj()
    tunnel.flowalerts.get_msg = Mock(return_value=msg)
    tunnel.check_gre_tunnel = Mock()
    tunnel.check_gre_scan = Mock()
    tunnel.analyze(msg)
    assert tunnel.check_gre_tunnel.call_count == 1
    assert tunnel.check_gre_scan.call_count == 1


def test_analyze_without_message(
    mocker,
):
    tunnel = ModuleFactory().create_tunnel_analyzer_obj()
    mock_check_gre_tunnel = mocker.patch.object(tunnel, "check_gre_tunnel")

    tunnel.analyze(None)
    assert mock_check_gre_tunnel.call_count == 0
