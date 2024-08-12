"""Unit test for modules/flowalerts/tunnel.py"""

from tests.module_factory import ModuleFactory
import json
import pytest


@pytest.mark.parametrize(
    "test_input, expected_call_count",
    [
        # testcase 1: Check if GRE tunnel is detected
        # and evidence is set
        ({"flow": {"tunnel_type": "Tunnel::GRE"}}, True),
        # testcase 2: Check if non-GRE tunnel is ignored
        ({"flow": {"tunnel_type": "Tunnel::IP"}}, False),
        # testcase 3: Check if invalid tunnel type is ignored
        ({"flow": {"tunnel_type": "Invalid"}}, False),
    ],
)
def test_check_GRE_tunnel(mocker, mock_db, test_input, expected_call_count):
    """
    Tests the check_gre_tunnel function for various
    tunnel types and checks if the evidence is set correctly.
    """
    tunnel = ModuleFactory().create_tunnel_analyzer_obj(mock_db)
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidnceHelper.GRE_tunnel"
    )
    tunnel.check_gre_tunnel(test_input)
    assert mock_set_evidence.call_count == expected_call_count


def test_analyze_with_message(mocker, mock_db):
    """Tests analyze when flowalerts.get_msg returns data."""

    msg = {
        "channel": "new_tunnel",
        "data": json.dumps({"tunnel_type": "Tunnel::GRE"}),
    }
    expected_check_gre_call_count = 1
    tunnel = ModuleFactory().create_tunnel_analyzer_obj(mock_db)
    mocker.patch.object(
        tunnel.flowalerts,
        "get_msg",
        return_value=msg,
    )
    mock_check_gre_tunnel = mocker.patch.object(tunnel, "check_gre_tunnel")
    tunnel.analyze(msg)
    assert mock_check_gre_tunnel.call_count == expected_check_gre_call_count


def test_analyze_without_message(mocker, mock_db):
    tunnel = ModuleFactory().create_tunnel_analyzer_obj(mock_db)
    mock_check_gre_tunnel = mocker.patch.object(tunnel, "check_gre_tunnel")

    tunnel.analyze(None)
    assert mock_check_gre_tunnel.call_count == 0
