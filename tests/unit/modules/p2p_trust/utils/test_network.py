"""Keep P2P network identity independent of the optional host inventory."""

import sqlite3
from pathlib import Path

import pytest

from modules.p2p_trust.utils.network import (
    network_for_observation,
    network_id_for_state,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "state,run_name,expected",
    [
        (
            {"gateway_mac": "AA:BB:CC:DD:EE:FF"},
            "capture:123",
            "gateway:aa:bb:cc:dd:ee:ff",
        ),
        ({}, "capture:123", "run:capture:123"),
        ({}, "", ""),
    ],
)
def test_network_identity_without_host_inventory(
    state: dict[str, str], run_name: str, expected: str
) -> None:
    """Keep private address reuse isolated by gateway or run.

    Parameters:
        state: Captured network settings.
        run_name: Fallback run identity.
        expected: Stable P2P validation identity.
    """
    _factory = ModuleFactory()
    assert network_id_for_state(state, run_name) == expected


@pytest.mark.parametrize(
    "observed,expected",
    [(15, "gateway:home"), (25, "gateway:guest"), (35, "")],
)
def test_legacy_observation_resolves_its_original_network(
    tmp_path: Path, observed: float, expected: str
) -> None:
    """Resolve old reviews using historical endpoints, never today's subnet.

    Parameters:
        tmp_path: Optional legacy inventory directory.
        observed: Timestamp of the old detection.
        expected: Recorded network or unknown.
    """
    _factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE hosts(network_id TEXT,ip TEXT,network_label TEXT);"
            "CREATE TABLE network_names(network_id TEXT,name TEXT);"
            "CREATE TABLE host_endpoint_observations(network_id TEXT,ip TEXT,first_seen REAL,last_seen REAL);"
            "INSERT INTO host_endpoint_observations VALUES"
            "('gateway:home','192.168.1.10',10,20),"
            "('gateway:guest','192.168.1.10',21,30);"
        )
    assert (
        network_for_observation(path, "192.168.1.10", observed)["network_id"]
        == expected
    )


def test_absent_legacy_inventory_keeps_old_feedback_unknown(
    tmp_path: Path,
) -> None:
    """Do not create host inventory databases during P2P operation.

    Parameters:
        tmp_path: Directory containing no legacy inventory.
    """
    _factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    assert (
        network_for_observation(path, "192.168.1.10", 15)["network_id"] == ""
    )
    assert not path.exists()
