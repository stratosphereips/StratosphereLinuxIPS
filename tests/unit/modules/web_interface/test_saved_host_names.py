"""Display durable learned names on every host surface after Redis expiry."""

import json
import sqlite3
from pathlib import Path

import pytest

from modules.web_interface.history import connect_history
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from tests.module_factory import ModuleFactory
from tests.unit.modules.web_interface.test_server import _network_scope_reader


@pytest.mark.parametrize("device", [False, True])
def test_expired_names_are_restored_in_labels_inventory_details_and_search(
    tmp_path: Path, device: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recover names from history with empty live and snapshot name fields.

    Parameters:
        tmp_path: Independent databases.
        device: Grouped devices or individual addresses.
        monkeypatch: Keeps live filtering at a fixed observation time.
    """
    _factory = ModuleFactory()
    now = 2_000_000_000.0
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: now)
    reader = _network_scope_reader(tmp_path)
    reader.redis.pipeline.return_value.execute.return_value = [None] * 4
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = HostProfileStore(
        reader.host_profiles_path, "first-run", lambda _: state, ["en0"]
    )
    store._save(
        "192.168.1.128",
        "en0",
        now - 14 * 86400,
        [("mac", "00:08:9b:d1:04:d2"), ("mdns_hostname", "elhuevito.local")],
        observed_traffic=True,
    )
    returned = HostProfileStore(
        reader.host_profiles_path, "returned-run", lambda _: state, ["en0"]
    )
    returned._save(
        "192.168.1.128",
        "en0",
        now - 60,
        [("mac", "00:08:9b:d1:04:d2")],
        observed_traffic=True,
    )
    with connect_history(reader.history_path) as connection:
        connection.execute(
            "INSERT INTO host_snapshots VALUES (?,?,?)",
            (
                "192.168.1.128",
                now,
                json.dumps(
                    {
                        "ip": "192.168.1.128",
                        "scope": "local",
                        "hostname": "",
                        "mac": "",
                    }
                ),
            ),
        )
        connection.execute(
            "INSERT INTO flow_index(uid,flow_rowid,event_time,src_ip,dst_ip,proto,bytes,packets) VALUES ('returned',1,?,'192.168.1.128','8.8.8.8','tcp',100,1)",
            (now - 60,),
        )
    query = {
        "network": ["current"],
        "range": ["all"],
        "device": ["1" if device else "0"],
    }
    assert reader.host_names({**query, "ip": ["192.168.1.128"]})["names"][
        "192.168.1.128"
    ] == {"name": "elhuevito.local", "source": "mDNS"}
    page = reader.hosts({**query, "search": ["elhuevito"]})
    assert len(page["items"]) == 1
    assert page["items"][0]["hostname"] == "elhuevito.local"
    assert page["items"][0]["mac"] == "00:08:9b:d1:04:d2"
    detail = reader.host("192.168.1.128", query)
    assert detail["hostname"] == "elhuevito.local"
    assert detail["hostname_source"] == "mDNS"


def test_reassigned_ip_does_not_use_stale_snapshot_or_dns_cache(
    tmp_path: Path,
) -> None:
    """Reject expired identity from another device that owned the same IP.

    Parameters:
        tmp_path: Independent identity and history files.
    """
    _factory = ModuleFactory()
    reader = _network_scope_reader(tmp_path)
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = HostProfileStore(
        reader.host_profiles_path, "old", lambda _: state, ["en0"]
    )
    store._save(
        "192.168.1.128",
        "en0",
        100,
        [("mac", "00:08:9b:d1:04:d2"), ("hostname", "elhuevito")],
        observed_traffic=True,
    )
    store._save(
        "192.168.1.128",
        "en0",
        300,
        [("mac", "02:00:00:00:00:99")],
        observed_traffic=True,
    )
    with connect_history(reader.history_path) as connection:
        connection.execute(
            "INSERT INTO host_snapshots VALUES (?,?,?)",
            (
                "192.168.1.128",
                100,
                json.dumps(
                    {
                        "ip": "192.168.1.128",
                        "hostname": "elhuevito",
                        "mac": "00:08:9b:d1:04:d2",
                        "dns": {"domains": ["elhuevito.local"]},
                    }
                ),
            ),
        )
    reader.redis.pipeline.return_value.execute.return_value = [
        None,
        json.dumps({"domains": ["elhuevito.local"]}),
        None,
        "02:00:00:00:00:99",
    ]
    assert (
        reader.host_names({"ip": ["192.168.1.128"]})["names"]["192.168.1.128"][
            "name"
        ]
        == ""
    )
    records = [
        {
            "ip": "192.168.1.128",
            "hostname": "elhuevito",
            "mac": "00:08:9b:d1:04:d2",
        }
    ]
    reader._restore_host_identities(records, {})
    assert records[0]["hostname"] == ""
    assert records[0]["mac"] == "02:00:00:00:00:99"
    with sqlite3.connect(reader.host_profiles_path) as connection:
        assert (
            connection.execute(
                "SELECT value FROM facts WHERE kind='hostname'"
            ).fetchone()[0]
            == "elhuevito"
        )
