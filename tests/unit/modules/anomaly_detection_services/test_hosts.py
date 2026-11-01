"""Exercise quiet host training, newly active ports and bounded persistence."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.anomaly_detection_services.hosts import (
    HostInventory,
    HostServices,
)
from modules.anomaly_detection_services.store import BaselineStore
from slips_files.core.structures.evidence import EvidenceType
from tests.module_factory import ModuleFactory
from tests.unit.modules.anomaly_detection_services.test_models import flow


@pytest.mark.parametrize(
    "changes",
    [
        {},
        {"state": "S1", "history": "ShA"},
        {"state": "SH", "history": "Sh", "dpkts": 1},
        {"proto": "udp", "history": "Dd"},
    ],
)
def test_quiet_capture_host_reports_first_answering_port(
    changes: dict,
) -> None:
    """Find a new service without requiring any training connections.

    Parameters:
        changes: TCP establishment or bidirectional UDP fields.
    """
    module = ModuleFactory().create_service_anomaly_obj(training_hours=0.0167)
    start = flow()["starttime"]
    module._capture_started = start
    module.db.get_network_state.return_value.update(
        host_ip="192.0.2.20",
        mac="02:00:00:00:00:20",
    )
    with patch(
        "modules.anomaly_detection_services.anomaly_detection_services.time.time",
        return_value=start,
    ):
        module._refresh_local_hosts()
    assert len(module.host_inventory.hosts) == 1
    assert not next(iter(module.host_inventory.hosts.values())).ports
    candidate = flow(
        uid="quiet-first-service",
        starttime=start + 61,
        dport=23423,
        dmac="02:00:00:00:00:20",
        **changes,
    )
    module.handle_flow({"twid": "timewindow7", "flow": candidate})

    module.db.set_evidence.assert_called_once()
    evidence = module.db.set_evidence.call_args.args[0]
    assert evidence.evidence_type == EvidenceType.ANOMALOUS_FLOW
    assert evidence.uid == [candidate["uid"]]
    assert evidence.profile.ip == candidate["saddr"]
    assert evidence.victim.value == candidate["daddr"]
    assert evidence.dst_port == 23423
    assert evidence.timewindow.number == 7
    assert "newly active service" in evidence.description
    assert "0 known services" in evidence.description
    assert next(iter(module.detector.services.values())).summary.count == 0
    assert module.detector.client_count == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"state": "S0", "history": "S", "dpkts": 0},
        {"state": "REJ", "history": "Sr"},
        {"proto": "udp", "dpkts": 0},
    ],
)
def test_probes_do_not_invent_answering_hosts_or_ports(changes: dict) -> None:
    """A silent or refused port cannot create a new-service finding.

    Parameters:
        changes: Unanswered or refused connection fields.
    """
    module = ModuleFactory().create_service_anomaly_obj(training_hours=0.0167)
    start = flow()["starttime"]
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(
                uid="probe",
                starttime=start + 61,
                **changes,
            ),
        }
    )
    module.db.set_evidence.assert_not_called()
    assert not module.host_inventory.port_count
    assert all(
        "192.0.2.20" not in host.addresses
        for host in module.host_inventory.hosts.values()
    )


@pytest.mark.parametrize("live", [True, False])
def test_outbound_activity_starts_the_host_clock(live: bool) -> None:
    """Start learning from outbound traffic before any incoming connections.

    Parameters:
        live: Live capture or recorded input with its own timestamp clock.
    """
    module = ModuleFactory().create_service_anomaly_obj(training_hours=0.0167)
    module.live = live
    start = flow()["starttime"]
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(
                uid="outgoing-ssh",
                saddr="192.0.2.20",
                daddr="192.0.2.10",
            ),
        }
    )
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(
                uid="incoming-ncat",
                starttime=start + 61,
                dport=23423,
            ),
        }
    )
    module.db.set_evidence.assert_called_once()
    assert (
        "newly active service"
        in module.db.set_evidence.call_args.args[0].description
    )


def test_newly_seen_hosts_and_remote_internet_ports_do_not_raise_findings() -> (
    None
):
    """Give unseen local hosts their own warmup and exclude remote Internet servers."""
    module = ModuleFactory().create_service_anomaly_obj(training_hours=0.0167)
    start = flow()["starttime"]
    for index, destination in enumerate(("8.8.8.8", "1.1.1.1", "192.0.2.30")):
        module.handle_flow(
            {
                "twid": "timewindow1",
                "flow": flow(
                    uid=f"discovery-{index}",
                    starttime=start + index * 120,
                    daddr=destination,
                    dport=443,
                ),
            }
        )
    module.db.set_evidence.assert_not_called()
    assert all(
        not address.startswith(("8.8.", "1.1."))
        for host in module.host_inventory.hosts.values()
        for address in host.addresses
    )


def test_new_service_warning_repeats_without_teaching_normality() -> None:
    """Respect flow deduplication and cooldown without trusting an unusual port."""
    module = ModuleFactory().create_service_anomaly_obj(
        training_hours=0.0167,
        alert_cooldown_seconds=60,
    )
    inventory = module.host_inventory
    start = flow()["starttime"]
    host = inventory.observe_host(
        "network", "ip:192.0.2.20", "192.0.2.20", start
    )
    assert inventory.check_service(host, "tcp", 23423, start + 61)
    assert inventory.check_service(host, "tcp", 23423, start + 62) is None
    assert inventory.check_service(host, "tcp", 23423, start + 121)
    assert not inventory.hosts[host].ports["tcp:23423"]["normal"]
    module.settings.mode = "train"
    assert inventory.check_service(host, "tcp", 23423, start + 122) is None
    module.settings.mode = "auto"
    assert inventory.check_service(host, "tcp", 23423, start + 200) is None
    assert inventory.hosts[host].ports["tcp:23423"]["normal"]


def test_known_ports_duplicates_and_disabled_check_stay_quiet() -> None:
    """Keep old ports normal, and emit only once for a duplicated new flow."""
    module = ModuleFactory().create_service_anomaly_obj(
        training_hours=0.0167,
        alert_cooldown_seconds=0,
    )
    start = flow()["starttime"]
    module.handle_flow(
        {"twid": "timewindow1", "flow": flow(uid="known-training")}
    )
    candidate = {
        "twid": "timewindow1",
        "flow": flow(uid="known-later", starttime=start + 61),
    }
    module.handle_flow(candidate)
    module.db.set_evidence.assert_not_called()
    candidate["flow"].update(uid="new-port", dport=23423)
    module.handle_flow(candidate)
    module.handle_flow(candidate)
    module.db.set_evidence.assert_called_once()
    module.settings.detect_new_services = False
    candidate["flow"].update(uid="disabled", dport=23424)
    module.handle_flow(candidate)
    assert module.db.set_evidence.call_count == 1


def test_identity_aliases_roaming_and_device_replacement() -> None:
    """Retain ports through missing MAC data, but isolate networks and replacements."""
    module = ModuleFactory().create_service_anomaly_obj(training_hours=0.0167)
    inventory = module.host_inventory
    start = flow()["starttime"]
    key = inventory.observe_host(
        "network", "ip:192.0.2.20", "192.0.2.20", start
    )
    assert inventory.check_service(key, "tcp", 22, start) is None
    key = inventory.observe_host(
        "network", "mac:02:00:00:00:00:20", "192.0.2.20", start + 10
    )
    assert len(inventory.hosts) == 1
    assert (
        inventory.observe_host(
            "network", "ip:192.0.2.20", "192.0.2.20", start + 20
        )
        == key
    )
    assert (
        inventory.observe_host(
            "network", "mac:02:00:00:00:00:20", "192.0.2.21", start + 30
        )
        == key
    )
    assert inventory.check_service(key, "tcp", 22, start + 61) is None
    assert inventory.check_service(key, "udp", 22, start + 61)
    replacement = inventory.observe_host(
        "network", "mac:02:00:00:00:00:99", "192.0.2.20", start + 61
    )
    roaming = inventory.observe_host(
        "another-network", "mac:02:00:00:00:00:20", "192.0.2.21", start + 61
    )
    assert replacement != key != roaming
    assert inventory.check_service(replacement, "tcp", 22, start + 61) is None
    assert inventory.check_service(roaming, "tcp", 22, start + 61) is None


def test_host_port_and_alias_limits_fail_conservatively() -> None:
    """Bound total state without treating forgotten normal ports as new."""
    module = ModuleFactory().create_service_anomaly_obj(
        max_hosts=1, max_services=1, training_hours=0.0167
    )
    inventory = module.host_inventory
    start = flow()["starttime"]
    key = inventory.observe_host(
        "network", "mac:02:00:00:00:00:20", "192.0.2.20", start
    )
    for index in range(20):
        inventory.observe_host(
            "network", "mac:02:00:00:00:00:20", f"192.0.2.{index}", start
        )
    assert len(inventory.hosts[key].addresses) == len(inventory.aliases) == 8
    assert (
        inventory.observe_host(
            "network", "ip:192.0.2.100", "192.0.2.100", start
        )
        is None
    )
    assert inventory.check_service(key, "tcp", 22, start) is None
    assert inventory.check_service(key, "tcp", 23423, start + 61) is None
    assert not inventory.hosts[key].complete
    assert inventory.port_count == 1


def test_new_ports_share_a_host_warning_limit() -> None:
    """Prevent a port burst from bypassing limits by using many different services."""
    module = ModuleFactory().create_service_anomaly_obj(
        training_hours=0.0167,
        max_new_services_per_host_hour=2,
    )
    inventory = module.host_inventory
    start = flow()["starttime"]
    key = inventory.observe_host(
        "network", "ip:192.0.2.20", "192.0.2.20", start
    )
    results = [
        inventory.check_service(key, "tcp", port, start + 61)
        for port in (23423, 23424, 23425)
    ]
    assert [bool(result) for result in results] == [True, True, False]
    assert inventory.check_service(key, "tcp", 23425, start + 3661)


def test_checkpoint_restores_quiet_training_and_frozen_detection(
    tmp_path: Path,
) -> None:
    """Resume a zero-connection host clock and keep new ports unusual after restart.

    Parameters:
        tmp_path: Isolated checkpoint directory.
    """
    module = ModuleFactory().create_service_anomaly_obj(training_hours=0.0167)
    start = flow()["starttime"]
    key = module.host_inventory.observe_host(
        "network", "ip:192.0.2.20", "192.0.2.20", start
    )
    path = tmp_path / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        store.save(module.detector, module.host_inventory)
    restored = HostInventory(module.settings)
    with closing(BaselineStore(path, module.settings)) as store:
        restored.restore(store.load_hosts())
        module.settings.mode = "detect"
        assert restored.check_service(key, "tcp", 23423, start + 61)
        store.save(module.detector, restored)
    again = HostInventory(module.settings)
    with closing(BaselineStore(path, module.settings)) as store:
        again.restore(store.load_hosts())
    assert again.hosts[key].first_seen == start
    assert not again.hosts[key].ports["tcp:23423"]["normal"]
    assert again.check_service(key, "tcp", 23423, start + 62) is None


def test_old_checkpoint_adds_inventory_without_replacing_service_learning(
    tmp_path: Path,
) -> None:
    """Extend the existing schema while retaining learned clients and ports.

    Parameters:
        tmp_path: Isolated old-format checkpoint directory.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    module.handle_flow({"twid": "timewindow1", "flow": flow()})
    service_key, service = next(iter(module.detector.services.items()))
    original = json.dumps(service.to_dict())
    path = tmp_path / "baseline.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE services(key TEXT PRIMARY KEY,updated REAL,data TEXT)"
        )
        connection.execute("PRAGMA user_version=1")
        connection.execute(
            "INSERT INTO services VALUES (?,?,?)",
            (service_key, service.last_seen, original),
        )
    with closing(BaselineStore(path, module.settings)) as store:
        assert store.load_hosts() == {}
        assert store.load()[service_key].summary.count == 1
        assert (
            store.connection.execute("SELECT data FROM services").fetchone()[0]
            == original
        )
        data = HostServices(flow()["starttime"], flow()["starttime"])
        assert HostServices.from_dict(data.to_dict(), module.settings) == data
        store.connection.execute(
            "INSERT INTO host_services VALUES ('bad',1,'{')"
        )
        store.connection.commit()
        with pytest.raises(ValueError):
            store.load_hosts()
        assert (
            store.connection.execute(
                "SELECT data FROM host_services"
            ).fetchone()[0]
            == "{"
        )


def test_inactive_ports_and_hosts_expire_without_unbounded_state() -> None:
    """Expire unused ports even when their host remains active."""
    module = ModuleFactory().create_service_anomaly_obj(retention_days=1)
    inventory = module.host_inventory
    start = flow()["starttime"]
    key = inventory.observe_host(
        "network", "ip:192.0.2.20", "192.0.2.20", start
    )
    inventory.check_service(key, "tcp", 22, start)
    inventory.observe_host(
        "network", "ip:192.0.2.20", "192.0.2.20", start + 43200
    )
    inventory.prune(start + 95040)
    assert key in inventory.hosts
    assert not inventory.hosts[key].ports
    assert inventory.port_count == 0
    inventory.prune(start + 3 * 86400)
    assert not inventory.hosts and not inventory.aliases
    assert key in inventory.deleted


def test_expired_deletion_records_stay_bounded_while_saving_is_unavailable() -> (
    None
):
    """Bound pending deletions during prolonged checkpoint contention."""
    module = ModuleFactory().create_service_anomaly_obj(
        max_hosts=1, retention_days=1
    )
    inventory = module.host_inventory
    start = flow()["starttime"]
    for day in range(100):
        inventory.observe_host(
            f"network-{day}",
            "ip:192.0.2.20",
            "192.0.2.20",
            start + day * 2 * 86400,
        )
        assert len(inventory.hosts) <= 1
        assert len(inventory.deleted) <= 2


def test_quiet_host_checkpoint_retries_a_busy_database(tmp_path: Path) -> None:
    """Keep a quiet host's training clock pending until its checkpoint can commit.

    Parameters:
        tmp_path: Isolated checkpoint directory.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    key = module.host_inventory.observe_host(
        "network", "ip:192.0.2.20", "192.0.2.20", flow()["starttime"]
    )
    path = tmp_path / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        module.store = store
        with sqlite3.connect(path) as writer:
            writer.execute("BEGIN IMMEDIATE")
            module._checkpoint(force=True)
            assert key in module.host_inventory.dirty
            writer.rollback()
        module._checkpoint(force=True)
        assert not module.host_inventory.dirty
        assert key in store.load_hosts()
        module.store = None


def test_historical_training_flows_and_labels_do_not_teach_bad_ports() -> None:
    """Use start time for delayed flows and exclude explicitly malicious training."""
    module = ModuleFactory().create_service_anomaly_obj(training_hours=0.0167)
    start = flow()["starttime"]
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(
                uid="bad-training-port",
                ground_truth_label="Malware",
            ),
        }
    )
    assert not module.host_inventory.port_count
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(
                uid="after-training",
                starttime=start + 61,
            ),
        }
    )
    module.db.set_evidence.assert_called_once()
    assert (
        "newly active service"
        in module.db.set_evidence.call_args.args[0].description
    )
    assert module.detector.client_count == 0
    module.db.set_evidence.reset_mock()
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(
                uid="late-normal",
                starttime=start + 20,
                dur=1000,
                dport=2222,
            ),
        }
    )
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(
                uid="known-late-port",
                starttime=start + 80,
                dport=2222,
            ),
        }
    )
    module.db.set_evidence.assert_not_called()


def test_restored_ip_alias_uses_the_most_recent_device() -> None:
    """Missing MAC data must not select an older device that reused the IP."""
    module = ModuleFactory().create_service_anomaly_obj()
    inventory = module.host_inventory
    newest = json.dumps(
        ["network", "mac:02:00:00:00:00:20"], separators=(",", ":")
    )
    oldest = json.dumps(
        ["network", "mac:02:00:00:00:00:99"], separators=(",", ":")
    )
    inventory.restore(
        {
            newest: HostServices(100, 200, ["192.0.2.20"]),
            oldest: HostServices(50, 150, ["192.0.2.20"]),
        }
    )
    assert (
        inventory.observe_host("network", "ip:192.0.2.20", "192.0.2.20", 201)
        == newest
    )


def test_reduced_limits_preserve_incomplete_inventory_across_checkpoints(
    tmp_path: Path,
) -> None:
    """Persist saturation instead of classifying omitted normal ports as new.

    Parameters:
        tmp_path: Isolated checkpoint directory.
    """
    module = ModuleFactory().create_service_anomaly_obj(
        max_services=1, training_hours=0.0167
    )
    inventory = module.host_inventory
    start = flow()["starttime"]
    key = inventory.observe_host(
        "network", "ip:192.0.2.20", "192.0.2.20", start
    )
    inventory.check_service(key, "tcp", 22, start)
    path = tmp_path / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        store.save(module.detector, inventory)
        assert not inventory.dirty
        assert inventory.check_service(key, "tcp", 23423, start + 61) is None
        assert key in inventory.dirty
        store.save(module.detector, inventory)
        assert not store.load_hosts()[key].complete
    data = inventory.hosts[key].to_dict()
    data["ports"]["udp:53"] = {
        "first_reply": start,
        "last_seen": start,
        "normal": True,
    }
    assert not HostServices.from_dict(data, module.settings).complete


def test_ipv6_local_address_and_network_changes_keep_clocks_separate() -> None:
    """Train a monitored IPv6 address without carrying its ports to another router."""
    module = ModuleFactory().create_service_anomaly_obj(training_hours=0.0167)
    start = flow()["starttime"]
    module._capture_started = start
    state = module.db.get_network_state.return_value
    state.update(
        host_ip="192.0.2.20",
        mac="02:00:00:00:00:20",
        addresses=[
            {"ip": "fd00:1::20", "network": "fd00:1::/64"},
        ],
    )
    with patch(
        "modules.anomaly_detection_services.anomaly_detection_services.time.time",
        return_value=start,
    ):
        module._refresh_local_hosts()
    candidate = {
        "twid": "timewindow1",
        "flow": flow(
            uid="ipv6-new-port",
            starttime=start + 61,
            saddr="fd00:1::10",
            daddr="fd00:1::20",
            dport=23423,
            dmac="02:00:00:00:00:20",
        ),
    }
    module.handle_flow(candidate)
    module.db.set_evidence.assert_called_once()
    module.db.set_evidence.reset_mock()
    state.update(gateway_mac="02:00:00:00:00:99", changed_at=start + 100)
    module._networks.clear()
    candidate["flow"].update(uid="other-network", starttime=start + 101)
    module.handle_flow(candidate)
    module.db.set_evidence.assert_not_called()


@pytest.mark.parametrize(
    "changes",
    [
        {"first_seen": -1},
        {"last_seen": float("nan")},
        {"ports": {"tcp:0": {"first_reply": 1, "normal": True}}},
        {"ports": {"tcp:22": {"first_reply": 1, "normal": "true"}}},
    ],
)
def test_invalid_host_checkpoints_are_rejected(changes: dict) -> None:
    """Reject corrupt saved host state instead of silently restarting its learning.

    Parameters:
        changes: Corrupt persisted field.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    data = {"first_seen": 100, "last_seen": 200, **changes}
    with pytest.raises((ValueError, TypeError)):
        HostServices.from_dict(data, module.settings)
