"""Tests for permanent, network-scoped host identity storage."""

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from slips_files.core.database.sqlite_db import host_profiles
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("delayed", [False, True])
def test_poll_gap_keeps_hotspot_hosts_on_the_hotspot(
    tmp_path: Path, delayed: bool
) -> None:
    """Persist frame hardware and observations under the corroborated network.

    Parameters:
        tmp_path: Isolated host archive.
        delayed: Whether Home Wi-Fi is already current during processing.
    """
    _factory = ModuleFactory()
    home = {
        "changed_at": 1793385000,
        "local_network": "192.168.1.0/24",
        "gateway_mac": "d8:58:d7:1:ff:e1",
    }
    hotspot = {
        "changed_at": 1793385863.053489,
        "local_network": "172.20.10.0/28",
        "host_ip": "172.20.10.2",
        "mac": "12:5b:07:66:c0:22",
        "gateway_ip": "172.20.10.1",
        "gateway_mac": "ce:3f:36:4b:ad:64",
    }
    state = (
        dict(home, changed_at=1793385953.500989, history=[home, hotspot])
        if delayed
        else dict(hotspot, history=[home])
    )
    path = tmp_path / "hosts.sqlite"
    store = HostProfileStore(path, "roaming", lambda _: state, ["en0"])
    store.observe_flow(
        SimpleNamespace(
            type_="conn",
            interface="en0",
            starttime=1793385861.47659,
            saddr="172.20.10.1",
            daddr="172.20.10.2",
            smac="ce:3f:36:4b:ad:64",
            dmac="12:5b:07:66:c0:22",
        )
    )
    for address, mac in [
        ("172.20.10.1", "ce:3f:36:4b:ad:64"),
        ("172.20.10.2", "12:5b:07:66:c0:22"),
    ]:
        profiles = HostProfileStore.read(path, address)
        assert len(profiles) == 1
        assert profiles[0]["network_id"] == "gateway:ce:3f:36:4b:ad:64"
        assert any(
            fact["kind"] == "mac" and fact["value"] == mac
            for fact in profiles[0]["facts"]
        )


@pytest.mark.parametrize("known_network", [False, True])
def test_arp_name_follows_mac_and_does_not_follow_a_reused_ip(
    tmp_path: Path, known_network: bool
) -> None:
    """Keep a saved device name on its MAC across addresses and restarts.

    Parameters:
        tmp_path: Isolated permanent database.
        known_network: Whether the router MAC is known during capture.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {"local_network": "192.168.1.0/24", "gateway_ip": "192.168.1.1",
             "gateway_mac": "aa:bb:cc:dd:ee:01" if known_network else ""}
    store = HostProfileStore(path, "run", lambda _: state, ["en0"])
    store.observe_flow(SimpleNamespace(type_="arp", interface="en0", starttime=100,
        saddr="192.168.1.20", daddr="192.168.1.1", operation="request",
        src_hw="02:00:00:00:00:20", smac="02:00:00:00:00:20", dst_hw="00:00:00:00:00:00", dmac="ff:ff:ff:ff:ff:ff"))
    network_id = HostProfileStore.read(path, "192.168.1.20")[0]["network_id"]
    HostProfileStore.set_host_annotation(path, "192.168.1.20", network_id, "iPad-Storm", "Tablet")
    restarted = HostProfileStore(path, "run", lambda _: state, ["en0"])
    restarted.observe_flow(SimpleNamespace(type_="conn", interface="en0", starttime=200,
        saddr="fe80::20", daddr="ff02::fb", smac="02:00:00:00:00:20", dmac="33:33:00:00:00:fb"))
    assert HostProfileStore.read(path, "fe80::20")[0]["user_name"] == "iPad-Storm"
    restarted.observe_flow(SimpleNamespace(type_="arp", interface="en0", starttime=300,
        saddr="192.168.1.20", daddr="192.168.1.1", operation="request",
        src_hw="02:00:00:00:00:99", smac="02:00:00:00:00:99", dst_hw="00:00:00:00:00:00", dmac="ff:ff:ff:ff:ff:ff"))
    assert HostProfileStore.read(path, "192.168.1.20")[0]["user_name"] == ""
    assert HostProfileStore.read(path, "fe80::20")[0]["user_name"] == "iPad-Storm"
    assert not any(fact["kind"] == "mac" for fact in HostProfileStore.read(path, "192.168.1.1")[0]["facts"])


@pytest.mark.parametrize(
    "kind, target, target_mac, hardware, expected",
    [
        ("conn", "8.8.8.8", "aa:bb:cc:dd:ee:01", "", ""),
        ("conn", "172.17.0.1", "aa:bb:cc:dd:ee:01", "", ""),
        ("conn", "192.168.1.30", "aa:bb:cc:dd:ee:01", "", ""),
        ("conn", "192.168.1.1", "aa:bb:cc:dd:ee:01", "", "aa:bb:cc:dd:ee:01"),
        ("conn", "fe80::30", "02:00:00:00:00:30", "", "02:00:00:00:00:30"),
        ("arp", "192.168.1.30", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", ""),
        ("arp", "192.168.1.30", "02:00:00:00:00:30", "02:00:00:00:00:30", "02:00:00:00:00:30"),
    ],
)
def test_endpoint_mac_requires_local_ownership(
    tmp_path: Path, kind: str, target: str, target_mac: str,
    hardware: str, expected: str,
) -> None:
    """Retain local endpoint MACs without assigning a router MAC to routed IPs.

    Parameters:
        tmp_path: Isolated database directory.
        kind: Parsed connection or ARP record.
        target: Destination IP address.
        target_mac: Destination Ethernet address.
        hardware: Explicit ARP target hardware address.
        expected: Accepted device MAC, or empty if ownership is unproven.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {"local_network": "192.168.1.0/24", "gateway_ip": "192.168.1.1",
             "gateway_mac": "aa:bb:cc:dd:ee:01"}
    store = HostProfileStore(path, "run", lambda _: state, ["en0"])
    store.observe_flow(SimpleNamespace(type_=kind, interface="en0", starttime=100,
        saddr="192.168.1.20", daddr=target, smac="02:00:00:00:00:20",
        dmac=target_mac, dst_hw=hardware))
    facts = HostProfileStore.read(path, target)[0]["facts"]
    assert [fact["value"] for fact in facts if fact["kind"] == "mac"] == (
        [expected] if expected else []
    )


def test_repeated_mac_writes_are_throttled_and_changes_are_immediate(
    tmp_path: Path,
) -> None:
    """Avoid per-connection MAC writes while recording replacement devices.

    Parameters:
        tmp_path: Isolated database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    store = HostProfileStore(path, "run", lambda _: {
        "local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:01",
    }, ["en0"])
    flow = SimpleNamespace(type_="conn", interface="en0", starttime=100,
        saddr="192.168.1.20", daddr="8.8.8.8", smac="02:00:00:00:00:20")
    with patch.object(host_profiles.time, "monotonic", return_value=100):
        store.observe_flow(flow)
        store.observe_flows([flow] * 100)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT SUM(observations) FROM facts WHERE kind='mac'").fetchone()[0] == 1
    with patch.object(host_profiles.time, "monotonic", return_value=101):
        flow.smac = "02:00:00:00:00:99"
        store.observe_flow(flow)
    with patch.object(host_profiles.time, "monotonic", return_value=162):
        store.observe_flow(flow)
    with sqlite3.connect(path) as connection:
        assert dict(connection.execute("SELECT value, observations FROM facts WHERE kind='mac'")) == {
            "02:00:00:00:00:20": 1, "02:00:00:00:00:99": 2,
        }


def test_legacy_annotation_uses_mac_observed_when_named(tmp_path: Path) -> None:
    """Recover old annotations without naming a newer device at the same IP.

    Parameters:
        tmp_path: Isolated database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    store = HostProfileStore(path, "run", lambda _: {
        "local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:01",
    }, ["en0"])
    for ip, mac, timestamp in [("192.168.1.20", "02:00:00:00:00:20", 100),
                               ("192.168.1.20", "02:00:00:00:00:99", 300),
                               ("fe80::20", "02:00:00:00:00:20", 400)]:
        store.observe_flow(SimpleNamespace(type_="conn", interface="en0", starttime=timestamp,
            saddr=ip, daddr="8.8.8.8", smac=mac))
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO host_annotations VALUES (?, ?, ?, ?, ?)",
            ("gateway:aa:bb:cc:dd:ee:01", "192.168.1.20", "iPad-Storm", "Tablet", 200))
    assert HostProfileStore.read(path, "192.168.1.20")[0]["user_name"] == ""
    alias = HostProfileStore.read(path, "fe80::20")[0]
    assert (alias["user_name"], alias["user_note"]) == ("iPad-Storm", "Tablet")


def test_network_scoped_annotations_do_not_name_an_unverified_reused_ip(
    tmp_path: Path,
) -> None:
    """A name from a previous network cannot label the current reused address.

    Parameters:
        tmp_path: Isolated permanent database.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    old = {
        "gateway_mac": "aa:bb:cc:dd:ee:01",
        "local_network": "192.168.1.0/24",
    }
    store = HostProfileStore(path, "old", lambda _: old, ["en0"])
    store.observe_flow(
        SimpleNamespace(
            type_="conn",
            interface="en0",
            starttime=100,
            saddr="192.168.1.112",
            daddr="8.8.8.8",
        )
    )
    HostProfileStore.set_host_annotation(
        path,
        "192.168.1.112",
        "gateway:aa:bb:cc:dd:ee:01",
        "iPad-Storm",
        "Tablet",
    )
    assert (
        HostProfileStore.annotations_for_ips(
            path, ["192.168.1.112"], ["gateway:aa:bb:cc:dd:ee:02"]
        )
        == {}
    )
    assert (
        HostProfileStore.annotations_for_ips(
            path, ["192.168.1.112"], ["gateway:aa:bb:cc:dd:ee:01"]
        )["192.168.1.112"]["name"]
        == "iPad-Storm"
    )


@pytest.mark.parametrize("recorded", [False, True])
def test_replayed_identity_never_uses_a_later_network(
    tmp_path: Path, recorded: bool
) -> None:
    """A retained DNS row cannot assign an old device to today's reused IP.

    Parameters:
        tmp_path: Isolated permanent database.
        recorded: Whether packet-time network settings are still available.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    previous = {
        "changed_at": 100,
        "gateway_mac": "aa:bb:cc:dd:ee:01",
        "local_network": "192.168.1.0/24",
    }
    current = {
        "changed_at": 300,
        "gateway_mac": "aa:bb:cc:dd:ee:02",
        "local_network": "192.168.1.0/24",
        "history": [previous] if recorded else [],
    }
    store = HostProfileStore(path, "replay", lambda _: current, ["en0"])
    store.observe_flow(
        SimpleNamespace(
            type_="dns",
            interface="en0",
            starttime=150,
            saddr="192.168.1.1",
            daddr="224.0.0.251",
            sport=5353,
            dport=5353,
            query="storm.local",
            answers=["192.168.1.112"],
            mdns_bindings=["storm.local|192.168.1.112"],
        )
    )
    profiles = HostProfileStore.read(path, "192.168.1.112")
    assert profiles[0]["network_id"] == (
        "gateway:aa:bb:cc:dd:ee:01" if recorded else "run:replay"
    )
    assert all(
        profile["network_id"] != "gateway:aa:bb:cc:dd:ee:02"
        for profile in profiles
    )


@pytest.mark.parametrize("ipad_mac", ["", "02:00:00:00:01:12"])
def test_ambiguous_mdns_answers_never_transfer_a_saved_device_name(
    tmp_path: Path, ipad_mac: str
) -> None:
    """A router answering an iPad query must not inherit its manual name.

    Parameters:
        tmp_path: Isolated permanent database.
        ipad_mac: Whether the named iPad has a known MAC address.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {
        "gateway_mac": "aa:bb:cc:dd:ee:01",
        "local_network": "192.168.1.0/24",
    }
    store = HostProfileStore(path, "run", lambda _: state, ["en0"])
    for ip in ("192.168.1.112", "192.168.1.1"):
        store.observe_flow(
            SimpleNamespace(
                interface="en0",
                starttime=100,
                type_="conn",
                saddr=ip,
                daddr="8.8.8.8",
            )
        )
    with sqlite3.connect(path) as connection:
        for ip in ("192.168.1.112", "192.168.1.1"):
            connection.execute(
                "INSERT INTO facts VALUES (?, ?, 'mdns_name', 'storm.local', 100, 100, 1)",
                ("gateway:aa:bb:cc:dd:ee:01", ip),
            )
        if ipad_mac:
            connection.execute(
                "INSERT INTO facts VALUES (?, ?, 'mac', ?, 100, 100, 1)",
                ("gateway:aa:bb:cc:dd:ee:01", "192.168.1.112", ipad_mac),
            )
    HostProfileStore.set_host_annotation(
        path,
        "192.168.1.112",
        "gateway:aa:bb:cc:dd:ee:01",
        "iPad-Storm",
        "Tablet",
    )
    names = HostProfileStore.annotations_for_ips(
        path, ["192.168.1.112", "192.168.1.1"]
    )
    assert names["192.168.1.112"] == {"name": "iPad-Storm", "note": "Tablet"}
    assert names["192.168.1.1"] == {"name": "", "note": ""}


@pytest.mark.parametrize("mdns", [False, True])
def test_dns_advertisements_do_not_establish_device_network_presence(
    tmp_path: Path, mdns: bool,
) -> None:
    """Advertising a home address from a guest capture cannot record its visit.

    Parameters:
        tmp_path: Isolated permanent identity database.
        mdns: Include an explicit multicast DNS address-owner binding.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    home = {"changed_at":100,"gateway_mac":"aa:bb:cc:dd:ee:01","local_network":"192.168.1.0/24"}
    guest = {"changed_at":200,"gateway_mac":"aa:bb:cc:dd:ee:02","local_network":"192.168.1.0/24"}
    ip = "192.168.1.185"
    store = HostProfileStore(path,"home",lambda _: home,["en0"])
    store.observe_flow(SimpleNamespace(type_="arp",interface="en0",starttime=110,
        saddr=ip,daddr="192.168.1.1",src_hw="2c:cf:67:5a:2e:bd",dst_hw="00:00:00:00:00:00"))
    HostProfileStore.set_host_annotation(path,ip,"gateway:aa:bb:cc:dd:ee:01","homeassistant","Keep this name")
    other = HostProfileStore(path,"guest",lambda _: guest,["en0"])
    other.observe_flow(SimpleNamespace(type_="dns",interface="en0",starttime=210,
        saddr="192.168.1.1",daddr="224.0.0.251" if mdns else "192.168.1.100",
        sport=5353 if mdns else 53,dport=5353 if mdns else 50000,
        query="homeassistant.local",answers=[ip],
        mdns_bindings=[f"homeassistant.local|{ip}"] if mdns else []))
    profiles = {row["network_id"]:row for row in HostProfileStore.read(path,ip)}
    assert profiles["gateway:aa:bb:cc:dd:ee:01"]["user_name"] == "homeassistant"
    assert profiles["gateway:aa:bb:cc:dd:ee:01"]["endpoint_last_seen"] == 110
    advertised = profiles["gateway:aa:bb:cc:dd:ee:02"]
    assert advertised["endpoint_last_seen"] is None
    assert advertised["user_name"] == ""
    assert advertised["facts"][0]["kind"] == ("mdns_hostname" if mdns else "dns_name")
    observed = HostProfileStore.observation_times(path,["gateway:aa:bb:cc:dd:ee:02"])
    assert ip not in observed
    assert observed["192.168.1.1"] == 210
    assert HostProfileStore.network_for_observation(path,ip,210)["network_id"] == ""


@pytest.mark.parametrize("kind", ["hostname", "reverse_dns"])
def test_cached_private_identity_does_not_create_a_named_network_visit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    """Keep cached names without claiming the device visited the current network.

    Parameters:
        tmp_path: Isolated permanent identity database.
        monkeypatch: Advance metadata time after roaming.
        kind: Cached identity update being retained.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    home = {"gateway_mac":"aa:bb:cc:dd:ee:01","local_network":"192.168.1.0/24"}
    store = HostProfileStore(path,"home",lambda _: home,["en0"])
    store.observe_flow(SimpleNamespace(type_="conn",interface="en0",starttime=110,
        saddr="192.168.1.185",daddr="8.8.8.8"))
    guest = {"gateway_mac":"aa:bb:cc:dd:ee:02","local_network":"192.168.1.0/24"}
    other = HostProfileStore(path,"guest",lambda _: guest,["en0"])
    monkeypatch.setattr(host_profiles.time,"time",lambda:300)
    if kind == "hostname":
        other.observe_hostname("homeassistant","profile_192.168.1.185")
    else:
        other.observe_ip_info("192.168.1.185",{"reverse_dns":"homeassistant.local"})
    profiles = HostProfileStore.read(path,"192.168.1.185")
    assert {row["network_id"] for row in profiles} == {"gateway:aa:bb:cc:dd:ee:01","run:guest"}
    assert HostProfileStore.observation_times(path,["gateway:aa:bb:cc:dd:ee:02"]) == {}
    assert next(row for row in profiles if row["network_id"]=="run:guest")["endpoint_last_seen"] is None


@pytest.mark.parametrize("migrated", [False, True])
def test_legacy_observations_do_not_prove_endpoint_presence(
    tmp_path: Path, migrated: bool,
) -> None:
    """Retain earlier data while refusing unverified legacy network visits.

    Parameters:
        tmp_path: Isolated permanent identity database.
        migrated: Whether the new endpoint table has already been created.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    HostProfileStore(path,"old",lambda _: {},[])
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO hosts VALUES ('gateway:guest','192.168.1.185','Stratoguest',100,500)")
        connection.execute("INSERT INTO host_observations VALUES ('gateway:guest','192.168.1.185',100,500)")
        if not migrated:
            connection.execute("DROP TABLE host_endpoint_observations")
    assert HostProfileStore.observation_times(path,["gateway:guest"]) == {}
    assert HostProfileStore.network_for_observation(path,"192.168.1.185",300)["network_id"] == ""
    profiles = HostProfileStore.read(path,"192.168.1.185")
    assert profiles[0]["network_label"] == "Stratoguest"
    assert profiles[0]["endpoint_last_seen"] is None
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM host_observations").fetchone()[0] == 1


def test_public_endpoint_keeps_its_public_identity_namespace(tmp_path: Path) -> None:
    """Record remote traffic in its capture without treating the public IP as local.

    Parameters:
        tmp_path: Isolated permanent identity database.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {"gateway_mac":"aa:bb:cc:dd:ee:01","local_network":"192.168.1.0/24"}
    store = HostProfileStore(path,"home",lambda _: state,["en0"])
    store.observe_flow(SimpleNamespace(type_="conn",interface="en0",starttime=110,
        saddr="192.168.1.20",daddr="8.8.8.8"))
    assert HostProfileStore.network_for_observation(path,"8.8.8.8",110) == {
        "network_id":"public","network_name":"","network_label":"Public internet"}
    assert HostProfileStore.observation_times(path,["gateway:aa:bb:cc:dd:ee:01"])["8.8.8.8"] == 110


def test_only_parsed_traffic_advances_network_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Names and IP metadata never move the network's actual observation time.

    Parameters:
        tmp_path: Isolated permanent database.
        monkeypatch: Advances the metadata clock without observing another packet.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {
        "gateway_mac": "aa:bb:cc:dd:ee:01",
        "local_network": "192.168.1.0/24",
        "changed_at": 100,
    }
    store = HostProfileStore(path, "run", lambda _: state, ["en0"])
    store.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime=110,
            type_="arp",
            saddr="192.168.1.20",
            daddr="192.168.1.1",
        )
    )
    monkeypatch.setattr(
        "slips_files.core.database.sqlite_db.host_profiles.time.time",
        lambda: 500,
    )
    store.observe_hostname("refreshed-name", "profile_192.168.1.20")
    store.observe_ip_info("192.168.1.20", {"reverse_dns": "refreshed.local"})
    assert HostProfileStore.read(path, "192.168.1.20")[0]["last_seen"] == 110
    assert (
        HostProfileStore.observation_times(
            path, ["gateway:aa:bb:cc:dd:ee:01"]
        )["192.168.1.20"]
        == 110
    )
    state = {
        "gateway_mac": "aa:bb:cc:dd:ee:02",
        "local_network": "192.168.1.0/24",
        "changed_at": 200,
    }
    other = HostProfileStore(path, "second", lambda _: state, ["en0"])
    other.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime=210,
            type_="arp",
            saddr="192.168.1.20",
            daddr="192.168.1.1",
        )
    )
    assert (
        HostProfileStore.observation_times(
            path, ["gateway:aa:bb:cc:dd:ee:02"]
        )["192.168.1.20"]
        == 210
    )
    assert (
        HostProfileStore.observation_times(
            path, ["gateway:aa:bb:cc:dd:ee:01"]
        )["192.168.1.20"]
        == 110
    )


def test_triage_persists_by_verified_mac_and_isolates_reused_ips(tmp_path: Path) -> None:
    """Review marks follow a known MAC but never an unrelated device reusing its IP."""
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {"local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:01"}
    store = HostProfileStore(path, "first", lambda _: state, ["en0"])
    store.observe_flow(SimpleNamespace(interface="en0", starttime="100", type_="dhcp",
        saddr="192.168.1.20", daddr="192.168.1.1", host_name="laptop", smac="02:00:00:00:00:20"))
    HostProfileStore.set_host_annotation(path, "192.168.1.20", "gateway:aa:bb:cc:dd:ee:01", "Laptop", "Check DNS")
    HostProfileStore.set_host_triage(path, "192.168.1.20", "gateway:aa:bb:cc:dd:ee:01", "to_analyze", ["lab", "dns"])
    restarted = HostProfileStore(path, "second", lambda _: state, ["en0"])
    restarted.observe_flow(SimpleNamespace(interface="en0", starttime="200", type_="dhcp",
        saddr="192.168.1.21", daddr="192.168.1.1", host_name="laptop", smac="02:00:00:00:00:20"))
    assert HostProfileStore.triage_for_ips(path, ["192.168.1.21"])["192.168.1.21"] == {
        "status": "to_analyze", "labels": ["lab", "dns"]}
    assert HostProfileStore.annotations_for_ips(path, ["192.168.1.21"])["192.168.1.21"]["note"] == "Check DNS"
    state = {"local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:02"}
    other = HostProfileStore(path, "third", lambda _: state, ["en0"])
    other.observe_flow(SimpleNamespace(interface="en0", starttime="300", type_="dhcp",
        saddr="192.168.1.20", daddr="192.168.1.1", host_name="unrelated", smac="02:00:00:00:00:30"))
    profiles = HostProfileStore.triage_for_profiles(path, ["192.168.1.20"])
    assert profiles[("gateway:aa:bb:cc:dd:ee:02", "192.168.1.20")] == {"status": "", "labels": []}
    assert HostProfileStore.triage_for_ips(path, ["192.168.1.20"])["192.168.1.20"] == {"status": "", "labels": []}
    assert profiles[("gateway:aa:bb:cc:dd:ee:01", "192.168.1.20")]["status"] == "to_analyze"
    HostProfileStore.set_host_triage(path, "192.168.1.21", "gateway:aa:bb:cc:dd:ee:01", "", [])
    assert HostProfileStore.triage_for_ips(path, ["192.168.1.20", "192.168.1.21"])["192.168.1.21"] == {"status": "", "labels": []}


def test_own_interface_mac_is_saved_without_gateway_mac_confusion(tmp_path: Path) -> None:
    """Learn this machine's L2 address for its IPv4 and IPv6 profiles."""
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {"local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:01",
             "host_ip": "192.168.1.163", "mac": "02:00:00:00:00:20",
             "addresses": [{"ip": "192.168.1.163"}, {"ip": "fe80::20"}]}
    store = HostProfileStore(path, "run", lambda _: state, ["en0"])
    for ip in ("192.168.1.163", "fe80::20", "8.8.8.8"):
        store.observe_flow(SimpleNamespace(interface="en0", starttime="100", type_="conn", saddr=ip, daddr="1.1.1.1"))
    for ip in ("192.168.1.163", "fe80::20"):
        macs = [fact["value"] for fact in HostProfileStore.read(path, ip)[0]["facts"] if fact["kind"] == "mac"]
        assert macs == [state["mac"]]
    assert not any(fact["kind"] == "mac" for fact in HostProfileStore.read(path, "8.8.8.8")[0]["facts"])


def test_review_write_failure_rolls_back_name_and_note(tmp_path: Path) -> None:
    """A failed mark write cannot leave a partially saved host review.

    Parameters:
        tmp_path: Isolated permanent database location.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    store = HostProfileStore(path, "run", lambda _: {}, [])
    store.observe_hostname("dns.google", "profile_8.8.8.8")
    HostProfileStore.set_host_annotation(path, "8.8.8.8", "public", "DNS", "Original note")
    with patch.object(HostProfileStore, "set_host_triage", side_effect=sqlite3.OperationalError("write failed")):
        with pytest.raises(sqlite3.OperationalError):
            HostProfileStore.set_host_annotation(path, "8.8.8.8", "public", "Changed", "Changed note", "reviewed", ["dns"])
    annotation = HostProfileStore.annotations_for_ips(path, ["8.8.8.8"])["8.8.8.8"]
    assert annotation == {"name": "DNS", "note": "Original note"}


def test_profiles_persist_across_runs_and_separate_private_networks(
    tmp_path: Path,
) -> None:
    """Reuse public clues while isolating identical local IPs by router MAC.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    first = HostProfileStore(path, "run-one", lambda _: state, ["en0"])
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    first.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime="100",
            type_="http",
            saddr="192.168.1.20",
            daddr="8.8.8.8",
            host="example.org",
            uri="/about",
        )
    )
    first.observe_ip_info(
        "8.8.8.8",
        {
            "reverse_dns": "dns.google",
            "asn": {"number": "AS15169", "org": "Example Network"},
            "threatintelligence": {"source": ["feed-one"]},
        },
    )
    first.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime="110",
            type_="ssl",
            saddr="192.168.1.20",
            daddr="8.8.8.8",
            server_name="secure.example.org",
        )
    )

    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:02",
    }
    second = HostProfileStore(path, "run-two", lambda _: state, ["en0"])
    second.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime="200",
            type_="dhcp",
            saddr="192.168.1.20",
            daddr="192.168.1.1",
            host_name="other-laptop",
            smac="02:00:00:00:00:20",
        )
    )

    local = HostProfileStore.read(path, "192.168.1.20")
    public = HostProfileStore.read(path, "8.8.8.8")

    assert len(local) == 2
    assert local[0]["network_id"] == "gateway:aa:bb:cc:dd:ee:02"
    assert local[1]["network_id"] == "gateway:aa:bb:cc:dd:ee:01"
    assert {fact["value"] for fact in local[0]["facts"]} == {
        "other-laptop",
        "02:00:00:00:00:20",
    }
    assert len(public) == 1
    assert public[0]["network_id"] == "public"
    assert {fact["value"] for fact in public[0]["facts"]} >= {
        "example.org",
        "http://example.org/about",
        "dns.google",
        "AS15169 Example Network",
        "feed-one",
        "secure.example.org",
    }


def test_ipv6_link_local_uses_the_captured_network(tmp_path: Path) -> None:
    """Keep link-local hosts on the interface's known router network.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {
        "interface": "en0",
        "local_network": "192.168.1.0/24",
        "gateway_mac": "AA:BB:CC:DD:EE:01",
    }
    store = HostProfileStore(path, "run-one", lambda _: state, ["en0"])
    store.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime="100",
            type_="conn",
            saddr="fe80::1234",
            daddr="fe80::5678",
        )
    )

    profile = HostProfileStore.read(path, "fe80::1234")[0]
    assert profile["network_id"] == "gateway:aa:bb:cc:dd:ee:01"
    assert profile["network_label"] == ("Link-local on en0 · router aa:bb:cc:dd:ee:01")


def test_user_annotation_persists_for_exact_network_host(
    tmp_path: Path,
) -> None:
    """Keep a manual name and note separate for reused private IPs.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = HostProfileStore(path, "run-one", lambda _: state, ["en0"])
    store.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime="100",
            type_="conn",
            saddr="192.168.1.20",
            daddr="8.8.8.8",
        )
    )
    network_id = "gateway:aa:bb:cc:dd:ee:01"
    HostProfileStore.set_host_annotation(
        path, "192.168.1.20", network_id, "My iPad", "Tablet in the kitchen"
    )

    state["gateway_mac"] = "aa:bb:cc:dd:ee:02"
    another = HostProfileStore(path, "run-two", lambda _: state, ["en0"])
    another.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime="200",
            type_="conn",
            saddr="192.168.1.20",
            daddr="8.8.8.8",
        )
    )
    profiles = HostProfileStore.read(path, "192.168.1.20")

    assert profiles[0]["user_name"] == ""
    assert profiles[1]["user_name"] == "My iPad"
    assert profiles[1]["user_note"] == "Tablet in the kitchen"
    assert HostProfileStore.annotations_for_ips(path, ["192.168.1.20"])[
        "192.168.1.20"
    ] == {"name": "", "note": ""}

    HostProfileStore.set_host_annotation(path, "192.168.1.20", network_id, "", "")
    assert HostProfileStore.read(path, "192.168.1.20")[1]["user_name"] == ""


@pytest.mark.parametrize("known_mac", [False, True])
def test_saved_name_uses_mac_before_confirmed_mdns(
    tmp_path: Path, known_mac: bool,
) -> None:
    """Keep names on known MACs, with confirmed mDNS fallback for unknown MACs.

    Parameters:
        tmp_path: Isolated permanent database directory.
        known_mac: Whether each address belongs to a different known MAC.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    HostProfileStore(path, "run-one", lambda _: {}, ["en0"])
    with sqlite3.connect(path) as connection:
        for index, ip in enumerate(("192.168.1.20", "192.168.1.21", "192.168.1.22")):
            network_id = f"gateway:aa:bb:cc:dd:ee:0{index + 1}"
            connection.execute(
                "INSERT INTO hosts VALUES (?, ?, ?, ?, ?)",
                (network_id, ip, "Home", float(index), float(index)),
            )
            connection.execute(
                "INSERT INTO facts VALUES (?, ?, ?, ?, ?, ?, ?)",
                (network_id, ip, "mdns_hostname", "cherry.local", 1, 1, 1),
            )
            if known_mac:
                connection.execute(
                    "INSERT INTO facts VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        network_id,
                        ip,
                        "mac",
                        f"02:00:00:00:00:0{index + 1}",
                        1,
                        1,
                        1,
                    ),
                )
        connection.execute(
            "INSERT INTO host_annotations VALUES (?, ?, ?, ?, ?)",
            ("gateway:aa:bb:cc:dd:ee:01", "192.168.1.20", "Cherry", "", 1),
        )

    assert HostProfileStore.read(path, "192.168.1.21")[0]["user_name"] == (
        "" if known_mac else "Cherry"
    )
    HostProfileStore.set_host_annotation(
        path, "192.168.1.21", "gateway:aa:bb:cc:dd:ee:02", "Cherry II", ""
    )
    assert HostProfileStore.read(path, "192.168.1.22")[0]["user_name"] == (
        "" if known_mac else "Cherry II"
    )
    assert HostProfileStore.read(path, "192.168.1.21")[0]["user_name"] == "Cherry II"
    assert HostProfileStore.read(path, "192.168.1.20")[0]["user_name"] == "Cherry"
    HostProfileStore.set_host_annotation(
        path, "192.168.1.21", "gateway:aa:bb:cc:dd:ee:02", "", ""
    )
    assert HostProfileStore.read(path, "192.168.1.22")[0]["user_name"] == ""


def test_device_annotation_survives_network_and_address_changes(
    tmp_path: Path,
) -> None:
    """Keep an old saved name on the same MAC, without naming a reused IP.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    network = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    old = HostProfileStore(path, "old-run", lambda _: network, ["en0"])
    old.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime="100",
            type_="dhcp",
            saddr="192.168.1.20",
            daddr="192.168.1.1",
            host_name="",
            smac="02:00:00:00:00:20",
        )
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO host_annotations VALUES (?, ?, ?, ?, ?)",
            (
                "gateway:aa:bb:cc:dd:ee:01",
                "192.168.1.20",
                "Cherry",
                "My device",
                150.0,
            ),
        )

    network["gateway_mac"] = "aa:bb:cc:dd:ee:02"
    current = HostProfileStore(path, "new-run", lambda _: network, ["en0"])
    for ip, mac, when in (
        ("192.168.1.21", "02:00:00:00:00:20", "200"),
        ("192.168.1.20", "02:00:00:00:00:21", "201"),
    ):
        current.observe_flow(
            SimpleNamespace(
                interface="en0",
                starttime=when,
                type_="dhcp",
                saddr=ip,
                daddr="192.168.1.1",
                host_name="",
                smac=mac,
            )
        )
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE device_annotations")

    assert HostProfileStore.read(path, "192.168.1.21")[0]["user_name"] == "Cherry"
    assert HostProfileStore.read(path, "192.168.1.20")[0]["user_name"] == ""
    assert HostProfileStore.annotations_for_ips(
        path, ["192.168.1.21", "192.168.1.20"]
    ) == {
        "192.168.1.21": {"name": "Cherry", "note": "My device"},
        "192.168.1.20": {"name": "", "note": ""},
    }

    HostProfileStore.set_host_annotation(
        path,
        "192.168.1.21",
        "gateway:aa:bb:cc:dd:ee:02",
        "Cherry II",
        "Updated note",
    )
    assert HostProfileStore.read(path, "192.168.1.21")[0]["user_name"] == "Cherry II"
    assert HostProfileStore.read(path, "192.168.1.20")[1]["user_name"] == "Cherry II"

    HostProfileStore.set_host_annotation(
        path, "192.168.1.21", "gateway:aa:bb:cc:dd:ee:02", "", ""
    )
    assert HostProfileStore.read(path, "192.168.1.21")[0]["user_name"] == ""
    assert HostProfileStore.read(path, "192.168.1.20")[1]["user_name"] == ""


@pytest.mark.parametrize(
    "value, expected",
    [
        ("02:AA:BB:CC:DD:EE", "02:aa:bb:cc:dd:ee"),
        ("00:00:00:00:00:00", ""),
        ("01:00:5e:00:00:01", ""),
        ("unknown", ""),
    ],
)
def test_device_annotation_uses_only_unicast_macs(value: str, expected: str) -> None:
    """Reject shared and invalid MACs before linking saved host names.

    Parameters:
        value: Candidate stored MAC value.
        expected: Safe normalized device MAC, if any.
    """
    _module_factory = ModuleFactory()
    assert HostProfileStore._usable_mac(value) == expected


@pytest.mark.parametrize(
    "port, expected_kind",
    [("5353", None), ("53", "dns_name")],
)
def test_dns_answers_identify_the_answered_host(
    tmp_path: Path, port: str, expected_kind: str | None
) -> None:
    """Keep flat multicast answers from asserting address ownership.

    Parameters:
        tmp_path: Isolated permanent database directory.
        port: DNS destination port.
        expected_kind: Stored name source.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    store = HostProfileStore(path, "run", lambda _: {}, [])
    store.observe_flow(
        SimpleNamespace(
            interface="",
            starttime="100",
            type_="dns",
            saddr="8.8.8.8",
            daddr="1.1.1.1",
            dport=port,
            query="printer.local",
            answers=["9.9.9.9", "not-an-ip"],
        )
    )

    profile = HostProfileStore.read(path, "9.9.9.9")[0]
    assert [(fact["kind"], fact["value"]) for fact in profile["facts"]] == (
        [(expected_kind, "printer.local")] if expected_kind else []
    )
    assert HostProfileStore.read(path, "not-an-ip") == []


def test_unknown_private_networks_do_not_merge_across_runs(
    tmp_path: Path,
) -> None:
    """Isolate local IPs when Slips cannot identify the actual network.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    for run in ("one", "two"):
        store = HostProfileStore(path, run, lambda _: {}, [])
        store.observe_hostname("device-" + run, "profile_10.0.0.5")

    profiles = HostProfileStore.read(path, "10.0.0.5")
    assert {profile["network_id"] for profile in profiles} == {
        "run:one",
        "run:two",
    }
    assert {
        tuple(fact["value"] for fact in profile["facts"]) for profile in profiles
    } == {("device-one",), ("device-two",)}


def test_distinct_clues_are_bounded_per_host_and_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Limit distinct URLs while retaining counts for an existing clue.

    Parameters:
        tmp_path: Isolated permanent database directory.
        monkeypatch: Restores the fact limit after the test.
    """
    _module_factory = ModuleFactory()
    monkeypatch.setattr(host_profiles, "MAX_FACTS_PER_KIND", 2)
    path = tmp_path / "host_profiles.sqlite"
    store = HostProfileStore(path, "run", lambda _: {}, [])
    for uri in ("/one", "/two", "/three", "/one"):
        store.observe_flow(
            SimpleNamespace(
                interface="",
                starttime="100",
                type_="http",
                saddr="8.8.8.8",
                daddr="9.9.9.9",
                host="example.org",
                uri=uri,
            )
        )

    facts = HostProfileStore.read(path, "9.9.9.9")[0]["facts"]
    urls = {fact["value"]: fact for fact in facts if fact["kind"] == "url"}
    assert set(urls) == {"http://example.org/one", "http://example.org/two"}
    assert urls["http://example.org/one"]["observations"] == 2


def test_historical_flow_keeps_its_capture_time(tmp_path: Path) -> None:
    """Use the capture timestamp when profiling an old saved file.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    store = HostProfileStore(path, "old-run", lambda _: {}, [])
    store.observe_flow(
        SimpleNamespace(
            interface="",
            starttime="2020-01-02T03:04:05+00:00",
            type_="ssl",
            saddr="8.8.8.8",
            daddr="9.9.9.9",
            server_name="old.example",
        )
    )

    expected = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc).timestamp()
    profile = HostProfileStore.read(path, "9.9.9.9")[0]
    assert profile["first_seen"] == expected
    assert profile["facts"][0]["first_seen"] == expected


def test_dhcp_request_identifies_client_before_it_has_an_address(
    tmp_path: Path,
) -> None:
    """Use the requested address when DHCP still reports an empty client IP.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    store = HostProfileStore(path, "run", lambda _: {}, [])
    store.observe_flow(
        SimpleNamespace(
            interface="",
            starttime="100",
            type_="dhcp",
            saddr="0.0.0.0",
            daddr="10.0.0.1",
            requested_addr="10.0.0.25",
            host_name="new-device",
            smac="02:00:00:00:00:25",
        )
    )

    profile = HostProfileStore.read(path, "10.0.0.25")[0]
    assert {fact["value"] for fact in profile["facts"]} == {
        "new-device",
        "02:00:00:00:00:25",
    }


@pytest.mark.parametrize(
    "ip,country,expected_country",
    [
        ("192.168.1.10", "Private", False),
        ("192.168.1.10", "United States", False),
        ("8.8.8.8", "Unknown", False),
        ("8.8.8.8", "United States", True),
    ],
)
def test_country_facts_are_real_public_geolocations(
    tmp_path: Path, ip: str, country: str, expected_country: bool
) -> None:
    """Ignore private/unknown labels, including facts saved by older runs.

    Parameters:
        tmp_path: Isolated permanent database directory.
        ip: Address whose country metadata is stored.
        country: Location label returned by IP info.
        expected_country: Whether the label is a real public geolocation.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    store = HostProfileStore(path, "run", lambda _: {}, [])
    store.observe_ip_info(ip, {"reverse_dns": "example.org", "geocountry": country})
    profile = HostProfileStore.read(path, ip)[0]
    saved_countries = {
        fact["value"] for fact in profile["facts"] if fact["kind"] == "country"
    }
    assert saved_countries == ({country} if expected_country else set())

    if not expected_country:
        with sqlite3.connect(path) as connection:
            connection.execute(
                "INSERT INTO facts VALUES (?, ?, ?, ?, ?, ?, ?)",
                (profile["network_id"], ip, "country", country, 1, 1, 1),
            )
        profile = HostProfileStore.read(path, ip)[0]
        assert all(fact["kind"] != "country" for fact in profile["facts"])


def test_network_names_survive_runs_and_label_existing_host_profiles(
    tmp_path: Path,
) -> None:
    """Apply a saved router name and a current-run name to earlier records.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    unidentified = HostProfileStore(path, "run-one", lambda _: {}, [])
    unidentified.observe_hostname("early-device", "profile_192.168.1.20")
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "AA:BB:CC:DD:EE:01",
    }
    identified = HostProfileStore(path, "run-two", lambda _: state, ["en0"])
    identified.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime="200",
            type_="conn",
            saddr="192.168.1.20",
            daddr="8.8.8.8",
        )
    )
    router_id = HostProfileStore.network_id_for_state(state, "run-two")
    HostProfileStore.set_network_name(path, router_id, "Home Wi-Fi")
    HostProfileStore.set_network_name(path, "run:run-one", "Home Wi-Fi")

    profiles = HostProfileStore.read(path, "192.168.1.20")

    assert router_id == "gateway:aa:bb:cc:dd:ee:01"
    assert {profile["network_label"] for profile in profiles} == {"Home Wi-Fi"}
    assert {profile["network_name"] for profile in profiles} == {"Home Wi-Fi"}
    assert HostProfileStore.network_names(path, [router_id])[router_id] == (
        "Home Wi-Fi"
    )
    HostProfileStore.set_network_name(path, router_id, "")
    assert router_id not in HostProfileStore.network_names(path, [router_id])
