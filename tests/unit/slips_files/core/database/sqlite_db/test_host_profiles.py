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
    store = _factory.create_host_profile_store_obj(path, "roaming", lambda _: state, ["en0"])
    store.save_host_identity_from_flow(
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
        profiles = store.get_host_profiles(address)
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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    store.save_host_identity_from_flow(SimpleNamespace(type_="arp", interface="en0", starttime=100,
        saddr="192.168.1.20", daddr="192.168.1.1", operation="request",
        src_hw="02:00:00:00:00:20", smac="02:00:00:00:00:20", dst_hw="00:00:00:00:00:00", dmac="ff:ff:ff:ff:ff:ff"))
    network_id = store.get_host_profiles("192.168.1.20")[0]["network_id"]
    store.set_host_annotation("192.168.1.20", network_id, "iPad-Storm", "Tablet")
    restarted = _module_factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    restarted.save_host_identity_from_flow(SimpleNamespace(type_="conn", interface="en0", starttime=200,
        saddr="fe80::20", daddr="ff02::fb", smac="02:00:00:00:00:20", dmac="33:33:00:00:00:fb"))
    assert restarted.get_host_profiles("fe80::20")[0]["user_name"] == "iPad-Storm"
    restarted.save_host_identity_from_flow(SimpleNamespace(type_="arp", interface="en0", starttime=300,
        saddr="192.168.1.20", daddr="192.168.1.1", operation="request",
        src_hw="02:00:00:00:00:99", smac="02:00:00:00:00:99", dst_hw="00:00:00:00:00:00", dmac="ff:ff:ff:ff:ff:ff"))
    assert restarted.get_host_profiles("192.168.1.20")[0]["user_name"] == ""
    assert restarted.get_host_profiles("fe80::20")[0]["user_name"] == "iPad-Storm"
    assert not any(fact["kind"] == "mac" for fact in restarted.get_host_profiles("192.168.1.1")[0]["facts"])


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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    store.save_host_identity_from_flow(SimpleNamespace(type_=kind, interface="en0", starttime=100,
        saddr="192.168.1.20", daddr=target, smac="02:00:00:00:00:20",
        dmac=target_mac, dst_hw=hardware))
    facts = store.get_host_profiles(target)[0]["facts"]
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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: {
        "local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:01",
    }, ["en0"])
    flow = SimpleNamespace(type_="conn", interface="en0", starttime=100,
        saddr="192.168.1.20", daddr="8.8.8.8", smac="02:00:00:00:00:20")
    with patch.object(host_profiles.time, "monotonic", return_value=100):
        store.save_host_identity_from_flow(flow)
        store.save_host_identity_from_flows([flow] * 100)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT SUM(observations) FROM facts WHERE kind='mac'").fetchone()[0] == 1
    with patch.object(host_profiles.time, "monotonic", return_value=101):
        flow.smac = "02:00:00:00:00:99"
        store.save_host_identity_from_flow(flow)
    with patch.object(host_profiles.time, "monotonic", return_value=162):
        store.save_host_identity_from_flow(flow)
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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: {
        "local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:01",
    }, ["en0"])
    for ip, mac, timestamp in [("192.168.1.20", "02:00:00:00:00:20", 100),
                               ("192.168.1.20", "02:00:00:00:00:99", 300),
                               ("fe80::20", "02:00:00:00:00:20", 400)]:
        store.save_host_identity_from_flow(SimpleNamespace(type_="conn", interface="en0", starttime=timestamp,
            saddr=ip, daddr="8.8.8.8", smac=mac))
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO host_annotations VALUES (?, ?, ?, ?, ?)",
            ("gateway:aa:bb:cc:dd:ee:01", "192.168.1.20", "iPad-Storm", "Tablet", 200))
    assert store.get_host_profiles("192.168.1.20")[0]["user_name"] == ""
    alias = store.get_host_profiles("fe80::20")[0]
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
    store = _module_factory.create_host_profile_store_obj(path, "old", lambda _: old, ["en0"])
    store.save_host_identity_from_flow(
        SimpleNamespace(
            type_="conn",
            interface="en0",
            starttime=100,
            saddr="192.168.1.112",
            daddr="8.8.8.8",
        )
    )
    store.set_host_annotation(
        "192.168.1.112",
        "gateway:aa:bb:cc:dd:ee:01",
        "iPad-Storm",
        "Tablet",
    )
    assert (
        store.get_annotations_of_ips(
            ["192.168.1.112"], ["gateway:aa:bb:cc:dd:ee:02"]
        )
        == {}
    )
    assert (
        store.get_annotations_of_ips(
            ["192.168.1.112"], ["gateway:aa:bb:cc:dd:ee:01"]
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
    store = _module_factory.create_host_profile_store_obj(path, "replay", lambda _: current, ["en0"])
    store.save_host_identity_from_flow(
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
    profiles = store.get_host_profiles("192.168.1.112")
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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    for ip in ("192.168.1.112", "192.168.1.1"):
        store.save_host_identity_from_flow(
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
    store.set_host_annotation(
        "192.168.1.112",
        "gateway:aa:bb:cc:dd:ee:01",
        "iPad-Storm",
        "Tablet",
    )
    names = store.get_annotations_of_ips(
        ["192.168.1.112", "192.168.1.1"]
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
    store = _module_factory.create_host_profile_store_obj(path,"home",lambda _: home,["en0"])
    store.save_host_identity_from_flow(SimpleNamespace(type_="arp",interface="en0",starttime=110,
        saddr=ip,daddr="192.168.1.1",src_hw="2c:cf:67:5a:2e:bd",dst_hw="00:00:00:00:00:00"))
    store.set_host_annotation(ip,"gateway:aa:bb:cc:dd:ee:01","homeassistant","Keep this name")
    other = _module_factory.create_host_profile_store_obj(path,"guest",lambda _: guest,["en0"])
    other.save_host_identity_from_flow(SimpleNamespace(type_="dns",interface="en0",starttime=210,
        saddr="192.168.1.1",daddr="224.0.0.251" if mdns else "192.168.1.100",
        sport=5353 if mdns else 53,dport=5353 if mdns else 50000,
        query="homeassistant.local",answers=[ip],
        mdns_bindings=[f"homeassistant.local|{ip}"] if mdns else []))
    profiles = {row["network_id"]:row for row in other.get_host_profiles(ip)}
    assert profiles["gateway:aa:bb:cc:dd:ee:01"]["user_name"] == "homeassistant"
    assert profiles["gateway:aa:bb:cc:dd:ee:01"]["endpoint_last_seen"] == 110
    advertised = profiles["gateway:aa:bb:cc:dd:ee:02"]
    assert advertised["endpoint_last_seen"] is None
    assert advertised["user_name"] == ""
    assert advertised["facts"][0]["kind"] == ("mdns_hostname" if mdns else "dns_name")
    observed = other.get_last_observation_times(["gateway:aa:bb:cc:dd:ee:02"])
    assert ip not in observed
    assert observed["192.168.1.1"] == 210
    assert other.get_network_of_observation(ip,210)["network_id"] == ""


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
    store = _module_factory.create_host_profile_store_obj(path,"home",lambda _: home,["en0"])
    store.save_host_identity_from_flow(SimpleNamespace(type_="conn",interface="en0",starttime=110,
        saddr="192.168.1.185",daddr="8.8.8.8"))
    guest = {"gateway_mac":"aa:bb:cc:dd:ee:02","local_network":"192.168.1.0/24"}
    other = _module_factory.create_host_profile_store_obj(path,"guest",lambda _: guest,["en0"])
    monkeypatch.setattr(host_profiles.time,"time",lambda:300)
    if kind == "hostname":
        other.save_hostname_of_profile("homeassistant","profile_192.168.1.185")
    else:
        other.save_host_identity_from_ip_info("192.168.1.185",{"reverse_dns":"homeassistant.local"})
    profiles = other.get_host_profiles("192.168.1.185")
    assert {row["network_id"] for row in profiles} == {"gateway:aa:bb:cc:dd:ee:01","run:guest"}
    assert other.get_last_observation_times(["gateway:aa:bb:cc:dd:ee:02"]) == {}
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
    store = _module_factory.create_host_profile_store_obj(path,"old",lambda _: {},[])
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO hosts VALUES ('gateway:guest','192.168.1.185','Stratoguest',100,500)")
        connection.execute("INSERT INTO host_observations VALUES ('gateway:guest','192.168.1.185',100,500)")
        if not migrated:
            connection.execute("DROP TABLE host_endpoint_observations")
    # the next Slips start adds the tables an older store is missing
    store = _module_factory.create_host_profile_store_obj(path, "new")
    assert store.get_last_observation_times(["gateway:guest"]) == {}
    assert store.get_network_of_observation("192.168.1.185",300)["network_id"] == ""
    profiles = store.get_host_profiles("192.168.1.185")
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
    store = _module_factory.create_host_profile_store_obj(path,"home",lambda _: state,["en0"])
    store.save_host_identity_from_flow(SimpleNamespace(type_="conn",interface="en0",starttime=110,
        saddr="192.168.1.20",daddr="8.8.8.8"))
    assert store.get_network_of_observation("8.8.8.8",110) == {
        "network_id":"public","network_name":"","network_label":"Public internet"}
    assert store.get_last_observation_times(["gateway:aa:bb:cc:dd:ee:01"])["8.8.8.8"] == 110


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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    store.save_host_identity_from_flow(
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
    store.save_hostname_of_profile("refreshed-name", "profile_192.168.1.20")
    store.save_host_identity_from_ip_info("192.168.1.20", {"reverse_dns": "refreshed.local"})
    assert store.get_host_profiles("192.168.1.20")[0]["last_seen"] == 110
    assert (
        store.get_last_observation_times(
            ["gateway:aa:bb:cc:dd:ee:01"]
        )["192.168.1.20"]
        == 110
    )
    state = {
        "gateway_mac": "aa:bb:cc:dd:ee:02",
        "local_network": "192.168.1.0/24",
        "changed_at": 200,
    }
    other = _module_factory.create_host_profile_store_obj(path, "second", lambda _: state, ["en0"])
    other.save_host_identity_from_flow(
        SimpleNamespace(
            interface="en0",
            starttime=210,
            type_="arp",
            saddr="192.168.1.20",
            daddr="192.168.1.1",
        )
    )
    assert (
        other.get_last_observation_times(
            ["gateway:aa:bb:cc:dd:ee:02"]
        )["192.168.1.20"]
        == 210
    )
    assert (
        other.get_last_observation_times(
            ["gateway:aa:bb:cc:dd:ee:01"]
        )["192.168.1.20"]
        == 110
    )


def test_triage_persists_by_verified_mac_and_isolates_reused_ips(tmp_path: Path) -> None:
    """Review marks follow a known MAC but never an unrelated device reusing its IP."""
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {"local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:01"}
    store = _module_factory.create_host_profile_store_obj(path, "first", lambda _: state, ["en0"])
    store.save_host_identity_from_flow(SimpleNamespace(interface="en0", starttime="100", type_="dhcp",
        saddr="192.168.1.20", daddr="192.168.1.1", host_name="laptop", smac="02:00:00:00:00:20"))
    store.set_host_annotation("192.168.1.20", "gateway:aa:bb:cc:dd:ee:01", "Laptop", "Check DNS")
    store.set_host_triage("192.168.1.20", "gateway:aa:bb:cc:dd:ee:01", "to_analyze", ["lab", "dns"])
    restarted = _module_factory.create_host_profile_store_obj(path, "second", lambda _: state, ["en0"])
    restarted.save_host_identity_from_flow(SimpleNamespace(interface="en0", starttime="200", type_="dhcp",
        saddr="192.168.1.21", daddr="192.168.1.1", host_name="laptop", smac="02:00:00:00:00:20"))
    assert restarted.get_triage_of_ips(["192.168.1.21"])["192.168.1.21"] == {
        "status": "to_analyze", "labels": ["lab", "dns"]}
    assert restarted.get_annotations_of_ips(["192.168.1.21"])["192.168.1.21"]["note"] == "Check DNS"
    state = {"local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:02"}
    other = _module_factory.create_host_profile_store_obj(path, "third", lambda _: state, ["en0"])
    other.save_host_identity_from_flow(SimpleNamespace(interface="en0", starttime="300", type_="dhcp",
        saddr="192.168.1.20", daddr="192.168.1.1", host_name="unrelated", smac="02:00:00:00:00:30"))
    profiles = other.get_triage_of_profiles(["192.168.1.20"])
    assert profiles[("gateway:aa:bb:cc:dd:ee:02", "192.168.1.20")] == {"status": "", "labels": []}
    assert other.get_triage_of_ips(["192.168.1.20"])["192.168.1.20"] == {"status": "", "labels": []}
    assert profiles[("gateway:aa:bb:cc:dd:ee:01", "192.168.1.20")]["status"] == "to_analyze"
    other.set_host_triage("192.168.1.21", "gateway:aa:bb:cc:dd:ee:01", "", [])
    assert other.get_triage_of_ips(["192.168.1.20", "192.168.1.21"])["192.168.1.21"] == {"status": "", "labels": []}


def test_own_interface_mac_is_saved_without_gateway_mac_confusion(tmp_path: Path) -> None:
    """Learn this machine's L2 address for its IPv4 and IPv6 profiles."""
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {"local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:01",
             "host_ip": "192.168.1.163", "mac": "02:00:00:00:00:20",
             "addresses": [{"ip": "192.168.1.163"}, {"ip": "fe80::20"}]}
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    for ip in ("192.168.1.163", "fe80::20", "8.8.8.8"):
        store.save_host_identity_from_flow(SimpleNamespace(interface="en0", starttime="100", type_="conn", saddr=ip, daddr="1.1.1.1"))
    for ip in ("192.168.1.163", "fe80::20"):
        macs = [fact["value"] for fact in store.get_host_profiles(ip)[0]["facts"] if fact["kind"] == "mac"]
        assert macs == [state["mac"]]
    assert not any(fact["kind"] == "mac" for fact in store.get_host_profiles("8.8.8.8")[0]["facts"])


def test_review_write_failure_rolls_back_name_and_note(tmp_path: Path) -> None:
    """A failed mark write cannot leave a partially saved host review.

    Parameters:
        tmp_path: Isolated permanent database location.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: {}, [])
    store.save_hostname_of_profile("dns.google", "profile_8.8.8.8")
    store.set_host_annotation("8.8.8.8", "public", "DNS", "Original note")
    with patch.object(HostProfileStore, "_save_host_triage", side_effect=sqlite3.OperationalError("write failed")):
        with pytest.raises(sqlite3.OperationalError):
            store.set_host_annotation("8.8.8.8", "public", "Changed", "Changed note", "reviewed", ["dns"])
    annotation = store.get_annotations_of_ips(["8.8.8.8"])["8.8.8.8"]
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
    first = _module_factory.create_host_profile_store_obj(path, "run-one", lambda _: state, ["en0"])
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    first.save_host_identity_from_flow(
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
    first.save_host_identity_from_ip_info(
        "8.8.8.8",
        {
            "reverse_dns": "dns.google",
            "asn": {"number": "AS15169", "org": "Example Network"},
            "threatintelligence": {"source": ["feed-one"]},
        },
    )
    first.save_host_identity_from_flow(
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
    second = _module_factory.create_host_profile_store_obj(path, "run-two", lambda _: state, ["en0"])
    second.save_host_identity_from_flow(
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

    local = second.get_host_profiles("192.168.1.20")
    public = second.get_host_profiles("8.8.8.8")

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
    store = _module_factory.create_host_profile_store_obj(path, "run-one", lambda _: state, ["en0"])
    store.save_host_identity_from_flow(
        SimpleNamespace(
            interface="en0",
            starttime="100",
            type_="conn",
            saddr="fe80::1234",
            daddr="fe80::5678",
        )
    )

    profile = store.get_host_profiles("fe80::1234")[0]
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
    store = _module_factory.create_host_profile_store_obj(path, "run-one", lambda _: state, ["en0"])
    store.save_host_identity_from_flow(
        SimpleNamespace(
            interface="en0",
            starttime="100",
            type_="conn",
            saddr="192.168.1.20",
            daddr="8.8.8.8",
        )
    )
    network_id = "gateway:aa:bb:cc:dd:ee:01"
    store.set_host_annotation(
        "192.168.1.20", network_id, "My iPad", "Tablet in the kitchen"
    )

    state["gateway_mac"] = "aa:bb:cc:dd:ee:02"
    another = _module_factory.create_host_profile_store_obj(path, "run-two", lambda _: state, ["en0"])
    another.save_host_identity_from_flow(
        SimpleNamespace(
            interface="en0",
            starttime="200",
            type_="conn",
            saddr="192.168.1.20",
            daddr="8.8.8.8",
        )
    )
    profiles = another.get_host_profiles("192.168.1.20")

    assert profiles[0]["user_name"] == ""
    assert profiles[1]["user_name"] == "My iPad"
    assert profiles[1]["user_note"] == "Tablet in the kitchen"
    assert another.get_annotations_of_ips(["192.168.1.20"])[
        "192.168.1.20"
    ] == {"name": "", "note": ""}

    another.set_host_annotation("192.168.1.20", network_id, "", "")
    assert another.get_host_profiles("192.168.1.20")[1]["user_name"] == ""


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
    store = _module_factory.create_host_profile_store_obj(path, "run-one", lambda _: {}, ["en0"])
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

    assert store.get_host_profiles("192.168.1.21")[0]["user_name"] == (
        "" if known_mac else "Cherry"
    )
    store.set_host_annotation(
        "192.168.1.21", "gateway:aa:bb:cc:dd:ee:02", "Cherry II", ""
    )
    assert store.get_host_profiles("192.168.1.22")[0]["user_name"] == (
        "" if known_mac else "Cherry II"
    )
    assert store.get_host_profiles("192.168.1.21")[0]["user_name"] == "Cherry II"
    assert store.get_host_profiles("192.168.1.20")[0]["user_name"] == "Cherry"
    store.set_host_annotation(
        "192.168.1.21", "gateway:aa:bb:cc:dd:ee:02", "", ""
    )
    assert store.get_host_profiles("192.168.1.22")[0]["user_name"] == ""


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
    old = _module_factory.create_host_profile_store_obj(path, "old-run", lambda _: network, ["en0"])
    old.save_host_identity_from_flow(
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
    current = _module_factory.create_host_profile_store_obj(path, "new-run", lambda _: network, ["en0"])
    for ip, mac, when in (
        ("192.168.1.21", "02:00:00:00:00:20", "200"),
        ("192.168.1.20", "02:00:00:00:00:21", "201"),
    ):
        current.save_host_identity_from_flow(
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
    # the next Slips start adds the tables an older store is missing
    current = _module_factory.create_host_profile_store_obj(
        path, "new-run", lambda _: network, ["en0"]
    )

    assert current.get_host_profiles("192.168.1.21")[0]["user_name"] == "Cherry"
    assert current.get_host_profiles("192.168.1.20")[0]["user_name"] == ""
    assert current.get_annotations_of_ips(
        ["192.168.1.21", "192.168.1.20"]
    ) == {
        "192.168.1.21": {"name": "Cherry", "note": "My device"},
        "192.168.1.20": {"name": "", "note": ""},
    }

    current.set_host_annotation(
        "192.168.1.21",
        "gateway:aa:bb:cc:dd:ee:02",
        "Cherry II",
        "Updated note",
    )
    assert current.get_host_profiles("192.168.1.21")[0]["user_name"] == "Cherry II"
    assert current.get_host_profiles("192.168.1.20")[1]["user_name"] == "Cherry II"

    current.set_host_annotation(
        "192.168.1.21", "gateway:aa:bb:cc:dd:ee:02", "", ""
    )
    assert current.get_host_profiles("192.168.1.21")[0]["user_name"] == ""
    assert current.get_host_profiles("192.168.1.20")[1]["user_name"] == ""


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
    assert HostProfileStore._normalize_unicast_mac(value) == expected


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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: {}, [])
    store.save_host_identity_from_flow(
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

    profile = store.get_host_profiles("9.9.9.9")[0]
    assert [(fact["kind"], fact["value"]) for fact in profile["facts"]] == (
        [(expected_kind, "printer.local")] if expected_kind else []
    )
    assert store.get_host_profiles("not-an-ip") == []


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
        store = _module_factory.create_host_profile_store_obj(path, run, lambda _: {}, [])
        store.save_hostname_of_profile("device-" + run, "profile_10.0.0.5")

    profiles = store.get_host_profiles("10.0.0.5")
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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: {}, [])
    for uri in ("/one", "/two", "/three", "/one"):
        store.save_host_identity_from_flow(
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

    facts = store.get_host_profiles("9.9.9.9")[0]["facts"]
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
    store = _module_factory.create_host_profile_store_obj(path, "old-run", lambda _: {}, [])
    store.save_host_identity_from_flow(
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
    profile = store.get_host_profiles("9.9.9.9")[0]
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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: {}, [])
    store.save_host_identity_from_flow(
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

    profile = store.get_host_profiles("10.0.0.25")[0]
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
    store = _module_factory.create_host_profile_store_obj(path, "run", lambda _: {}, [])
    store.save_host_identity_from_ip_info(ip, {"reverse_dns": "example.org", "geocountry": country})
    profile = store.get_host_profiles(ip)[0]
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
        profile = store.get_host_profiles(ip)[0]
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
    unidentified = _module_factory.create_host_profile_store_obj(path, "run-one", lambda _: {}, [])
    unidentified.save_hostname_of_profile("early-device", "profile_192.168.1.20")
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "AA:BB:CC:DD:EE:01",
    }
    identified = _module_factory.create_host_profile_store_obj(path, "run-two", lambda _: state, ["en0"])
    identified.save_host_identity_from_flow(
        SimpleNamespace(
            interface="en0",
            starttime="200",
            type_="conn",
            saddr="192.168.1.20",
            daddr="8.8.8.8",
        )
    )
    router_id = HostProfileStore.build_network_id(state, "run-two")
    identified.set_network_name(router_id, "Home Wi-Fi")
    identified.set_network_name("run:run-one", "Home Wi-Fi")

    profiles = identified.get_host_profiles("192.168.1.20")

    assert router_id == "gateway:aa:bb:cc:dd:ee:01"
    assert {profile["network_label"] for profile in profiles} == {"Home Wi-Fi"}
    assert {profile["network_name"] for profile in profiles} == {"Home Wi-Fi"}
    assert identified.get_network_names([router_id])[router_id] == (
        "Home Wi-Fi"
    )
    identified.set_network_name(router_id, "")
    assert router_id not in identified.get_network_names([router_id])


def test_failed_flow_batch_saves_none_of_its_flows(tmp_path: Path) -> None:
    """Roll back the whole batch, so the module can safely read it again.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    store = _module_factory.create_host_profile_store_obj(
        tmp_path / "hosts.sqlite"
    )

    def yield_one_flow_then_fail():
        yield SimpleNamespace(
            type_="conn", starttime="100", saddr="8.8.8.8", daddr="1.1.1.1"
        )
        raise RuntimeError("flow could not be parsed")

    with pytest.raises(RuntimeError):
        store.save_host_identity_from_flows(yield_one_flow_then_fail())

    assert store.get_host_profiles("8.8.8.8") == []
    # the connection is usable again after the rollback
    store.save_host_identity_from_flow(
        SimpleNamespace(
            type_="conn", starttime="100", saddr="8.8.8.8", daddr="1.1.1.1"
        )
    )
    assert len(store.get_host_profiles("8.8.8.8")) == 1


def test_store_files_are_private_to_the_slips_user(tmp_path: Path) -> None:
    """Keep host names and notes unreadable for other users of the machine.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    db_path = tmp_path / "host_profiles" / "hosts.sqlite"
    _module_factory.create_host_profile_store_obj(db_path)

    assert db_path.parent.stat().st_mode & 0o777 == 0o700
    assert db_path.stat().st_mode & 0o777 == 0o600
