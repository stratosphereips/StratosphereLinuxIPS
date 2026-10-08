"""Tests for permanent, network-scoped host identity storage."""

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone

import pytest

from slips_files.core.database.sqlite_db import host_profiles
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from tests.module_factory import ModuleFactory


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
    assert profile["network_label"] == (
        "Link-local on en0 · router aa:bb:cc:dd:ee:01"
    )


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

    HostProfileStore.set_host_annotation(
        path, "192.168.1.20", network_id, "", ""
    )
    assert HostProfileStore.read(path, "192.168.1.20")[1]["user_name"] == ""


@pytest.mark.parametrize(
    "port, expected_kind",
    [("5353", "mdns_name"), ("53", "dns_name")],
)
def test_dns_answers_identify_the_answered_host(
    tmp_path: Path, port: str, expected_kind: str
) -> None:
    """Attach DNS and multicast DNS names to returned IPs.

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
    assert [(fact["kind"], fact["value"]) for fact in profile["facts"]] == [
        (expected_kind, "printer.local")
    ]
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
        tuple(fact["value"] for fact in profile["facts"])
        for profile in profiles
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
    store.observe_ip_info(
        ip, {"reverse_dns": "example.org", "geocountry": country}
    )
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
