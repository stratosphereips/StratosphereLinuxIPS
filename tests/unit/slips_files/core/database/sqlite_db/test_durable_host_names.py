"""Keep learned host names available after transient caches disappear."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "kind,value,source",
    [
        ("hostname", "elhuevito", "Hostname"),
        ("mdns_hostname", "elhuevito.local", "mDNS"),
        ("reverse_dns", "elhuevito", "rDNS"),
    ],
)
def test_learned_names_survive_network_changes_and_restarts(
    tmp_path: Path, kind: str, value: str, source: str
) -> None:
    """Resolve old names when a known device returns weeks later.

    Parameters:
        tmp_path: Independent permanent store.
        kind: Source of the saved name.
        value: Name saved before leaving the network.
        source: Displayed provenance.
    """
    _factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    home = _factory.create_host_profile_store_obj(path, "first-run", lambda _: state, ["en0"])
    home._save_host_facts(
        "192.168.1.128",
        "en0",
        100,
        [("mac", "00:08:9b:d1:04:d2"), (kind, value)],
        observed_traffic=True,
    )
    guest_state = {**state, "gateway_mac": "aa:bb:cc:dd:ee:02"}
    guest = _factory.create_host_profile_store_obj(path, "guest-run", lambda _: guest_state, ["en0"])
    guest._save_host_facts(
        "192.168.1.128",
        "en0",
        200,
        [("mac", "02:00:00:00:00:99")],
        observed_traffic=True,
    )
    unknown = guest.get_identities_of_ips(
        ["192.168.1.128"], ["gateway:aa:bb:cc:dd:ee:02"]
    )
    assert unknown["192.168.1.128"]["name"] == ""
    returned = _factory.create_host_profile_store_obj(path, "returned-run", lambda _: state, ["en0"])
    returned.save_host_identity_from_flow(
        SimpleNamespace(
            type_="conn",
            interface="en0",
            starttime=100 + 21 * 86400,
            saddr="192.168.1.128",
            daddr="8.8.8.8",
            smac="00:08:9b:d1:04:d2",
        )
    )
    assert returned.get_identities_of_ips(["192.168.1.128"])[
        "192.168.1.128"
    ] == {
        "name": value,
        "source": source,
        "mac": "00:08:9b:d1:04:d2",
        "identity_changed": True,
    }


@pytest.mark.parametrize("new_ip", ["192.168.1.130", "fe80::128"])
def test_learned_name_follows_mac_but_not_reassigned_ip(
    tmp_path: Path, new_ip: str
) -> None:
    """Carry a device's name to another address without renaming a new owner.

    Parameters:
        tmp_path: Independent identity database.
        new_ip: New IPv4 or IPv6 address of the original device.
    """
    _factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = _factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    store._save_host_facts(
        "192.168.1.128",
        "en0",
        100,
        [("mac", "00:08:9b:d1:04:d2"), ("hostname", "elhuevito")],
        observed_traffic=True,
    )
    store._save_host_facts(
        new_ip,
        "en0",
        200,
        [("mac", "00:08:9b:d1:04:d2")],
        observed_traffic=True,
    )
    store._save_host_facts(
        "192.168.1.128",
        "en0",
        300,
        [("mac", "02:00:00:00:00:99")],
        observed_traffic=True,
    )
    identities = store.get_identities_of_ips(
        ["192.168.1.128", new_ip]
    )
    assert identities[new_ip]["name"] == "elhuevito"
    assert identities["192.168.1.128"]["name"] == ""


def test_live_mac_rejects_an_old_address_name_before_archival(
    tmp_path: Path,
) -> None:
    """Do not use history belonging to a different currently observed device.

    Parameters:
        tmp_path: Independent permanent store.
    """
    _factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = _factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    store._save_host_facts(
        "192.168.1.128",
        "en0",
        100,
        [("mac", "00:08:9b:d1:04:d2"), ("hostname", "elhuevito")],
        observed_traffic=True,
    )
    identities = store.get_identities_of_ips(
        ["192.168.1.128"],
        current_macs={"192.168.1.128": "02:00:00:00:00:99"},
    )
    assert identities["192.168.1.128"]["name"] == ""


@pytest.mark.parametrize(
    "kind,value",
    [
        ("mdns_name", "router-question.local"),
        ("mdns_hostname", "_http._tcp.local"),
        ("mdns_hostname", "12345678-1234-1234-1234-123456789abc.local"),
        ("dns_name", "visited-website.example"),
        ("sni", "visited-website.example"),
    ],
)
def test_unverified_names_are_not_device_names(
    tmp_path: Path, kind: str, value: str
) -> None:
    """Exclude DNS questions, service records and visited server names.

    Parameters:
        tmp_path: Independent store.
        kind: Metadata that does not establish a device name.
        value: Observed question, service or server.
    """
    _factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = _factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    store._save_host_facts(
        "192.168.1.128", "en0", 100, [(kind, value)], observed_traffic=True
    )
    assert (
        store.get_identities_of_ips(["192.168.1.128"])[
            "192.168.1.128"
        ]["name"]
        == ""
    )


def test_new_store_knows_no_identities(
    tmp_path: Path,
) -> None:
    """Return no identity for an address the store has never seen.

    Parameters:
        tmp_path: Directory of a new identity database.
    """
    _factory = ModuleFactory()
    store = _factory.create_host_profile_store_obj(tmp_path / "new.sqlite")
    assert store.get_identities_of_ips(["192.168.1.128"]) == {}


@pytest.mark.parametrize(
    "mac_time,expected", [(100, "elhuevito.local"), (200, "")]
)
def test_name_can_follow_an_earlier_mac_but_never_a_later_owner(
    tmp_path: Path, mac_time: float, expected: str
) -> None:
    """Handle quiet devices without binding an old name to a new IP owner.

    Parameters:
        tmp_path: Independent store.
        mac_time: First hardware observation, before or after the name.
        expected: Name associated with that hardware observation.
    """
    _factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    state = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = _factory.create_host_profile_store_obj(path, "run", lambda _: state, ["en0"])
    store._save_host_facts(
        "192.168.1.128",
        "en0",
        mac_time,
        [("mac", "00:08:9b:d1:04:d2")],
        observed_traffic=True,
    )
    store._save_host_facts(
        "192.168.1.128",
        "en0",
        150,
        [("mdns_hostname", "elhuevito.local")],
        from_packet=True,
    )
    assert (
        store.get_identities_of_ips(["192.168.1.128"])[
            "192.168.1.128"
        ]["name"]
        == expected
    )


@pytest.mark.parametrize(
    "gateway,cached_name,expected",
    [
        ("aa:bb:cc:dd:ee:01", None, "elhuevito.local"),
        ("aa:bb:cc:dd:ee:01", "old-cache", "elhuevito.local"),
        ("aa:bb:cc:dd:ee:02", "elhuevito.local", None),
    ],
)
def test_core_hostname_uses_durable_network_identity(
    tmp_path: Path, gateway: str, cached_name: str | None, expected: str | None
) -> None:
    """Use the same durable identity for console output and alert summaries.

    Parameters:
        tmp_path: Isolated permanent store.
        gateway: Router currently monitored by the core caller.
        cached_name: Missing or potentially stale Redis value.
        expected: Name permitted in this network context.
    """
    _factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    home = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = _factory.create_host_profile_store_obj(path, "run", lambda _: home, ["en0"])
    store._save_host_facts(
        "192.168.1.128",
        "en0",
        100,
        [("mac", "00:08:9b:d1:04:d2"), ("mdns_hostname", "elhuevito.local")],
        observed_traffic=True,
    )
    assert (
        store.get_hostname_of_profile(
            "profile_192.168.1.128",
            [{**home, "gateway_mac": gateway}],
            cached_name=cached_name,
        )
        == expected
    )


def test_a_conflicting_cache_mac_cannot_override_archived_ownership(
    tmp_path: Path,
) -> None:
    """Treat conflicting cache and archival hardware identities as unverified.

    Parameters:
        tmp_path: Independent identity database.
    """
    _factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    home = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = _factory.create_host_profile_store_obj(path, "run", lambda _: home, ["en0"])
    store._save_host_facts(
        "192.168.1.128",
        "en0",
        100,
        [("mac", "00:08:9b:d1:04:d2"), ("hostname", "elhuevito")],
        observed_traffic=True,
    )
    store._save_host_facts(
        "192.168.1.130",
        "en0",
        200,
        [("mac", "02:00:00:00:00:99"), ("hostname", "different-device")],
        observed_traffic=True,
    )
    assert (
        store.get_hostname_of_profile(
            "profile_192.168.1.128",
            [home],
            current_mac="02:00:00:00:00:99",
            cached_name="different-device",
        )
        is None
    )


@pytest.mark.parametrize("profileid", ["not-an-address", "profile_bad"])
def test_invalid_core_profile_has_no_hostname(
    tmp_path: Path, profileid: str
) -> None:
    """Reject invalid profile identifiers, even when a cached name exists.

    Parameters:
        tmp_path: Directory of a new identity database.
        profileid: Invalid profile identifier.
    """
    _factory = ModuleFactory()
    store = _factory.create_host_profile_store_obj(tmp_path / "new.sqlite")
    assert (
        store.get_hostname_of_profile(profileid, [], cached_name="cached")
        is None
    )
