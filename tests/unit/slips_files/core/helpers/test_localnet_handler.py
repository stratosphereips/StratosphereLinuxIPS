import ipaddress
from unittest.mock import MagicMock, Mock, call, patch

import netifaces
import pytest

from slips_files.core.helpers.localnet_handler import LocalnetHandler


def create_profiler(
    *, client_ips=None, running_non_stop=False, localnet_cache=None
):
    profiler = Mock()
    profiler.client_ips = client_ips or []
    profiler.args = Mock(interface=None, access_point=None)
    profiler.db = Mock()
    profiler.db.is_running_non_stop.return_value = running_non_stop
    profiler.handle_setting_local_net_lock = MagicMock()
    profiler.is_ignored_ip.return_value = False
    return profiler


def test_get_private_client_ips_filters_private_entries():
    profiler = create_profiler()
    handler = LocalnetHandler(profiler)

    private_clients = handler.get_private_client_ips(
        [
            "192.168.1.2",
            "8.8.8.8",
            ipaddress.IPv4Network("10.0.0.0/8"),
        ]
    )

    assert private_clients == [
        "192.168.1.2",
        ipaddress.IPv4Network("10.0.0.0/8"),
    ]


def test_get_private_client_ips_returns_empty_list_for_non_iterable():
    profiler = create_profiler()
    handler = LocalnetHandler(profiler)

    assert handler.get_private_client_ips(1) == []


def test_get_local_net_of_flow_prefers_configured_default_localnet():
    profiler = create_profiler(
        client_ips=[ipaddress.IPv4Network("192.168.1.0/24")]
    )
    handler = LocalnetHandler(profiler)
    flow = Mock(saddr="10.0.0.8")

    localnet = handler._get_local_net_of_flow(flow)

    assert localnet == {"default": "192.168.1.0/24"}


def test_get_local_net_of_flow_returns_ipv6_network():
    profiler = create_profiler()
    handler = LocalnetHandler(profiler)
    flow = Mock(saddr="fd00:1::abcd")

    localnet = handler._get_local_net_of_flow(flow)

    assert localnet == {"default": "fd00:1::/64"}


@patch("slips_files.core.helpers.localnet_handler.netifaces.ifaddresses")
@patch("slips_files.core.helpers.localnet_handler.utils.get_all_interfaces")
def test_get_localnet_of_given_interface_returns_ipv4_networks(
    mock_get_all_interfaces, mock_ifaddresses
):
    profiler = create_profiler(running_non_stop=True)
    handler = LocalnetHandler(profiler)
    mock_get_all_interfaces.return_value = ["eth0", "wlan0"]
    mock_ifaddresses.side_effect = [
        {
            netifaces.AF_INET: [
                {"addr": "192.168.1.12", "netmask": "255.255.255.0"}
            ]
        },
        {netifaces.AF_INET: [{"addr": "10.0.0.25", "netmask": "255.0.0.0"}]},
    ]

    localnets = handler._get_localnet_of_given_interfaces_using_netifaces()

    assert localnets == {
        "eth0": "192.168.1.0/24",
        "wlan0": "10.0.0.0/8",
    }


@patch("slips_files.core.helpers.localnet_handler.netifaces.ifaddresses")
@patch("slips_files.core.helpers.localnet_handler.utils.get_all_interfaces")
def test_get_localnet_of_given_interface_returns_ipv6_networks(
    mock_get_all_interfaces, mock_ifaddresses
):
    profiler = create_profiler(running_non_stop=True)
    handler = LocalnetHandler(profiler)
    mock_get_all_interfaces.return_value = ["eth0"]
    mock_ifaddresses.return_value = {
        netifaces.AF_INET6: [
            {"addr": "fd00:1::1234%eth0", "prefixlen": "64"}
        ]
    }

    localnets = handler._get_localnet_of_given_interfaces_using_netifaces()

    assert localnets == {"eth0": "fd00:1::/64"}


def test_handle_setting_local_net_updates_cache_and_db():
    profiler = create_profiler(running_non_stop=False)
    handler = LocalnetHandler(profiler)
    handler.localnet_cache = {"old": "127.0.0.0/8"}
    handler._should_set_localnet = Mock(return_value=True)
    handler._get_local_net_of_flow = Mock(
        return_value={"default": "192.168.1.0/24"}
    )
    flow = Mock(saddr="192.168.1.8", interface="eth0")

    handler.handle_setting_local_net(flow)

    assert handler.localnet_cache == {"default": "192.168.1.0/24"}
    profiler.db.set_local_network.assert_called_once_with(
        "192.168.1.0/24", "default"
    )


@pytest.mark.parametrize(
    "running_non_stop, localnet_cache, client_ips, saddr, interface, "
    "is_ignored_ip, expected",
    [
        (
            False,
            {"default": "192.168.1.0/24"},
            [],
            "192.168.1.8",
            "eth0",
            False,
            False,
        ),
        (
            True,
            {"eth0": "192.168.1.0/24"},
            [],
            "192.168.1.8",
            "eth0",
            False,
            False,
        ),
        (False, {}, [], "0.0.0.0", "eth0", False, False),
        (
            False,
            {},
            [ipaddress.IPv4Network("10.0.0.0/8")],
            "8.8.8.8",
            "eth0",
            False,
            True,
        ),
        (False, {}, [], "not-an-ip", "eth0", False, False),
        (False, {}, [], "224.0.0.1", "eth0", True, False),
        (False, {}, [], "8.8.8.8", "eth0", False, False),
        (False, {}, [], "192.168.1.8", "eth0", False, True),
        (False, {}, [], "fd00:1::abcd", "eth0", False, True),
    ],
)
def test_should_set_localnet(
    running_non_stop,
    localnet_cache,
    client_ips,
    saddr,
    interface,
    is_ignored_ip,
    expected,
):
    profiler = create_profiler(
        client_ips=client_ips,
        running_non_stop=running_non_stop,
        localnet_cache=localnet_cache,
    )
    profiler.is_ignored_ip.return_value = is_ignored_ip
    handler = LocalnetHandler(profiler)
    handler.localnet_cache = localnet_cache
    flow = Mock(saddr=saddr, interface=interface)

    assert handler._should_set_localnet(flow) is expected


def test_handle_setting_local_net_stores_interface_localnets_in_non_stop_mode():
    profiler = create_profiler(running_non_stop=True)
    handler = LocalnetHandler(profiler)
    handler._should_set_localnet = Mock(return_value=True)
    handler._get_localnet_of_given_interfaces_using_netifaces = Mock(
        return_value={
            "eth0": "192.168.1.0/24",
            "wlan0": "10.0.0.0/8",
        }
    )
    flow = Mock(saddr="192.168.1.8", interface="eth0")

    handler.handle_setting_local_net(flow)

    assert handler.localnet_cache == {
        "eth0": "192.168.1.0/24",
        "wlan0": "10.0.0.0/8",
    }
    profiler.db.set_local_network.assert_has_calls(
        [
            call("192.168.1.0/24", "eth0"),
            call("10.0.0.0/8", "wlan0"),
        ],
        any_order=False,
    )
