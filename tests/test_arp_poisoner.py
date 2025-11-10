import time
import json
import pytest
from unittest.mock import patch, MagicMock
from tests.module_factory import ModuleFactory


@pytest.fixture
def poisoner():
    obj = ModuleFactory().create_arp_poisoner_obj()
    obj.db.get_gateway_ip = MagicMock(return_value="192.168.1.1")
    obj.db.get_gateway_mac = MagicMock(return_value="aa:bb:cc:dd:ee:ff")
    obj.args.interface = "eth0"
    return obj


def test__is_time_to_repoison(poisoner):
    target = "192.168.1.5"
    poisoner._time_since_last_repoison = {target: time.time() - 30}
    assert poisoner._is_time_to_repoison(target)

    poisoner._time_since_last_repoison = {target: time.time()}
    assert not poisoner._is_time_to_repoison(target)


def test_is_broadcast_true(poisoner):
    assert poisoner.is_broadcast("192.168.1.255", "192.168.1.0/24")


def test_is_broadcast_false(poisoner):
    assert not poisoner.is_broadcast("192.168.1.10", "192.168.1.0/24")


@pytest.mark.parametrize(
    "ip, is_public, in_net, is_bcast, is_gw, expected",
    [
        ("1.2.3.4", True, True, False, False, False),  # public ip
        ("192.168.1.255", False, True, True, False, False),  # bc
        ("192.168.1.1", False, True, False, True, False),  # gw ip
        ("192.168.1.5", False, True, False, False, True),  # in net
    ],
)
def test_can_poison_ip(
    poisoner, ip, is_public, in_net, is_bcast, is_gw, expected
):
    with patch(
        "slips_files.common.slips_utils.utils.is_public_ip",
        return_value=is_public,
    ):
        poisoner.db.get_local_network = MagicMock(
            return_value="192.168.1.0/24"
        )
        if is_gw:
            poisoner.db.get_gateway_ip = MagicMock(return_value=ip)
        poisoner.is_broadcast = MagicMock(return_value=is_bcast)
        assert poisoner._can_poison_ip(ip) == expected


def test__arp_scan(poisoner):
    fake_output = (
        "192.168.1.10 aa:bb:cc:dd:ee:01\n192.168.1.11 aa:bb:cc:dd:ee:02"
    )
    with patch("subprocess.check_output", return_value=fake_output):
        pairs = poisoner._arp_scan("eth0")
    assert ("192.168.1.10", "aa:bb:cc:dd:ee:01") in pairs
    assert ("192.168.1.11", "aa:bb:cc:dd:ee:02") in pairs


def test__get_mac_using_arp(poisoner):
    from scapy.all import ARP, Ether

    arp = ARP(hwsrc="aa:bb:cc:dd:ee:ff")
    ether = Ether()
    pkt = ether / arp

    fake_resp = [(None, pkt)]  # emulate srp's (sent, received) tuple
    with (
        patch(
            "modules.arp_poisoner.arp_poisoner.srp",
            return_value=(fake_resp, None),
        ),
        patch("scapy.config.conf.L2socket", new=MagicMock()),
    ):
        mac = poisoner._get_mac_using_arp("192.168.1.5")
        assert mac == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize(
    "ip, expected",
    [
        ("192.168.1.5", None),
    ],
)
def test__get_mac_using_arp_none(poisoner, ip, expected):
    with (
        patch(
            "modules.arp_poisoner.arp_poisoner.srp", return_value=([], None)
        ),
        patch("scapy.config.conf.L2socket", new=MagicMock()),
    ):
        assert poisoner._get_mac_using_arp(ip) is expected


@pytest.mark.parametrize(
    "ip, mac, gw_mac",
    [
        ("192.168.1.100", "aa:bb:cc:dd:ee:01", "aa:aa:aa:aa:aa:aa"),
    ],
)
def test__cut_targets_internet(poisoner, ip, mac, gw_mac):
    poisoner.args.interface = "eth0"
    with (
        patch(
            "modules.arp_poisoner.arp_poisoner.sendp", return_value=([], None)
        ) as sendp,
        patch("scapy.config.conf.L2socket", new=MagicMock()),
        patch(
            "scapy.config.conf.ifaces.dev_from_name", return_value=MagicMock()
        ),
        patch.object(
            poisoner.db, "get_gateway_ip", return_value="192.168.1.1"
        ),
        patch.object(poisoner.db, "get_gateway_mac", return_value=gw_mac),
    ):
        poisoner._cut_targets_internet(ip, mac, gw_mac)
        assert sendp.call_count == 2


def test__isolate_target_from_localnet(poisoner):
    with (
        patch(
            "modules.arp_poisoner.arp_poisoner.sendp", return_value=([], None)
        ) as sendp,
        patch("scapy.config.conf.L2socket", new=MagicMock()),
        patch(
            "scapy.config.conf.ifaces.dev_from_name", return_value=MagicMock()
        ),
    ):
        poisoner._arp_scan = MagicMock(
            return_value={
                ("192.168.1.100", "aa:bb:cc:dd:ee:01"),
                ("192.168.1.101", "aa:bb:cc:dd:ee:02"),
            }
        )
        poisoner._isolate_target_from_localnet(
            "192.168.1.100", "aa:aa:aa:aa:aa:aa"
        )
        assert sendp.call_count == 2


def test__attack_uses_cache(poisoner):
    with (
        patch(
            "slips_files.common.slips_utils.utils"
            ".get_mac_for_ip_using_cache",
            return_value="aa:bb:cc:dd:ee:01",
        ),
        patch.object(poisoner, "_cut_targets_internet") as cut,
        patch.object(poisoner, "_isolate_target_from_localnet") as iso,
        patch.object(poisoner, "log"),
    ):
        poisoner._attack("192.168.1.5", first_time=True)
        cut.assert_called_once()
        iso.assert_called_once()


def test__attack_fallback_to_arp(poisoner):
    with patch(
        "slips_files.common.slips_utils.utils.get_mac_for_ip_using_cache",
        return_value=None,
    ):
        with patch.object(
            poisoner, "_get_mac_using_arp", return_value="aa:bb:cc:dd:ee:01"
        ):
            with (
                patch.object(poisoner, "_cut_targets_internet") as cut,
                patch.object(poisoner, "_isolate_target_from_localnet") as iso,
            ):
                poisoner._attack("192.168.1.5")
                cut.assert_called_once()
                iso.assert_called_once()


def test__attack_fails(poisoner):
    with patch(
        "slips_files.common.slips_utils.utils.get_mac_for_ip_using_cache",
        return_value=None,
    ):
        with patch.object(poisoner, "_get_mac_using_arp", return_value=None):
            assert poisoner._attack("192.168.1.5") is None


@pytest.mark.parametrize("should_unblock", [False, True])
def test_keep_attackers_poisoned(should_unblock):
    poisoner = ModuleFactory().create_arp_poisoner_obj()
    poisoner._is_time_to_repoison = MagicMock(return_value=True)
    poisoner.unblocker.requests = {"192.168.1.5"}
    poisoner.unblocker.check_if_time_to_unblock = MagicMock(
        return_value=should_unblock
    )
    poisoner.unblocker.del_request = MagicMock()

    with patch.object(poisoner, "_attack") as _attack:
        poisoner.keep_attackers_poisoned()

        if should_unblock:
            _attack.assert_not_called()
            poisoner.unblocker.del_request.assert_called_once_with(
                "192.168.1.5"
            )
        else:
            _attack.assert_called_once_with("192.168.1.5")
            poisoner.unblocker.del_request.assert_not_called()


def test_main(poisoner):
    msg = {"data": json.dumps({"ip": "192.168.1.5", "tw": 1})}
    with patch.object(poisoner, "get_msg", side_effect=[msg, None]):
        with patch.object(poisoner, "can_poison_ip", return_value=True):
            with (
                patch.object(poisoner, "_attack") as poison,
                patch.object(poisoner.unblocker, "unblock_request"),
            ):
                poisoner.main()
                poison.assert_called_once()
                poisoner.unblocker.unblock_request.assert_called_once()


def test_main_tw_closed(poisoner):

    raw_data = "profile_1234_tw_999"
    tw_msg = {"data": json.dumps(raw_data)}

    with patch.object(poisoner, "get_msg", side_effect=[None, tw_msg, True]):
        with patch.object(poisoner.unblocker, "update_requests") as update:
            poisoner.main()
            update.assert_called_once()
