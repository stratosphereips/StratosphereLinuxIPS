import pytest
from unittest.mock import Mock, patch

from modules.arp.filter import ARPEvidenceFilter
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "p2p_enabled, is_private, peer_trust, expected",
    [
        (True, True, 0.5, True),
        (True, True, 0.2, False),
        (True, False, 0.5, False),
        (False, True, 0.5, False),
        (True, True, None, False),
    ],
)
def test_is_slips_peer(p2p_enabled, is_private, peer_trust, expected):
    arp = ModuleFactory().create_arp_filter_obj()
    with patch(
        "modules.arp.filter.utils.is_private_ip",
        return_value=is_private,
    ), patch.object(
        arp.db,
        "get_peer_trust",
        return_value=peer_trust,
    ):
        arp.p2p_enabled = p2p_enabled
        assert arp.is_slips_peer("192.168.1.100") == expected


@pytest.mark.parametrize(
    "ip, our_ips, blocking, has_poisoner, expected",
    [
        ("192.168.1.10", ["192.168.1.10"], True, True, True),
        ("192.168.1.10", ["192.168.1.10"], True, False, False),
        ("192.168.1.10", ["192.168.1.20"], True, True, False),
        ("192.168.1.10", ["192.168.1.10"], False, True, False),
    ],
)
def test_is_self_defense(ip, our_ips, blocking, has_poisoner, expected):
    db = Mock()
    db.get_pids.return_value = {"ARP Poisoner": 123} if has_poisoner else {}
    args = Mock()
    args.blocking = blocking

    arp = ARPEvidenceFilter(conf=Mock(), slips_args=args, db=db)
    arp.our_ips = our_ips

    assert arp.is_self_defense(ip) == expected


@pytest.mark.parametrize(
    "is_slips_peer_return, is_self_defense_return, expected_result",
    [
        (False, False, False),
        (True, False, True),
        (False, True, True),
    ],
)
def test_should_discard_evidence_combines_both_checks(
    is_slips_peer_return, is_self_defense_return, expected_result
):
    arp = ModuleFactory().create_arp_filter_obj()
    with patch.object(
        arp, "is_slips_peer", return_value=is_slips_peer_return
    ), patch.object(
        arp, "is_self_defense", return_value=is_self_defense_return
    ):
        result = arp.should_discard_evidence("1.2.3.4")
        assert result == expected_result
