"""Bounded progress for DHCP requests and Zeek's ICMP scan notices."""

from types import SimpleNamespace
from tests.module_factory import ModuleFactory


def test_dhcp_logarithmic_growth_does_not_use_redis_sets() -> None:
    """Distinct addresses, rather than repeated renewals, confirm broad requests."""
    module = ModuleFactory().create_network_discovery_obj()
    for i in range(12000):
        flow = SimpleNamespace(starttime=1000+i/10000, requested_addr=f"198.18.{i//256}.{i%256}", uids=[f"dhcp-{i}"], smac="02:00:00:00:00:01", interface="eth0")
        module.check_dhcp_scan("profile_192.0.2.1", "timewindow1", flow)
    records = [c.args[0] for c in module.db.set_evidence.call_args_list]
    assert [r.confidence for r in records] == [.8, .95, 1, 1, 1]
    assert all("approximately" in r.description for r in records[-2:])
    assert all(len(r.uid) <= 20 for r in records)
    group = next(iter(module.dhcp_groups.values()))
    assert not group.addresses
    assert len(group.progress.counter.registers) == 1024
    module.db.add_dhcp_requested_addr.assert_not_called()
    module.db.get_dhcp_requested_addrs.assert_not_called()


def test_dhcp_retries_client_mac_and_quiet_periods_are_separate() -> None:
    """Renewals do not add addresses and different clients cannot add counts."""
    module = ModuleFactory().create_network_discovery_obj()
    for i in range(20):
        flow = SimpleNamespace(starttime=1000+i, requested_addr="192.0.2.2", uids=[f"dhcp-{i}"], smac="02:00:00:00:00:01", interface="eth0")
        module.check_dhcp_scan("profile_192.0.2.1", "timewindow1", flow)
    module.db.set_evidence.assert_not_called()
    assert len(next(iter(module.dhcp_groups.values())).addresses) == 1
    for i in range(4):
        flow = SimpleNamespace(starttime=1400, requested_addr=f"192.0.2.{i+3}", uids=[f"next-{i}"], smac=f"02:00:00:00:00:{i+1:02x}", interface="eth0")
        module.check_dhcp_scan("profile_192.0.2.1", "timewindow1", flow)
    module.db.set_evidence.assert_not_called()


def test_icmp_notices_keep_bounded_logarithmic_reports_and_valid_confidence() -> None:
    """Use Zeek's provided host count, suppress duplicate notices and clamp scores."""
    module = ModuleFactory().create_network_discovery_obj()
    for count in (5, 5, 20, 100, 100, 1000, 2000, 10000):
        flow = SimpleNamespace(note="ICMPAddressScan", msg=f"ICMP scan on {count} hosts", saddr="192.0.2.1", uid=f"notice-{count}", starttime=1000+count/10000, interface="eth0")
        module.check_icmp_sweep("timewindow1", flow)
    records = [c.args[0] for c in module.db.set_evidence.call_args_list]
    assert [r.confidence for r in records] == [.65, .95, 1, 1, 1]
    assert len(module.notice_groups) == 1
