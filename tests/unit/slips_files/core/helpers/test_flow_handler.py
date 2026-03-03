# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.core.structures.flow_attributes import Role
from tests.module_factory import ModuleFactory

from unittest.mock import Mock, call
from slips_files.core.flows.zeek import DHCP
import json
from dataclasses import asdict


def test_handle_dns():
    flow = Mock()
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow_handler.handle_dns()

    flow_handler.db.add_out_dns.assert_called_with(
        flow_handler.profileid, flow_handler.twid, flow
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


def test_handle_ftp():
    flow = Mock()
    flow.used_port = 21  # Assuming FTP typically uses port 21
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow_handler.handle_ftp()

    flow_handler.db.set_ftp_port.assert_called_with(21)
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


def test_handle_http():
    flow = Mock()
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow_handler.handle_http()

    flow_handler.db.add_out_http.assert_called_with(
        flow_handler.profileid, flow_handler.twid, flow
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


# testing handle_ssl
def test_handle_ssl(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow_handler.handle_ssl()

    flow_handler.db.add_out_ssl.assert_called_with(
        flow_handler.profileid, flow_handler.twid, flow
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


# testing handle_ssh
def test_handle_ssh(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow_handler.handle_ssh()

    flow_handler.db.add_out_ssh.assert_called_with(
        flow_handler.profileid, flow_handler.twid, flow
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


# testing handle_weird
def test_handle_weird(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow_handler.handle_weird()

    expected_payload = {
        "profileid": flow_handler.profileid,
        "twid": flow_handler.twid,
        "flow": asdict(flow),
    }
    flow_handler.db.publish.assert_called_with(
        "new_weird", json.dumps(expected_payload)
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


# testing handle_tunnel
def test_handle_tunnel(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)

    flow_handler.handle_tunnel()

    expected_payload = {
        "profileid": flow_handler.profileid,
        "twid": flow_handler.twid,
        "flow": asdict(flow),
    }
    flow_handler.db.publish.assert_called_with(
        "new_tunnel", json.dumps(expected_payload)
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


def test_handle_conn(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow.daddr = "192.168.1.1"
    flow.dport = 80
    flow.proto = "tcp"
    flow.interface = "eth0"
    flow.smac = "aa:bb:cc:dd:ee:ff"
    flow.dmac = "11:22:33:44:55:66"
    flow.saddr = "10.0.0.1"

    mock_symbol = Mock()
    mock_symbol.compute.return_value = ("A", "B", "C")
    flow_handler.symbol = mock_symbol

    flow_handler.running_non_stop = False

    flow_handler.handle_conn()

    flow_handler.symbol.compute.assert_called_once_with(
        flow, flow_handler.twid, "OutTuples"
    )

    flow_handler.db.add_tuple.assert_called_once_with(
        flow_handler.profileid,
        flow_handler.twid,
        ("A", "B", "C"),
        Role.CLIENT,
        flow,
    )

    flow_handler.db.add_ips.assert_called_once_with(
        flow_handler.profileid,
        flow_handler.twid,
        flow,
        Role.CLIENT,
    )

    flow_handler.db.add_mac_addr_to_profile.assert_called_once_with(
        flow_handler.profileid,
        flow.smac,
        flow.interface,
    )

    flow_handler.db.publish_new_mac.assert_has_calls(
        [
            call(flow.smac, flow.saddr),
            call(flow.dmac, flow.daddr),
        ]
    )


# testing handle_files
def test_handle_files(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)

    flow_handler.handle_files()

    expected_payload = {
        "flow": asdict(flow),
        "type": "zeek",
        "profileid": flow_handler.profileid,
        "twid": flow_handler.twid,
    }
    flow_handler.db.publish.assert_called_with(
        "new_downloaded_file", json.dumps(expected_payload)
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


# testing handle_arp
def test_handle_arp(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow.dmac = "aa:bb:cc:dd:ee:ff"
    flow.smac = "ff:ee:dd:cc:bb:aa"
    flow.daddr = "192.168.1.1"
    flow.saddr = "192.168.1.2"
    flow.interface = "eth0"

    flow_handler.handle_arp()

    expected_payload = {
        "flow": asdict(flow),
        "profileid": flow_handler.profileid,
        "twid": flow_handler.twid,
    }
    flow_handler.db.publish.assert_called_with(
        "new_arp", json.dumps(expected_payload)
    )
    flow_handler.db.add_mac_addr_to_profile.assert_called_with(
        flow_handler.profileid, flow.smac, flow.interface
    )
    flow_handler.db.publish_new_mac.assert_has_calls(
        [call(flow.dmac, flow.daddr), call(flow.smac, flow.saddr)]
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


# testing handle_smtp
def test_handle_smtp(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow_handler.handle_smtp()

    expected_payload = {
        "flow": asdict(flow),
        "profileid": flow_handler.profileid,
        "twid": flow_handler.twid,
    }
    flow_handler.db.publish.assert_called_with(
        "new_smtp", json.dumps(expected_payload)
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


def test_handle_software(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)
    flow_handler.handle_software()

    flow_handler.db.add_software_to_profile.assert_called_with(
        flow_handler.profileid, flow
    )
    flow_handler.db.publish_new_software.assert_called_with(
        flow_handler.profileid, flow
    )
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


def test_handle_notice(flow):
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)

    flow.note = "Gateway_addr_identified: 192.168.1.1"
    flow.msg = "Gateway_addr_identified: 192.168.1.1"
    flow.interface = "eth0"

    flow_handler.db.get_gateway_ip.return_value = False
    flow_handler.db.get_gateway_mac.return_value = False
    flow_handler.db.get_mac_addr_from_profile.return_value = "xyz"

    flow_handler.handle_notice()

    flow_handler.db.add_out_notice.assert_called_with(
        flow_handler.profileid, flow_handler.twid, flow
    )
    flow_handler.db.set_default_gateway.assert_any_call(
        "IP", "192.168.1.1", "eth0"
    )
    flow_handler.db.set_default_gateway.assert_any_call("MAC", "xyz", "eth0")
    flow_handler.db.add_altflow.assert_called_with(
        flow, flow_handler.profileid, flow_handler.twid, "benign"
    )


def test_handle_dhcp():
    flow = DHCP(
        starttime=1234567890,
        uids=["uid1", "uid2", "uid3"],
        smac="aa:bb:cc:dd:ee:ff",
        server_addr="192.168.1.2",
        client_addr="192.168.1.1",
        host_name="test-host",
        requested_addr="192.168.1.4",
        interface="eth0",
    )
    flow_handler = ModuleFactory().create_flow_handler_obj(flow)

    flow_handler.handle_dhcp()

    flow_handler.db.publish_new_mac.assert_called_with(flow.smac, flow.saddr)
    flow_handler.db.add_mac_addr_to_profile.assert_called_with(
        flow_handler.profileid, flow.smac, flow.interface
    )
    flow_handler.db.store_dhcp_server.assert_called_with("192.168.1.2")
    flow_handler.db.mark_profile_as_dhcp.assert_called_with(
        flow_handler.profileid
    )
    flow_handler.db.publish_new_dhcp.assert_called_with(
        flow_handler.profileid, flow
    )

    for uid in flow.uids:
        flow.uid = uid
        flow_handler.db.add_altflow.assert_called_with(
            flow, flow_handler.profileid, flow_handler.twid, "benign"
        )
