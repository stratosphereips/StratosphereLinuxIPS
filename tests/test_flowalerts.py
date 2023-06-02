"""Unit test for modules/flowalerts/flowalerts.py"""
from slips_files.core.flows.zeek import Conn
from tests.module_factory import ModuleFactory
import pytest
import binascii
import base64
import os
import json
from numpy import arange

# dummy params used for testing
profileid = 'profile_192.168.1.1'
twid = 'timewindow1'
uid = 'CAeDWs37BipkfP21u8'
timestamp = 1635765895.037696
saddr = '192.168.1.1'
daddr = '192.168.1.2'
dst_profileid = f'profile_{daddr}'


def test_port_belongs_to_an_org(database, output_queue):
    flowalerts = ModuleFactory().create_flowalerts_obj()
    # store in the db that both ips have apple as a vendor
    MAC_info = {'MAC': '123', 'Vendor': 'Apple, Inc'}
    database.add_mac_addr_to_profile(profileid, MAC_info)
    database.add_mac_addr_to_profile(dst_profileid, MAC_info)

    # belongs to apple
    portproto = '65509/tcp'
    database.set_organization_of_port('apple', '', portproto)
    assert (
            flowalerts.port_belongs_to_an_org(daddr, portproto, profileid) is True
    )
    # doesn't belong to any org
    portproto = '78965/tcp'
    assert (
            flowalerts.port_belongs_to_an_org(daddr, portproto, profileid) is False
    )


def test_check_unknown_port(output_queue, database):
    flowalerts = ModuleFactory().create_flowalerts_obj()
    database.set_port_info('23/udp', 'telnet')
    # now we have info 23 udp
    assert (
        flowalerts.check_unknown_port('23', 'udp', daddr, profileid, twid, uid, timestamp, 'Established') is False
    )


def test_check_if_resolution_was_made_by_different_version(
    output_queue, database
):
    flowalerts = ModuleFactory().create_flowalerts_obj()
    # tell the db that this ipv6 belongs to the same profileid
    ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    database.set_ipv6_of_profile(profileid, ipv6)
    other_ip = database.get_the_other_ip_version(profileid)
    assert json.loads(other_ip) == ipv6
    database.set_dns_resolution(
        'example.com', [daddr], timestamp, uid, 'AAAA', ipv6, twid
    )
    res = flowalerts.check_if_resolution_was_made_by_different_version(
        profileid, daddr
    )
    assert res is True


def test_check_dns_arpa_scan(output_queue, database):
    flowalerts = ModuleFactory().create_flowalerts_obj()
    # make 10 different arpa scans
    for ts in arange(0, 1, 1 / 10):
        is_arpa_scan = flowalerts.check_dns_arpa_scan(
            f'{ts}example.in-addr.arpa', timestamp + ts, profileid, twid, uid
        )

    assert is_arpa_scan is True


# check_multiple_ssh_clients is tested in test_dataset
def test_detect_DGA(output_queue, database):
    flowalerts = ModuleFactory().create_flowalerts_obj()
    rcode_name = 'NXDOMAIN'
    # arbitrary ip to be able to call detect_DGA
    daddr = '10.0.0.1'
    for i in range(10):
        dga_detected = flowalerts.detect_DGA(
            rcode_name, f'example{i}.com', timestamp, daddr, profileid, twid, uid
        )
    assert dga_detected is True


def test_detect_young_domains(output_queue, database):
    flowalerts = ModuleFactory().create_flowalerts_obj()
    domain = 'example.com'
    # age in days
    age = 50
    database.setInfoForDomains(domain, {'Age': age})
    assert (
        flowalerts.detect_young_domains(domain, timestamp, profileid, twid, uid) is True
    )
