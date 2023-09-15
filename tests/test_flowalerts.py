"""Unit test for modules/flowalerts/flowalerts.py"""
from slips_files.core.flows.zeek import Conn
from tests.module_factory import ModuleFactory
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


def test_port_belongs_to_an_org(mock_rdb):
    flowalerts = ModuleFactory().create_flowalerts_obj(mock_rdb)

    # belongs to apple
    portproto = '65509/tcp'

    # mock the db response to say that the org of this port
    # is apple and the mac vendor of the
    # given profile is also apple
    mock_rdb.get_organization_of_port.return_value = json.dumps(
        {'ip':[], 'org_name':'apple'}
        )
    mock_rdb.get_mac_vendor_from_profile.return_value = 'apple'

    assert flowalerts.port_belongs_to_an_org(daddr, portproto, profileid) is True

    # doesn't belong to any org
    portproto = '78965/tcp'
    # expectations
    mock_rdb.get_organization_of_port.return_value = None
    assert flowalerts.port_belongs_to_an_org(daddr, portproto, profileid) is False


def test_check_unknown_port(mocker, mock_rdb):
    flowalerts = ModuleFactory().create_flowalerts_obj(mock_rdb)
    # database.set_port_info('23/udp', 'telnet')
    mock_rdb.get_port_info.return_value = 'telnet'
    # now we have info 23 udp
    assert flowalerts.check_unknown_port(
        '23',
        'udp',
        daddr,
        profileid,
        twid,
        uid,
        timestamp,
        'Established'
        ) is False

    # test when the port is unknown
    mock_rdb.get_port_info.return_value = None
    mock_rdb.is_ftp_port.return_value = False
    # mock the flowalerts call to port_belongs_to_an_org
    flowalerts_mock = mocker.patch("modules.flowalerts.flowalerts.FlowAlerts.port_belongs_to_an_org")
    flowalerts_mock.return_value = False


    assert flowalerts.check_unknown_port(
        '1337',
        'udp',
        daddr,
        profileid,
        twid,
        uid,
        timestamp,
        'Established'
        ) is True


def test_check_if_resolution_was_made_by_different_version(
        mock_rdb
):
    flowalerts = ModuleFactory().create_flowalerts_obj(mock_rdb)

    # now  this ipv6 belongs to the same profileid, is supposed to be
    # the other version of the ipv4 of the used profileid
    mock_rdb.get_the_other_ip_version.return_value = json.dumps(
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        )
    # now the daddr given to check_if_resolution_was_made_by_different_version()
    # is supposed to be resolved by the ipv6 of the profile, not th eipv4
    mock_rdb.get_dns_resolution.return_value = {
        'resolved-by': '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        }

    # give flowalerts the ipv4 and the daddr, it should detect that it
    # was resolved by the othger versio
    assert flowalerts.check_if_resolution_was_made_by_different_version(
        profileid, daddr
    ) is True

    # check the case when the resolution wasn't done by another IP
    mock_rdb.get_the_other_ip_version.return_value = json.dumps(
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        )
    mock_rdb.get_dns_resolution.return_value = {'resolved-by': []}

    assert flowalerts.check_if_resolution_was_made_by_different_version(
        profileid, '2.3.4.5'
    ) is False



def test_check_dns_arpa_scan(mock_rdb):
    flowalerts = ModuleFactory().create_flowalerts_obj(mock_rdb)
    # make 10 different arpa scans
    for ts in arange(0, 1, 1 / 10):
        is_arpa_scan = flowalerts.check_dns_arpa_scan(
            f'{ts}example.in-addr.arpa', timestamp + ts, profileid, twid, uid
        )

    assert is_arpa_scan is True


def test_check_multiple_ssh_versions(mock_rdb):
    flowalerts = ModuleFactory().create_flowalerts_obj(mock_rdb)
    # in the first flow, we only have 1 use ssh client so no version incompatibility
    mock_rdb.get_software_from_profile.return_value = {'SSH::CLIENT': {'version-major': 8, 'version-minor': 1, 'uid': 'YTYwNjBiMjIxZDkzOWYyYTc4'}}

    flow2 = {'starttime': 1632302619.444328, 'uid': 'M2VhNTA3ZmZiYjU3OGMxMzJk', 'saddr': '192.168.1.247', 'daddr': '', 'software': 'SSH::CLIENT', 'unparsed_version': 'OpenSSH_9.1', 'version_major': 9, 'version_minor': 1, 'type_': 'software'}

    # in flow 2 slips should detect a client version change
    assert flowalerts.check_multiple_ssh_versions(flow2, 'timewindow1') is True

def test_detect_DGA(mock_rdb):
    flowalerts = ModuleFactory().create_flowalerts_obj(mock_rdb)
    rcode_name = 'NXDOMAIN'
    # arbitrary ip to be able to call detect_DGA
    daddr = '10.0.0.1'
    for i in range(10):
        dga_detected = flowalerts.detect_DGA(
            rcode_name, f'example{i}.com', timestamp, daddr, profileid, twid, uid
        )
    assert dga_detected is True


def test_detect_young_domains(mock_rdb):
    flowalerts = ModuleFactory().create_flowalerts_obj(mock_rdb)
    domain = 'example.com'

    # age in days
    mock_rdb.getDomainData.return_value = {'Age': 50}
    assert (
        flowalerts.detect_young_domains(domain, timestamp, profileid, twid, uid) is True
    )

    # more than the age threshold
    mock_rdb.getDomainData.return_value = {'Age': 1000}
    assert (
        flowalerts.detect_young_domains(domain, timestamp, profileid, twid, uid) is False
    )
