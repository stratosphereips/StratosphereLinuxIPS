"""Unit test for modules/flowalerts/conn.py"""

from tests.module_factory import ModuleFactory
import json
from unittest.mock import MagicMock, Mock
import pytest
from ipaddress import ip_address

# dummy params used for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
uid = "CAeDWs37BipkfP21u8"
timestamp = 1635765895.037696
saddr = "192.168.1.1"
daddr = "192.168.1.2"
dst_profileid = f"profile_{daddr}"


@pytest.mark.parametrize(
    "dport, proto, daddr, expected_result",
    [  # Testcase 1: Protocol is not UDP
        (1234, "tcp", "192.168.1.0", False),
        # Testcase 2: Port number is less than 30000
        (8080, "udp", "192.168.1.0", False),
        # Testcase 3: It is a P2P connection
        (30001, "udp", "192.168.1.6", True),
        # Testcase 4: New IP, becomes P2P after 5 connections
        (30001, "udp", "192.168.1.7", True),
        # Testcase 5: 6th connection to the same IP,
        # different port > 30000
        (30002, "udp", "192.168.1.6", True),
        # Testcase 6: Existing IP, but already marked as P2P
        (30003, "udp", "192.168.1.1", True),
    ],
)
def test_is_p2p(mock_db, dport, proto, daddr, expected_result):
    mock_conn = MagicMock()
    mock_conn.p2p_daddrs = {
        "192.168.1.1": 1,
        "192.168.1.2": 1,
        "192.168.1.3": 1,
        "192.168.1.4": 1,
        "192.168.1.5": 1,
    }
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    conn.p2p_daddrs = mock_conn.p2p_daddrs
    assert conn.is_p2p(dport, proto, daddr) == expected_result


@pytest.mark.parametrize(
    "dport, proto, expected_result, mock_port_info, "
    "mock_is_ftp_port, mock_port_belongs_to_an_org",
    [  # Testcase 1: Known port, info available in the database
        ("23", "udp", False, "telnet", False, False),
        # Testcase 2: Unknown port, belongs to an organization
        ("1337", "udp", False, None, False, True),
    ],
)
def test_check_unknown_port(
    mocker,
    mock_db,
    dport,
    proto,
    expected_result,
    mock_port_info,
    mock_is_ftp_port,
    mock_port_belongs_to_an_org,
):
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_db.get_port_info.return_value = mock_port_info
    mock_db.is_ftp_port.return_value = mock_is_ftp_port
    flowalerts_mock = mocker.patch(
        "modules.flowalerts.conn.Conn.port_belongs_to_an_org"
    )
    flowalerts_mock.return_value = mock_port_belongs_to_an_org

    assert (
        conn.check_unknown_port(
            dport, proto, daddr, profileid, twid, uid, timestamp, "Established"
        )
        is expected_result
    )


@pytest.mark.parametrize(
    "origstate, saddr, daddr, dport, uids, expected_calls",
    [
        (  # Testcase1:5 rejections, evidence should be set
            "REJ",
            "192.168.1.1",
            "192.168.1.2",
            80,
            [f"uid_{i}" for i in range(5)],
            1,
        ),
        (  # Testcase2: Less than 5 rejections, no evidence
            "REJ",
            "192.168.1.1",
            "192.168.1.2",
            80,
            [f"uid_{i}" for i in range(4)],
            0,
        ),
        (  # Testcase3: Non-REJ state, no evidence
            "Established",
            "192.168.1.1",
            "192.168.1.2",
            80,
            ["uid_1"],
            0,
        ),
    ],
)
def test_check_multiple_reconnection_attempts(
    mocker, mock_db, origstate, saddr, daddr, dport, uids, expected_calls
):
    """
    Tests the check_multiple_reconnection_attempts function
    with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence."
        "SetEvidnceHelper.multiple_reconnection_attempts"
    )
    mock_db.get_reconnections_for_tw.return_value = {}

    for uid in uids:
        conn.check_multiple_reconnection_attempts(
            origstate, saddr, daddr, dport, uid, profileid, twid, timestamp
        )

    assert mock_set_evidence.call_count == expected_calls


@pytest.mark.parametrize(
    "ip_address, expected_result",
    [  # Testcase1:Gateway
        ("192.168.1.1", True),
        # Testcase2:Multicast
        ("224.0.0.1", True),
        # Testcase3:Link-local
        ("169.254.1.1", True),
        # Testcase4:Reserved
        ("240.0.0.0", True),
        # Testcase5:Normal IP
        ("8.8.8.8", False),
    ],
)
def test_is_ignored_ip_data_upload(mock_db, ip_address, expected_result):
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    conn.gateway = "192.168.1.1"

    assert conn.is_ignored_ip_data_upload(ip_address) is expected_result


@pytest.mark.parametrize(
    "all_flows, expected_bytes_sent",
    [
        (  # Testcase 1: Normal flows with data
            {
                "uid1": {
                    "daddr": "8.8.8.8",
                    "sbytes": 1024,
                    "starttime": "2023-11-01 12:00:00",
                },
                "uid2": {
                    "daddr": "8.8.8.8",
                    "sbytes": 2048,
                    "starttime": "2023-11-01 12:02:00",
                },
            },
            {"8.8.8.8": (3072, ["uid1", "uid2"], "2023-11-01 12:02:00")},
        ),
        (  # Testcase 2: Flows with no 'sbytes'
            {
                "uid1": {
                    "daddr": "8.8.8.8",
                    "starttime": "2023-11-01 12:00:00",
                },
                "uid2": {
                    "daddr": "8.8.4.4",
                    "sbytes": 2048,
                    "starttime": "2023-11-01 12:02:00",
                },
            },
            {"8.8.4.4": (2048, ["uid2"], "2023-11-01 12:02:00")},
        ),
    ],
)
def test_get_sent_bytes(mock_db, all_flows, expected_bytes_sent):
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    bytes_sent = conn.get_sent_bytes(all_flows)
    assert bytes_sent == expected_bytes_sent


@pytest.mark.parametrize(
    "sbytes, daddr, expected_result, expected_call_count",
    [  # Testcase1: Exceeds threshold
        (100 * 1024 * 1024 + 1, "192.168.1.2", True, 1),
        # Testcase2: Below threshold
        (10 * 1024 * 1024, "192.168.1.2", False, 0),
        # Testcase3: Ignored IP
        (100 * 1024 * 1024 + 1, "192.168.1.1", False, 0),
        # Testcase4: No daddr
        (100 * 1024 * 1024 + 1, None, False, 0),
    ],
)
def test_check_data_upload(
    mocker, mock_db, sbytes, daddr, expected_result, expected_call_count
):
    """
    Tests the check_data_upload function with
    various scenarios for data upload.
    """
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence." "SetEvidnceHelper.data_exfiltration"
    )
    conn.gateway = "192.168.1.1"

    assert (
        conn.check_data_upload(sbytes, daddr, uid, profileid, twid, timestamp)
        is expected_result
    )
    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "flow_type, appproto, daddr, input_type, "
    "is_doh_server, is_dns_server, "
    "client_ips, expected_result",
    [
        # Testcase 1: Not a 'conn' flow type
        ("dns", "dns", "8.8.8.8", "pcap", False, False, [], True),
        # Testcase 2: DNS application protocol
        ("conn", "dns", "8.8.8.8", "pcap", False, False, [], True),
        # Testcase 3: Ignored IP
        ("conn", "http", "192.168.1.1", "pcap", False, False, [], True),
        # Testcase 4: Client IP
        ("conn", "http", "10.0.0.1", "pcap", False, False, ["10.0.0.1"], True),
        # Testcase 5: DoH server
        ("conn", "http", "1.1.1.1", "pcap", True, False, [], True),
        # Testcase 6: DNS server
        ("conn", "http", "8.8.8.8", "pcap", False, True, [], True),
        # Testcase 7: Should not ignore
        ("conn", "http", "93.184.216.34", "pcap", False, False, [], False),
    ],
)
def test_should_ignore_conn_without_dns(
    mocker,
    mock_db,
    flow_type,
    appproto,
    daddr,
    input_type,
    is_doh_server,
    is_dns_server,
    client_ips,
    expected_result,
):
    """Tests the should_ignore_conn_without_dns
    function with various scenarios."""
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_db.get_input_type.return_value = input_type
    mock_db.is_doh_server.return_value = is_doh_server
    conn.dns_analyzer = Mock()
    conn.dns_analyzer.is_dns_server = Mock(return_value=is_dns_server)

    conn.client_ips = client_ips
    mocker.patch(
        "slips_files.common.slips_utils.utils.is_ignored_ip",
        side_effect=lambda ip: ip_address(ip).is_private,
    )

    assert (
        conn.should_ignore_conn_without_dns(flow_type, appproto, daddr)
        is expected_result
    )


@pytest.mark.parametrize(
    "profileid, daddr, mock_get_the_other_ip_version_return_value, "
    "mock_get_dns_resolution_return_value, expected_result",
    [
        (  # Test case 1: Resolution done by the other IP version
            profileid,
            daddr,
            json.dumps("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            {"resolved-by": ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]},
            True,
        ),
        (  # Test case 2: Resolution not done by another IP
            profileid,
            "2.3.4.5",
            json.dumps("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            {"resolved-by": []},
            False,
        ),
        (  # Test case 3: No other IP version found
            profileid,
            daddr,
            None,
            {"resolved-by": ["192.168.1.2"]},
            False,
        ),
        (  # Test case 4: 'resolved-by' is a string, not a list
            profileid,
            daddr,
            json.dumps("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            {"resolved-by": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
            True,
        ),
    ],
)
def test_check_if_resolution_was_made_by_different_version(
    mock_db,
    profileid,
    daddr,
    mock_get_the_other_ip_version_return_value,
    mock_get_dns_resolution_return_value,
    expected_result,
):
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_db.get_the_other_ip_version.return_value = (
        mock_get_the_other_ip_version_return_value
    )
    mock_db.get_dns_resolution.return_value = (
        mock_get_dns_resolution_return_value
    )

    assert (
        conn.check_if_resolution_was_made_by_different_version(
            profileid, daddr
        )
        is expected_result
    )


@pytest.mark.parametrize(
    "sport, dport, proto, " "saddr, daddr, expected_calls",
    [
        (  # Testcase 1: Connection to port 0, evidence should be set
            0,
            80,
            "tcp",
            "192.168.1.1",
            "192.168.1.2",
            1,
        ),
        (  # Testcase 2: Connection from port 0, evidence should be set
            80,
            0,
            "tcp",
            "192.168.1.1",
            "192.168.1.2",
            1,
        ),
        (  # Testcase 3:  Both ports are non-zero, no evidence
            80,
            80,
            "tcp",
            "192.168.1.1",
            "192.168.1.2",
            0,
        ),
        (  # Testcase 4: IGMP protocol, no evidence
            0,
            0,
            "igmp",
            "192.168.1.1",
            "192.168.1.2",
            0,
        ),
    ],
)
def test_check_conn_to_port_0(
    mocker, mock_db, sport, dport, proto, saddr, daddr, expected_calls
):
    """
    Tests the check_conn_to_port_0 function with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence."
        "SetEvidnceHelper.for_port_0_connection"
    )

    conn.check_conn_to_port_0(
        sport, dport, proto, saddr, daddr, profileid, twid, uid, timestamp
    )
    assert mock_set_evidence.call_count == expected_calls


@pytest.mark.parametrize(
    "state, daddr, dport, proto," " appproto, allbytes, expected_calls",
    [
        (  # Testcase 1: Established connection on port 80, not HTTP
            "Established",
            "192.168.1.2",
            80,
            "tcp",
            "ftp",
            1024,
            1,
        ),
        (  # Testcase 2: Established connection on port 80, HTTP
            "Established",
            "192.168.1.2",
            80,
            "tcp",
            "http",
            1024,
            0,
        ),
        (  # Testcase 3: Not an established connection
            "Syn",
            "192.168.1.2",
            80,
            "tcp",
            "ftp",
            1024,
            0,
        ),
        (  # Testcase 4: Different port than 80
            "Established",
            "192.168.1.2",
            8080,
            "tcp",
            "ftp",
            1024,
            0,
        ),
        (  # Testcase 5:  Different protocol than TCP
            "Established",
            "192.168.1.2",
            80,
            "udp",
            "ftp",
            1024,
            0,
        ),
        (  # Testcase 6: Zero bytes transferred
            "Established",
            "192.168.1.2",
            80,
            "tcp",
            "ftp",
            0,
            0,
        ),
    ],
)
def test_check_non_http_port_80_conns(
    mocker,
    mock_db,
    state,
    daddr,
    dport,
    proto,
    appproto,
    allbytes,
    expected_calls,
):
    """
    Tests the check_non_http_port_80_conns
    function with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence."
        "SetEvidnceHelper.non_http_port_80_conn"
    )

    conn.check_non_http_port_80_conns(
        state,
        daddr,
        dport,
        proto,
        appproto,
        allbytes,
        profileid,
        twid,
        uid,
        timestamp,
    )
    assert mock_set_evidence.call_count == expected_calls


@pytest.mark.parametrize(
    "dur, daddr, saddr, expected_result, " "expected_evidence_call",
    [
        (  # Test case 1: Duration above threshold
            2000,
            "192.168.1.2",
            "192.168.1.1",
            True,
            1,
        ),
        (  # Test case 2: Duration below threshold
            1000,
            "192.168.1.2",
            "192.168.1.1",
            False,
            0,
        ),
        (  # Test case 4: Duration as string
            "2000",
            "192.168.1.2",
            "192.168.1.1",
            True,
            1,
        ),
    ],
)
def test_check_long_connection(
    mocker, mock_db, dur, daddr, saddr, expected_result, expected_evidence_call
):
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    conn.long_connection_threshold = 1500
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence." "SetEvidnceHelper.long_connection"
    )

    result = conn.check_long_connection(
        dur, daddr, saddr, profileid, twid, uid, timestamp
    )

    assert result == expected_result
    assert mock_set_evidence.call_count == expected_evidence_call


@pytest.mark.parametrize(
    "daddr, portproto, org_info, mac_vendor, "
    "ip_identification, is_ip_in_org, expected_result",
    [
        # Test case 1: IP belongs to organization's range
        (
            "192.168.1.2",
            "80/tcp",
            json.dumps({"ip": ["192.168.1.0/24"], "org_name": ["TestOrg"]}),
            "",
            "",
            False,
            True,
        ),
        # Test case 2: MAC vendor matches organization
        (
            "10.0.0.1",
            "443/tcp",
            json.dumps({"ip": [], "org_name": ["AppleInc"]}),
            "Apple, Inc.",
            "",
            True,
            True,
        ),
        # Test case 3: IP identification matches organization
        (
            "172.16.0.1",
            "8080/tcp",
            json.dumps({"ip": [], "org_name": ["Google"]}),
            "",
            "dns.google.com",
            False,
            True,
        ),
        # Test case 4: IP belongs to organization
        (
            "157.240.3.35",
            "443/tcp",
            json.dumps({"ip": [], "org_name": ["Facebook"]}),
            "",
            "",
            True,
            True,
        ),
        # Test case 5: IP doesn't belong to any organization
        (
            "203.0.113.1",
            "22/tcp",
            json.dumps({"ip": [], "org_name": []}),
            "",
            "",
            False,
            False,
        ),
    ],
)
def test_port_belongs_to_an_org(
    mocker,
    mock_db,
    daddr,
    portproto,
    org_info,
    mac_vendor,
    ip_identification,
    is_ip_in_org,
    expected_result,
):
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_db.get_organization_of_port.return_value = org_info
    mock_db.get_mac_vendor_from_profile.return_value = mac_vendor
    mock_db.get_ip_identification.return_value = ip_identification
    mocker.patch.object(
        conn.whitelist.org_analyzer, "is_ip_in_org", return_value=is_ip_in_org
    )

    assert (
        conn.port_belongs_to_an_org(daddr, portproto, profileid)
        == expected_result
    )


@pytest.mark.parametrize(
    "flow_type, smac, old_ip_list, saddr, expected_calls",
    [
        # Test case 1: New IP for existing MAC
        (
            "conn",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "192.168.1.3",
            1,
        ),
        # Test case 2: Same IP for existing MAC
        (
            "conn",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "192.168.1.2",
            0,
        ),
        # Test case 3: Non-conn flow type
        (
            "dns",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "192.168.1.3",
            0,
        ),
        # Test case 4: Public IP (should be ignored)
        (
            "conn",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "8.8.8.8",
            0,
        ),
        # Test case 5: IP already seen in connlog
        (
            "conn",
            "00:11:22:33:44:55",
            json.dumps(["192.168.1.2"]),
            "192.168.1.3",
            0,
        ),
    ],
)
def test_check_device_changing_ips(
    mocker, mock_db, flow_type, smac, old_ip_list, saddr, expected_calls
):
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_set_evidence = mocker.patch.object(
        conn.set_evidence, "device_changing_ips"
    )
    mock_db.was_ip_seen_in_connlog_before.return_value = expected_calls == 0
    mock_db.get_ip_of_mac.return_value = old_ip_list

    conn.check_device_changing_ips(
        flow_type, smac, f"profile_{saddr}", twid, uid, timestamp
    )
    assert mock_set_evidence.call_count == expected_calls


@pytest.mark.parametrize(
    "ip, ip_info, is_ip_asn_in_org_asn, "
    "is_domain_in_org, is_ip_in_org, expected_result",
    [
        # Test case 1: Well-known org by SNI
        (
            "8.8.8.8",
            {
                "SNI": {"server_name": "google.com"},
                "reverse_dns": "dns.google",
            },
            False,
            True,
            False,
            True,
        ),
        # Test case 2: Well-known org by reverse DNS
        (
            "157.240.3.35",
            {
                "SNI": None,
                "reverse_dns": "edge-star-mini-shv-01-amt2.facebook.com",
            },
            False,
            True,
            False,
            True,
        ),
        # Test case 3: Well-known org by ASN
        (
            "13.107.42.14",
            {"SNI": None, "reverse_dns": None},
            True,
            False,
            False,
            True,
        ),
        # Test case 4: Well-known org by IP range
        (
            "204.79.197.200",
            {"SNI": None, "reverse_dns": None},
            False,
            False,
            True,
            True,
        ),
        # Test case 5: Not a well-known org
        (
            "203.0.113.1",
            {"SNI": None, "reverse_dns": None},
            False,
            False,
            False,
            False,
        ),
    ],
)
def test_is_well_known_org(
    mocker,
    mock_db,
    ip,
    ip_info,
    is_ip_asn_in_org_asn,
    is_domain_in_org,
    is_ip_in_org,
    expected_result,
):
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_db.get_ip_info.return_value = ip_info
    mock_is_ip_asn_in_org_asn = mocker.patch(
        "slips_files.core.helpers.whitelist.organization_whitelist."
        "OrgAnalyzer.is_ip_asn_in_org_asn"
    )
    mock_is_ip_asn_in_org_asn.return_value = is_ip_asn_in_org_asn

    mock_is_domain_in_org = mocker.patch(
        "slips_files.core.helpers.whitelist.organization_whitelist."
        "OrgAnalyzer.is_domain_in_org"
    )
    mock_is_domain_in_org.return_value = is_domain_in_org

    mock_is_ip_in_org = mocker.patch(
        "slips_files.core.helpers.whitelist."
        "organization_whitelist.OrgAnalyzer.is_ip_in_org"
    )
    mock_is_ip_in_org.return_value = is_ip_in_org
    assert conn.is_well_known_org(ip) == expected_result


@pytest.mark.parametrize(
    "saddr, daddr, dport, proto, what_to_check, expected_calls",
    [
        (  # Test case 1: Different local network usage (dstip),
            # evidence should be set
            "192.168.1.1",
            "10.0.0.1",
            80,
            "tcp",
            "dstip",
            1,
        ),
        (  # Test case 2: Same local network usage, no evidence
            "192.168.1.1",
            "192.168.1.2",
            80,
            "tcp",
            "dstip",
            0,
        ),
        (  # Test case 3: Different local network usage (srcip),
            # evidence should be set
            "10.0.0.1",
            "192.168.1.2",
            80,
            "tcp",
            "srcip",
            1,
        ),
        (  # Test case 4:  Public IP used, no evidence
            "8.8.8.8",
            "192.168.1.2",
            80,
            "tcp",
            "srcip",
            0,
        ),
    ],
)
def test_check_different_localnet_usage(
    mocker, mock_db, saddr, daddr, dport, proto, what_to_check, expected_calls
):
    """
    Tests the check_different_localnet_usage function
    with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence."
        "SetEvidnceHelper.different_localnet_usage"
    )
    mock_db.get_local_network.return_value = "192.168.1.0/24"

    conn.check_different_localnet_usage(
        saddr,
        daddr,
        dport,
        proto,
        profileid,
        timestamp,
        twid,
        uid,
        what_to_check,
    )
    assert mock_set_evidence.call_count == expected_calls


@pytest.mark.parametrize(
    "daddr, dport, proto, saddr, expected_calls",
    [
        (  # Test case 1: Both IPs are private,
            # not a DNS connection to the gateway
            "192.168.1.2",
            80,
            "tcp",
            "192.168.1.1",
            1,
        ),
        (  # Test case 2: Both IPs are private but
            # it's a DNS connection to the gateway
            "192.168.1.1",
            53,
            "udp",
            "192.168.1.2",
            0,
        ),
        (  # Test case 3: One IP is not private
            "8.8.8.8",
            80,
            "tcp",
            "192.168.1.1",
            0,
        ),
    ],
)
def test_check_connection_to_local_ip(
    mocker, mock_db, daddr, dport, proto, saddr, expected_calls
):
    """
    Tests the check_connection_to_local_ip function with various scenarios.
    """
    conn = ModuleFactory().create_conn_analyzer_obj(mock_db)
    mock_set_evidence = mocker.patch.object(
        conn.set_evidence, "conn_to_private_ip"
    )
    mock_db.get_gateway_ip.return_value = "192.168.1.1"

    conn.check_connection_to_local_ip(
        daddr, dport, proto, saddr, twid, uid, timestamp
    )
    assert mock_set_evidence.call_count == expected_calls
