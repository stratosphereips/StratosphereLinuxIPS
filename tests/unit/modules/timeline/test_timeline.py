# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import Mock, patch

from slips_files.core.flows.suricata import (
    SuricataFlow,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "profileid, twid, uid, alt_flow, expected",
    [
        # testcase1: DNS altflow with successful resolution
        (
            "profile_192.168.1.100",
            "1",
            "uid123",
            {
                "type_": "dns",
                "query": "example.com",
                "answers": ["1.1.1.1"],
                "rcode_name": "NOERROR",
            },
            {
                "info": {"query": "example.com", "answers": ["1.1.1.1"]},
                "critical warning": "",
            },
        ),
        # testcase2: HTTP altflow with GET request
        (
            "profile_192.168.1.100",
            "1",
            "uid456",
            {
                "type_": "http",
                "method": "GET",
                "host": "example.com",
                "uri": "/",
                "status_code": 200,
                "status_msg": "OK",
                "resp_mime_types": ["text/html"],
                "user_agent": "Mozilla/5.0",
            },
            {
                "info": {
                    "Request": "GET http://example.com/",
                    "Status Code": "200/OK",
                    "MIME": "['text/html']",
                    "UA": "Mozilla/5.0",
                }
            },
        ),
        # testcase3: SSL altflow with successful validation
        (
            "profile_192.168.1.100",
            "1",
            "uid789",
            {
                "type_": "ssl",
                "validation_status": "ok",
                "resumed": False,
                "subject": "CN=example.com",
                "version": "TLSv1.2",
                "server_name": "example.com",
            },
            {
                "info": {
                    "critical warning": "",
                    "server_name": "CN=example.com",
                    "trusted": "Yes",
                    "resumed": "False",
                    "version": "TLSv1.2",
                    "dns_resolution": "example.com",
                }
            },
        ),
        # testcase4: SSH altflow with successful authentication
        (
            "profile_192.168.1.100",
            "1",
            "uid101",
            {
                "type_": "ssh",
                "auth_success": True,
                "auth_attempts": 1,
                "client": "SSH-2.0-OpenSSH_8.2p1",
                "server": "SSH-2.0-OpenSSH_7.4",
            },
            {
                "info": {
                    "login": "Successful",
                    "auth_attempts": 1,
                    "client": "SSH-2.0-OpenSSH_8.2p1",
                    "server": "SSH-2.0-OpenSSH_8.2p1",
                }
            },
        ),
        # testcase5: Unknown altflow type
        (
            "profile_192.168.1.100",
            "1",
            "uid202",
            {"type_": "unknown"},
            {"info": ""},
        ),
    ],
)
def test_process_altflow(profileid, twid, uid, alt_flow, expected):
    timeline = ModuleFactory().create_timeline_object()

    timeline.db.get_altflow_from_uid.return_value = alt_flow
    result = timeline.process_altflow(profileid, twid, Mock())
    assert result == expected


@pytest.mark.parametrize(
    "ip, db_dns_resolution, expected",
    [
        # testcase1: Successful DNS resolution
        ("192.168.1.1", {"domains": ["example.com"]}, "example.com"),
        # testcase2: Multiple DNS resolutions
        (
            "10.0.0.1",
            {"domains": ["multiple.com", "other.com", "another.com"]},
            "multiple.com, other.com, another.com",
        ),
        # testcase3: No DNS resolution found
        ("172.16.0.1", {"domains": []}, "????"),
        # testcase4: Empty DNS resolution
        ("8.8.8.8", {}, "????"),
    ],
)
def test_get_dns_resolution(ip, db_dns_resolution, expected):
    timeline = ModuleFactory().create_timeline_object()
    timeline.db.get_dns_resolution.return_value = db_dns_resolution
    result = timeline.get_dns_resolution(ip)
    assert result == expected


@pytest.mark.parametrize(
    "alt_flow, expected",
    [
        # testcase1: Successful SSH login attempt
        (
            {
                "auth_success": True,
                "auth_attempts": 1,
                "client": "SSH-2.0-OpenSSH_8.2p1",
                "server": "SSH-2.0-OpenSSH_7.4",
            },
            {
                "info": {
                    "login": "Successful",
                    "auth_attempts": 1,
                    "client": "SSH-2.0-OpenSSH_8.2p1",
                    "server": "SSH-2.0-OpenSSH_8.2p1",
                }
            },
        ),
        # testcase2: Unsuccessful SSH login attempt
        (
            {
                "auth_success": False,
                "auth_attempts": 3,
                "client": "SSH-2.0-PuTTY_0.74",
                "server": "SSH-2.0-OpenSSH_8.0",
            },
            {
                "info": {
                    "login": "Not Successful",
                    "auth_attempts": 3,
                    "client": "SSH-2.0-PuTTY_0.74",
                    "server": "SSH-2.0-PuTTY_0.74",
                }
            },
        ),
    ],
)
def test_process_ssh_altflow(alt_flow, expected):
    timeline = ModuleFactory().create_timeline_object()
    result = timeline.process_ssh_altflow(alt_flow)
    assert result == expected


@pytest.mark.parametrize(
    "saddr, dport_name, flow, expected_activity",
    [
        # testcase1: ICMP echo request (PING)
        (
            "192.168.1.100",
            "",
            {
                "sport": "0x0008",
                "dport": "0x0000",
                "ts": 1625097600,
                "saddr": "192.168.1.100",
                "daddr": "10.0.0.1",
                "dur": 0.5,
                "allbytes": 64,
            },
            {
                "timestamp": "",
                "dport_name": "PING echo",
                "preposition": "from",
                "saddr": "192.168.1.100",
                "size": 64,
                "duration": 0,
                "dns_resolution": "",
                "daddr": "10.0.0.1",
                "dport/proto": "0x0008/ICMP",
                "state": "",
                "warning": "",
                "sent": "",
                "recv": "",
                "tot": "",
                "critical warning": "",
            },
        ),
        # testcase2: ICMP Destination Net Unreachable message
        (
            "10.0.0.1",
            "",
            {
                "sport": 3,
                "dport": "0x0000",
                "ts": 1625097700,
                "saddr": "10.0.0.1",
                "daddr": "192.168.1.100",
                "dur": 0,
                "allbytes": 32,
            },
            {
                "timestamp": "",
                "dport_name": "ICMP Destination Net Unreachable",
                "preposition": "from",
                "saddr": "10.0.0.1",
                "size": 32,
                "duration": 0,
                "dns_resolution": "",
                "daddr": "192.168.1.100",
                "dport/proto": "3/ICMP",
                "state": "",
                "warning": "",
                "sent": "",
                "recv": "",
                "tot": "",
                "critical warning": "",
            },
        ),
    ],
)
def test_process_icmp_flow(saddr, dport_name, flow, expected_activity):
    timeline = ModuleFactory().create_timeline_object()
    timeline.is_human_timestamp = False
    flow = SuricataFlow(
        uid="unique-flow-id",
        saddr=flow["saddr"],
        sport=flow["sport"],
        daddr=flow["daddr"],
        dport=flow["dport"],
        proto="ICMP",
        appproto=False,
        starttime="1729870760.8416235",
        endtime="1729870760.8416235",
        spkts=1,
        dpkts=1,
        sbytes=flow["allbytes"] // 2,
        dbytes=flow["allbytes"] // 2,
        state="New",
    )
    flow.timestamp_human = ""
    result = timeline.process_icmp_flow(flow)
    assert result == expected_activity


@pytest.mark.parametrize(
    "saddr, dport_name, flow, expected_activity",
    [  # Testcase1:Standard IGMP join
        (
            "192.168.1.100",
            "",
            {
                "ts": 1625097600,
                "dur": 0.1,
                "daddr": "224.0.0.1",
                "allbytes": 32,
            },
            {
                "critical warning": "",
                "timestamp": 1625097600,
                "dport_name": "IGMP",
                "preposition": "from",
                "saddr": "192.168.1.100",
                "size": 32,
                "duration": 0.1,
            },
        ),
        # Testcase2: Different profile ID
        (
            "10.0.0.5",
            "IGMPv3",
            {
                "ts": 1625097800,
                "dur": 0.5,
                "daddr": "224.0.0.22",
                "allbytes": 64,
            },
            {
                "critical warning": "",
                "timestamp": 1625097800,
                "dport_name": "IGMP",
                "preposition": "from",
                "saddr": "10.0.0.5",
                "size": 64,
                "duration": 0.5,
            },
        ),
        # Testcase3: Large packet size
        (
            "172.16.1.10",
            "",
            {
                "ts": 1625098000,
                "dur": 0.01,
                "daddr": "224.0.0.252",
                "allbytes": 1500,
            },
            {
                "critical warning": "",
                "timestamp": 1625098000,
                "dport_name": "IGMP",
                "preposition": "from",
                "saddr": "172.16.1.10",
                "size": 1500,
                "duration": 0.01,
            },
        ),
    ],
)
def test_process_igmp_flow(saddr, dport_name, flow, expected_activity):
    timeline = ModuleFactory().create_timeline_object()
    timestamp_human = flow["ts"]
    flow = SuricataFlow(
        uid="unique-flow-id",
        saddr=saddr,
        sport="21",
        daddr=flow["daddr"],
        dur=flow["dur"],
        dport="23",
        proto=dport_name,
        appproto=False,
        starttime=flow["ts"],
        endtime="1729870760.8416235",
        spkts=1,
        dpkts=1,
        sbytes=flow["allbytes"] // 2,
        dbytes=flow["allbytes"] // 2,
        state="New",
    )
    flow.timestamp_human = timestamp_human
    timeline.is_human_timestamp = False
    result = timeline.process_igmp_flow(flow)
    assert result == expected_activity


@pytest.mark.parametrize(
    "flow, expected_dport_name",
    [
        # testcase1: Flow with appproto set to "http"
        ({"appproto": "http", "dport": 80, "proto": "tcp"}, "HTTP"),
        # testcase2: Flow with appproto empty but known port and protocol
        ({"appproto": "", "dport": 443, "proto": "tcp"}, "HTTPS"),
        # testcase3: Flow with appproto set to "failed"
        ({"appproto": "failed", "dport": 22, "proto": "tcp"}, "SSH"),
        # testcase4: Flow with unknown port and protocol
        ({"appproto": "", "dport": 12345, "proto": "udp"}, ""),
    ],
)
def test_interpret_dport(flow, expected_dport_name):
    timeline = ModuleFactory().create_timeline_object()

    timeline.db.get_port_info.side_effect = lambda x: {
        "80/tcp": "HTTP",
        "443/tcp": "HTTPS",
        "22/tcp": "SSH",
    }.get(x, "")
    flow = SuricataFlow(
        uid="unique-flow-id",
        saddr="192.168.1.1",
        sport="21",
        daddr="8.8.8.8",
        dur=4,
        dport=flow["dport"],
        proto=flow["proto"],
        appproto=flow["appproto"],
        starttime="1234",
        endtime="1729870760.8416235",
        spkts=1,
        dpkts=1,
        sbytes=2,
        dbytes=2,
        state="New",
    )
    result = timeline.interpret_dport(flow)
    assert result == expected_dport_name


@pytest.mark.parametrize(
    "saddr," "flow, expected_activity",
    [
        # testcase1: Outbound HTTP flow
        (
            "192.168.1.100",
            {
                "dur": 1.5,
                "daddr": "10.0.0.1",
                "state": "established",
                "ts": 1625097600,
                "dport": 80,
                "proto": "tcp",
                "bytes": 500,
                "appproto": "HTTP",
            },
            {
                "timestamp": 1625097600,
                "dport_name": "HTTP",
                "preposition": "to",
                "dns_resolution": "????",
                "daddr": "10.0.0.1",
                "dport/proto": "80/TCP",
                "state": "Established",
                "warning": "",
                "info": "",
                "sent": 500,
                "recv": 500,
                "tot": 1000,
                "duration": 1.5,
                "critical warning": "",
            },
        ),
        # testcase2: Inbound HTTPS flow with no data exchange
        (
            "10.0.0.1",
            {
                "dur": 2.0,
                "daddr": "10.0.0.1",
                "state": "closed",
                "ts": 1625097700,
                "dport": 443,
                "proto": "tcp",
                "bytes": 0,
                "appproto": "HTTPS",
            },
            {
                "timestamp": 1625097700,
                "dport_name": "HTTPS",
                "preposition": "to",
                "dns_resolution": "????",
                "daddr": "10.0.0.1",
                "dport/proto": "443/TCP",
                "state": "Established",
                "warning": "No data exchange!",
                "info": "",
                "sent": 0,
                "recv": 0,
                "tot": 0,
                "duration": 2.0,
                "critical warning": "",
            },
        ),
    ],
)
def test_process_tcp_udp_flow(saddr, flow, expected_activity):
    timeline = ModuleFactory().create_timeline_object()
    timeline.is_human_timestamp = False
    timeline.analysis_direction = "all"
    timeline.db.get_dns_resolution.return_value = {"domains": []}
    timeline.db.get_final_state_from_flags.return_value = "Established"
    flow = SuricataFlow(
        uid="1234",
        saddr=saddr,
        sport="21",
        daddr=flow["daddr"],
        dur=flow["dur"],
        dport=flow["dport"],
        proto=flow["proto"],
        appproto=flow["appproto"],
        starttime=flow["ts"],
        endtime="1729870760.8416235",
        spkts=1,
        dpkts=1,
        sbytes=flow["bytes"],
        dbytes=flow["bytes"],
        state=flow["state"],
    )
    flow.dport_name = flow.appproto
    flow.timestamp_human = flow.starttime
    result = timeline.process_tcp_udp_flow(flow)
    assert result == expected_activity


@pytest.mark.parametrize(
    "timestamp, is_human, expected",
    [
        # testcase1: Timestamp in epoch format,
        # no conversion needed
        (1625097600, False, "1625097600"),
        # testcase2: Timestamp in epoch format,
        # converted to human-readable
        (1625097600, True, "2021-07-01 00:00:00"),
        # testcase3: Another timestamp in epoch format,
        # no conversion needed
        (1609459200, False, "1609459200"),
        # testcase4: Another timestamp in epoch format,
        # converted to human-readable
        (1609459200, True, "2021-01-01 00:00:00"),
    ],
)
def test_convert_timestamp_to_slips_format(timestamp, is_human, expected):
    timeline = ModuleFactory().create_timeline_object()
    timeline.is_human_timestamp = is_human
    with patch(
        "slips_files.common.slips_utils.utils.convert_format",
        return_value=expected,
    ):
        result = timeline.convert_timestamp_to_slips_format(timestamp)
        assert result == expected


@pytest.mark.parametrize(
    "input_bytes, expected",
    [
        # testcase1: Valid byte value
        (100, 100),
        # testcase2: None value, converted to 0
        (None, 0),
        # testcase3: Invalid byte value, converted to 0
        ("invalid", 0),
    ],
)
def test_ensure_int_bytes(input_bytes, expected):
    timeline = ModuleFactory().create_timeline_object()
    result = timeline.ensure_int_bytes(input_bytes)
    assert result == expected


@pytest.mark.parametrize(
    "host_ip, daddr," "analysis_direction, expected_result",
    [
        # testcase1: Inbound traffic,
        # analysis direction is "all"
        ("192.168.1.100", "192.168.1.100", "all", True),
        # testcase2: Outbound traffic,
        # analysis direction is "all"
        ("192.168.1.100", "10.0.0.1", "all", False),
        # testcase3: Inbound traffic,
        # but analysis direction is "out"
        ("192.168.1.100", "192.168.1.100", "out", False),
        # testcase4: Inbound traffic for a different profile,
        # analysis direction is "all"
        ("10.0.0.1", "10.0.0.1", "all", True),
    ],
)
def test_is_inbound_traffic(
    host_ip, daddr, analysis_direction, expected_result
):
    timeline = ModuleFactory().create_timeline_object()
    timeline.host_ip = host_ip
    timeline.analysis_direction = analysis_direction
    flow = Mock()
    flow.daddr = daddr
    assert timeline.is_inbound_traffic(flow) == expected_result


@pytest.mark.parametrize(
    "alt_flow, expected",
    [
        # testcase1: DNS altflow with a successful A record resolution
        (
            {
                "query": "example.com",
                "answers": ["93.184.216.34"],
                "rcode_name": "NOERROR",
            },
            {
                "info": {"query": "example.com", "answers": ["93.184.216.34"]},
                "critical warning": "",
            },
        ),
        # testcase2: DNS altflow with a NXDOMAIN response (nonexistent domain)
        (
            {
                "query": "nonexistent.com",
                "answers": [],
                "rcode_name": "NXDOMAIN",
            },
            {
                "info": {"query": "nonexistent.com", "answers": "NXDOMAIN"},
                "critical warning": "",
            },
        ),
        # testcase3: DNS altflow with multiple A record resolutions
        (
            {
                "query": "multiple.com",
                "answers": ["1.1.1.1", "2.2.2.2"],
                "rcode_name": "NOERROR",
            },
            {
                "info": {
                    "query": "multiple.com",
                    "answers": ["1.1.1.1", "2.2.2.2"],
                },
                "critical warning": "",
            },
        ),
    ],
)
def test_process_dns_altflow(alt_flow, expected):
    timeline = ModuleFactory().create_timeline_object()
    result = timeline.process_dns_altflow(alt_flow)
    assert result == expected


@pytest.mark.parametrize(
    "alt_flow, expected",
    [
        # testcase1: HTTP altflow with a GET request and a
        # 200 OK response
        (
            {
                "method": "GET",
                "host": "example.com",
                "uri": "/index.html",
                "status_code": 200,
                "status_msg": "OK",
                "resp_mime_types": ["text/html"],
                "user_agent": "Mozilla/5.0",
            },
            {
                "info": {
                    "Request": "GET http://example.com/index.html",
                    "Status Code": "200/OK",
                    "MIME": "['text/html']",
                    "UA": "Mozilla/5.0",
                }
            },
        ),
        # testcase2: HTTP altflow with a POST request and a
        # 201 Created response
        (
            {
                "method": "POST",
                "host": "api.example.com",
                "uri": "/data",
                "status_code": 201,
                "status_msg": "Created",
                "resp_mime_types": ["application/json"],
                "user_agent": "",
            },
            {
                "info": {
                    "Request": "POST http://api.example.com/data",
                    "Status Code": "201/Created",
                    "MIME": "['application/json']",
                }
            },
        ),
    ],
)
def test_process_http_altflow(alt_flow, expected):
    timeline = ModuleFactory().create_timeline_object()
    result = timeline.process_http_altflow(alt_flow)
    assert result == expected


@pytest.mark.parametrize(
    "alt_flow, expected",
    [
        # testcase1: SSL altflow with successful validation
        (
            {
                "validation_status": "ok",
                "resumed": False,
                "subject": "CN=example.com",
                "version": "TLSv1.2",
                "server_name": "example.com",
            },
            {
                "info": {
                    "critical warning": "",
                    "server_name": "CN=example.com",
                    "trusted": "Yes",
                    "resumed": "False",
                    "version": "TLSv1.2",
                    "dns_resolution": "example.com",
                }
            },
        ),
        # testcase2: SSL altflow with unknown validation status
        # and resumed session
        (
            {
                "validation_status": "",
                "resumed": True,
                "subject": "",
                "version": "TLSv1.3",
                "server_name": "unknown.com",
            },
            {
                "info": {
                    "critical warning": "",
                    "server_name": "????",
                    "trusted": "??",
                    "resumed": "True",
                    "version": "TLSv1.3",
                    "dns_resolution": "unknown.com",
                }
            },
        ),
    ],
)
def test_process_ssl_altflow(alt_flow, expected):
    timeline = ModuleFactory().create_timeline_object()
    result = timeline.process_ssl_altflow(alt_flow)
    assert result == expected
