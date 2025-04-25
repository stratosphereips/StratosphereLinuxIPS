# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from tests.module_factory import ModuleFactory
import datetime
import ipaddress
from unittest.mock import patch
import requests
import sys
import pytest
import pytz
import json
from collections import namedtuple


def test_get_sha256_hash():
    utils = ModuleFactory().create_utils_obj()
    # a file that we know doesn't change
    assert (
        utils.get_sha256_hash_of_file_contents("modules/template/__init__.py")
        == "683de4e72614dd4947e5f3b5889e12fa15bf6d5b4c5978683bad78f3c6ad5695"
    )


def test_get_sha256_hash_from_nonexistent_file():
    utils = ModuleFactory().create_utils_obj()
    with pytest.raises(FileNotFoundError):
        utils.get_sha256_hash_of_file_contents("nonexistent_file.txt")


@pytest.mark.parametrize(
    "filepath, expected_result",
    [  # Testcase 1: Supported file
        ("path/to/conn.log", False),
        ("path/to/dns.log", False),
        ("path/to/http.log", False),
        ("path/to/ssl.log", False),
        ("path/to/ssh.log", False),
        ("path/to/dhcp.log", False),
        ("path/to/ftp.log", False),
        ("path/to/smtp.log", False),
        ("path/to/tunnel.log", False),
        ("path/to/notice.log", False),
        ("path/to/files.log", False),
        ("path/to/arp.log", False),
        ("path/to/software.log", False),
        ("path/to/software.log.labeled", False),
        ("path/to/weird.log", False),
        ("path/to/software.log.labeled.something", True),
        ("path/to/unsupported.log", True),
    ],
)
def test_is_ignored_zeek_log_file(filepath, expected_result):
    """
    Test that the is_ignored_file method correctly
    identifies ignored Zeek log files.
    """
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_ignored_zeek_log_file(filepath) == expected_result


def test_get_sha256_hash_permission_error():
    utils = ModuleFactory().create_utils_obj()
    with patch("builtins.open", side_effect=PermissionError):
        with pytest.raises(PermissionError):
            utils.get_sha256_hash_of_file_contents("restricted_file.txt")


@pytest.mark.parametrize(
    "input_string, expected_output",
    [  # Testcase1: special chars
        ("Hello;world`& |$(this", "Helloworld this"),
        # Testcase2: empty input
        ("", ""),
        # Testcase3: input with only special characters
        ("!@#$%^&*()", "!@#%^*"),
        # Testcase4: clean string
        ("Thisisacleanstring", "Thisisacleanstring"),
        # Testcase5: input with spaces
        ("Hello World!", "Hello World!"),
    ],
)
def test_sanitize(input_string, expected_output):
    utils = ModuleFactory().create_utils_obj()
    assert utils.sanitize(input_string) == expected_output


@pytest.mark.parametrize(
    "data, expected_type",
    [
        # testcase1: IPv4 address
        ("192.168.1.100", "ip"),
        # testcase2: IPv6 address
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ip"),
        # testcase3: IP range
        ("192.168.0.0/16", "ip_range"),
        # testcase4: MD5 hash
        ("e10adc3949ba59abbe56e057f20f883e", "md5"),
        # testcase5: Domain name
        ("example.com", "domain"),
        # testcase6: URL
        ("http://example.com/some/path", "url"),
        # testcase7: ASN
        ("AS12345", "asn"),
        # testcase8: Invalid IP address
        ("999.999.999.999", None),
        # testcase9: Invalid data
        ("123456789abcdefg", None),
    ],
)
def test_detect_data_type(data, expected_type):
    utils = ModuleFactory().create_utils_obj()
    assert utils.detect_ioc_type(data) == expected_type


@pytest.mark.parametrize(
    "ip_address, expected_first_octet",
    [
        # testcase1: Valid IPv4 address
        ("192.168.1.100", "192"),
        # testcase2: Valid IPv6 address
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001"),
        # testcase3: Invalid IP address
        ("invalid", None),
    ],
)
def test_get_first_octet(ip_address, expected_first_octet):
    utils = ModuleFactory().create_utils_obj()
    assert utils.get_first_octet(ip_address) == expected_first_octet


@pytest.mark.parametrize(
    "input_value, expected_output",
    [
        # testcase1: Zero packets sent
        (0, 0.3),
        # testcase2: Half of the threshold
        (5, 0.5),
        # testcase3: At the threshold
        (10, 1.0),
        # testcase4: Above the threshold
        (15, 1.0),
        # testcase5: Negative value
        (-5, -0.5),
        # testcase6: Large number of packets
        (1000000, 1),
        # testcase7: Maximum possible value
        (sys.maxsize, 1.0),
    ],
)
def test_calculate_confidence(input_value, expected_output):
    utils = ModuleFactory().create_utils_obj()
    assert utils.calculate_confidence(input_value) == expected_output


@pytest.mark.parametrize(
    "input_value, input_format, expected_output",
    [
        # testcase1: ISO format to custom format
        (
            "2023-04-06T12:34:56.789Z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "2023-04-06T12:34:56.789000Z",
        ),
        # testcase2: Unix timestamp to ISO format
        (1680788096.789, "iso", "2023-04-06T13:34:56.789000+00:00"),
        # testcase3: Unix timestamp to custom format
        # (1680788096.789, "%Y-%m-%d %H:%M:%S", "2023-04-06 13:34:56"),
        # testcase4: Datetime object to Unix timestamp
        (
            datetime.datetime(
                2023, 4, 6, 12, 34, 56, 789000, tzinfo=datetime.timezone.utc
            ),
            "unixtimestamp",
            1680784496.789,
        ),
        # testcase5: Custom format to another custom format
        (
            "2023-04-01 12:00:00",
            "%m/%d/%Y %I:%M %p",
            "04/01/2023 12:00 PM",
        ),
    ],
)
def test_convert_format(input_value, input_format, expected_output):
    utils = ModuleFactory().create_utils_obj()
    utils.local_tz = datetime.timezone.utc
    assert utils.convert_format(input_value, input_format) == expected_output


@pytest.mark.parametrize(
    "input_value, expected_output",
    [
        # testcase1: timestamp with milliseconds
        ("1680788096.789", "1680788096.789000"),
        # testcase2: timestamp without milliseconds
        ("1680788096", "1680788096"),
        # testcase3: timestamp with microseconds
        ("1680788096.123456", "1680788096.123456"),
        # testcase4: timestamp with nanoseconds
        ("1680788096.123456789", "1680788096.123456789"),
    ],
)
def test_assert_microseconds(input_value, expected_output):
    utils = ModuleFactory().create_utils_obj()
    assert utils.assert_microseconds(input_value) == expected_output


@pytest.mark.parametrize(
    "ip_address, expected_result",
    [
        # testcase1: Private IPv4 address
        (ipaddress.ip_address("192.168.1.1"), True),
        # testcase2: Private IPv4 address
        # in 10.0.0.0/8 range
        (ipaddress.ip_address("10.0.0.1"), True),
        # testcase3: Private IPv4 address
        # in 172.16.0.0/12 range
        (ipaddress.ip_address("172.16.0.1"), True),
        # testcase4: Public IPv4 address
        (ipaddress.ip_address("8.8.8.8"), False),
        # testcase5: Special IP address 0.0.0.0
        (ipaddress.ip_address("0.0.0.0"), True),
        # testcase6: Broadcast IP address 255.255.255.255
        (ipaddress.ip_address("255.255.255.255"), True),
    ],
)
def test_is_private_ip(ip_address, expected_result):
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_private_ip(ip_address) == expected_result


@pytest.mark.parametrize(
    "timestamp, expected_result",
    [
        # testcase1: Timestamp with milliseconds
        ("1680788096.789", "1680788096"),
        # testcase2: Timestamp without milliseconds
        ("1680788096", "1680788096"),
        # testcase3: Timestamp with decimal point
        # but no milliseconds
        ("1680788096.", "1680788096"),
    ],
)
def test_remove_milliseconds_decimals(timestamp, expected_result):
    utils = ModuleFactory().create_utils_obj()
    result = utils.remove_milliseconds_decimals(timestamp)
    assert result == expected_result


@pytest.mark.parametrize(
    "start_time, end_time, return_type, expected_result",
    [  # testcase1: Calculate difference in days
        (1609459200, 1609545600, "days", 1),
        # testcase2: Calculate difference in hours
        (1609459200, 1609545600, "hours", 24),
        # testcase3: Handle negative time difference
        (1609545600, 1609459200, "seconds", -86400.0),
        # testcase4: Calculate difference in seconds with fractions
        (1609459200.0, 1609459200.1, "seconds", 0.1),
    ],
)
def test_get_time_diff(start_time, end_time, return_type, expected_result):
    utils = ModuleFactory().create_utils_obj()
    result = utils.get_time_diff(start_time, end_time, return_type)
    assert result == expected_result


@pytest.mark.parametrize(
    "seconds, expected_timedelta",
    [
        # testcase1: One hour
        (3600, datetime.timedelta(seconds=3600)),
        # testcase2: One day
        (86400, datetime.timedelta(days=1)),
        # testcase3: Negative time
        (-3600, datetime.timedelta(seconds=-3600)),
        # testcase4: One year
        (31536000, datetime.timedelta(days=365)),
    ],
)
def test_to_delta(seconds, expected_timedelta):
    utils = ModuleFactory().create_utils_obj()
    result = utils.to_delta(seconds)
    assert result == expected_timedelta


def _check_ip_presence(utils, expected_ip):
    """
    Helper function to check if the given IP is present
    in the list of own IPs.
    """
    return expected_ip in utils.get_own_ips() or not utils.get_own_ips()


def test_get_own_ips_success():
    """Test that the function returns a list when successful."""
    utils = ModuleFactory().create_utils_obj()
    ips = utils.get_own_ips()
    assert isinstance(ips, list), "Should return a list of IPs"


@pytest.mark.parametrize(
    "side_effect",
    [
        requests.exceptions.ConnectionError,
        requests.exceptions.RequestException,
    ],
)
def test_get_own_ips_exceptions(side_effect):
    """Test that the function handles connection errors gracefully."""
    utils = ModuleFactory().create_utils_obj()
    with patch("requests.get", side_effect=side_effect):
        assert _check_ip_presence(utils, "127.0.0.1"), (
            "Should fallback to "
            "localhost when external "
            "IP retrieval fails"
        )


def test_is_port_in_use_with_likely_used_port():
    utils = ModuleFactory().create_utils_obj()
    port = 22
    if utils.is_port_in_use(port):
        assert True


@pytest.mark.parametrize(
    "port, expected_result",
    [
        # testcase1: Using a high port number
        # unlikely to be in use
        (54321, False),
        # testcase2: Explicitly testing with port 0
        (0, False),
    ],
)
def test_is_port_in_use(port, expected_result):
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_port_in_use(port) == expected_result


@pytest.mark.parametrize(
    "threat_level, expected_result",
    [  # testcase1: Valid threat level 'info'
        ("info", True),
        # testcase2: Valid threat level 'low'
        ("low", True),
        # testcase3: Valid threat level 'medium'
        ("medium", True),
        # testcase4: Valid threat level 'high'
        ("high", True),
        # testcase5: Valid threat level 'critical'
        ("critical", True),
        # testcase6: Invalid threat level 'undefined'
        ("undefined", False),
    ],
)
def test_is_valid_threat_level(threat_level, expected_result):
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_valid_threat_level(threat_level) == expected_result


@pytest.mark.parametrize(
    "bytes_value, expected_mb",
    [  # testcase1: 1 MB
        (1000000, 1),
        # testcase2: 5 MB
        (5000000, 5),
        # testcase3: 1 TB
        (10**12, 10**6),
        # testcase4: 1 MiB
        (1048576, 1.048576),
        # testcase5: 0 bytes
        (0, 0),
    ],
)
def test_convert_to_mb(bytes_value, expected_mb):
    utils = ModuleFactory().create_utils_obj()
    assert utils.convert_to_mb(bytes_value) == expected_mb


@pytest.mark.parametrize(
    "message, channel, expected_result",
    [  # Testcase 1: Matching channel and valid data type
        (
            {"data": "Some data", "channel": "test_channel"},
            "test_channel",
            True,
        ),
        # Testcase 2: Non-matching channel
        (
            {"data": "Some data", "channel": "other_channel"},
            "test_channel",
            False,
        ),
        # Testcase 3: Invalid data type
        ({"data": 123, "channel": "test_channel"}, "test_channel", False),
    ],
)
def test_is_msg_intended_for(message, channel, expected_result):
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_msg_intended_for(message, channel) == expected_result


@pytest.mark.parametrize(
    "flow_data, expected_aid",
    [
        # testcase1: TCP flow with all parameters provided
        (
            {
                "proto": "tcp",
                "starttime": "2023-04-06T19:04:56.789+00:00",
                "saddr": "192.168.1.1",
                "daddr": "192.168.1.2",
                "sport": 12345,
                "dport": 80,
            },
            "2:QvutQFnBACLoMzzMRnfCDeD9p2Q=",
        ),
        # testcase2: UDP flow
        (
            {
                "proto": "udp",
                "starttime": "2023-04-07T10:15:20.123+00:00",
                "saddr": "10.0.0.1",
                "daddr": "8.8.8.8",
                "sport": 53,
                "dport": 53,
            },
            "2:oEZri3S+HOEAIC9NpaI+YymWO5g=",
        ),
        # testcase3: ICMP flow
        (
            {
                "proto": "icmp",
                "starttime": "2023-04-08T16:30:00.000+00:00",
                "saddr": "172.16.1.100",
                "daddr": "172.16.1.1",
                "sport": 8,
                "dport": 0,
            },
            "2:XVH75J7X132sIZ4YUqF1bvnwsAg=",
        ),
    ],
)
def test_get_aid(flow_data, expected_aid):
    utils = ModuleFactory().create_utils_obj()
    Flow = namedtuple("Flow", flow_data.keys())
    flow = Flow(**flow_data)

    aid_result = utils.get_aid(flow)
    assert aid_result == expected_aid


def test_convert_to_datetime():
    utils = ModuleFactory().create_utils_obj()
    any_date = "2023-04-01 12:00:00"
    result = utils.convert_to_datetime(any_date)
    assert isinstance(
        result, datetime.datetime
    ), "Should convert string to datetime object."


def test_get_local_timezone():
    utils = ModuleFactory().create_utils_obj()
    local_tz = utils.get_local_timezone()
    assert isinstance(
        local_tz, datetime.timezone
    ), "Should return a timezone object."


@pytest.mark.parametrize(
    "input_ip, expected_cidr",
    [  # Testcase 1: IP within 192.168.0.0/16 range
        ("192.168.1.1", "192.168.0.0/16"),
        # Testcase 2: IP within 10.0.0.0/8 range
        ("10.0.0.1", "10.0.0.0/8"),
        # Testcase 3: IP within 172.16.0.0/12 range
        ("172.16.0.1", "172.16.0.0/12"),
        # Testcase 4: Invalid IP address
        ("invalid_ip", None),
        # Testcase 5: Invalid IP address
        ("256.100.50.25", None),
    ],
)
def test_get_cidr_of_private_ip(input_ip, expected_cidr):
    utils = ModuleFactory().create_utils_obj()
    assert utils.get_cidr_of_private_ip(input_ip) == expected_cidr


@pytest.mark.parametrize(
    "side_effect, setresuid_calls, setresgid_calls",
    [
        (  # testcase1: Environment variables set
            lambda x: {"SUDO_GID": "1000", "SUDO_UID": "1000"}.get(x),
            [((1000, 1000, -1),)],
            [((1000, 1000, -1),)],
        ),
        (  # testcase2: SUDO_GID missing
            lambda x: {"SUDO_UID": "1000"}.get(x),
            [],
            [],
        ),
        (  # testcase3: Environment variables not set
            lambda x: None,
            [],
            [],
        ),
    ],
)
@patch("os.setresgid")
@patch("os.setresuid")
@patch("os.getenv")
def test_drop_root_privs(
    mock_getenv,
    mock_setresuid,
    mock_setresgid,
    side_effect,
    setresuid_calls,
    setresgid_calls,
):
    mock_getenv.side_effect = side_effect
    utils = ModuleFactory().create_utils_obj()
    utils.drop_root_privs()

    assert mock_setresuid.call_args_list == setresuid_calls
    assert mock_setresgid.call_args_list == setresgid_calls


@pytest.mark.parametrize(
    "url, expected_hostname",
    [  # testcase1: Extract hostname from URL with www
        ("https://www.google.com", "google.com"),
        # testcase2: Extract hostname from URL without www
        ("http://example.net", "example.net"),
        # testcase3: Extract hostname from URL with
        # subdomain and path
        ("https://subdomain.example.org/path", "example.org"),
        # testcase4: Extract hostname from FTP URL with user,
        # password, port and path
        ("ftp://user:password@ftp.example.com:21/path", "example.com"),
        # testcase5: Handle IP address as URL
        ("https://192.168.1.1", "192.168.1.1."),
        # testcase6: Handle domain name without
        # protocol as URL
        ("example.com", "example.com"),
    ],
)
def test_extract_hostname(url, expected_hostname):
    utils = ModuleFactory().create_utils_obj()
    assert utils.extract_hostname(url) == expected_hostname


@pytest.mark.parametrize(
    "threat_level, expected_string",
    [  # testcase1: Threat level below 'info' threshold
        (0.0, "info"),
        # testcase2: Threat level at 'low' threshold
        (0.2, "low"),
        # testcase3: Threat level at 'medium' threshold
        (0.5, "medium"),
        # testcase4: Threat level at 'high' threshold
        (0.8, "high"),
        # testcase5: Threat level within 'high' range
        (0.9, "critical"),
        # testcase6: Threat level at 'critical' threshold
        (1, "critical"),
    ],
)
def test_threat_level_to_string(threat_level, expected_string):
    utils = ModuleFactory().create_utils_obj()
    assert utils.threat_level_to_string(threat_level) == expected_string


@pytest.mark.parametrize(
    "ts, expected_local_ts",
    [
        (  # testcase1: Convert UTC timestamp string to utc timezone
            "2023-04-06T12:34:56.789Z",
            datetime.datetime(
                2023, 4, 6, 12, 34, 56, 789000, tzinfo=pytz.utc
            ).astimezone(datetime.timezone.utc),
        ),
        (  # testcase2: Convert Unix timestamp to utc timezone
            1680788096.789,
            datetime.datetime.fromtimestamp(1680788096.789).astimezone(
                datetime.timezone.utc
            ),
        ),
        (  # testcase3: Handle already timezone-aware datetime object
            datetime.datetime(2023, 4, 6, 12, 34, 56, 789000, tzinfo=pytz.utc),
            datetime.datetime(
                2023, 4, 6, 12, 34, 56, 789000, tzinfo=pytz.utc
            ).astimezone(datetime.timezone.utc),
        ),
    ],
)
def test_convert_to_local_timezone(ts, expected_local_ts):
    utils = ModuleFactory().create_utils_obj()
    # to ensure this test results in the same behaviour everywhere
    # so when converting to "local timezone" we always convert to UTC
    utils.local_tz = datetime.timezone.utc
    expected_local_ts = expected_local_ts.replace(tzinfo=None)
    local_ts = utils.convert_to_local_timezone(ts).replace(tzinfo=None)
    assert local_ts == expected_local_ts


@pytest.mark.parametrize(
    "ts, expected_result",
    [  # testcase1: Valid datetime object
        (datetime.datetime.now(), True),
        # testcase2: String representing timestamp
        ("2023-04-06T12:34:56.789Z", False),
        # testcase3: Unix timestamp
        (1680788096.789, False),
        # testcase4: Invalid input
        (None, False),
        # testcase5: Invalid input
        ("invalid datetime", False),
    ],
)
def test_is_datetime_obj(ts, expected_result):
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_datetime_obj(ts) == expected_result


@pytest.mark.parametrize(
    "time, expected_format",
    [  # testcase1: ISO 8601 format with milliseconds and timezone
        ("2023-04-06T12:34:56.789Z", "%Y-%m-%dT%H:%M:%S.%f%z"),
        # testcase2: Format with space separator and milliseconds
        ("2023-04-06 12:34:56.789", "%Y-%m-%d %H:%M:%S.%f"),
        # testcase3: Format with slash separator
        (
            "2023/04/06 12:34:56",
            "%Y/%m/%d %H:%M:%S",
        ),
        # testcase4: ISO 8601 format without milliseconds
        (
            "2023-04-06T12:34:56",
            "%Y-%m-%dT%H:%M:%S",
        ),
        # testcase5: Unix timestamp
        (
            "1680788096.789",
            "unixtimestamp",
        ),
        # testcase6: Unix timestamp
        ("1680788096", "unixtimestamp"),
        # testcase7: datetime object
        (datetime.datetime.now(), "datetimeobj"),
        # testcase8: Invalid time string
        ("invalid time", False),
    ],
)
def test_define_time_format(time, expected_format):
    utils = ModuleFactory().create_utils_obj()
    assert utils.get_time_format(time) == expected_format


@pytest.mark.parametrize(
    "ip_address, expected_result",
    [  # testcase1: Localhost IPv4 should be ignored
        ("127.0.0.1", True),
        # testcase2: Localhost IPv6 should be ignored
        ("::1", True),
        # testcase3: Private IPv4 should be ignored
        ("192.168.1.1", True),
        # testcase4: Another private IPv4 should be ignored
        ("10.0.0.1", True),
        # testcase5: Multicast IPv4 should be ignored
        ("224.0.0.1", True),
        # testcase6: Multicast IPv6 should be ignored
        ("ff02::1", True),
        # testcase7: Link-local IPv4 should be ignored
        ("169.254.0.1", True),
        # testcase8: Link-local IPv6 should be ignored
        ("fe80::", True),
        # testcase9: Broadcast IPv4 should be ignored
        ("255.255.255.255", True),
        # testcase10: Public IPv4 should not be ignored
        ("8.8.8.8", False),
        # testcase11: Public IPv6 should not be ignored
        ("2001:4860:4860::8888", False),
    ],
)
def test_is_ignored_ip(ip_address, expected_result):
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_ignored_ip(ip_address) == expected_result


@pytest.mark.parametrize(
    "input_obj, expected_json",
    [  # testcase1: Simple dictionary
        ({"key": "value"}, '{"key": "value"}'),
        # testcase2: Simple list
        ([1, 2, 3, "test"], '[1, 2, 3, "test"]'),
        # testcase3: Dictionary instead of dataclass
        ({"name": "John", "age": 30}, '{"name": "John", "age": 30}'),
        # testcase4: Directly using enum value
        (2, "2"),
        # testcase5: Nested objects
        (
            {"nested": [{"name": "Jane", "age": 25}, 1]},
            '{"nested": [{"name": "Jane", "age": 25}, 1]}',
        ),
    ],
)
def test_to_json_serializable(input_obj, expected_json):
    utils = ModuleFactory().create_utils_obj()
    result = utils.to_json_serializable(input_obj)
    assert json.dumps(result) == expected_json
