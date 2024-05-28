from tests.module_factory import ModuleFactory
import datetime
import ipaddress
from unittest.mock import patch
import requests
from dataclasses import dataclass
from enum import Enum
import sys
import pytest
import socket


class MockFlow:
    def __init__(self, proto, starttime, saddr, daddr, sport, dport):
        self.proto = proto
        self.starttime = starttime
        self.saddr = saddr
        self.daddr = daddr
        self.sport = sport
        self.dport = dport


def test_get_hash_from_file():
    utils = ModuleFactory().create_utils_obj()
    # a file that we know doesn't change
    assert (
        utils.get_sha256_hash("modules/template/__init__.py")
        == "2d12747a3369505a4d3b722a0422f8ffc8af5514355cdb0eb18178ea7071b8d0"
    )


def test_get_hash_from_nonexistent_file():
    utils = ModuleFactory().create_utils_obj()
    with pytest.raises(FileNotFoundError):
        utils.get_sha256_hash("nonexistent_file.txt")


def test_get_hash_from_file_permission_error():
    utils = ModuleFactory().create_utils_obj()
    with patch("builtins.open", side_effect=PermissionError):
        with pytest.raises(PermissionError):
            utils.get_sha256_hash("restricted_file.txt")


@pytest.mark.parametrize(
    "input_string, expected_output",
    [
        ("Hello; world `& |$(this", "Helloworld`this"),  # special chars
        ("", ""),  # empty input
        ("!@#$%^&*()", ""),  # input with only special characters
        ("Thisisacleanstring", "Thisisacleanstring"),
        ("Hello World!", "HelloWorld"),  # input with spaces
    ],
)
def test_sanitize(input_string, expected_output):
    utils = ModuleFactory().create_utils_obj()
    assert utils.sanitize(input_string) == expected_output


@pytest.mark.parametrize(
    "data, expected_type",
    [
        ("192.168.1.100", "ip"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ip"),
        ("192.168.0.0/16", "ip_range"),
        ("e10adc3949ba59abbe56e057f20f883e", "md5"),
        ("example.com", "domain"),
        ("http://example.com/some/path", "url"),
        ("AS12345", "asn"),
        ("999.999.999.999", None),
        ("123456789abcdefg", None),
    ],
)
def test_detect_data_type(data, expected_type):
    utils = ModuleFactory().create_utils_obj()
    assert utils.detect_data_type(data) == expected_type


def test_get_first_octet():
    utils = ModuleFactory().create_utils_obj()

    # IPv4 address
    assert utils.get_first_octet("192.168.1.100") == "192"
    # IPv6 address
    assert (
        utils.get_first_octet("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        == "2001"
    )
    # invalid IP address
    assert utils.get_first_octet("invalid") is None


@pytest.mark.parametrize(
    "input_value, expected_output",
    [
        (0, 0.3),
        (5, 0.5),
        (10, 1.0),
        (15, 1.0),
        (-5, -0.5),
        (1000000, 1),
        (sys.maxsize, 1.0),
    ],
)
def test_calculate_confidence(input_value, expected_output):
    utils = ModuleFactory().create_utils_obj()
    assert utils.calculate_confidence(input_value) == expected_output


def test_convert_format():
    utils = ModuleFactory().create_utils_obj()
    assert (
        utils.convert_format(
            "2023-04-06T12:34:56.789Z", "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        == "2023-04-06T12:34:56.789000Z"
    )
    assert (
        utils.convert_format(1680788096.789, "iso")
        == "2023-04-06T13:34:56.789000+00:00"
    )
    assert (
        utils.convert_format(1680788096.789, "%Y-%m-%d %H:%M:%S")
        == "2023-04-06 19:04:56"
    )
    assert (
        utils.convert_format(
            datetime.datetime(2023, 4, 6, 12, 34, 56, 789000), "unixtimestamp"
        )
        == 1680764696.789
    )


def test_assert_microseconds():
    utils = ModuleFactory().create_utils_obj()
    assert utils.assert_microseconds("1680788096.789") == "1680788096.789000"
    assert utils.assert_microseconds("1680788096") == "1680788096"
    assert (
        utils.assert_microseconds("1680788096.123456") == "1680788096.123456"
    )
    assert (
        utils.assert_microseconds("1680788096.123456789")
        == "1680788096.123456789"
    )


def test_is_private_ip():
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_private_ip(ipaddress.ip_address("192.168.1.1"))
    assert utils.is_private_ip(ipaddress.ip_address("10.0.0.1"))
    assert utils.is_private_ip(ipaddress.ip_address("172.16.0.1"))
    assert not utils.is_private_ip(ipaddress.ip_address("8.8.8.8"))
    assert not utils.is_private_ip(ipaddress.ip_address("0.0.0.0"))
    assert not utils.is_private_ip(ipaddress.ip_address("255.255.255.255"))


@pytest.mark.parametrize(
    "timestamp, expected_result",
    [
        ("1680788096.789", "1680788096"),
        ("1680788096", "1680788096"),
        ("1680788096.", "1680788096"),
    ],
)
def test_remove_milliseconds_decimals(timestamp, expected_result):
    utils = ModuleFactory().create_utils_obj()
    result = utils.remove_milliseconds_decimals(timestamp)
    assert result == expected_result


@pytest.mark.parametrize(
    "start_time, end_time, return_type, expected_result",
    [
        (1609459200, 1609545600, "days", 1),
        (1609459200, 1609545600, "hours", 24),
        (1609545600, 1609459200, "seconds", lambda result: result < 0),
        (1609459200.0, 1609459200.1, "seconds", 0.1),
    ],
)
def test_get_time_diff(start_time, end_time, return_type, expected_result):
    utils = ModuleFactory().create_utils_obj()
    result = utils.get_time_diff(start_time, end_time, return_type)
    if callable(expected_result):
        assert expected_result(result)
    else:
        assert result == expected_result


@pytest.mark.parametrize(
    "seconds, expected_timedelta",
    [
        (3600, datetime.timedelta(seconds=3600)),
        (86400, datetime.timedelta(days=1)),
        (-3600, datetime.timedelta(seconds=-3600)),
        (31536000, datetime.timedelta(days=365)),
    ],
)
def test_to_delta(seconds, expected_timedelta):
    utils = ModuleFactory().create_utils_obj()
    result = utils.to_delta(seconds)
    assert result == expected_timedelta


def _check_ip_presence(utils, expected_ip):
    """
    Helper function to check if the given IP is present in the list of own IPs.
    """
    return expected_ip in utils.get_own_IPs() or not utils.get_own_IPs()


@pytest.mark.parametrize(
    "side_effect, expected_result",
    [
        (None, lambda utils: isinstance(utils.get_own_IPs(), list)),
        (
            requests.exceptions.ConnectionError,
            lambda utils: _check_ip_presence(utils, "127.0.0.1"),
        ),
        (
            requests.exceptions.RequestException,
            lambda utils: _check_ip_presence(utils, "127.0.0.1"),
        ),
    ],
)
def test_get_own_IPs(side_effect, expected_result):
    utils = ModuleFactory().create_utils_obj()
    if side_effect:
        with patch("requests.get", side_effect=side_effect):
            assert expected_result(
                utils
            ), "Should handle the situation gracefully"
    else:
        assert expected_result(utils), "Should return a list of IPs"


def test_is_port_in_use():
    utils = ModuleFactory().create_utils_obj()

    # Testing with a port that's likely unused
    port = 54321

    assert (
        utils.is_port_in_use(port) is False
    ), f"Port {port} should not be in use."

    # Testing with a port that's definitely in use
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_socket:
        temp_socket.bind(("localhost", 0))
        temp_socket.listen(1)
        used_port = temp_socket.getsockname()[1]
        assert (
            utils.is_port_in_use(used_port) is True
        ), f"Port {used_port} should be in use."


def test_is_valid_threat_level():
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_valid_threat_level("info")
    assert utils.is_valid_threat_level("low")
    assert utils.is_valid_threat_level("medium")
    assert utils.is_valid_threat_level("high")
    assert utils.is_valid_threat_level("critical")
    assert not utils.is_valid_threat_level("undefined")


def test_convert_to_mb():
    utils = ModuleFactory().create_utils_obj()
    assert utils.convert_to_mb(1000000) == 1
    assert utils.convert_to_mb(5000000) == 5
    assert utils.convert_to_mb(10**12) == 10**6
    assert utils.convert_to_mb(1048576) == 1.048576
    assert utils.convert_to_mb(0) == 0


def test_is_msg_intended_for():
    utils = ModuleFactory().create_utils_obj()
    message = {"data": "Some data", "channel": "test_channel"}
    assert utils.is_msg_intended_for(message, "test_channel") is True

    message = {"data": "Some data", "channel": "other_channel"}
    assert utils.is_msg_intended_for(message, "test_channel") is False

    message = {"data": 123, "channel": "test_channel"}
    assert utils.is_msg_intended_for(message, "test_channel") is False


def test_convert_format_between_non_default_formats():
    utils = ModuleFactory().create_utils_obj()
    original_format = "2023-04-01 12:00:00"
    expected_result = "04/01/2023 12:00 PM"
    assert (
        utils.convert_format(original_format, "%m/%d/%Y %I:%M %p")
        == expected_result
    )


@dataclass
class MockDataClass:
    id: int
    name: str


class MockEnum(Enum):
    TYPE1 = "Type 1"
    TYPE2 = "Type 2"


def test_get_aid():
    utils = ModuleFactory().create_utils_obj()
    mock_flow = MockFlow(
        proto="tcp",
        starttime="2023-04-06T19:04:56.789+00:00",
        saddr="192.168.1.1",
        daddr="192.168.1.2",
        sport=12345,
        dport=80,
    )
    aid_result = utils.get_aid(mock_flow)
    assert aid_result is not None, "AID generation failed or returned None."


def test_convert_to_datetime_around_dst():
    utils = ModuleFactory().create_utils_obj()
    any_date = "2023-04-01 12:00:00"
    result = utils.convert_to_datetime(any_date)
    assert isinstance(
        result, datetime.datetime
    ), "Should convert string to datetime object."


@pytest.mark.parametrize(
    "input_ip, expected_cidr",
    [
        ("192.168.1.1", "192.168.0.0/16"),
        ("10.0.0.1", "10.0.0.0/8"),
        ("172.16.0.1", "172.16.0.0/12"),
        ("invalid_ip", None),
        ("256.100.50.25", None),
    ],
)
def test_get_cidr_of_private_ip(input_ip, expected_cidr):
    utils = ModuleFactory().create_utils_obj()
    assert utils.get_cidr_of_private_ip(input_ip) == expected_cidr


@patch("os.setresgid")
@patch("os.setresuid")
@patch(
    "os.getenv",
    side_effect=lambda x: {"SUDO_GID": "1000", "SUDO_UID": "1000"}.get(x),
)
def test_drop_root_privs(mock_getenv, mock_setresuid, mock_setresgid):
    utils = ModuleFactory().create_utils_obj()
    utils.drop_root_privs()
    mock_setresuid.assert_called_once_with(1000, 1000, -1)
    mock_setresgid.assert_called_once_with(1000, 1000, -1)
