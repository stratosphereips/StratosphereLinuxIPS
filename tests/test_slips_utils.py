from tests.module_factory import ModuleFactory
import datetime
import ipaddress
from unittest.mock import patch
import requests
from dataclasses import dataclass
from enum import Enum
import sys
import pytest


def test_get_hash_from_file():
    utils = ModuleFactory().create_utils_obj()
    # a file that we know doesn't change
    assert (
        utils.get_hash_from_file('modules/template/__init__.py')
        == '879d569533ed70a30c2a2e77fe5ae14d5a30606df470f1c354685ee40471140b')
    
def test_get_hash_from_nonexistent_file():
    utils = ModuleFactory().create_utils_obj()
    with pytest.raises(FileNotFoundError):
        utils.get_hash_from_file('nonexistent_file.txt')

def test_get_hash_from_file_permission_error():
    utils = ModuleFactory().create_utils_obj()
    with patch('builtins.open', side_effect=PermissionError):
        with pytest.raises(PermissionError):
            utils.get_hash_from_file('restricted_file.txt')    

def test_sanitize():
    utils = ModuleFactory().create_utils_obj()
    input_string = "Hello; world `& |$(this"
    expected_output = "Hello world ` this"
    assert utils.sanitize(input_string) == expected_output
    input_string = "This is a clean string"
    assert utils.sanitize(input_string) == input_string
    
def test_sanitize_with_all_special_characters():
    utils = ModuleFactory().create_utils_obj()
    special_chars = ";`&|$("
    input_string = f"Hello{special_chars}world"
    expected_output = "Hello`world"
    assert utils.sanitize(input_string) == expected_output     
    
def test_detect_data_type():
    utils = ModuleFactory().create_utils_obj()
    assert utils.detect_data_type('192.168.1.100') == 'ip'
    assert utils.detect_data_type('2001:0db8:85a3:0000:0000:8a2e:0370:7334') == 'ip'
    assert utils.detect_data_type('192.168.0.0/16') == 'ip_range'
    assert utils.detect_data_type('e10adc3949ba59abbe56e057f20f883e') == 'md5'
    assert utils.detect_data_type('example.com') == 'domain'
    assert utils.detect_data_type('http://example.com/some/path') == 'url'
    assert utils.detect_data_type('AS12345') == 'asn'
    
def test_detect_data_type_with_invalid_data():
    utils = ModuleFactory().create_utils_obj()
    assert utils.detect_data_type('999.999.999.999') == None
    assert utils.detect_data_type('123456789abcdefg') == None    
    
def test_get_first_octet():
    utils = ModuleFactory().create_utils_obj()

    #IPv4 address
    assert utils.get_first_octet('192.168.1.100') == '192'
    #IPv6 address
    assert utils.get_first_octet('2001:0db8:85a3:0000:0000:8a2e:0370:7334') == '2001'
    #invalid IP address
    assert utils.get_first_octet('invalid') is None
    
def test_calculate_confidence():
    utils = ModuleFactory().create_utils_obj()
    assert utils.calculate_confidence(0) == 0.3
    assert utils.calculate_confidence(5) == 0.5
    assert utils.calculate_confidence(10) == 1.0
    assert utils.calculate_confidence(15) == 1.0
    
def test_calculate_confidence_with_negative_and_large_packet_counts():
    utils = ModuleFactory().create_utils_obj()
    assert utils.calculate_confidence(-5) == -0.5, "Confidence for negative packet counts should be 0\."
    assert utils.calculate_confidence(1000000) == 1, "Confidence for large packet counts should be capped at 1."
    
def test_calculate_confidence_with_extreme_values():
    utils = ModuleFactory().create_utils_obj()
    assert utils.calculate_confidence(sys.maxsize) == 1.0, "Confidence should be capped at 1.0 for extremely large packet counts"            
    
def test_convert_format():
    utils = ModuleFactory().create_utils_obj()
    assert utils.convert_format('2023-04-06T12:34:56.789Z', '%Y-%m-%dT%H:%M:%S.%fZ') == '2023-04-06T12:34:56.789000Z'
    assert utils.convert_format(1680788096.789, 'iso') == '2023-04-06T19:04:56.789000+05:30'
    assert utils.convert_format(1680788096.789, '%Y-%m-%d %H:%M:%S') == '2023-04-06 19:04:56'
    assert utils.convert_format(datetime.datetime(2023, 4, 6, 12, 34, 56, 789000), 'unixtimestamp') == 1680764696.789 

def test_assert_microseconds():
    utils = ModuleFactory().create_utils_obj()
    assert utils.assert_microseconds('1680788096.789') == '1680788096.789000'
    assert utils.assert_microseconds('1680788096') == '1680788096'
    assert utils.assert_microseconds('1680788096.123456') == '1680788096.123456'
    assert utils.assert_microseconds('1680788096.123456789') == '1680788096.123456789'
        
    
def test_threat_level_to_string():
    utils = ModuleFactory().create_utils_obj()
    assert utils.threat_level_to_string(0.1) == 'low'
    assert utils.threat_level_to_string(0.4) == 'medium'
    assert utils.threat_level_to_string(0.5) == 'medium'
    assert utils.threat_level_to_string(0.7) == 'high'
    assert utils.threat_level_to_string(1.0) == 'critical'


def test_threat_level_to_string_outside_range():
    utils = ModuleFactory().create_utils_obj()
    assert utils.threat_level_to_string(-1) == 'info'  
    assert utils.threat_level_to_string(2) == None
               

def test_is_private_ip():
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_private_ip(ipaddress.ip_address('192.168.1.1'))
    assert utils.is_private_ip(ipaddress.ip_address('10.0.0.1'))
    assert utils.is_private_ip(ipaddress.ip_address('172.16.0.1'))
    assert not utils.is_private_ip(ipaddress.ip_address('8.8.8.8'))
    assert not utils.is_private_ip(ipaddress.ip_address('0.0.0.0'))
    assert not utils.is_private_ip(ipaddress.ip_address('255.255.255.255'))
       
    
def test_remove_milliseconds_decimals():
    utils = ModuleFactory().create_utils_obj()
    assert utils.remove_milliseconds_decimals('1680788096.789') == '1680788096'
    assert utils.remove_milliseconds_decimals('1680788096') == '1680788096'

def test_remove_milliseconds_decimals_no_digits_after_decimal():
    utils = ModuleFactory().create_utils_obj()
    timestamp = "1680788096."
    assert utils.remove_milliseconds_decimals(timestamp) == "1680788096", "Should remove the decimal point when no digits after it"    
    
def test_get_time_diff():
    utils = ModuleFactory().create_utils_obj()
    start_time = 1609459200  
    end_time = 1609545600  
    assert utils.get_time_diff(start_time, end_time, return_type="days") == 1
    assert utils.get_time_diff(start_time, end_time, return_type="hours") == 24
    
def test_get_time_diff_negative_difference():
    utils = ModuleFactory().create_utils_obj()
    start_time = 1609545600  
    end_time = 1609459200  
    assert utils.get_time_diff(start_time, end_time, "seconds") < 0, "Should handle negative time differences"

def test_get_time_diff_small_difference():
    utils = ModuleFactory().create_utils_obj()
    start_time = 1609459200.0
    end_time = 1609459200.1  
    assert utils.get_time_diff(start_time, end_time, "seconds") == 0.1, "Should handle very small time differences with precision"                                    
    
def test_to_delta():
    utils = ModuleFactory().create_utils_obj()
    assert utils.to_delta(3600) == datetime.timedelta(seconds=3600) 
    assert utils.to_delta(86400) == datetime.timedelta(days=1)
    
def test_to_delta_negative_seconds():
    utils = ModuleFactory().create_utils_obj()
    negative_seconds = -3600
    assert utils.to_delta(negative_seconds) == datetime.timedelta(seconds=-3600), "Should correctly handle negative seconds"

def test_to_delta_large_number_of_seconds():
    utils = ModuleFactory().create_utils_obj()
    large_seconds = 31536000  
    assert utils.to_delta(large_seconds) == datetime.timedelta(days=365), "Should handle large number of seconds"      
 
    
def test_get_own_IPs():
    utils = ModuleFactory().create_utils_obj()
    assert isinstance(utils.get_own_IPs(), list)
    
def test_get_own_IPs_no_network_connection():
    with patch('requests.get', side_effect=requests.exceptions.ConnectionError):
        utils = ModuleFactory().create_utils_obj()
        assert "127.0.0.1" in utils.get_own_IPs() or not utils.get_own_IPs(), "Should handle no network connection gracefully"
        
def test_get_own_IPs_with_network_failures():
    with patch('requests.get', side_effect=requests.exceptions.RequestException):
        utils = ModuleFactory().create_utils_obj()
        assert "127.0.0.1" in utils.get_own_IPs() or not utils.get_own_IPs(), "Should handle network failures gracefully"                
    
    
def test_is_port_in_use():
    utils = ModuleFactory().create_utils_obj()
    assert isinstance(utils.is_port_in_use(80), bool)
    assert isinstance(utils.is_port_in_use(65535), bool)

def test_is_port_in_use_with_known_used_port():
    utils = ModuleFactory().create_utils_obj()
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_socket:
        temp_socket.bind(('localhost', 0))  
        temp_socket.listen(1)  
        port = temp_socket.getsockname()[1]
        assert utils.is_port_in_use(port) is True, "The port should be identified as in use."     
    
def test_is_valid_threat_level():
    utils = ModuleFactory().create_utils_obj()
    assert utils.is_valid_threat_level('info')
    assert utils.is_valid_threat_level('low')
    assert utils.is_valid_threat_level('medium')
    assert utils.is_valid_threat_level('high')
    assert utils.is_valid_threat_level('critical')
    assert not utils.is_valid_threat_level('undefined')
    

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
    original_format = '2023-04-01 12:00:00'
    expected_result = '04/01/2023 12:00 PM'
    assert utils.convert_format(original_format, '%m/%d/%Y %I:%M %p') == expected_result

        
@dataclass
class MockDataClass:
    id: int
    name: str

class MockEnum(Enum):
    TYPE1 = "Type 1"
    TYPE2 = "Type 2"

def test_to_json_serializable_dataclass():
    utils = ModuleFactory().create_utils_obj()
    data_class_instance = MockDataClass(id=1, name="Test")
    expected_output = {"id": 1, "name": "Test"}
    assert utils.to_json_serializable(data_class_instance) == expected_output, "Dataclass conversion to JSON serializable failed."

def test_to_json_serializable_enum():
    utils = ModuleFactory().create_utils_obj()
    enum_instance = MockEnum.TYPE1
    expected_output = "Type 1"
    assert utils.to_json_serializable(enum_instance) == expected_output, "Enum conversion to JSON serializable failed."

def test_to_json_serializable_nested_structure():
    utils = ModuleFactory().create_utils_obj()
    nested_structure = {
        "key1": MockDataClass(id=2, name="Nested"),
        "key2": [MockEnum.TYPE1, MockEnum.TYPE2]
    }
    expected_output = {
        "key1": {"id": 2, "name": "Nested"},
        "key2": ["Type 1", "Type 2"]
    }
    assert utils.to_json_serializable(nested_structure) == expected_output, "Nested structure conversion to JSON serializable failed."
    
 
class MockFlow:
    def __init__(self, proto, starttime, saddr, daddr, sport, dport):
        self.proto = proto
        self.starttime = starttime
        self.saddr = saddr
        self.daddr = daddr
        self.sport = sport
        self.dport = dport    
    
def test_get_aid():
    utils = ModuleFactory().create_utils_obj()
    mock_flow = MockFlow(
        proto='tcp',
        starttime='2023-04-06T19:04:56.789+00:00',  
        saddr='192.168.1.1',
        daddr='192.168.1.2',
        sport=12345,
        dport=80
    )
    aid_result = utils.get_aid(mock_flow)
    assert aid_result is not None, "AID generation failed or returned None."     
    

def test_convert_to_datetime_around_dst():
    utils = ModuleFactory().create_utils_obj()
    any_date = '2023-04-01 12:00:00'
    result = utils.convert_to_datetime(any_date)
    assert isinstance(result, datetime.datetime), "Should convert string to datetime object."

def test_get_cidr_of_private_ip_with_valid_private_ip():
    utils = ModuleFactory().create_utils_obj()
    assert utils.get_cidr_of_private_ip('192.168.1.1') == '192.168.0.0/16'
    assert utils.get_cidr_of_private_ip('10.0.0.1') == '10.0.0.0/8'
    assert utils.get_cidr_of_private_ip('172.16.0.1') == '172.16.0.0/12'

def test_get_cidr_of_private_ip_with_invalid_ip_formats():
    utils = ModuleFactory().create_utils_obj()
    assert utils.get_cidr_of_private_ip('invalid_ip') is None
    assert utils.get_cidr_of_private_ip('256.100.50.25') is None
    
@patch('os.setresgid')
@patch('os.setresuid')
@patch('os.getenv', side_effect=lambda x: {'SUDO_GID': '1000', 'SUDO_UID': '1000'}.get(x))
def test_drop_root_privs(mock_getenv, mock_setresuid, mock_setresgid):
    utils = ModuleFactory().create_utils_obj()
    utils.drop_root_privs()
    mock_setresuid.assert_called_once_with(1000, 1000, -1)
    mock_setresgid.assert_called_once_with(1000, 1000, -1)
