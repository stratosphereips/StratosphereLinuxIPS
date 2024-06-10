"""Unit test for modules/update_manager/update_manager.py"""

from tests.module_factory import ModuleFactory
import json
import os
import pytest
import time
from unittest.mock import Mock, mock_open
from modules.update_manager.update_manager import UpdateManager

@pytest.fixture
def update_manager_obj(mock_db, tmp_path):
    """Fixture to create an UpdateManager object with mocked dependencies and a valid output directory."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()  
    update_manager = UpdateManager(
        mock_db, output_dir=output_dir, redis_port=6379, termination_event=None
    )
    update_manager.init()  
    return update_manager

def test_getting_header_fields(mocker, mock_db):
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    url = "google.com/play"
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {"ETag": "1234"}
    mock_requests.return_value.text = ""
    response = update_manager.download_file(url)
    assert update_manager.get_e_tag(response) == "1234"

def test_check_if_update_based_on_update_period(mock_db):
    mock_db.get_TI_file_info.return_value = {"time": float("inf")}
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    url = "abc.com/x"
    # update period hasn't passed
    assert update_manager.check_if_update(url, float("inf")) is False

def test_check_if_update_based_on_e_tag(mocker, mock_db):
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)

    # period passed, etag same
    etag = "1234"
    url = "google.com/images"
    mock_db.get_TI_file_info.return_value = {"e-tag": etag}

    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {"ETag": "1234"}
    mock_requests.return_value.text = ""
    assert update_manager.check_if_update(url, float("-inf")) is False

    # period passed, etag different
    etag = "1111"
    url = "google.com/images"
    mock_db.get_TI_file_info.return_value = {"e-tag": etag}
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {"ETag": "2222"}
    mock_requests.return_value.text = ""
    assert update_manager.check_if_update(url, float("-inf")) is True

def test_check_if_update_based_on_last_modified(database, mocker, mock_db):
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)

    # period passed, no etag, last modified the same
    url = "google.com/photos"

    mock_db.get_TI_file_info.return_value = {"Last-Modified": 10.0}
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {"Last-Modified": 10.0}
    mock_requests.return_value.text = ""

    assert update_manager.check_if_update(url, float("-inf")) is False

    # period passed, no etag, last modified changed
    url = "google.com/photos"

    mock_db.get_TI_file_info.return_value = {"Last-Modified": 10}
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {"Last-Modified": 11}
    mock_requests.return_value.text = ""

    assert update_manager.check_if_update(url, float("-inf")) is True

def test_check_if_update_local_file(database, mock_db):
    """
    Test if check_if_update_local_file() correctly detects if we should update
    a local file based on the file hash
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    file_path = os.path.join(
        os.getcwd(), "slips_files/ports_info/ports_used_by_specific_orgs.csv"
    )
    # when we first see a file, the update manager should return True, we don't have info about the file
    assert update_manager.check_if_update_local_file(file_path) is True

    # if we already have info about the file in our db and the file hash hasn't changed, return False
    mock_db.get_TI_file_info.return_value = {
        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
    assert update_manager.check_if_update_local_file(file_path) is True

def test_get_feed_details(mocker, mock_db):
    """Test get_feed_details with a valid file."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)

    m = mock_open(read_data="https://example.com/feed.txt,medium,tag1,tag2")
    mocker.patch("builtins.open", m)
    feeds = update_manager.get_feed_details("path/to/feeds")

    assert feeds == {
        "https://example.com/feed.txt": {
            "tags": ["tag1 tag2"],
            "threat_level": "medium",
        }
    }

def test_log(mocker, update_manager_obj):
    """Test the log function."""
    mock_observer = Mock()
    update_manager_obj.notify_observers = (
        mock_observer  
    )
    update_manager_obj.log("This is a test log message.")

    mock_observer.assert_called_once_with(
        {
            "from": "Update Manager",
            "log_to_logfiles_only": True,
            "txt": "This is a test log message.",
            "verbose": 0,
            "debug": 1,
        }
    )

def test_read_configuration_with_valid_config(mocker, update_manager_obj):
    """Test read_configuration with a valid slips.conf file."""
    mock_config_parser = mocker.patch(
        "slips_files.common.parsers.config_parser.ConfigParser"
    )
    mock_config_parser.return_value.update_period.return_value = 3600
    mock_config_parser.return_value.remote_ti_data_path.return_value = (
        "modules/threat_intelligence/remote_data_files/"
    )
    mock_config_parser.return_value.ti_files.return_value = "path/to/ti_files"
    mock_config_parser.return_value.ja3_feeds.return_value = (
        "path/to/ja3_feeds"
    )
    mock_config_parser.return_value.ssl_feeds.return_value = (
        "path/to/ssl_feeds"
    )
    mock_config_parser.return_value.RiskIQ_credentials_path.return_value = (
        "path/to/riskiq_credentials"
    )
    mock_config_parser.return_value.riskiq_update_period.return_value = 86400
    mock_config_parser.return_value.mac_db_update_period.return_value = 86400
    mock_config_parser.return_value.mac_db_link.return_value = (
        "https://example.com/mac_db.json"
    )
    mock_config_parser.return_value.online_whitelist_update_period.return_value = (
        86400
    )
    mock_config_parser.return_value.online_whitelist.return_value = (
        "https://example.com/whitelist.txt"
    )

    update_manager_obj.read_configuration()

    assert update_manager_obj.update_period == 86400.0
    assert (
        update_manager_obj.path_to_remote_ti_files
        == "modules/threat_intelligence/remote_data_files/"
    )
    assert update_manager_obj.ti_feeds_path == "config/TI_feeds.csv"
    assert update_manager_obj.ja3_feeds_path == "config/JA3_feeds.csv"
    assert update_manager_obj.ssl_feeds_path == "config/SSL_feeds.csv"
    assert update_manager_obj.riskiq_update_period == 604800.0
    assert update_manager_obj.mac_db_update_period == 1209600.0
    assert (
        update_manager_obj.mac_db_link
        == "https://maclookup.app/downloads/json-database/get-db?t=22-08-19h=d1d39c52de447a7e7194331f379e1e99f94f35f1"
    )
    assert update_manager_obj.online_whitelist_update_period == 86400
    assert (
        update_manager_obj.online_whitelist
        == "https://tranco-list.eu/download/X5QNN/10000"
    )

def test_download_file(mocker, update_manager_obj):
    """Test download_file with a successful request."""
    url = "https://example.com/file.txt"
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.text = "file content"

    response = update_manager_obj.download_file(url)

    mock_requests.assert_called_once_with(url, timeout=5)
    assert response.text == "file content"

def test_read_ports_info(mocker, mock_db, tmp_path):
    """Test read_ports_info with a valid file."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    test_data = """Organization,IP,Ports Range,Protocol
TestOrg,192.168.1.1,80,tcp
TestOrg,192.168.1.2,443-445,udp"""
    test_file = tmp_path / "ports_info.csv"
    test_file.write_text(test_data, encoding="utf-8")
    mocker.patch("builtins.open", mock_open(read_data=test_data))
    update_manager.read_ports_info(str(test_file))
    mock_db.set_organization_of_port.assert_any_call(
        "TestOrg", "192.168.1.1", "80/tcp"
    )
    mock_db.set_organization_of_port.assert_any_call(
        "TestOrg", "192.168.1.2", "443/udp"
    )
    mock_db.set_organization_of_port.assert_any_call(
        "TestOrg", "192.168.1.2", "444/udp"
    )
    mock_db.set_organization_of_port.assert_any_call(
        "TestOrg", "192.168.1.2", "445/udp"
    )

def test_update_local_file(mocker, mock_db, tmp_path):
    """Test update_local_file with a valid file."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.new_hash = "test_hash"
    test_file = tmp_path / "test_file.txt"
    test_file.write_text("test content", encoding="utf-8")
    mocker.patch("builtins.open", mock_open(read_data="test content"))
    result = update_manager.update_local_file(str(test_file))
    mock_db.set_TI_file_info.assert_called_once_with(
        str(test_file), {"hash": "test_hash"}
    )
    assert result is True

@pytest.mark.parametrize(
    "db_info, mock_requests_status_code, expected_result, expected_db_call",
    [
        # Testcase1: Update period hasn't passed.
        ({"time": time.time()}, None, False, False),
        # Testcase2: Update period has passed and download fails.
        ({"time": 0}, 404, False, False),
        # Testcase3: Update period has passed and download succeeds.
        ({"time": 0}, 200, True, True),
    ],
)
def test_check_if_update_online_whitelist(
    mocker, mock_db, db_info, mock_requests_status_code, expected_result, expected_db_call
):
    """
    Test check_if_update_online_whitelist() with different scenarios:
    - Update period hasn't passed.
    - Update period has passed and download fails.
    - Update period has passed and download succeeds.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.online_whitelist = "https://example.com/whitelist.txt"

    mock_db.get_TI_file_info.return_value = db_info

    if mock_requests_status_code is not None:
        mock_requests = mocker.patch("requests.get")
        mock_requests.return_value.status_code = mock_requests_status_code

    result = update_manager.check_if_update_online_whitelist()
    assert result == expected_result

    if expected_db_call:
        mock_db.set_TI_file_info.assert_called_once_with(
            "tranco_whitelist", {"time": mocker.ANY}
        )
        assert "tranco_whitelist" in update_manager.responses
    else:
        mock_db.set_TI_file_info.assert_not_called()

@pytest.mark.parametrize(
    "headers, expected_last_modified",
    [
        # Testcase1: Header has Last-Modified field.
        ({"Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT"}, "Wed, 21 Oct 2015 07:28:00 GMT"),
        # Testcase2: Header doesn't have Last-Modified field.
        ({}, False),
    ],
)
def test_get_last_modified(mocker, update_manager_obj, headers, expected_last_modified):
    """
    Test get_last_modified() with different scenarios:
    - Header has Last-Modified field.
    - Header doesn't have Last-Modified field.
    """
    mock_response = mocker.Mock()
    mock_response.headers = headers
    assert update_manager_obj.get_last_modified(mock_response) == expected_last_modified

@pytest.mark.parametrize(
    "headers, expected_etag",
    [
        # Testcase1: Header has ETag field.
        (
            {"ETag": '"33a64df551425fcc55e4d42a148795d9f25f89d4"'},
            '"33a64df551425fcc55e4d42a148795d9f25f89d4"',
        ),
        # Testcase2: Header doesn't have ETag field.
        ({}, False),
    ],
)
def test_get_e_tag(mocker, update_manager_obj, headers, expected_etag):
    """
    Test get_e_tag() with different scenarios:
    - Header has ETag field.
    - Header doesn't have ETag field.
    """
    mock_response = mocker.Mock()
    mock_response.headers = headers
    assert update_manager_obj.get_e_tag(mock_response) == expected_etag

def test_write_file_to_disk(mocker, update_manager_obj, tmp_path):
    """
    Test write_file_to_disk() by writing content to a temporary file.
    """
    mock_response = mocker.Mock()
    mock_response.text = "test content"
    file_path = tmp_path / "test_file.txt"

    update_manager_obj.write_file_to_disk(mock_response, file_path)

    with open(file_path, "r") as f:
        assert f.read() == "test content"

def test_delete_old_source_ips(mock_db):
    """Test delete_old_source_IPs."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    mock_db.get_IPs_in_IoC.return_value = {
        "1.2.3.4": json.dumps(
            {"description": "old IP", "source": "old_file.txt"}
        ),
        "5.6.7.8": json.dumps(
            {"description": "new IP", "source": "new_file.txt"}
        ),
    }
    update_manager.delete_old_source_IPs("old_file.txt")
    mock_db.delete_ips_from_IoC_ips.assert_called_once_with(["1.2.3.4"])

def test_delete_old_source_domains(mock_db):
    """Test delete_old_source_Domains."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    mock_db.get_Domains_in_IoC.return_value = {
        "olddomain.com": json.dumps(
            {"description": "old domain", "source": "old_file.txt"}
        ),
        "newdomain.com": json.dumps(
            {"description": "new domain", "source": "new_file.txt"}
        ),
    }
    update_manager.delete_old_source_Domains("old_file.txt")

def test_update_riskiq_feed(mocker, mock_db):
    """
    Test update_riskiq_feed with a successful request and valid data.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.riskiq_email = "test@example.com"
    update_manager.riskiq_key = "test_key"
    mock_response = mocker.Mock()
    mock_response.json.return_value = {
        "indicators": [
            {"type": "domain", "value": "malicious.com"},
        ]
    }
    mocker.patch("requests.get", return_value=mock_response)
    result = update_manager.update_riskiq_feed()
    mock_db.add_domains_to_IoC.assert_called_once_with(
        {
            "malicious.com": json.dumps(
                {
                    "description": "malicious domain detected by RiskIQ",
                    "source": "https://api.riskiq.net/pt/v2/articles/indicators",
                }
            )
        }
    )
    mock_db.set_TI_file_info.assert_called_once_with(
        "riskiq_domains", {"time": mocker.ANY}
    )
    assert result is True

def test_delete_old_source_data_from_database(mock_db):
    """
    Test delete_old_source_data_from_database for deleting old IPs and domains.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    mock_db.get_IPs_in_IoC.return_value = {
        "1.2.3.4": json.dumps(
            {"description": "old IP", "source": "old_file.txt"}
        ),
        "5.6.7.8": json.dumps(
            {"description": "new IP", "source": "new_file.txt"}
        ),
    }
    mock_db.get_Domains_in_IoC.return_value = {
        "olddomain.com": json.dumps(
            {"description": "old domain", "source": "old_file.txt"}
        ),
        "newdomain.com": json.dumps(
            {"description": "new domain", "source": "new_file.txt"}
        ),
    }
    update_manager.delete_old_source_data_from_database("old_file.txt")
    mock_db.delete_ips_from_IoC_ips.assert_called_once_with(["1.2.3.4"])
    mock_db.delete_domains_from_IoC_domains.assert_called_once_with(
        ["olddomain.com"]
    )

def test_get_description_column():
    """
    Test get_description_column() with different header formats.
    """
    update_manager = ModuleFactory().create_update_manager_obj(Mock())
    # Testcase1 finding "desc" column
    header = "#,ip,desc"
    assert update_manager.get_description_column(header) == 2
    # Testcase2 finding "collect" column
    header = "#,ip,collect"
    assert update_manager.get_description_column(header) == 2
    # Testcase3 not finding a description column
    header = "#,ip,date"
    assert update_manager.get_description_column(header) is None

def test_is_ignored_line():
    """
    Test is_ignored_line() with different line types.
    """
    update_manager = ModuleFactory().create_update_manager_obj(Mock())
    # Testcase1 comment line
    assert update_manager.is_ignored_line("# This is a comment") is True
    # Testcase2 blank line
    assert update_manager.is_ignored_line("") is True
    # Testcase3 line with unsupported IoC type
    assert update_manager.is_ignored_line("email,test@example.com") is True
    # Testcase4 line with header keyword
    assert update_manager.is_ignored_line("type,ip") is True
    # Testcase5 valid line
    assert update_manager.is_ignored_line("1.2.3.4,Test description") is None

@pytest.mark.parametrize(
    "line, expected_amount_of_columns, expected_line_fields, expected_sep",
    [
        # Testcase1 comma-separated line
        ("1.2.3.4,Test description", 2, ["1.2.3.4", "Test description"], ","),
        # Testcase2 tab-separated line
        ("1.2.3.4\tTest description", 2, ["1.2.3.4", "Test description"], "\t"),
        # Testcase3 space-separated line
        ("1.2.3.4 Test description", 1, ["1.2.3.4 Test description"], "\t"),
    ],
)
def test_parse_line(line, expected_amount_of_columns, expected_line_fields, expected_sep):
    """
    Test parse_line() with different line formats.
    """
    update_manager = ModuleFactory().create_update_manager_obj(Mock())
    amount_of_columns, line_fields, sep = update_manager.parse_line(line, "")
    assert amount_of_columns == expected_amount_of_columns
    assert line_fields == expected_line_fields
    assert sep == expected_sep

def test_parse_ja3(mocker, mock_db, tmp_path):
    """Test parse_ja3_feed with an invalid JA3 fingerprint."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    test_data = """# ja3_md5,first_seen,last_seen,description
    invalid_ja3,2023-01-01,2023-02-01,Malicious JA3
    """
    test_file = tmp_path / "ja3_feed.txt"
    test_file.write_text(test_data, encoding="utf-8")  
    mocker.patch("builtins.open", mock_open(read_data=test_data))
    result = update_manager.parse_ja3_feed(
        "https://example.com/ja3_feed.txt", str(test_file)
    )
    mock_db.add_ja3_to_IoC.assert_not_called()
    assert result is False

@pytest.mark.parametrize(
    "line_fields, expected_data_column",
    [
        (["1.2.3.4", "Test description"], 0),  # Testcase1 Valid IP
        (["example.com", "Test description"], 0),  # Testcase2 Valid domain
        (["invalid_data", "Test description"], "Error"),  # Testcase3 Invalid data
    ],
)
def test_get_data_column(mock_db, line_fields, expected_data_column):
    """
    Test get_data_column with different input scenarios:
    - Valid IP address.
    - Valid domain name.
    - Invalid data.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    amount_of_columns = 2
    file_path = "test_file.txt"
    data_column = update_manager.get_data_column(
        amount_of_columns, line_fields, file_path
    )
    assert data_column == expected_data_column

@pytest.mark.parametrize(
    "line, line_fields, separator, data_column, description_column, file_path, expected_data, expected_description",
    [
        (
            "1.2.3.4,Test description",
            ["1.2.3.4", "Test description"],
            ",",
            0,
            1,
            "test_file.txt",
            "1.2.3.4",
            "Test description",
        ),
        (
            "example.com,Test description",
            ["example.com", "Test description"],
            ",",
            0,
            1,
            "test_file.txt",
            "example.com",
            "Test description",
        ),
        (
            "1.2.3.4",
            ["1.2.3.4"],
            ",",
            0,
            1,
            "test_file.txt",
            False,
            False,
        ),  
    ],
)
def test_extract_ioc_from_line(
    mock_db,
    line,
    line_fields,
    separator,
    data_column,
    description_column,
    file_path,
    expected_data,
    expected_description,
):
    """
    Test extract_ioc_from_line with different scenarios:
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    data, description = update_manager.extract_ioc_from_line(
        line,
        line_fields,
        separator,
        data_column,
        description_column,
        file_path,
    )
    assert data == expected_data
    assert description == expected_description

def test_add_to_ip_ctr_new_ip(mock_db):
    """Test add_to_ip_ctr with a new IP address."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    ip = "1.2.3.4"
    blacklist = "test_blacklist.txt"
    update_manager.add_to_ip_ctr(ip, blacklist)
    assert update_manager.ips_ctr[ip] == {
        "times_found": 1,
        "blacklists": ["test_blacklist.txt"],
    }

def test_parse_ti_feed_invalid_data(mocker, mock_db, tmp_path):
    """Test parse_ti_feed with invalid data."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.url_feeds = {
        "https://example.com/invalid.txt": {
            "threat_level": "low",
            "tags": ["tag3"],
        }
    }
    test_data = """# Comment
    invalid_data,Description
    """
    test_file = tmp_path / "invalid.txt"
    test_file.write_text(test_data, encoding="utf-8")
    mocker.patch("builtins.open", mock_open(read_data=test_data))
    result = update_manager.parse_ti_feed(
        "https://example.com/invalid.txt", str(test_file)
    )
    mock_db.add_ips_to_IoC.assert_not_called()
    mock_db.add_domains_to_IoC.assert_not_called()
    assert result is False

@pytest.mark.parametrize(
    "file_content, cached_hash, expected_result",
    [
        ("test content", {}, True),  #Testcase1 New file
        ("new content", "old_hash", True),  #Testcase2 Updated file
        (
            "test content",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            True,
        ),  #Testcase3 Unchanged file
    ],
)
def test_check_if_update_org(
    mock_db, tmp_path, file_content, cached_hash, expected_result
):
    """Test check_if_update_org with different file and cache scenarios."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    test_file = tmp_path / "test_org"
    test_file.write_text(file_content, encoding="utf-8")
    mock_db.get_TI_file_info.return_value = {"hash": cached_hash}
    result = update_manager.check_if_update_org(str(test_file))
    assert result is expected_result


def test_update_mac_db_success(mocker, mock_db):
    """
    Test update_mac_db with a successful response and valid data.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.mac_db_link = "https://example.com/mac_db.json"
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.text = '[{"mac":"00:00:00:00:00:01","vendor":"VendorA"},{"mac":"00:00:00:00:00:02","vendor":"VendorB"}]'
    update_manager.responses["mac_db"] = mock_response
    result = update_manager.update_mac_db()
    assert result is True
    mock_db.set_TI_file_info.assert_called_once_with(
        update_manager.mac_db_link, {"time": mocker.ANY}
    )

def test_update_online_whitelist_success(mocker, mock_db, tmp_path):
    """
    Test update_online_whitelist with a successful response and valid data.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.online_whitelist = "https://example.com/whitelist.txt"
    update_manager.path_to_remote_ti_files = tmp_path
    mock_response = mocker.Mock()
    mock_response.text = "rank,domain\n1,google.com\n2,example.com"
    update_manager.responses["tranco_whitelist"] = mock_response
    update_manager.update_online_whitelist()
    mock_db.store_tranco_whitelisted_domain.assert_any_call("example.com")
    mock_db.store_tranco_whitelisted_domain.assert_any_call("example.com")

def test_shutdown_gracefully(mocker, mock_db):
    """
    Test shutdown_gracefully to ensure timers are canceled.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.timer_manager = mocker.Mock()
    update_manager.mac_db_update_manager = mocker.Mock()
    update_manager.online_whitelist_update_timer = mocker.Mock()
    result = update_manager.shutdown_gracefully()
    update_manager.timer_manager.cancel.assert_called_once()
    update_manager.mac_db_update_manager.cancel.assert_called_once()
    update_manager.online_whitelist_update_timer.cancel.assert_called_once()
    assert result is True

@pytest.mark.parametrize(
    "ips_ctr, expected_output",
    [
        # Testcase 1: No repeated IPs
        ({}, ""),
        # Testcase 2: IPs repeated in 1, 2, and 3 blacklists
        (
            {
                "1.2.3.4": {"times_found": 1, "blacklists": ["blacklist1.txt"]},
                "5.6.7.8": {
                    "times_found": 2,
                    "blacklists": ["blacklist2.txt", "blacklist3.txt"],
                },
                "9.10.11.12": {
                    "times_found": 3,
                    "blacklists": [
                        "blacklist4.txt",
                        "blacklist5.txt",
                        "blacklist6.txt",
                    ],
                },
            },
            "",  
        ),
    ],
)
def test_print_duplicate_ip_summary(capsys, mock_db, ips_ctr, expected_output):
    """
    Test print_duplicate_ip_summary with different IP repetition scenarios.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.ips_ctr = ips_ctr
    update_manager.first_time_reading_files = True
    update_manager.print_duplicate_ip_summary()
    captured = capsys.readouterr()
    assert captured.out == expected_output
