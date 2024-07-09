"""Unit test for modules/update_manager/update_manager.py"""

from tests.module_factory import ModuleFactory
import json
import requests
import pytest
import time
from unittest.mock import Mock, mock_open, patch


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


@pytest.mark.parametrize(
    "new_hash, old_hash, expected_result",
    [  # Testcase1: File not in DB, update needed
        ("hash123", False, True),
        # Testcase2: Hashes match, no update needed
        ("hash456", "hash456", False),
        # Testcase3: Hashes different, update needed
        ("hash789", "hash123", True),
    ],
)
def test_check_if_update_local_file(
    mocker, mock_db, new_hash, old_hash, expected_result
):
    """
    Test if check_if_update_local_file() correctly detects
    if we should update a local file based on the file hash.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)

    mocker.patch(
        "slips_files.common.slips_utils.Utils.get_hash_from_file",
        return_value=new_hash,
    )
    mock_db.get_TI_file_info.return_value = {"hash": old_hash}

    file_path = "path/to/my/file.txt"
    assert (
        update_manager.check_if_update_local_file(file_path) is expected_result
    )


@pytest.mark.parametrize(
    "mock_data, expected_feeds",
    [
        # Testcase1: Valid file with multiple feeds and tags.
        (
            "https://example.com/feed1.txt,"
            "medium,tag1,tag2\nhttps://example.com/feed2.txt,high,tag3",
            {
                "https://example.com/feed1.txt": {
                    "tags": ["tag1 tag2"],
                    "threat_level": "medium",
                },
                "https://example.com/feed2.txt": {
                    "tags": ["tag3"],
                    "threat_level": "high",
                },
            },
        ),
        # Testcase2: File with comments and invalid threat level.
        (
            "# This is a comment\nhttps://example.com/feed3.txt,"
            "invalid,tag4\nhttps://example.com/feed4.txt,low,tag5",
            {
                "https://example.com/feed3.txt": {
                    "tags": ["tag4"],
                    "threat_level": "low",
                },
                "https://example.com/feed4.txt": {
                    "tags": ["tag5"],
                    "threat_level": "low",
                },
            },
        ),
        # Testcase3: Empty file.
        ("", {}),
    ],
)
def test_get_feed_details(mocker, mock_db, mock_data, expected_feeds):
    """Test get_feed_details with different file contents."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    mock_feeds_file = mock_open(read_data=mock_data)
    mocker.patch("builtins.open", mock_feeds_file)
    feeds = update_manager.get_feed_details("path/to/feeds")
    assert feeds == expected_feeds


@pytest.mark.parametrize(
    "message, expected_call_args",
    [
        # Testcase1: Log a simple message.
        (
            "Test message",
            {
                "from": "Update Manager",
                "log_to_logfiles_only": True,
                "txt": "Test message",
                "verbose": 0,
                "debug": 1,
            },
        ),
        # Testcase2: Log an empty message.
        (
            "",
            {
                "from": "Update Manager",
                "log_to_logfiles_only": True,
                "txt": "",
                "verbose": 0,
                "debug": 1,
            },
        ),
    ],
)
def test_log(mock_db, message, expected_call_args):
    """Test the log function with different message types."""
    mock_observer = Mock()
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.notify_observers = mock_observer
    update_manager.log(message)
    mock_observer.assert_called_once_with(expected_call_args)


def test_download_file(mocker, mock_db):
    """Test download_file with a successful request."""
    url = "https://example.com/file.txt"
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.text = "file content"
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    response = update_manager.download_file(url)

    mock_requests.assert_called_once_with(url, timeout=5)
    assert response.text == "file content"


@pytest.mark.parametrize(
    "test_data, expected_calls",
    [
        # Testcase1: Valid file with single and range ports.
        (
            """Organization,IP,Ports Range,Protocol
TestOrg,192.168.1.1,80,tcp
TestOrg,192.168.1.2,443-445,udp""",
            [
                ("TestOrg", "192.168.1.1", "80/tcp"),
                ("TestOrg", "192.168.1.2", "443/udp"),
                ("TestOrg", "192.168.1.2", "444/udp"),
                ("TestOrg", "192.168.1.2", "445/udp"),
            ],
        ),
        # Testcase2: File with invalid line format.
        (
            """Organization,IP,Ports Range,Protocol
TestOrg,192.168.1.1,80
TestOrg,192.168.1.2,443-445,udp""",
            [
                ("TestOrg", "192.168.1.2", "443/udp"),
                ("TestOrg", "192.168.1.2", "444/udp"),
                ("TestOrg", "192.168.1.2", "445/udp"),
            ],
        ),
        # Testcase3: Empty file.
        (
            "",
            [],
        ),
    ],
)
def test_read_ports_info(mocker, mock_db, tmp_path, test_data, expected_calls):
    """Test read_ports_info with different file contents."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    mocker.patch("builtins.open", mock_open(read_data=test_data))
    update_manager.read_ports_info(str(tmp_path / "ports_info.csv"))
    for call in expected_calls:
        mock_db.set_organization_of_port.assert_any_call(*call)


@pytest.mark.parametrize(
    "test_data, file_name, expected_db_call",
    [
        # Testcase1: Update ports_used_by_specific_orgs.csv.
        (
            """Organization,IP,Ports Range,Protocol
            TestOrg,192.168.1.1,80,tcp
            TestOrg,192.168.1.2,443-445,udp""",
            "ports_used_by_specific_orgs.csv",
            "set_organization_of_port",
        ),
        # Testcase2: Update services.csv.
        (
            """ssh,22,tcp
            http,80,tcp""",
            "services.csv",
            "set_port_info",
        ),
    ],
)
def test_update_local_file(
    mocker, mock_db, tmp_path, test_data, file_name, expected_db_call
):
    """Test update_local_file with a valid file."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.new_hash = "test_hash"
    mocker.patch("builtins.open", mock_open(read_data=test_data))
    result = update_manager.update_local_file(str(tmp_path / file_name))
    mock_db.set_TI_file_info.assert_called_once_with(
        str(tmp_path / file_name), {"hash": "test_hash"}
    )
    assert result is True


def test_check_if_update_online_whitelist_download_updated(mocker, mock_db):
    """Update period passed, download succeeds."""
    mock_db.get_TI_file_info.return_value = {"time": 0}
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.online_whitelist = "https://example.com/whitelist.txt"

    update_manager.download_file = Mock(return_value=Mock(status_code=200))

    result = update_manager.check_if_update_online_whitelist()

    assert result is True
    mock_db.set_TI_file_info.assert_called_once_with(
        "tranco_whitelist", {"time": mocker.ANY}
    )
    assert "tranco_whitelist" in update_manager.responses


def test_check_if_update_online_whitelist_not_updated(mock_db):
    """Update period hasn't passed - no update needed."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.online_whitelist = "https://example.com/whitelist.txt"
    mock_db.get_TI_file_info.return_value = {"time": time.time()}
    result = update_manager.check_if_update_online_whitelist()
    assert result is False
    mock_db.set_TI_file_info.assert_not_called()


@pytest.mark.parametrize(
    "headers, expected_last_modified",
    [
        # Testcase1: Header has Last-Modified field.
        (
            {"Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT"},
            "Wed, 21 Oct 2015 07:28:00 GMT",
        ),
        # Testcase2: Header doesn't have Last-Modified field.
        ({}, False),
    ],
)
def test_get_last_modified(mocker, mock_db, headers, expected_last_modified):
    """
    Test get_last_modified() with different scenarios:
    """
    mock_response = mocker.Mock()
    mock_response.headers = headers
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    assert (
        update_manager.get_last_modified(mock_response)
        == expected_last_modified
    )


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
def test_get_e_tag(mocker, mock_db, headers, expected_etag):
    """
    Test get_e_tag() with different scenarios:
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    mock_response = mocker.Mock()
    mock_response.headers = headers
    assert update_manager.get_e_tag(mock_response) == expected_etag


def test_write_file_to_disk(mocker, mock_db, tmp_path):
    """
    Test write_file_to_disk() by writing content to a temporary file.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    mock_response = mocker.Mock()
    mock_response.text = "test content"
    file_path = tmp_path / "test_file.txt"

    update_manager.write_file_to_disk(mock_response, file_path)

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
    (mock_db.delete_ips_from_IoC_ips.assert_called_once_with(["1.2.3.4"]))


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
    Test update_riskiq_feed with a
    successful request and valid data.
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


def test_update_riskiq_feed_invalid_api_key(mocker, mock_db):
    """
    Test when RiskIQ API returns an error (e.g., invalid API key)
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.riskiq_email = "test@example.com"
    update_manager.riskiq_key = "invalid_key"
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"message": "Invalid API key"}
    mocker.patch("requests.get", return_value=mock_response)

    result = update_manager.update_riskiq_feed()
    assert result is False
    mock_db.add_domains_to_IoC.assert_not_called()
    mock_db.set_TI_file_info.assert_not_called()


def test_update_riskiq_feed_request_exception(mocker, mock_db):
    """Test when there's an error during the request to RiskIQ."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.riskiq_email = "test@example.com"
    update_manager.riskiq_key = "test_key"
    mocker.patch(
        "requests.get",
        side_effect=requests.exceptions.RequestException("Connection error"),
    )

    result = update_manager.update_riskiq_feed()
    assert result is False
    mock_db.add_domains_to_IoC.assert_not_called()
    mock_db.set_TI_file_info.assert_not_called()


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


@pytest.mark.parametrize(
    "header, expected_description_column",
    [
        # Testcase1: finding "desc" column
        ("#,ip,desc", 2),
        # Testcase2: finding "collect" column
        ("#,ip,collect", 2),
        # Testcase3: not finding a description column
        ("#,ip,date", None),
    ],
)
def test_get_description_column_index(
    mock_db, header, expected_description_column
):
    """
    Test get_description_column() with different header formats.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    description_column = update_manager.get_description_column_index(header)
    assert description_column == expected_description_column


@pytest.mark.parametrize(
    "line, expected_result",
    [  # Testcase1:comment line
        ("# This is a comment", True),
        # Testcase2:blank line
        ("", True),
        # Testcase3:line with unsupported IoC type
        ("email,test@example.com", True),
        # Testcase4:line with header keyword
        ("type,ip", True),
        # Testcase5:valid line
        ("1.2.3.4,Test description", None),
    ],
)
def test_is_ignored_line(mock_db, line, expected_result):
    """
    Test is_ignored_line() with different line types.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    assert update_manager.is_ignored_line(line) is expected_result


@pytest.mark.parametrize(
    "line, expected_amount_of_columns, expected_line_fields, expected_sep",
    [
        # Testcase1:comma-separated line
        ("1.2.3.4,Test description", 2, ["1.2.3.4", "Test description"], ","),
        # Testcase2:tab-separated line
        (
            "1.2.3.4\tTest description",
            2,
            ["1.2.3.4", "Test description"],
            "\t",
        ),
        # Testcase3:space-separated line
        ("1.2.3.4 Test description", 1, ["1.2.3.4 Test description"], "\t"),
    ],
)
def test_parse_line(
    line, expected_amount_of_columns, expected_line_fields, expected_sep
):
    """
    Test parse_line() with different line formats.
    """
    update_manager = ModuleFactory().create_update_manager_obj(Mock())
    amount_of_columns, line_fields, sep = (
        update_manager.get_feed_fields_and_sep(line, "")
    )
    assert amount_of_columns == expected_amount_of_columns
    assert line_fields == expected_line_fields
    assert sep == expected_sep


@pytest.mark.parametrize(
    "line_fields, expected_data_column",
    [  # Testcase1:Valid IP
        (["1.2.3.4", "Test description"], 0),
        # Testcase2:Valid domain
        (["example.com", "Test description"], 0),
        # Testcase3:Invalid data
        (["invalid_data", "Test description"], "Error"),
    ],
)
def test_get_data_column(mock_db, line_fields, expected_data_column):
    """
    Test get_data_column with different input scenarios:
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    amount_of_columns = 2
    file_path = "test_file.txt"
    data_column = update_manager.get_data_column(
        amount_of_columns, line_fields, file_path
    )
    assert data_column == expected_data_column


@pytest.mark.parametrize(
    "line, line_fields, separator, data_column, "
    "description_column, file_path, "
    "expected_data, expected_description",
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


@patch("os.path.getsize", return_value=10)
def test_parse_ti_feed_valid_data(mocker, mock_db):
    """
    Test parse_ti_feed with valid data
    containing both IP and domain.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.url_feeds = {
        "https://example.com/test.txt": {
            "threat_level": "low",
            "tags": ["tag3"],
        }
    }
    test_data = """# Comment
    1.2.3.4,Test description
    example.com,Another description"""
    with patch("builtins.open", mock_open(read_data=test_data)):
        result = update_manager.parse_ti_feed(
            "https://example.com/test.txt", "test.txt"
        )
    mock_db.add_ips_to_IoC.assert_any_call(
        {
            "1.2.3.4": '{"description": "Test description", '
            '"source": "test.txt", '
            '"threat_level": "low", '
            '"tags": ["tag3"]}'
        }
    )
    mock_db.add_domains_to_IoC.assert_any_call(
        {
            "example.com": '{"description": "Another description",'
            ' "source": "test.txt",'
            ' "threat_level": "low", '
            '"tags": ["tag3"]}'
        }
    )
    assert result is True


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
    mocker.patch("builtins.open", mock_open(read_data=test_data))
    result = update_manager.parse_ti_feed(
        "https://example.com/invalid.txt", str(tmp_path / "invalid.txt")
    )
    mock_db.add_ips_to_IoC.assert_not_called()
    mock_db.add_domains_to_IoC.assert_not_called()
    assert result is False


@pytest.mark.parametrize(
    "file_content, cached_hash, expected_result",
    [  # Testcase1: New file
        ("test content", {}, True),
        # Testcase2: Updated file
        ("new content", "old_hash", True),
    ],
)
def test_check_if_update_org(
    mocker, mock_db, file_content, cached_hash, expected_result
):
    """Test check_if_update_org with different file and cache scenarios."""
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)

    mock_db.get_TI_file_info.return_value = {"hash": cached_hash}
    mocker.patch(
        "slips_files.common." "slips_utils.Utils.get_hash_from_file",
        return_value=hash(file_content.encode()),
    )
    result = update_manager.check_if_update_org("test_org")
    assert result is expected_result


@pytest.mark.parametrize(
    "status_code, expected_result, db_call_count",
    [  # Testcase1: Successful download and update
        (200, True, 1),
        # Testcase2: Download failed
        (404, False, 0),
        # Testcase3: Server error
        (500, False, 0),
    ],
)
def test_update_mac_db(
    mocker, mock_db, status_code, expected_result, db_call_count
):
    """
    Test update_mac_db with different response status codes.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.mac_db_link = "https://example.com/mac_db.json"

    mock_response = mocker.Mock()
    mock_response.status_code = status_code
    mock_response.text = '[{"mac":"00:00:00:00:00:01",' '"vendor":"VendorA"}]'
    update_manager.responses["mac_db"] = mock_response
    mock_open = mocker.mock_open()
    mocker.patch("builtins.open", mock_open)

    result = update_manager.update_mac_db()

    assert result is expected_result
    assert mock_db.set_TI_file_info.call_count == db_call_count


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
                "1.2.3.4": {
                    "times_found": 1,
                    "blacklists": ["blacklist1.txt"],
                },
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


def test_parse_ssl_feed_valid_data(mocker, mock_db, tmp_path):
    """
    Test parse_ssl_feed with valid data containing multiple SSL fingerprints.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.ssl_feeds = {
        "https://example.com/test_ssl_feed.csv": {
            "threat_level": "medium",
            "tags": ["tag1", "tag2"],
        }
    }
    test_data = """# Listingdate,SHA1 Fingerprint,Description
    2023-03-08 07:58:29,6cec09bcb575352785d313c7e978f26bfbd528ab,AsyncRAT C&C
    2023-03-09 08:00:00,aaabbbcccdddeeeeffff00001111222233334444,Cobalt Strike C2"""
    mocker.patch("builtins.open", mock_open(read_data=test_data))
    result = update_manager.parse_ssl_feed(
        "https://example.com/test_ssl_feed.csv",
        str(tmp_path / "test_ssl_feed.csv"),
    )

    mock_db.add_ssl_sha1_to_IoC.assert_called_once_with(
        {
            "aaabbbcccdddeeeeffff00001111222233334444": json.dumps(
                {
                    "description": "Cobalt Strike C2",
                    "source": "test_ssl_feed.csv",
                    "threat_level": "medium",
                    "tags": ["tag1", "tag2"],
                }
            ),
        }
    )
    assert result is True


def test_parse_ssl_feed_no_valid_fingerprints(mocker, mock_db, tmp_path):
    """
    Test parse_ssl_feed with a file that doesn't contain any valid SSL fingerprints.
    """
    update_manager = ModuleFactory().create_update_manager_obj(mock_db)
    update_manager.ssl_feeds = {
        "https://example.com/test_ssl_feed.csv": {
            "threat_level": "medium",
            "tags": ["tag1", "tag2"],
        }
    }
    test_data = """# ja3_md5,first_seen,last_seen,Listingreason
    8f52d1ce303fb4a6515836aec3cc16b1,
    2017-07-15 19:05:11,2019-07-27 20:00:57,TrickBot"""
    mocker.patch("builtins.open", mock_open(read_data=test_data))
    result = update_manager.parse_ssl_feed(
        "https://example.com/test_ssl_feed.csv",
        str(tmp_path / "test_ssl_feed.csv"),
    )

    mock_db.add_ssl_sha1_to_IoC.assert_not_called()
    assert result is False
