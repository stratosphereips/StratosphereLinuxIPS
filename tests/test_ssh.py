"""Unit test for modules/flowalerts/ssh.py"""

from tests.module_factory import ModuleFactory
import json
from unittest.mock import patch
from unittest.mock import MagicMock
import pytest

# dummy params used for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
uid = "CAeDWs37BipkfP21u8"
timestamp = 1635765895.037696
daddr = "192.168.1.2"


@pytest.mark.parametrize(
    "auth_success, expected_called_zeek, expected_called_slips",
    [
        # Test case 1: auth_success is 'true' -
        # should call detect_successful_ssh_by_zeek
        ("true", True, False),
        # Test case 2: auth_success is 'T'
        # - should call detect_successful_ssh_by_zeek
        ("T", True, False),
        # Test case 3: auth_success is 'false'
        # - should call detect_successful_ssh_by_slips
        ("false", False, True),
        # Test case 4: auth_success is 'F'
        # - should call detect_successful_ssh_by_slips
        ("F", False, True),
        # Test case 5: auth_success is any other value
        # - should call detect_successful_ssh_by_slips
        ("some_other_value", False, True),
    ],
)
def test_check_successful_ssh(
    mocker, mock_db, auth_success, expected_called_zeek, expected_called_slips
):
    ssh = ModuleFactory().create_ssh_analyzer_obj(mock_db)
    mock_detect_zeek = mocker.patch(
        "modules.flowalerts.ssh.SSH.detect_successful_ssh_by_zeek"
    )
    mock_detect_slips = mocker.patch(
        "modules.flowalerts.ssh.SSH.detect_successful_ssh_by_slips"
    )

    ssh.check_successful_ssh(uid, timestamp, profileid, twid, auth_success)

    assert mock_detect_zeek.called == expected_called_zeek
    assert mock_detect_slips.called == expected_called_slips


@pytest.mark.parametrize(
    "auth_success, expected_call_count",
    [
        # Testcase 1: Successful SSH login should not trigger alert
        ("true", False),
        # Testcase 2: Successful SSH login should not trigger alert
        ("T", False),
        # Testcase 3: Failed SSH login should trigger alert after threshold
        ("F", True),
    ],
)
def test_check_ssh_password_guessing(
    mock_db, auth_success, expected_call_count
):
    ssh = ModuleFactory().create_ssh_analyzer_obj(mock_db)
    mock_set_evidence = MagicMock()
    ssh.set_evidence.pw_guessing = mock_set_evidence
    for i in range(ssh.pw_guessing_threshold):
        ssh.check_ssh_password_guessing(
            daddr, f"uid_{i}", timestamp, profileid, twid, auth_success
        )
    assert mock_set_evidence.call_count == expected_call_count
    ssh.password_guessing_cache = {}


@patch("slips_files.common.parsers.config_parser.ConfigParser")
def test_read_configuration(mock_config_parser, mock_db):
    """Test the read_configuration method."""
    mock_parser = mock_config_parser.return_value
    mock_parser.ssh_succesful_detection_threshold.return_value = 12345
    ssh = ModuleFactory().create_ssh_analyzer_obj(mock_db)
    ssh.read_configuration()
    assert ssh.ssh_succesful_detection_threshold == 4290


def test_detect_successful_ssh_by_slips(mock_db):
    ssh = ModuleFactory().create_ssh_analyzer_obj(mock_db)
    ssh.ssh_succesful_detection_threshold = 1000

    mock_db_return = {
        "test_uid": json.dumps(
            {
                "sbytes": 2000,
                "dbytes": 2000,
                "daddr": "192.168.1.2",
                "saddr": "192.168.1.1",
            }
        )
    }
    ssh.db.get_flow = MagicMock(return_value=mock_db_return)

    ssh.set_evidence = MagicMock()

    result = ssh.detect_successful_ssh_by_slips(
        "test_uid", "timestamp", "profileid", "twid", "false"
    )
    expected_result = True
    assert result == expected_result
    ssh.set_evidence.ssh_successful.assert_called_once_with(
        "twid",
        "192.168.1.1",
        "192.168.1.2",
        4000,
        "test_uid",
        "timestamp",
        by="Slips",
    )
    assert "test_uid" not in ssh.connections_checked_in_ssh_timer_thread


def test_detect_successful_ssh_by_zeek(mock_db):
    ssh = ModuleFactory().create_ssh_analyzer_obj(mock_db)

    uid = "test_uid"
    timestamp = "1234567890"
    profileid = "profile_192.168.1.1"
    twid = "tw1"
    flow_data = {
        "daddr": "192.168.1.2",
        "saddr": "192.168.1.1",
        "sbytes": 1000,
        "dbytes": 1000,
    }
    mock_flow = {uid: json.dumps(flow_data)}
    ssh.db.search_tws_for_flow = MagicMock(return_value=mock_flow)
    ssh.set_evidence = MagicMock()
    ssh.connections_checked_in_ssh_timer_thread = []
    result = ssh.detect_successful_ssh_by_zeek(uid, timestamp, profileid, twid)
    expected_result = True
    assert result == expected_result
    ssh.set_evidence.ssh_successful.assert_called_once_with(
        twid,
        flow_data["saddr"],
        flow_data["daddr"],
        flow_data["sbytes"] + flow_data["dbytes"],
        uid,
        timestamp,
        by="Zeek",
    )
    assert uid not in ssh.connections_checked_in_ssh_timer_thread
    ssh.db.search_tws_for_flow.assert_called_once_with(profileid, twid, uid)


def test_detect_successful_ssh_by_zeek_flow_exists_auth_success(mock_db):
    ssh = ModuleFactory().create_ssh_analyzer_obj(mock_db)

    mock_flow = {
        "test_uid": json.dumps(
            {
                "daddr": "192.168.1.2",
                "saddr": "192.168.1.1",
                "sbytes": 1000,
                "dbytes": 1000,
                "auth_success": True,
            }
        )
    }

    ssh.db.search_tws_for_flow = MagicMock(return_value=mock_flow)
    ssh.set_evidence = MagicMock()

    result = ssh.detect_successful_ssh_by_zeek(
        "test_uid", "timestamp", "profileid", "twid"
    )

    expected_result = True
    assert result == expected_result
    ssh.set_evidence.ssh_successful.assert_called_once_with(
        "twid",
        "192.168.1.1",
        "192.168.1.2",
        2000,
        "test_uid",
        "timestamp",
        by="Zeek",
    )
    assert "test_uid" not in ssh.connections_checked_in_ssh_timer_thread


def test_detect_successful_ssh_by_zeek_flow_exists_auth_fail(mock_db):
    ssh = ModuleFactory().create_ssh_analyzer_obj(mock_db)

    mock_flow = {
        "test_uid": json.dumps(
            {
                "daddr": "192.168.1.2",
                "saddr": "192.168.1.1",
                "sbytes": 1000,
                "dbytes": 1000,
                "auth_success": False,
            }
        )
    }

    ssh.db.search_tws_for_flow = MagicMock(return_value=mock_flow)
    ssh.set_evidence = MagicMock()

    result = ssh.detect_successful_ssh_by_zeek(
        "test_uid", "timestamp", "profileid", "twid"
    )

    expected_result = True
    assert result == expected_result
    ssh.set_evidence.ssh_successful.assert_called_once_with(
        "twid",
        "192.168.1.1",
        "192.168.1.2",
        2000,
        "test_uid",
        "timestamp",
        by="Zeek",
    )
    assert "test_uid" not in ssh.connections_checked_in_ssh_timer_thread


def test_analyze_no_message(mock_db):
    ssh = ModuleFactory().create_ssh_analyzer_obj(mock_db)
    ssh.flowalerts = MagicMock()
    ssh.flowalerts.get_msg.return_value = None
    ssh.check_successful_ssh = MagicMock()
    ssh.check_ssh_password_guessing = MagicMock()

    ssh.analyze({})

    ssh.check_successful_ssh.assert_not_called()
    ssh.check_ssh_password_guessing.assert_not_called()


@pytest.mark.parametrize("auth_success", ["true", "false"])
def test_analyze_with_message(mock_db, auth_success):
    ssh = ModuleFactory().create_ssh_analyzer_obj(mock_db)
    ssh.check_successful_ssh = MagicMock()
    ssh.check_ssh_password_guessing = MagicMock()

    flow_data = {
        "stime": timestamp,
        "uid": uid,
        "daddr": daddr,
        "auth_success": auth_success,
    }
    msg_data = {
        "profileid": profileid,
        "twid": twid,
        "flow": json.dumps(flow_data),
    }

    ssh.analyze({"channel": "new_ssh", "data": json.dumps(msg_data)})

    ssh.check_successful_ssh.assert_called_once_with(
        uid, timestamp, profileid, twid, auth_success
    )
    ssh.check_ssh_password_guessing.assert_called_once_with(
        daddr, uid, timestamp, profileid, twid, auth_success
    )
