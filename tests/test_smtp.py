"""Unit test for modules/flowalerts/flowalerts.py"""

from tests.module_factory import ModuleFactory
import json
from unittest.mock import MagicMock
import pytest

# dummy params used for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
uid = "CAeDWs37BipkfP21u8"
timestamp = 1635765895.037696
saddr = "192.168.1.1"
daddr = "192.168.1.2"


@pytest.mark.parametrize(
    "timestamps, expected_call_count",
    [
        # Test case 1: Threshold not reached, no evidence should be set
        ([timestamp], 0),
        # Test case 2: Threshold reached, evidence should be set
        ([timestamp + i for i in range(3)], 1),
        # Test case 3: Threshold reached with some time elapsed between attempts, evidence should be set
        ([timestamp, timestamp + 5, timestamp + 9], 1),
        # Test case 4: Threshold not reached, attempts spread over more than 10 seconds, no evidence should be set
        ([timestamp, timestamp + 6, timestamp + 11], 0),
    ],
)
def test_check_smtp_bruteforce(mock_db, timestamps, expected_call_count):
    """Tests the check_smtp_bruteforce method of the SMTP class."""
    smtp = ModuleFactory().create_smtp_analyzer_obj(mock_db)
    mock_set_evidence = MagicMock()
    smtp.set_evidence.smtp_bruteforce = mock_set_evidence

    smtp.smtp_bruteforce_cache = {profileid: ([], [])}
    for i, ts in enumerate(timestamps):
        flow = {
            "daddr": daddr,
            "saddr": saddr,
            "last_reply": "bad smtp-auth user",
            "uid": f"uid_{i}",
            "starttime": ts,
        }
        smtp.check_smtp_bruteforce(profileid, twid, flow)

    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "msg_data, expected_check_args",
    [
        (
            {
                "profileid": profileid,
                "twid": twid,
                "flow": {
                    "daddr": daddr,
                    "saddr": saddr,
                    "last_reply": "bad smtp-auth user",
                    "uid": uid,
                    "starttime": timestamp,
                },
            },
            (
                profileid,
                twid,
                {
                    "daddr": daddr,
                    "saddr": saddr,
                    "last_reply": "bad smtp-auth user",
                    "uid": uid,
                    "starttime": timestamp,
                },
            ),
        ),
        (
            {"profileid": profileid, "twid": twid, "flow": {}},
            (profileid, twid, {}),
        ),
    ],
)
def test_analyze_with_valid_message(mock_db, msg_data, expected_check_args):
    """Tests the analyze method of the SMTP class when a valid message is received."""
    smtp = ModuleFactory().create_smtp_analyzer_obj(mock_db)
    smtp.check_smtp_bruteforce = MagicMock()
    mock_flowalerts = MagicMock()
    smtp.flowalerts = mock_flowalerts
    mock_flowalerts.get_msg.return_value = {"data": json.dumps(msg_data)}

    smtp.analyze()

    smtp.flowalerts.get_msg.assert_called_once_with("new_smtp")
    smtp.check_smtp_bruteforce.assert_called_once_with(*expected_check_args)


def test_analyze_with_no_message(mock_db):
    """Tests the analyze method of the SMTP class when no message is received."""
    smtp = ModuleFactory().create_smtp_analyzer_obj(mock_db)
    smtp.check_smtp_bruteforce = MagicMock()
    mock_flowalerts = MagicMock()
    smtp.flowalerts = mock_flowalerts
    mock_flowalerts.get_msg.return_value = None

    smtp.analyze()

    smtp.flowalerts.get_msg.assert_called_once_with("new_smtp")
    smtp.check_smtp_bruteforce.assert_not_called()
