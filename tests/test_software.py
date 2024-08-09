"""Unit test for modules/flowalerts/software.py"""

from tests.module_factory import ModuleFactory
import json
from unittest.mock import MagicMock
import pytest


@pytest.mark.parametrize(
    "cached_software, flow, expected_result",
    [
        # testcase1:No previous software info
        (
            None,
            {
                "starttime": 1632302619.444328,
                "uid": "M2VhNTA3ZmZiYjU3OGMxMzJk",
                "saddr": "192.168.1.247",
                "daddr": "192.168.1.50",
                "software": "SSH::CLIENT",
                "unparsed_version": "OpenSSH_9.1",
                "version_major": 9,
                "version_minor": 1,
                "type_": "software",
            },
            False,
        ),
        # testcase2: Same SSH client version
        (
            {
                "SSH::CLIENT": {
                    "version-major": 8,
                    "version-minor": 1,
                    "uid": "YTYwNjBiMjIxZDkzOWYyYTc4",
                }
            },
            {
                "starttime": 1632302619.444328,
                "uid": "M2VhNTA3ZmZiYjU3OGMxMzJk",
                "saddr": "192.168.1.247",
                "daddr": "192.168.1.50",
                "software": "SSH::CLIENT",
                "unparsed_version": "OpenSSH_8.1",
                "version_major": 8,
                "version_minor": 1,
                "type_": "software",
            },
            False,
        ),
        # testcase3: Different SSH client version
        (
            {
                "SSH::CLIENT": {
                    "version-major": 8,
                    "version-minor": 1,
                    "uid": "YTYwNjBiMjIxZDkzOWYyYTc4",
                }
            },
            {
                "starttime": 1632302619.444328,
                "uid": "M2VhNTA3ZmZiYjU3OGMxMzJk",
                "saddr": "192.168.1.247",
                "daddr": "192.168.1.50",
                "software": "SSH::CLIENT",
                "unparsed_version": "OpenSSH_9.1",
                "version_major": 9,
                "version_minor": 1,
                "type_": "software",
            },
            True,
        ),
        # testcase4: Different SSH client major version, same minor version
        (
            {
                "SSH::CLIENT": {
                    "version-major": 8,
                    "version-minor": 1,
                    "uid": "YTYwNjBiMjIxZDkzOWYyYTc4",
                }
            },
            {
                "starttime": 1632302619.444328,
                "uid": "M2VhNTA3ZmZiYjU3OGMxMzJk",
                "saddr": "192.168.1.247",
                "daddr": "192.168.1.50",
                "software": "SSH::CLIENT",
                "unparsed_version": "OpenSSH_9.1",
                "version_major": 9,
                "version_minor": 1,
                "type_": "software",
            },
            True,
        ),
        # testcase5: Different SSH client minor version, same major version
        (
            {
                "SSH::CLIENT": {
                    "version-major": 8,
                    "version-minor": 1,
                    "uid": "YTYwNjBiMjIxZDkzOWYyYTc4",
                }
            },
            {
                "starttime": 1632302619.444328,
                "uid": "M2VhNTA3ZmZiYjU3OGMxMzJk",
                "saddr": "192.168.1.247",
                "daddr": "192.168.1.50",
                "software": "SSH::CLIENT",
                "unparsed_version": "OpenSSH_8.2",
                "version_major": 8,
                "version_minor": 2,
                "type_": "software",
            },
            True,
        ),
    ],
)
def test_check_multiple_ssh_versions(
    mock_db, cached_software, flow, expected_result
):
    software = ModuleFactory().create_software_analyzer_obj(mock_db)
    mock_db.get_software_from_profile.return_value = cached_software
    assert (
        software.check_multiple_ssh_versions(flow, "timewindow1")
        is expected_result
    )


@pytest.mark.parametrize(
    "msg_data",
    [
        # Testcase1: Client version change detected
        (
            {
                "sw_flow": {
                    "starttime": 1632302619.444328,
                    "uid": "M2VhNTA3ZmZiYjU3OGMxMzJk",
                    "saddr": "192.168.1.247",
                    "daddr": "192.168.1.50",
                    "software": "SSH::CLIENT",
                    "unparsed_version": "OpenSSH_9.1",
                    "version_major": 9,
                    "version_minor": 1,
                    "type_": "software",
                },
                "twid": "timewindow1",
            }
        ),
        # Testcase2: Server version change detected
        (
            {
                "sw_flow": {
                    "starttime": 1632302619.444328,
                    "uid": "M2VhNTA3ZmZiYjU3OGMxMzJk",
                    "saddr": "192.168.1.247",
                    "daddr": "192.168.1.50",
                    "software": "SSH::SERVER",
                    "unparsed_version": "OpenSSH_9.1",
                    "version_major": 9,
                    "version_minor": 1,
                    "type_": "software",
                },
                "twid": "timewindow1",
            }
        ),
    ],
)
def test_analyze_version_change_detected(mock_db, msg_data):
    software = ModuleFactory().create_software_analyzer_obj(mock_db)
    software.check_multiple_ssh_versions = MagicMock()
    msg = {"channel": "new_software", "data": json.dumps(msg_data)}
    software.analyze(msg)

    assert software.check_multiple_ssh_versions.call_count == 2


def test_analyze_no_version_change(mock_db):
    software = ModuleFactory().create_software_analyzer_obj(mock_db)
    software.check_multiple_ssh_versions = MagicMock()
    software.analyze({})
    software.check_multiple_ssh_versions.assert_not_called()
