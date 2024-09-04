"""Unit test for modules/flowalerts/download_file.py"""

from unittest.mock import Mock

from tests.module_factory import ModuleFactory
import json
import pytest


@pytest.mark.parametrize(
    "ssl_info, db_result, expected_call_count",
    [
        (  # Testcase 1: Malicious SSL certificate found
            {
                "type": "zeek",
                "flow": {
                    "source": "SSL",
                    "analyzers": "SHA1",
                    "sha1": "malicious_sha1",
                },
            },
            {"malicious": True},
            1,
        ),
        (  # Testcase 2: Non-malicious SSL certificate
            {
                "type": "zeek",
                "flow": {
                    "source": "SSL",
                    "analyzers": "SHA1",
                    "sha1": "benign_sha1",
                },
            },
            None,
            0,
        ),
        (  # Testcase 3: Not an SSL certificate
            {
                "type": "zeek",
                "flow": {
                    "source": "OTHER",
                    "analyzers": "SHA1",
                    "sha1": "some_sha1",
                },
            },
            None,
            0,
        ),
    ],
)
def test_check_malicious_ssl(mocker, ssl_info, db_result, expected_call_count):
    downloadfile = ModuleFactory().create_downloaded_file_analyzer_obj()
    downloadfile.set_evidence.malicious_ssl = Mock()

    downloadfile.db.get_ssl_info.return_value = db_result
    downloadfile.check_malicious_ssl(ssl_info)

    assert (
        downloadfile.set_evidence.malicious_ssl.call_count
        == expected_call_count
    )
    downloadfile.set_evidence.malicious_ssl.assert_has_calls(
        [mocker.call(ssl_info, db_result)] * expected_call_count
    )


@pytest.mark.parametrize(
    "msg, expected_call_count",
    [
        # Test case 1: Valid SSL data
        (
            {
                "data": json.dumps(
                    {
                        "type": "zeek",
                        "flow": {
                            "source": "SSL",
                            "analyzers": "SHA1",
                            "sha1": "test_sha1",
                        },
                    }
                )
            },
            1,
        ),
        # Test case 2: Non-zeek data
        ({"data": json.dumps({"type": "not_zeek", "flow": {}})}, 1),
    ],
)
def test_analyze_with_data(msg, expected_call_count):
    downloadfile = ModuleFactory().create_downloaded_file_analyzer_obj()
    downloadfile.check_malicious_ssl = Mock()
    msg.update({"channel": "new_downloaded_file"})

    downloadfile.analyze(msg)

    assert downloadfile.check_malicious_ssl.call_count == expected_call_count
    downloadfile.check_malicious_ssl.assert_called_with(
        json.loads(msg["data"])
    )


def test_analyze_no_msg(mocker):
    downloadfile = ModuleFactory().create_downloaded_file_analyzer_obj()
    downloadfile.check_malicious_ssl = Mock()
    downloadfile.analyze({})
    downloadfile.check_malicious_ssl.assert_not_called()
