"""Unit test for modules/flowalerts/download_file.py"""

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
def test_check_malicious_ssl(
    mocker, mock_db, ssl_info, db_result, expected_call_count
):
    downloadfile = ModuleFactory().create_downloaded_file_analyzer_obj(mock_db)
    mock_set_evidence = mocker.patch.object(
        downloadfile.set_evidence, "malicious_ssl"
    )

    mock_db.is_blacklisted_ssl.return_value = db_result
    downloadfile.check_malicious_ssl(ssl_info)

    assert mock_set_evidence.call_count == expected_call_count
    mock_set_evidence.assert_has_calls(
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
def test_analyze_with_data(mocker, mock_db, msg, expected_call_count):
    downloadfile = ModuleFactory().create_downloaded_file_analyzer_obj(mock_db)
    mock_check_malicious_ssl = mocker.patch.object(
        downloadfile, "check_malicious_ssl"
    )
    msg.update({"channel": "new_downloaded_file"})

    downloadfile.analyze(msg)

    assert mock_check_malicious_ssl.call_count == expected_call_count
    mock_check_malicious_ssl.assert_called_with(json.loads(msg["data"]))


def test_analyze_no_msg(mocker, mock_db):
    downloadfile = ModuleFactory().create_downloaded_file_analyzer_obj(mock_db)
    mock_check_malicious_ssl = mocker.patch.object(
        downloadfile, "check_malicious_ssl"
    )
    downloadfile.analyze({})
    mock_check_malicious_ssl.assert_not_called()
