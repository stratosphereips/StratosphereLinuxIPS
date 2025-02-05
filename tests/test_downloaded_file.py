# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/flowalerts/download_file.py"""

from dataclasses import asdict
from unittest.mock import Mock

from slips_files.core.flows.zeek import (
    Files,
)
from tests.module_factory import ModuleFactory
import json
import pytest


@pytest.mark.parametrize(
    "flow, db_result, expected_call_count",
    [
        (  # Testcase 1: Malicious SSL certificate found
            Files(
                starttime="1726593782.8840969",
                uid="123",
                saddr="192.168.1.80",
                daddr="1.1.1.1",
                size=5,
                md5="",
                source="SSL",
                analyzers="SHA1",
                sha1="malicious_sha1",
                tx_hosts=["192.168.1.80"],
                rx_hosts=["1.1.1.1"],
            ),
            {"malicious": True},
            1,
        ),
        (  # Testcase 2: Non-malicious SSL certificate
            Files(
                starttime="1726593782.8840969",
                uid="123",
                saddr="192.168.1.80",
                daddr="1.1.1.1",
                size=5,
                md5="",
                source="SSL",
                analyzers="SHA1",
                sha1="malicious_sha1",
                tx_hosts=["192.168.1.80"],
                rx_hosts=["1.1.1.1"],
            ),
            None,
            0,
        ),
        (  # Testcase 3: Not an SSL certificate
            Files(
                starttime="1726593782.8840969",
                uid="123",
                saddr="192.168.1.80",
                daddr="1.1.1.1",
                size=5,
                md5="",
                source="SSL",
                analyzers="SHA1",
                sha1="malicious_sha1",
                tx_hosts=["192.168.1.80"],
                rx_hosts=["1.1.1.1"],
            ),
            None,
            0,
        ),
    ],
)
def test_check_malicious_ssl(flow, db_result, expected_call_count):
    twid = "timewindow1"
    downloaded_file_handler = (
        ModuleFactory().create_downloaded_file_analyzer_obj()
    )
    downloaded_file_handler.set_evidence.malicious_ssl = Mock()

    downloaded_file_handler.db.is_blacklisted_ssl.return_value = db_result
    downloaded_file_handler.check_malicious_ssl(twid, flow)

    assert (
        downloaded_file_handler.set_evidence.malicious_ssl.call_count
        == expected_call_count
    )


@pytest.mark.parametrize(
    "msg, expected_call_count",
    [
        # Test case 1: Valid SSL data
        (
            {
                "channel": "new_downloaded_file",
                "data": json.dumps(
                    {
                        "flow": asdict(
                            Files(
                                starttime="1726593782.8840969",
                                uid="123",
                                saddr="192.168.1.80",
                                daddr="1.1.1.1",
                                size=5,
                                md5="",
                                source="SSL",
                                analyzers="SHA1",
                                sha1="malicious_sha1",
                                tx_hosts=["192.168.1.80"],
                                rx_hosts=["1.1.1.1"],
                            )
                        ),
                        "twid": "timewindow1",
                    }
                ),
            },
            1,
        ),
    ],
)
def test_analyze_with_data(msg, expected_call_count):
    downloaded_file_handler = (
        ModuleFactory().create_downloaded_file_analyzer_obj()
    )
    downloaded_file_handler.check_malicious_ssl = Mock()
    downloaded_file_handler.analyze(msg)

    assert (
        downloaded_file_handler.check_malicious_ssl.call_count
        == expected_call_count
    )
    msg = json.loads(msg["data"])
    flow = downloaded_file_handler.classifier.convert_to_flow_obj(msg["flow"])
    downloaded_file_handler.check_malicious_ssl.assert_called_with(
        msg["twid"], flow
    )


def test_analyze_no_msg():
    downloaded_file_handler = (
        ModuleFactory().create_downloaded_file_analyzer_obj()
    )
    downloaded_file_handler.check_malicious_ssl = Mock()
    downloaded_file_handler.analyze({})
    downloaded_file_handler.check_malicious_ssl.assert_not_called()
