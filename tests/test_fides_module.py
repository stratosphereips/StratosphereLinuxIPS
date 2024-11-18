"""Unit test for modules/fidesModule/fidesModule.py"""

import json
from dataclasses import asdict
import pytest
import os

from tests.module_factory import ModuleFactory
from unittest.mock import (
    patch,
    MagicMock,
    Mock,
)
from modules.http_analyzer.http_analyzer import utils
from modules.fidesModule.fidesModule import FidesModule
import requests

@pytest.fixture
def cleanup_database():
    # name of the database created by Fides
    db_name = "p2p_db.sqlite"

    yield  # Let the test run

    # Cleanup itself
    if os.path.exists(db_name):
        os.remove(db_name)

def test_pre_main(mocker, cleanup_database):
    fides_module = ModuleFactory().create_fidesModule_obj()
    mocker.patch("slips_files.common.slips_utils.Utils.drop_root_privs")
    fides_module.pre_main()
    utils.drop_root_privs.assert_called_once()


# @pytest.mark.parametrize(
#     "uri, request_body_len, expected_result",
#     [
#         ("/path/to/file", 0, False),  # Non-empty URI
#         ("/", 100, False),  # Non-zero request body length
#         ("/", "invalid_length", False),  # Invalid request body length
#     ],
# )
#
# def test_check_multiple_empty_connections(
#     uri, request_body_len, expected_result
# ):
#     http_analyzer = ModuleFactory().create_http_analyzer_obj()
#     host = "google.com"
#     flow = HTTP(
#         starttime="1726593782.8840969",
#         uid=str("uid_55"),
#         saddr="192.168.1.5",
#         daddr="147.32.80.7",
#         method="WEIRD_METHOD",
#         host="google.com",
#         uri=uri,
#         version=0,
#         user_agent="",
#         request_body_len=request_body_len,
#         response_body_len=10,
#         status_code="",
#         status_msg="",
#         resp_mime_types="",
#         resp_fuids="",
#     )
#     result = http_analyzer.check_multiple_empty_connections(twid, flow)
#     assert result is expected_result
#
#     if uri == "/" and request_body_len == 0 and expected_result is False:
#         for i in range(http_analyzer.empty_connections_threshold):
#             flow = HTTP(
#                 starttime="1726593782.8840969",
#                 uid=str(f"uid_{i}"),
#                 saddr="192.168.1.5",
#                 daddr="147.32.80.7",
#                 method="WEIRD_METHOD",
#                 host="google.com",
#                 uri=uri,
#                 version=0,
#                 user_agent="",
#                 request_body_len=request_body_len,
#                 response_body_len=10,
#                 status_code="",
#                 status_msg="",
#                 resp_mime_types="",
#                 resp_fuids="",
#             )
#             http_analyzer.check_multiple_empty_connections(twid, flow)
#         assert http_analyzer.connections_counter[host] == ([], 0)
#
#
# @pytest.mark.parametrize(
#     "host, response_body_len, method, expected_result",
#     [
#         ("pastebin.com", "invalid_length", "GET", False),
#         ("8.8.8.8", "1024", "GET", False),
#         ("pastebin.com", "512", "GET", False),
#         ("pastebin.com", "2048", "POST", False),
#         ("pastebin.com", "2048", "GET", True),  # Large download from Pastebin
#     ],
# )
# def test_check_pastebin_downloads(
#     host, response_body_len, method, expected_result
# ):
#     http_analyzer = ModuleFactory().create_http_analyzer_obj()
#     flow = HTTP(
#         starttime="1726593782.8840969",
#         uid=str("uid_1"),
#         saddr="192.168.1.5",
#         daddr="147.32.80.7",
#         method=method,
#         host="google.com",
#         uri=host,
#         version=0,
#         user_agent="",
#         request_body_len=5,
#         response_body_len=response_body_len,
#         status_code="",
#         status_msg="",
#         resp_mime_types="",
#         resp_fuids="",
#     )
#     if host != "pastebin.com":
#         http_analyzer.db.get_ip_identification.return_value = (
#             "Not a Pastebin domain"
#         )
#     else:
#         http_analyzer.db.get_ip_identification.return_value = "pastebin.com"
#         http_analyzer.pastebin_downloads_threshold = 1024
#     result = http_analyzer.check_pastebin_downloads(twid, flow)
#     assert result == expected_result
#
#
# @pytest.mark.parametrize(
#     "mock_response",
#     [
#         # Unexpected response format
#         MagicMock(status_code=200, text="Unexpected response format"),
#         # Timeout
#         MagicMock(side_effect=requests.exceptions.ReadTimeout),
#     ],
# )
# def test_get_ua_info_online_error_cases(mock_response):
#     http_analyzer = ModuleFactory().create_http_analyzer_obj()
#     with patch("requests.get", return_value=mock_response):
#         assert http_analyzer.get_ua_info_online(SAFARI_UA) is False
