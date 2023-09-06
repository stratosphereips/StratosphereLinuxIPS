"""Unit test for modules/update_manager/update_manager.py"""
from tests.module_factory import ModuleFactory
import json

def test_getting_header_fields(mocker, mock_rdb):
    update_manager = ModuleFactory().create_update_manager_obj(mock_rdb)
    url = 'google.com/play'
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'ETag': '1234'}
    mock_requests.return_value.text = ""
    response = update_manager.download_file(url)
    assert update_manager.get_e_tag(response) == '1234'


def test_check_if_update_based_on_update_period(mock_rdb):
    mock_rdb.get_TI_file_info.return_value = {'time': float('inf')}
    update_manager = ModuleFactory().create_update_manager_obj(mock_rdb)
    url = 'abc.com/x'
    # update period hasn't passed
    assert update_manager.check_if_update(url, float('inf')) is False

def test_check_if_update_based_on_e_tag(mocker, mock_rdb):
    update_manager = ModuleFactory().create_update_manager_obj(mock_rdb)

    # period passed, etag same
    etag = '1234'
    url = 'google.com/images'
    mock_rdb.get_TI_file_info.return_value =  {'e-tag': etag}

    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'ETag': '1234'}
    mock_requests.return_value.text = ""
    assert update_manager.check_if_update(url, float('-inf')) is False


    # period passed, etag different
    etag = '1111'
    url = 'google.com/images'
    mock_rdb.get_TI_file_info.return_value =  {'e-tag': etag}
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'ETag': '2222'}
    mock_requests.return_value.text = ""
    assert update_manager.check_if_update(url, float('-inf')) is True

def test_check_if_update_based_on_last_modified(database, mocker, mock_rdb):
    update_manager = ModuleFactory().create_update_manager_obj(mock_rdb)

    # period passed, no etag, last modified the same
    url = 'google.com/photos'

    mock_rdb.get_TI_file_info.return_value = {'Last-Modified': 10.0}
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'Last-Modified': 10.0}
    mock_requests.return_value.text = ""

    assert update_manager.check_if_update(url, float('-inf')) is False

    # period passed, no etag, last modified changed
    url = 'google.com/photos'

    mock_rdb.get_TI_file_info.return_value = {'Last-Modified': 10}
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'Last-Modified': 11}
    mock_requests.return_value.text = ""

    assert update_manager.check_if_update(url, float('-inf')) is True


