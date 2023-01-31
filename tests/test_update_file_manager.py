"""Unit test for modules/update_manager/update_file_manager.py"""
from ..modules.update_manager.update_file_manager import UpdateFileManager
import json

def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def create_update_manager_instance(outputQueue):
    """Create an instance of update_manager.py
    needed by every other test in this file"""
    update_manager = UpdateFileManager(outputQueue, 6380)
    # override the self.print function to avoid broken pipes
    update_manager.print = do_nothing
    return update_manager



def test_getting_header_fields(outputQueue, mocker):
    update_manager = create_update_manager_instance(outputQueue)
    url = 'google.com/play'
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'ETag': '1234'}
    mock_requests.return_value.text = ""
    response = update_manager.download_file(url)
    assert update_manager.get_e_tag(response) == '1234'


def test_check_if_update_based_on_update_period(outputQueue, database):
    update_manager = create_update_manager_instance(outputQueue)
    url = 'abc.com/x'
    # update period hasnt passed
    assert update_manager._UpdateFileManager__check_if_update(url, float('inf')) == False

def test_check_if_update_based_on_e_tag(outputQueue, database, mocker):
    update_manager = create_update_manager_instance(outputQueue)

    # period passed, etag same
    etag = '1234'
    url = 'google.com/images'
    database.set_TI_file_info(url, {'e-tag': etag})
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'ETag': '1234'}
    mock_requests.return_value.text = ""
    assert update_manager._UpdateFileManager__check_if_update(url, float('-inf')) == False


    # period passed, etag different
    etag = '1111'
    url = 'google.com/images'
    database.set_TI_file_info(url, {'e-tag': etag})
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'ETag': '2222'}
    mock_requests.return_value.text = ""
    assert update_manager._UpdateFileManager__check_if_update(url, float('-inf')) == True

def test_check_if_update_based_on_last_modified(outputQueue, database, mocker):
    update_manager = create_update_manager_instance(outputQueue)

    # period passed, no etag, last modified the same
    url = 'google.com/photos'
    database.set_TI_file_info(url, {'Last-Modified': 10.0})

    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'Last-Modified': 10.0}
    mock_requests.return_value.text = ""
    assert update_manager._UpdateFileManager__check_if_update(url, float('-inf')) == False

    # period passed, no etag, last modified changed
    url = 'google.com/photos'
    database.set_TI_file_info(url, {'Last-Modified': 10})
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.headers = {'Last-Modified': 11}
    mock_requests.return_value.text = ""
    assert update_manager._UpdateFileManager__check_if_update(url, float('-inf')) == True


def test_read_ports_info(outputQueue, database):
    update_manager = create_update_manager_instance(outputQueue)
    filepath = 'slips_files/ports_info/ports_used_by_specific_orgs.csv'
    assert update_manager.read_ports_info(filepath) > 100

    org = json.loads(database.get_organization_of_port('5243/udp'))
    assert 'org_name' in org
    assert org['org_name'] == 'Viber'

    org = json.loads(database.get_organization_of_port('65432/tcp'))
    assert 'org_name' in org
    assert org['org_name'] == 'Apple'
