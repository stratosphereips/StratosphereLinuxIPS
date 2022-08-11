"""Unit test for modules/update_manager/update_file_manager.py"""
import os

from ..modules.update_manager.update_file_manager import UpdateFileManager
import configparser
import pytest
import json


def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def create_update_manager_instance(outputQueue):
    """Create an instance of update_manager.py
    needed by every other test in this file"""
    config = configparser.ConfigParser()
    update_manager = UpdateFileManager(outputQueue, config, 6380)
    # override the self.print function to avoid broken pipes
    update_manager.print = do_nothing
    return update_manager


@pytest.mark.parametrize(
    'file,etag',
    [
        (
            'https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/master/modules/template/__init__.py',
            'W/"4920b25bf5708ae099fc36dcf3a7fcf9393754f9c92e170b2dd04c08b58e6dca"',
        )
    ],
)
def test_getting_header_fields(outputQueue, file, etag):
    update_manager = create_update_manager_instance(outputQueue)
    response = update_manager.download_file(file)
    assert response != False
    assert update_manager.get_e_tag(response) == etag


@pytest.mark.parametrize(
    'url',
    [
        'https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv'
    ],
)
def test_download_file(outputQueue, url):
    update_manager = create_update_manager_instance(outputQueue)
    response = update_manager.download_file(url)
    assert str(response) == '<Response [200]>', 'Connection error'


@pytest.mark.parametrize(
    'url',
    [
        (
            'https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv'
        )
    ],
)
def test_check_if_update(outputQueue, database, url):
    """we're tetsing this condition old_e_tag != new_e_tag"""
    update_manager = create_update_manager_instance(outputQueue)
    # modify old e-tag of this file and store it in the database
    response = update_manager.download_file(url)
    assert response != False
    old_etag = update_manager.get_e_tag(response)
    old_etag = '*' + old_etag[1:]
    database.set_TI_file_info(url.split('/')[-1], {'e-tag': old_etag})
    # we call this function to set the new self.new_e_tag
    # to something different than the old modified one
    # check_if_update returns a response if we should update or false if we shouldn't update
    is_file_updated = update_manager._UpdateFileManager__check_if_update(url)
    assert is_file_updated != False


@pytest.mark.parametrize(
    'url',
    [
        (
            'https://osint.digitalside.it/Threat-Intel/lists/latestips.txt'
        )
    ],
)
def test_check_if_update2(outputQueue, database, url):
    """we're tetsing old_e_tag == new_e_tag, it shouldn't update"""
    update_manager = create_update_manager_instance(outputQueue)

    # setup old e-tag to be the current e-tag
    response = update_manager.download_file(url)
    assert response != False
    old_etag = update_manager.get_e_tag(response)
    database.set_TI_file_info(url.split('/')[-1], {'e-tag': old_etag})
    is_file_updated = update_manager._UpdateFileManager__check_if_update(url)
    assert is_file_updated == False


def test_read_ports_info(outputQueue, database):
    update_manager = create_update_manager_instance(outputQueue)
    filepath = 'slips_files/ports_info/ports_used_by_specific_orgs.csv'
    assert update_manager.read_ports_info(filepath) > 39000
    org = json.loads(database.get_organization_of_port('5243/udp'))
    assert 'org_name' in org
    assert org['org_name'] == 'Viber'
    org = json.loads(database.get_organization_of_port('65432/tcp'))
    assert 'org_name' in org
    assert org['org_name'] == 'Apple'
