""" Unit test for modules/UpdateManager/update_file_manager.py """
import os

from ..modules.UpdateManager.update_file_manager import UpdateFileManager
import configparser
import pytest

def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_update_manager_instance(outputQueue):
    """ Create an instance of update_manager.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    update_manager = UpdateFileManager(outputQueue, config)
    # override the self.print function to avoid broken pipes
    update_manager.print = do_nothing
    return update_manager



@pytest.mark.parametrize('file,etag', [('https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/master/modules/template/__init__.py','c53b10ca5dc87b9dd21a6618940553ac09e8213c22b2c11ad31e997970d70a11')])
def test_get_e_tag_from_web(outputQueue, file, etag):
    update_manager = create_update_manager_instance(outputQueue)
    assert update_manager.get_e_tag_from_web(file) == etag

@pytest.mark.parametrize('url', ['https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv'])
def test_download_file(outputQueue, url):
    update_manager = create_update_manager_instance(outputQueue)
    filename = 'tests/AIP_blacklist_for_IPs_seen_last_24_hours.csv'
    assert update_manager.download_file(url, filename) == True
    os.remove(filename)

@pytest.mark.parametrize('url', [('https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv')])
def test_download_malicious_file(outputQueue, database, url):
    """we're tetsing this condition old_e_tag != new_e_tag"""
    update_manager = create_update_manager_instance(outputQueue)
    # modify old e-tag of this file and store it in the database
    old_etag = update_manager.get_e_tag_from_web(url)
    old_etag = '*' + old_etag[1:]
    database.set_TI_file_info(url.split('/')[-1], {'e-tag':old_etag})
    # we call this function to set the new self.new_e_tag
    # to something different than the old modified one
    assert update_manager._UpdateFileManager__check_if_update(url) == True

@pytest.mark.parametrize('url', [('https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv')])
def test_download_malicious_file2(outputQueue, database, url):
    """we're tetsing old_e_tag == new_e_tag, it shouldn't update"""
    update_manager = create_update_manager_instance(outputQueue)

    # setup old e-tag to be the current e-tag
    old_etag = update_manager.get_e_tag_from_web(url)
    database.set_TI_file_info(url.split('/')[-1], {'e-tag':old_etag})

    assert update_manager._UpdateFileManager__check_if_update(url) == False
