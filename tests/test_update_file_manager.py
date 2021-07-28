""" Unit test for modules/UpdateManager/UpdateManager.py """
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
    filepath = '.'
    assert update_manager.download_file(url,filepath) == True

@pytest.mark.parametrize('url', [('https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv')])
def test_download_malicious_file(outputQueue, database,url):
    """we're tetsing this condition old_e_tag == new_e_tag"""
    update_manager = create_update_manager_instance(outputQueue)
    old_etag = update_manager.get_e_tag_from_web(url)
    database.set_malicious_file_info(url.split('/')[-1],{'e-tag':old_etag})
    assert update_manager.download_malicious_file(url) == True

@pytest.mark.parametrize('url', [('https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv')])
def test_download_malicious_file2(outputQueue, database,url):
    """we're tetsing old_e_tag != new_e_tag"""
    update_manager = create_update_manager_instance(outputQueue)
    # setup old e-tag
    old_etag = update_manager.get_e_tag_from_web(url)
    # edit old e-tag to be different from the new e-tag
    old_etag = old_etag.replace('0','*')
    database.set_malicious_file_info(url.split('/')[-1],{'e-tag':old_etag})
    assert update_manager.download_malicious_file(url) == True
