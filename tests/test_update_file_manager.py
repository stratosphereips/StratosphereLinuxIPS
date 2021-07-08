""" Unit test for modules/UpdateManager/UpdateManager.py """
from ..modules.UpdateManager.update_file_manager import UpdateFileManager
import configparser


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

def test_get_e_tag_from_web(outputQueue):
    update_manager = create_update_manager_instance(outputQueue)
    file_to_download = 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv'
    # returns an etag
    assert update_manager.get_e_tag_from_web(file_to_download) != False

def test_download_file(outputQueue):
    update_manager = create_update_manager_instance(outputQueue)
    url = 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv'
    filepath = '.'
    assert update_manager.download_file(url,filepath) == True





