"""Unit test for modules/threat_intelligence/threat_intelligence.py"""
from ..modules.threat_intelligence.threat_intelligence import Module
from ..slips_files.common.slips_utils import utils
import configparser
import os
import pytest


def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def create_threatintel_instance(outputQueue):
    """Create an instance of threatintel.py
    needed by every other test in this file"""
    threatintel = Module(outputQueue, 1234)
    # override the self.print function to avoid broken pipes
    threatintel.print = do_nothing
    return threatintel


def test_parse_ti_file(database, outputQueue):
    threatintel = create_threatintel_instance(outputQueue)
    local_ti_files_dir = threatintel.path_to_local_ti_files
    local_ti_file = os.path.join(local_ti_files_dir, 'own_malicious_iocs.csv')
    # this is an ip we know we have in own_maicious_iocs.csv
    assert threatintel.parse_local_ti_file(local_ti_file) == True
    assert database.search_IP_in_IoC('54.192.46.116')


@pytest.mark.parametrize(
    'current_hash, old_hash, expected_return',
    [
    ('111', '222', '111'),
    ('111', '111', False),
    (False , '222', False),
    ],
)
def test_check_local_ti_files_for_update(
        outputQueue, current_hash, old_hash, expected_return, mocker
):
    """
    first case the cur hash is diff from the old hash so slips should update
    second case the cur is the same so we shouldnt
    third, cur hash is false meaning we cant get the file hash
    """
    # since this is a clear db, then we should update the local ti file
    threatintel = create_threatintel_instance(outputQueue)
    own_malicious_iocs = os.path.join(threatintel.path_to_local_ti_files, 'own_malicious_iocs.csv')

    mock_hash = mocker.patch("slips_files.common.slips_utils.Utils.get_hash_from_file")
    mock_hash.return_value = current_hash

    mock_hash = mocker.patch("slips_files.core.database.database.Database.get_TI_file_info")
    mock_hash.return_value = {'hash': old_hash}

    assert threatintel.should_update_local_ti_file(own_malicious_iocs) == expected_return
