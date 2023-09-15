"""Unit test for modules/threat_intelligence/threat_intelligence.py"""
from tests.module_factory import ModuleFactory
import os
import pytest



def test_parse_local_ti_file(mock_rdb):
    threatintel = ModuleFactory().create_threatintel_obj(mock_rdb)
    local_ti_files_dir = threatintel.path_to_local_ti_files
    local_ti_file = os.path.join(local_ti_files_dir, 'own_malicious_iocs.csv')
    # this is an ip we know we have in own_maicious_iocs.csv
    assert threatintel.parse_local_ti_file(local_ti_file) is True


@pytest.mark.parametrize(
    'current_hash, old_hash, expected_return',
    [
    ('111', '222', '111'),
    ('111', '111', False),
    (False , '222', False),
    ],
)
def test_check_local_ti_files_for_update(
     current_hash, old_hash, expected_return, mocker, mock_rdb
):
    """
    first case the cur hash is diff from the old hash so slips should update
    second case the cur is the same so we shouldnt
    third, cur hash is false meaning we cant get the file hash
    """
    # since this is a clear db, then we should update the local ti file
    threatintel = ModuleFactory().create_threatintel_obj(mock_rdb)
    own_malicious_iocs = os.path.join(threatintel.path_to_local_ti_files, 'own_malicious_iocs.csv')

    mock_hash = mocker.patch("slips_files.common.slips_utils.Utils.get_hash_from_file")
    mock_hash.return_value = current_hash

    mock_rdb.get_TI_file_info.return_value = {'hash': old_hash}

    assert threatintel.should_update_local_ti_file(own_malicious_iocs) == expected_return
