"""Unit test for modules/threat_intelligence/threat_intelligence.py"""

from tests.module_factory import ModuleFactory
import os
import pytest


def test_parse_local_ti_file(mock_db):
    """
    Test parsing of a local threat intelligence file.

    Ensures that the `parse_local_ti_file` method successfully parses known threat
    intelligence entries from "own_malicious_iocs.csv" and properly integrates
    them into the system.

    Args:
        mock_db: A fixture or mock representing the database to prevent actual
                 database modifications during testing.
    """
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    local_ti_files_dir = threatintel.path_to_local_ti_files
    local_ti_file = os.path.join(local_ti_files_dir, "own_malicious_iocs.csv")
    # this is an ip we know we have in own_malicious_iocs.csv
    assert threatintel.parse_local_ti_file(local_ti_file) is True

def test_parse_ja3_file(mock_db):
    """
    Test parsing of a JA3 hash file.

    Validates that the `parse_ja3_file` method can accurately process and store
    entries from "own_malicious_JA3.csv" containing JA3 hashes and associated
    threat levels and descriptions.

    Args:
        mock_db: A mock database object to intercept database calls for isolation.
    """
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    local_ja3_file_dir = threatintel.path_to_local_ti_files
    local_ja3_file = os.path.join(local_ja3_file_dir, "own_malicious_JA3.csv")

    assert threatintel.parse_ja3_file(local_ja3_file) is True

def test_parse_jarm_file(mock_db):
    """
    Test parsing of a JARM hash file.

    Confirms that the `parse_jarm_file` method is capable of interpreting and storing
    data from "own_malicious_JARM.csv", which includes JARM hashes along with their
    threat assessments and descriptions.

    Args:
        mock_db: A mock database object used to verify interactions without affecting
                 real data.
    """
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    local_jarm_file_dir = threatintel.path_to_local_ti_files
    local_jarm_file = os.path.join(local_jarm_file_dir, "own_malicious_JARM.csv")

    assert threatintel.parse_jarm_file(local_jarm_file) is True
                                  

@pytest.mark.parametrize(
    "current_hash, old_hash, expected_return",
    [
        ("111", "222", "111"),
        ("111", "111", False),
        (False, "222", False),
    ],
)
def test_check_local_ti_files_for_update(
    current_hash, old_hash, expected_return, mocker, mock_db
):
    """
    Test the logic for updating local threat intelligence files based on hash comparison.

    This test verifies the `should_update_local_ti_file` method's ability to decide
    whether a local threat intelligence file needs to be updated by comparing its
    current hash against a previously stored hash. The test covers scenarios including
    changed hashes, matching hashes, and errors in retrieving the current hash.

    Args:
        current_hash: The hash value of the current file, simulated for test scenarios.
        old_hash: The previously stored hash value for comparison.
        expected_return: The expected outcome of the comparison (new hash or False).
        mocker: The pytest-mock mocker object for patching dependencies.
        mock_db: A mock database object for simulating database interactions.
    """
    # since this is a clear db, then we should update the local ti file
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    own_malicious_iocs = os.path.join(
        threatintel.path_to_local_ti_files, "own_malicious_iocs.csv"
    )

    mock_hash = mocker.patch(
        "slips_files.common.slips_utils.Utils.get_hash_from_file"
    )
    
    mock_hash.return_value = current_hash

    mock_db.get_TI_file_info.return_value = {"hash": old_hash}

    # the test asserts return value of should_update_local_tii_file matches expected_return for each scenario. This method should return new hash if an update is needed or False if not
    assert (
        threatintel.should_update_local_ti_file(own_malicious_iocs)
        == expected_return
    )
