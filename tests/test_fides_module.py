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

"""
The sqlite database used by and implemented in FidesModule has its own unit tests. You may find them here here: modules/fidesModule/tests/test_sqlite_db.py
"""

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
