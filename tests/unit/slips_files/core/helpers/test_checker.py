# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
from unittest import mock
import psutil
import pytest
from unittest.mock import patch
from tests.module_factory import ModuleFactory


def test_clear_redis_cache():
    checker = ModuleFactory().create_checker_obj()
    checker.clear_redis_cache()
    checker.main.redis_man.clear_redis_cache_database.assert_called_once()
    assert checker.main.input_information == ""
    assert checker.main.zeek_dir == ""
    checker.main.redis_man.log_redis_server_pid.assert_called_once_with(
        6379, mock.ANY
    )
    checker.main.terminate_slips.assert_called_once()


@pytest.mark.parametrize(
    "args, expected_calls",
    [
        # Test case 1: Help flag
        ({"help": True}, ["print_version", "terminate_slips"]),
        # Test case 2: Interface and filepath flags
        (
            {"interface": "eth0", "filepath": "/path/to/file"},
            ["terminate_slips"],
        ),
        # Test case 3: Interface/filepath with input_module
        ({"interface": "eth0", "input_module": "module"}, ["terminate_slips"]),
        # Test case 4: Save/db flag without root privileges
        ({"save": True}, ["terminate_slips"]),
        # Test case 5: Invalid verbose/debug value
        ({"verbose": "4"}, ["terminate_slips"]),
        # Test case 6: Redis not running
        ({}, ["terminate_slips"]),
        # Test case 7: Invalid config file
        ({"config": "/nonexistent/path"}, ["terminate_slips"]),
        # Test case 8: Invalid interface
        ({"interface": "nonexistent0"}, ["terminate_slips"]),
        # Test case 9: Invalid input module
        ({"input_module": "nonexistent_module"}, ["terminate_slips"]),
        # Test case 10: Blocking without interface
        ({"blocking": True}, ["terminate_slips"]),
        # Test case 11: Version flag
        ({"version": True}, ["print_version", "terminate_slips"]),
        # Test case 12: Blocking with interface but not root
        ({"interface": "eth0", "blocking": True}, ["terminate_slips"]),
        # Test case 13: Clear blocking without root
        ({"clearblocking": True}, ["terminate_slips"]),
        # Test case 14: Save and load DB simultaneously
        ({"save": True, "db": True}, ["terminate_slips"]),
    ],
)
def test_check_given_flags(args, expected_calls, monkeypatch):

    checker = ModuleFactory().create_checker_obj()
    checker.main.terminate_slips.reset_mock()
    checker.main.print_version.reset_mock()

    for arg, value in args.items():
        setattr(checker.main.args, arg, value)

    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os.path, "exists", lambda x: False)
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {"eth0": None})
    checker.main.redis_man.check_redis_database.return_value = False
    checker.input_module_exists = mock.MagicMock(return_value=False)

    checker.check_given_flags()

    for method_name in expected_calls:
        method = getattr(checker.main, method_name)
        assert (
            method.called
        ), f"Expected '{method_name}' to be called, but it was not."


def test_check_given_flags_root_user(monkeypatch):
    checker = ModuleFactory().create_checker_obj()
    checker.main.args.clearblocking = True
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    with mock.patch.object(checker, "delete_blocking_chain") as mock_delete:
        checker.check_given_flags()
        mock_delete.assert_called_once()
        checker.main.terminate_slips.assert_called()


def test_check_input_type_interface():

    checker = ModuleFactory().create_checker_obj()
    checker.main.args.interface = "eth0"
    checker.main.args.filepath = None
    checker.main.args.db = None
    checker.main.args.input_module = None

    result = checker.check_input_type()
    assert result == ("interface", "eth0", False)


def test_check_input_type_db():

    checker = ModuleFactory().create_checker_obj()
    checker.main.args.interface = None
    checker.main.args.filepath = None
    checker.main.args.db = True
    checker.main.args.input_module = None

    checker.main.redis_man.load_db = mock.MagicMock()

    result = checker.check_input_type()
    assert result is None
    checker.main.redis_man.load_db.assert_called_once()


def test_check_input_type_input_module():

    checker = ModuleFactory().create_checker_obj()
    checker.main.args.interface = None
    checker.main.args.filepath = None
    checker.main.args.db = None
    checker.main.args.input_module = "zeek"

    result = checker.check_input_type()
    assert result == ("zeek", "input_module", "zeek")


@pytest.mark.parametrize(
    "filepath, is_file, is_dir, expected_result",
    [
        # Test case 1: Filepath input (file)
        ("/path/to/file", True, False, ("mock_type", "/path/to/file", False)),
        # Test case 2: Filepath input (directory)
        ("/path/to/dir", False, True, ("mock_type", "/path/to/dir", False)),
    ],
)
def test_check_input_type_filepath(filepath, is_file, is_dir, expected_result):
    checker = ModuleFactory().create_checker_obj()
    checker.main.args.interface = None
    checker.main.args.filepath = filepath
    checker.main.args.db = None
    checker.main.args.input_module = None

    with mock.patch("os.path.isfile", return_value=is_file), mock.patch(
        "os.path.isdir", return_value=is_dir
    ), mock.patch.object(
        checker.main, "get_input_file_type", return_value="mock_type"
    ):

        result = checker.check_input_type()
        assert result == expected_result


def test_check_input_type_stdin():

    checker = ModuleFactory().create_checker_obj()
    checker.main.args.interface = None
    checker.main.args.filepath = "stdin-type"
    checker.main.args.db = None
    checker.main.args.input_module = None

    with mock.patch("os.path.isfile", return_value=False), mock.patch(
        "os.path.isdir", return_value=False
    ), mock.patch.object(
        checker.main,
        "handle_flows_from_stdin",
        return_value=("mock_type", "mock_line_type"),
    ):

        result = checker.check_input_type()
        assert result == ("mock_type", "stdin-type", "mock_line_type")


def test_check_input_type_no_input():

    checker = ModuleFactory().create_checker_obj()
    checker.main.args.interface = None
    checker.main.args.filepath = None
    checker.main.args.db = None
    checker.main.args.input_module = None

    with pytest.raises(SystemExit) as excinfo:
        checker.check_input_type()

    assert excinfo.value.code == -1


@pytest.mark.parametrize(
    "module_name, available_modules, module_dir_content, expected_result",
    [
        # Test case 1: Module exists and is correctly structured
        ("valid_module", ["valid_module"], ["valid_module.py"], True),
        # Test case 2: Module directory doesn't exist
        ("nonexistent_module", ["other_module"], [], False),
        # Test case 3: Module directory exists but .py file is missing
        (
            "incomplete_module",
            ["incomplete_module"],
            ["other_file.txt"],
            False,
        ),
    ],
)
def test_input_module_exists(
    module_name, available_modules, module_dir_content, expected_result
):
    checker = ModuleFactory().create_checker_obj()
    with patch("os.listdir") as mock_listdir:
        mock_listdir.side_effect = [available_modules, module_dir_content]
        result = checker.input_module_exists(module_name)
        assert result == expected_result
