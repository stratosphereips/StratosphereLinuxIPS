# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import shutil
from unittest.mock import patch, mock_open, Mock, call
import os
import redis
import pytest

import slips_files
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "redis_port, redis_pid, is_daemon, " "save_db, expected_output",
    [
        # Testcase 1: Normal case
        (
            32768,
            1234,
            False,
            False,
            "Date,input_info,32768,1234,zeek_dir,"
            "output_dir,os_pid,False,False\n",
        ),
        # Testcase 2: Daemon mode
        (
            32769,
            9101,
            True,
            False,
            "Date,input_info,32769,9101,zeek_dir,"
            "output_dir,os_pid,True,False\n",
        ),
        # Testcase 3: Save DB
        (
            32770,
            1122,
            False,
            True,
            "Date,input_info,32770,1122,zeek_dir,"
            "output_dir,os_pid,False,True\n",
        ),
    ],
)
def test_log_redis_server_pid_normal_ports(
    redis_port, redis_pid, is_daemon, save_db, expected_output, mock_db
):
    redis_manager = ModuleFactory().create_redis_manager_obj()
    redis_manager.main.input_information = "input_info"
    redis_manager.main.zeek_dir = "zeek_dir"
    redis_manager.main.args.output = "output_dir"
    redis_manager.main.args.daemon = is_daemon
    redis_manager.main.args.save = save_db
    redis_manager.remove_old_logline = Mock()
    slips_files.common.slips_utils.utils.convert_format = Mock(
        return_value="Date"
    )

    with (
        patch("builtins.open", mock_open()) as mock_file,
        patch("os.getpid", return_value="os_pid"),
    ):
        redis_manager.log_redis_server_pid(redis_port, redis_pid)
        mock_file().write.assert_called_with(expected_output)
        redis_manager.remove_old_logline.assert_not_called()


@pytest.mark.parametrize(
    "redis_port, redis_pid, db_path",
    [
        # Testcase 1: Normal case
        (32850, 1234, "/path/to/db1.rdb"),
        # Testcase 2: Different port and PID
        (32851, 5678, "/path/to/db2.rdb"),
        # Testcase 3: Another variation
        (32852, 9101, "/path/to/db3.rdb"),
    ],
)
def test_load_redis_db(redis_port, redis_pid, db_path, mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()
    redis_manager.main.args.db = db_path

    with (
        patch.object(
            redis_manager, "get_pid_of_redis_server", return_value=redis_pid
        ) as mock_get_pid,
        patch.object(redis_manager, "log_redis_server_pid") as mock_log,
        patch.object(redis_manager, "remove_old_logline") as mock_remove,
        patch("builtins.print") as mock_print,
    ):
        redis_manager.load_redis_db(redis_port)

        assert redis_manager.main.input_information == os.path.basename(
            db_path
        )
        assert redis_manager.zeek_folder == '""'
        mock_get_pid.assert_called_once_with(redis_port)
        mock_log.assert_called_once_with(redis_port, redis_pid)
        mock_remove.assert_called_once_with(redis_port)
        mock_print.assert_called_once_with(
            f"{db_path} loaded successfully.\n"
            f"Run ./kalipso.sh and choose port {redis_port}"
        )


def test_load_db_success(mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()
    redis_manager.main.args.db = "/path/to/db.rdb"
    redis_manager.main.db.init_redis_server = Mock()
    redis_manager.main.db.load = Mock(return_value=True)
    redis_manager.main.terminate_slips = Mock()

    with (
        patch.object(
            redis_manager, "get_pid_of_redis_server", return_value=1234
        ) as mock_get_pid,
        patch.object(redis_manager, "flush_redis_server") as mock_flush,
        patch.object(redis_manager, "kill_redis_server") as mock_kill,
        patch.object(redis_manager, "load_redis_db") as mock_load_redis_db,
    ):
        redis_manager.load_db()

        assert redis_manager.input_type == "database"
        redis_manager.main.db.init_redis_server.assert_called_once()
        mock_get_pid.assert_called_once_with(32850)
        mock_flush.assert_called_once_with(pid=1234)
        mock_kill.assert_called_once_with(1234)
        redis_manager.main.db.load.assert_called_once_with("/path/to/db.rdb")
        mock_load_redis_db.assert_called_once_with(32850)
        redis_manager.main.terminate_slips.assert_called_once()


def test_load_db_failure(mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()
    rdb_path = "/path/to/db.rdb"
    redis_manager.main.args.db = rdb_path
    redis_manager.main.db.init_redis_server = Mock()
    redis_manager.main.db.load = Mock(return_value=False)
    redis_manager.main.terminate_slips = Mock()

    with (
        patch.object(
            redis_manager, "get_pid_of_redis_server", return_value=1234
        ) as mock_get_pid,
        patch.object(redis_manager, "flush_redis_server") as mock_flush,
        patch.object(redis_manager, "kill_redis_server") as mock_kill,
        patch.object(redis_manager, "load_redis_db") as mock_load_redis_db,
        patch("builtins.print") as mock_print,
    ):
        redis_manager.load_db()

        assert redis_manager.input_type == "database"
        redis_manager.main.db.init_redis_server.assert_called_once()
        mock_get_pid.assert_called_once_with(32850)
        mock_flush.assert_called_once_with(pid=1234)
        mock_kill.assert_called_once_with(1234)
        redis_manager.main.db.load.assert_called_once_with(rdb_path)
        mock_print.assert_called_once_with(
            f"Error loading the database {rdb_path}"
        )
        redis_manager.main.terminate_slips.assert_called_once()
        mock_load_redis_db.assert_not_called()


@pytest.mark.parametrize(
    "ping_side_effect, expected_system_calls, expected_result",
    [
        # Testcase1: Redis server is already running
        ([None], 0, True),
        # Testcase2: Redis server needs to be started once
        ([redis.exceptions.ConnectionError, None], 1, True),
        # Testcase3: Redis server needs to be started twice
        (
            [
                redis.exceptions.ConnectionError,
                redis.exceptions.ConnectionError,
                None,
            ],
            2,
            True,
        ),
    ],
)
def test_check_redis_database(
    ping_side_effect, expected_system_calls, expected_result, mock_db
):
    redis_manager = ModuleFactory().create_redis_manager_obj()
    mock_redis = Mock()
    mock_redis.ping.side_effect = ping_side_effect

    with (
        patch("redis.StrictRedis", return_value=mock_redis),
        patch("os.system") as mock_system,
        patch("time.sleep") as mock_sleep,
    ):
        result = redis_manager.check_redis_database()

        assert result == expected_result
        assert mock_redis.ping.call_count == len(ping_side_effect)
        assert mock_system.call_count == expected_system_calls
        assert mock_sleep.call_count == expected_system_calls


def test_check_redis_database_failure(mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    mock_redis = Mock()
    mock_redis.ping.side_effect = redis.exceptions.ConnectionError

    with (
        patch("redis.StrictRedis", return_value=mock_redis),
        patch("os.system") as mock_system,
        patch("time.sleep") as mock_sleep,
        patch.object(redis_manager.main, "terminate_slips") as mock_terminate,
    ):
        result = redis_manager.check_redis_database()

        expected_result = False
        assert result == expected_result
        assert mock_redis.ping.call_count == 3
        assert mock_system.call_count == 2
        assert mock_sleep.call_count == 2
        mock_terminate.assert_called_once()


def test_get_random_redis_port_first_available(mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    mock_socket = Mock()
    mock_socket.bind.return_value = None

    with patch("socket.socket", return_value=mock_socket):
        result = redis_manager.get_random_redis_port()

        assert result == redis_manager.start_port
        mock_socket.bind.assert_called_once_with(("localhost", 32768))
        mock_socket.close.assert_called_once()


def test_get_random_redis_port_some_in_use(mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    mock_socket = Mock()
    mock_socket.bind.side_effect = [OSError] * 32 + [None]

    with patch("socket.socket", return_value=mock_socket):
        result = redis_manager.get_random_redis_port()
        assert result == redis_manager.start_port + 32
        assert mock_socket.bind.call_count == 33
        assert mock_socket.close.call_count == 33


def test_get_random_redis_port_all_in_use(mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    mock_socket = Mock()
    mock_socket.bind.side_effect = OSError

    with (
        patch("socket.socket", return_value=mock_socket),
        patch("builtins.print") as mock_print,
    ):
        result = redis_manager.get_random_redis_port()

        expected_result = False
        assert result == expected_result
        assert mock_socket.bind.call_count == 83
        assert mock_socket.close.call_count == 83
        mock_print.assert_called_once_with(
            f"All ports from {redis_manager.start_port} to "
            f"{redis_manager.end_port} are used. "
            "Unable to start slips.\n"
        )


def test_clear_redis_cache_database(mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    with patch("redis.StrictRedis") as mock_redis:
        mock_redis_instance = Mock()
        mock_redis.return_value = mock_redis_instance
        result = redis_manager.clear_redis_cache_database()
        mock_redis.assert_called_once_with(
            host="localhost",
            port=6379,
            db=1,
            charset="utf-8",
            decode_responses=True,
        )
        mock_redis_instance.flushdb.assert_called_once()
        assert result


@pytest.mark.parametrize(
    "port",
    [
        # Testcase 1: Using the starting port of slips range
        32768,
        # Testcase 2: Another port within slips range
        32769,
        # Testcase 3: One more port for good measure
        32770,
    ],
)
def test_print_port_in_use(port, mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    with patch("builtins.print") as mock_print:
        redis_manager.print_port_in_use(port)

        expected_output = (
            f"[Main] Port {port} is already in use by another process\n"
            f"Choose another port using -P <portnumber>\n"
            f"Or kill your open redis ports using: ./slips.py -k "
        )
        mock_print.assert_called_once_with(expected_output)


@pytest.mark.parametrize(
    "port, cmd_output, expected_pid",
    [
        # Testcase 1: PID found for port 32768
        (32768, b"user 1234 ... redis-server *:32768\n", 1234),
        # Testcase 2: PID found for port 32769
        (32769, b"user 5678 ... redis-server *:32769\n", 5678),
        # Testcase 3: PID found for port 6379
        (6379, b"user 9101 ... redis-server *:6379\n", 9101),
        # Testcase 4: PID not found for port 32770
        (32770, b"user 1234 ... redis-server *:32768\n", False),
    ],
)
def test_get_pid_of_redis_server(port, cmd_output, expected_pid, mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    with patch("subprocess.Popen") as mock_popen:
        mock_popen.return_value.communicate.return_value = (cmd_output, None)
        result = redis_manager.get_pid_of_redis_server(port)
        assert result == expected_pid


@pytest.mark.parametrize(
    "redis_port, file_content, expected_output",
    [
        # Testcase 1: Remove duplicate port, keeping last
        (
            6379,
            "line1\nline2,6379\nline3\nline4,6379\n",
            "line1\nline3\nline4,6379\n",
        ),
        # Testcase 2: Remove all occurrences of port
        (32768, "line1,32768\nline2\nline3,32768\nline4\n", "line2\nline4\n"),
    ],
)
def test_remove_old_logline(
    redis_port, file_content, expected_output, mock_db
):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    mock_file = mock_open(read_data=file_content)
    with (
        patch("builtins.open", mock_file) as mocked_open,
        patch("os.replace") as mock_replace,
    ):
        redis_manager.remove_old_logline(redis_port)

        mocked_open.assert_any_call(redis_manager.running_logfile, "r")
        mocked_open.assert_any_call("tmp_running_slips_log.txt", "w")
        written_handle = mocked_open.return_value.__enter__.return_value
        write_calls = written_handle.write.call_args_list
        expected_calls = [
            call(line + "\n") for line in expected_output.strip().split("\n")
        ]
        assert write_calls == expected_calls, (
            f"Expected calls: {expected_calls}, "
            f"Actual calls: {write_calls}"
        )
        mock_replace.assert_called_once_with(
            "tmp_running_slips_log.txt", redis_manager.running_logfile
        )


@pytest.mark.parametrize(
    "redis_port, file_content, expected_output",
    [
        # Testcase 1: Remove port 6379
        (6379, "line1\nline2,6379\nline3\nline4,6379\n", "line1\nline3\n"),
        # Testcase 2: Remove port 32768
        (32768, "line1,32768\nline2\nline3,32768\nline4\n", "line2\nline4\n"),
    ],
)
def test_remove_server_from_log(
    redis_port, file_content, expected_output, mock_db
):
    redis_manager = ModuleFactory().create_redis_manager_obj()
    shutil.move = Mock()

    with patch(
        "builtins.open", mock_open(read_data=file_content)
    ) as mock_file:
        redis_manager.remove_server_from_log(redis_port)

        mock_file().write.assert_has_calls(
            [call(line + "\n") for line in expected_output.strip().split("\n")]
        )
        shutil.move.assert_called_once_with(
            "tmp_running_slips_log.txt", redis_manager.running_logfile
        )


@pytest.mark.parametrize(
    "file_content, expected_output",
    [
        # Testcase 1: Normal case with multiple servers
        (
            "Date, File or interface, Used port, Server PID, Output Zeek Dir, "
            "Logs Dir, Slips PID, Is Daemon, Save the DB"
            "\n2024/11/25 15:11:50.571184,dataset/test6-malicious.suricata.json,"
            "32768,16408,dir/zeek_files,dir,16398,False,False",
            {
                "16408": {
                    "file_or_interface": "dataset/test6-malicious.suricata.json",
                    "is_daemon": "False",
                    "output_dir": "dir",
                    "pid": "16408",
                    "port": "32768",
                    "save_the_db": "False",
                    "slips_pid": "16398",
                    "timestamp": "2024/11/25 15:11:50.571184",
                    "zeek_dir": "dir/zeek_files",
                },
            },
        ),
        # Testcase 2: Empty file
        ("", {}),
        # Testcase 3: File with invalid data
        (
            "# Comment\nDate,File,Port,PID\n2024-01-01,file1,"
            "invalid,1000\n2024-01-02,file2,32769,invalid\n",
            {},
        ),
    ],
)
def test_get_open_redis_servers(file_content, expected_output, mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    with patch("builtins.open", mock_open(read_data=file_content)):
        result = redis_manager.get_open_redis_servers()
        assert result == expected_output
        assert redis_manager.open_servers_pids == expected_output


@pytest.mark.parametrize(
    "file_content, expected_output, expected_return",
    [
        # Testcase 1: Normal case with multiple servers
        (
            "# Comment\nDate,File,Port,PID\n2024-01-01,file1,"
            "32768,1000\n2024-01-02,file2,32769,2000\n",
            "Choose which one to kill [0,1,2 etc..]\n[0] Close all "
            "Redis servers\n[1] file1 - port 32768\n[2] file2 - port 32769\n",
            {1: (32768, 1000), 2: (32769, 2000)},
        ),
        # Testcase 2: Empty file
        ("", "No open redis servers in running_slips_info.txt", {}),
    ],
)
def test_print_open_redis_servers(
    file_content, expected_output, expected_return, mock_db
):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    with (
        patch("builtins.open", mock_open(read_data=file_content)),
        patch("builtins.print") as mock_print,
    ):
        result = redis_manager.print_open_redis_servers()

        mock_print.assert_called_once_with(expected_output)
        assert result == expected_return


@pytest.mark.parametrize(
    "cmd_output, pid, expected_port",
    [
        # Testcase 1: Normal case
        (
            b"user 1000 1.0 0.5 redis-server *:6379\nuser "
            b"2000 1.0 0.5 redis-server *:32768\n",
            2000,
            32768,
        ),
        # Testcase 2: PID not found
        (b"user 1000 1.0 0.5 redis-server *:6379\n", 2000, False),
        # Testcase 3: Invalid port format
        (b"user 2000 1.0 0.5 redis-server *:invalid\n", 2000, False),
    ],
)
def test_get_port_of_redis_server(cmd_output, pid, expected_port, mock_db):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    with patch("subprocess.Popen") as mock_popen:
        mock_popen.return_value.communicate.return_value = (cmd_output, None)
        result = redis_manager.get_port_of_redis_server(pid)
        assert result == expected_port


@pytest.mark.parametrize(
    "pid, os_kill_side_effect, " "expected_result, expected_calls",
    [
        # Testcase 1: Process killed successfully after one try
        (
            1234,
            [None, ProcessLookupError],
            True,
            [call(1234, 0), call(1234, 9)],
        ),
        # Testcase 2: Process already killed
        (5678, [ProcessLookupError], True, [call(5678, 0)]),
        # Testcase 3: Permission error while killing
        (9101, [PermissionError], False, [call(9101, 0)]),
    ],
)
def test_kill_redis_server(
    pid, os_kill_side_effect, expected_result, expected_calls, mock_db
):
    redis_manager = ModuleFactory().create_redis_manager_obj()

    with patch("os.kill", side_effect=os_kill_side_effect) as mock_kill:
        result = redis_manager.kill_redis_server(pid)

        assert result == expected_result
        mock_kill.assert_has_calls(expected_calls)
