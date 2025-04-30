# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from tests.module_factory import ModuleFactory
from unittest.mock import (
    patch,
    MagicMock,
    Mock,
)
import shutil
import os
import json
import signal


@pytest.mark.parametrize(
    "input_type,input_information",
    # the pcaps here must have a conn.log when read by zeek
    [("pcap", "dataset/test7-malicious.pcap")],
)
def test_handle_pcap_and_interface(input_type, input_information):
    # no need to test interfaces because in that case read_zeek_files runs
    # in a loop and never returns
    input = ModuleFactory().create_input_obj(input_information, input_type)
    input.zeek_pid = "False"
    input.is_zeek_tabs = False
    input.start_observer = Mock()
    input.read_zeek_files = Mock()
    input.zeek_thread = Mock()
    with (
        patch.object(input, "get_flows_number", return_value=500),
        patch("time.sleep"),
    ):
        assert input.handle_pcap_and_interface() is True
    input.zeek_thread.start.assert_called_once()
    input.read_zeek_files.assert_called_once()
    input.start_observer.assert_called_once()

    # delete the zeek logs created
    shutil.rmtree(input.zeek_dir)


@pytest.mark.parametrize(
    "zeek_dir, is_tabs",
    [
        ("dataset/test10-mixed-zeek-dir/", False),  # tabs
        ("dataset/test9-mixed-zeek-dir/", True),  # json
    ],
)
def test_read_zeek_folder(zeek_dir: str, is_tabs: bool):
    input = ModuleFactory().create_input_obj(zeek_dir, "zeek_folder")
    input.given_path = zeek_dir
    input.testing = True
    input.is_zeek_tabs = is_tabs
    input.db.get_all_zeek_files.return_value = [
        os.path.join(zeek_dir, "conn.log")
    ]
    input.db.is_growing_zeek_dir.return_value = False
    input.mark_process_as_done_processing = Mock()
    input.mark_process_as_done_processing.return_value = True
    input.start_observer = Mock()
    input.start_observer.return_value = True
    assert input.read_zeek_folder() is True


@pytest.mark.parametrize(
    "path, expected_val",
    [
        ("dataset/test10-mixed-zeek-dir/conn.log", True),  # tabs
        ("dataset/test9-mixed-zeek-dir/conn.log", False),  # json
    ],
)
def test_is_zeek_tabs_file(path: str, expected_val: bool):
    input = ModuleFactory().create_input_obj(path, "zeek_folder")
    assert input.is_zeek_tabs_file(path) == expected_val


@pytest.mark.parametrize(
    "input_information,expected_output",
    [
        ("dataset/test10-mixed-zeek-dir/conn.log", True),  # tabs
        ("dataset/test9-mixed-zeek-dir/conn.log", True),  # json
        ("dataset/test9-mixed-zeek-dir/conn", False),  # json
        ("dataset/test9-mixed-zeek-dir/x509.log", False),  # json
    ],
)
def test_handle_zeek_log_file(input_information, expected_output):
    input = ModuleFactory().create_input_obj(
        input_information, "zeek_log_file"
    )
    assert input.handle_zeek_log_file() == expected_output


@pytest.mark.parametrize(
    "path, is_tabs, line_cached",
    [
        ("dataset/test10-mixed-zeek-dir/conn.log", True, False),
        ("dataset/test9-mixed-zeek-dir/conn.log", False, True),
    ],
)
def test_cache_nxt_line_in_file(path: str, is_tabs: str, line_cached: bool):
    """
    :param line_cached: should slips cache
    the first line of this file or not
    """
    input = ModuleFactory().create_input_obj(path, "zeek_log_file")
    input.cache_lines = {}
    input.file_time = {}
    input.is_zeek_tabs = is_tabs

    assert input.cache_nxt_line_in_file(path) == line_cached
    if line_cached:
        assert input.cache_lines[path]["type"] == path
        assert input.cache_lines[path]["data"]


@pytest.mark.parametrize(
    "path, is_tabs, zeek_line, expected_val",
    [
        (
            "dataset/test10-mixed-zeek-dir/conn.log",
            True,
            "1601998375.703087       ClqdMB11qLHjikB6bd      "
            "2001:718:2:1663:dc58:6d9:ef13:51a5      63580   "
            "2a00:1450:4014:80c::200a443     udp     -       "
            "30.131973       6224    10110   SF      -       -       "
            "0       Dd      14      6896    15     10830    -",
            1601998375.703087,
        ),
        (
            "dataset/test9-mixed-zeek-dir/conn.log",
            False,
            '{"ts":271.102532,"uid":"CsYeNL1xflv3dW9hvb",'
            '"id.orig_h":"10.0.2.15","id.orig_p":59393,'
            '"id.resp_h":"216.58.201.98","id.resp_p":443,'
            '"proto":"udp","duration":0.5936019999999758,'
            '"orig_bytes":5219,"resp_bytes":5685,"conn_state":"SF",'
            '"missed_bytes":0,"history":"Dd","orig_pkts":9,"orig_ip_bytes":5471,'
            '"resp_pkts":10,"resp_ip_bytes":5965}',
            271.102532,
        ),
        (
            "dataset/test9-mixed-zeek-dir/conn.log",
            False,
            '{"ts":"corrupted","uid":"CsYeNL1xflv3dW9hvb",'
            '"id.orig_h":"10.0.2.15","id.orig_p":59393,'
            '"id.resp_h":"216.58.201.98","id.resp_p":443,'
            '"proto":"udp","duration":0.5936019999999758,"orig_bytes":5219,'
            '"resp_bytes":5685,"conn_state":"SF","missed_bytes":0,'
            '"history":"Dd","orig_pkts":9,"orig_ip_bytes":5471,"resp_pkts":10,'
            '"resp_ip_bytes":5965}',
            (False, False),
        ),
    ],
)
def test_get_ts_from_line(
    path: str, is_tabs: str, zeek_line: str, expected_val: float
):
    input = ModuleFactory().create_input_obj(path, "zeek_log_file")
    input.is_zeek_tabs = is_tabs
    input.get_ts_from_line(zeek_line)


@pytest.mark.parametrize(
    "last_updated_file_time, now, bro_timeout, expected_val, ",
    [
        (0, 20, 10, True),
        (0, 10, 10, True),
        (0, 5, 10, False),
        (0, 5, float("inf"), False),
    ],
)
def test_reached_timeout(
    last_updated_file_time, now, bro_timeout, expected_val
):
    input = ModuleFactory().create_input_obj("", "zeek_log_file")
    input.last_updated_file_time = last_updated_file_time
    input.bro_timeout = bro_timeout
    input.cache_lines = False
    with patch("datetime.datetime") as dt:
        dt.now.return_value = now
        assert input.reached_timeout() == expected_val


@pytest.mark.skipif(
    "nfdump" not in shutil.which("nfdump"), reason="nfdump is not installed"
)
@pytest.mark.parametrize("path", ["dataset/test1-normal.nfdump"])
def test_handle_nfdump(path):
    input = ModuleFactory().create_input_obj(path, "nfdump")
    assert input.handle_nfdump() is True


def test_get_earliest_line():
    input = ModuleFactory().create_input_obj("", "zeek_log_file")
    input.file_time = {
        "software.log": 3,
        "ssh.log": 2,
        "notice.log": 1,
        "dhcp.log": 4,
        "arp.log": 5,
        "conn.log": 5,
        "dns.log": 6,
    }
    input.cache_lines = {
        "software.log": "line3",
        "ssh.log": "line2",
        "notice.log": "line1",
        "dhcp.log": "line4",
        "arp.log": "line5",
        "conn.log": "line5",
        "dns.log": "line6",
    }
    assert input.get_earliest_line() == ("line1", "notice.log")


@pytest.mark.parametrize(
    "input_type,input_information",
    [
        ("binetflow", "dataset/test2-malicious.binetflow"),
        ("binetflow", "dataset/test5-mixed.binetflow"),
    ],
)
def test_handle_binetflow(input_type, input_information):
    input = ModuleFactory().create_input_obj(input_information, input_type)
    with patch.object(input, "get_flows_number", return_value=5):
        assert input.handle_binetflow() is True


@pytest.mark.parametrize(
    "input_information",
    ["dataset/test6-malicious.suricata.json"],
)
def test_handle_suricata(input_information):
    input = ModuleFactory().create_input_obj(input_information, "suricata")
    assert input.handle_suricata() is True


@pytest.mark.parametrize(
    "line_type, line",
    [
        (
            "zeek",
            '{"ts":271.102532,"uid":"CsYeNL1xflv3dW9hvb",'
            '"id.orig_h":"10.0.2.15","id.orig_p":59393,'
            '"id.resp_h":"216.58.201.98","id.resp_p":443,'
            '"proto":"udp","duration":0.5936019999999758,'
            '"orig_bytes":5219,"resp_bytes":5685,"conn_state":"SF",'
            '"missed_bytes":0,"history":"Dd",'
            '"orig_pkts":9,"orig_ip_bytes":5471,"resp_pkts":10,'
            '"resp_ip_bytes":5965}',
        ),
        (
            "suricata",
            '{"timestamp":"2021-06-06T15:57:37.272281+0200",'
            '"flow_id":2054715089912378,"event_type":"flow",'
            '"src_ip":"193.46.255.92","src_port":49569,'
            '"dest_ip":"192.168.1.129","dest_port":8014,'
            '"proto":"TCP","flow":{"pkts_toserver":2,"pkts_toclient":2,'
            '"bytes_toserver":120,"bytes_toclient":120,'
            '"start":"2021-06-07T15:45:48.950842+0200",'
            '"end":"2021-06-07T15:45:48.951095+0200",'
            '"age":0,"state":"closed","reason":"shutdown",'
            '"alerted":false},"tcp":{"tcp_flags":"16",'
            '"tcp_flags_ts":"02","tcp_flags_tc":"14","syn":true,'
            '"rst":true,"ack":true,"state":"closed"},"host":"stratosphere.org"}',
        ),
        (
            "argus",
            "2019/04/05 16:15:09.194268,0.031142,udp,10.8.0.69,8278,  "
            "<->,8.8.8.8,53,CON,0,0,2,186,64,1,",
        ),
    ],
)
def test_read_from_stdin(line_type: str, line: str):
    input = ModuleFactory().create_input_obj(
        line_type,
        "stdin",
        line_type=line_type,
    )
    with patch.object(input, "stdin", return_value=[line, "done\n"]):
        assert input.read_from_stdin()
        line_sent: dict = input.profiler_queue.get()
        expected_received_line = (
            json.loads(line) if line_type == "zeek" else line
        )
        assert line_sent["line"]["data"] == expected_received_line
        assert line_sent["line"]["line_type"] == line_type
        assert line_sent["input_type"] == "stdin"


@pytest.mark.parametrize(
    "line, input_type, expected_line, expected_input_type",
    [
        # Testcase 1: Normal Zeek line
        (
            {"type": "zeek", "data": {"ts": 12345, "uid": "abcdef"}},
            "pcap",
            {"type": "zeek", "data": {"ts": 12345, "uid": "abcdef"}},
            "pcap",
        ),
        # Testcase 2: Different line type
        (
            {
                "type": "suricata",
                "data": {
                    "timestamp": "2023-04-19T12:00:00.000000",
                    "flow_id": 12345,
                },
            },
            "suricata",
            {
                "type": "suricata",
                "data": {
                    "timestamp": "2023-04-19T12:00:00.000000",
                    "flow_id": 12345,
                },
            },
            "suricata",
        ),
    ],
)
def test_give_profiler(line, input_type, expected_line, expected_input_type):
    """Test that the give_profiler function correctly sends the given line to
    the profiler queue."""
    input_process = ModuleFactory().create_input_obj("", input_type)
    input_process.total_flows = (
        1000 if expected_line.get("total_flows") else None
    )
    input_process.give_profiler(line)
    line_sent = input_process.profiler_queue.get()
    assert line_sent["line"] == expected_line
    assert line_sent["input_type"] == expected_input_type


def test_get_file_handle_existing_file():
    """
    Test that the get_file_handle method correctly
    returns the file handle for an existing file.
    """
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    filename = "test_file.log"
    with open(filename, "w") as f:
        f.write("test content")

    file_handle = input_process.get_file_handle(filename)

    assert file_handle is not False
    assert file_handle.name == filename
    os.remove(filename)


def test_shutdown_gracefully_all_components_active():
    """
    Test shutdown_gracefully when all components (open files, zeek, remover thread) are active.
    """
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    input_process.stop_observer = MagicMock(return_value=True)
    input_process.stop_queues = MagicMock(return_value=True)
    input_process.remover_thread = MagicMock()
    input_process.remover_thread.start()
    input_process.zeek_thread = MagicMock()
    input_process.zeek_thread.start()
    input_process.open_file_handlers = {"test_file.log": MagicMock()}
    input_process.zeek_pid = 123

    with patch("os.kill") as mock_kill:
        assert input_process.shutdown_gracefully()
        mock_kill.assert_called_with(input_process.zeek_pid, signal.SIGKILL)
    assert input_process.open_file_handlers["test_file.log"].close.called


def test_shutdown_gracefully_no_open_files():
    """
    Test shutdown_gracefully when there are no open files.
    """
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    input_process.stop_observer = MagicMock(return_value=True)
    input_process.stop_queues = MagicMock(return_value=True)
    input_process.remover_thread = MagicMock()
    input_process.remover_thread.start()
    input_process.zeek_thread = MagicMock()
    input_process.zeek_thread.start()
    input_process.open_file_handlers = {}
    input_process.zeek_pid = os.getpid()

    with patch("os.kill") as mock_kill:
        assert input_process.shutdown_gracefully() is True
        mock_kill.assert_called_once_with(
            input_process.zeek_pid, signal.SIGKILL
        )


def test_shutdown_gracefully_zeek_not_running():
    """
    Test shutdown_gracefully when Zeek is not running.
    """
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    input_process.stop_observer = MagicMock(return_value=True)
    input_process.stop_queues = MagicMock(return_value=True)
    input_process.remover_thread = MagicMock()
    input_process.remover_thread.start()
    input_process.open_file_handlers = {"test_file.log": MagicMock()}
    input_process.zeek_pid = os.getpid()

    with patch("os.kill") as mock_kill:
        assert input_process.shutdown_gracefully() is True
        mock_kill.assert_called_once_with(
            input_process.zeek_pid, signal.SIGKILL
        )
    assert input_process.open_file_handlers["test_file.log"].close.called


def test_shutdown_gracefully_remover_thread_not_running():
    """
    Test shutdown_gracefully when the remover thread is not running.
    """
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    input_process.stop_observer = MagicMock(return_value=True)
    input_process.stop_queues = MagicMock(return_value=True)
    input_process.zeek_thread = MagicMock()
    input_process.zeek_thread.start()
    input_process.open_file_handlers = {"test_file.log": MagicMock()}
    input_process.zeek_pid = os.getpid()

    with patch("os.kill") as mock_kill:
        assert input_process.shutdown_gracefully() is True
        mock_kill.assert_called_once_with(
            input_process.zeek_pid, signal.SIGKILL
        )
    assert input_process.open_file_handlers["test_file.log"].close.called


def test_close_all_handles():
    """Test that the close_all_handles method closes all open file handles."""
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    mock_handle1 = MagicMock()
    mock_handle2 = MagicMock()
    input_process.open_file_handlers = {
        "file1": mock_handle1,
        "file2": mock_handle2,
    }

    input_process.close_all_handles()

    mock_handle1.close.assert_called_once()
    mock_handle2.close.assert_called_once()


def test_shutdown_gracefully_no_zeek_pid():
    """
    Test shutdown_gracefully when the Zeek PID is not set.
    """
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    input_process.stop_observer = MagicMock(return_value=True)
    input_process.stop_queues = MagicMock(return_value=True)
    input_process.remover_thread = MagicMock()
    input_process.remover_thread.start()
    input_process.zeek_thread = MagicMock()
    input_process.zeek_thread.start()
    input_process.open_file_handlers = {"test_file.log": MagicMock()}

    with patch("os.kill") as mock_kill:
        assert input_process.shutdown_gracefully() is True
        mock_kill.assert_not_called()
    assert input_process.open_file_handlers["test_file.log"].close.called


def test_get_file_handle_non_existing_file():
    """
    Test that the get_file_handle method returns False for a non-existing file.
    """
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    filename = "non_existing_file.log"
    file_handle = input_process.get_file_handle(filename)
    assert file_handle is False


@pytest.mark.parametrize(
    "data, expected_chunks",
    [  # Testcase 1: String length is multiple of chunk size
        (b"This is a test string.", [b"This is a", b" test str", b"ing."]),
        # Testcase 2: String length is less than chunk size
        (b"Hello", [b"Hello"]),
        # Testcase 3: String length is more than chunk size
        (
            b"This is a longer string that exceeds the chunk size.",
            [
                b"This is a longer ",
                b"string that exceed",
                b"s the chunk size.",
            ],
        ),
    ],
)
def test__make_gen(data, expected_chunks):
    """
    Test that the _make_gen function yields chunks of data from a file.
    """
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    reader = MagicMock(side_effect=[*expected_chunks, b""])
    gen = input_process._make_gen(reader)
    for expected_chunk in expected_chunks:
        assert next(gen) == expected_chunk
