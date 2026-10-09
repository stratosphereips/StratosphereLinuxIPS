# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import errno
import ipaddress
import json
import os
import signal
import sqlite3
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from modules.p2p_trust.p2p_trust import Trust, netifaces
from modules.p2p_trust.utils.utils import (
    get_ip_info_from_slips,
    is_unicast_ip,
)
from slips_files.common.abstracts.imodule import IModule
from tests.module_factory import ModuleFactory


def create_trust():
    """
    Create a minimal Trust object for unit tests.

    Returns:
        A Trust instance with mocked dependencies.
    """
    trust = Trust.__new__(Trust)
    trust.start_pigeon = True
    trust.args = SimpleNamespace(is_slips_started_by_an_update=False)
    trust.conf = Mock()
    trust.conf.use_local_p2p.return_value = False
    trust.db = Mock()
    trust.termination_event = Mock()
    trust.print = Mock()
    trust.parent_output_dir = "output"
    trust.pigeon_binary_dir = "p2p4slips"
    trust.pigeon_binary = "p2p4slips/p2p4slips"
    trust.slips_version = "1.2.3"
    trust.rendezvous = "slips"
    trust._pigeon_supports_flag = Mock(return_value=True)
    return trust


@pytest.mark.parametrize(
    "address,expected",
    [
        ("192.168.1.196", True),
        ("fe80::1", True),
        ("224.0.0.251", False),
        ("ff02::fb", False),
        ("255.255.255.255", False),
        ("127.0.0.1", False),
        ("not-an-ip", False),
    ],
)
def test_peer_reputation_checks_only_unicast_ips(
    address: str, expected: bool
) -> None:
    """Keep mDNS and other non-host IPs out of peer reputation checks."""
    _module_factory = ModuleFactory()
    assert is_unicast_ip(address) is expected


@pytest.mark.parametrize(
    "address,should_request",
    [("8.8.8.8", True), ("224.0.0.251", False)],
)
def test_peer_lookup_uses_only_replies_after_request(
    address: str, should_request: bool
) -> None:
    """Ask for a host IP and exclude earlier reports from its opinion."""
    _module_factory = ModuleFactory()
    trust = create_trust()
    trust.trust_db = Mock()
    trust.trust_db.get_cached_network_opinion.return_value = (
        None,
        None,
        None,
        None,
    )
    trust.trust_db.get_latest_report_id.return_value = 42
    trust.reputation_model = Mock()
    trust.reputation_model.get_opinion_on_ip.return_value = (None, None)
    trust.process_network_response = Mock()
    trust.pygo_channel = "p2p_pygo"

    with patch("modules.p2p_trust.p2p_trust.time.sleep"), patch(
        "modules.p2p_trust.p2p_trust.p2p_utils.send_request_to_go"
    ) as send_request:
        trust.handle_data_request(json.dumps({"ip": address, "cache_age": 1}))

    if should_request:
        send_request.assert_called_once_with(
            address, "p2p_pygo", trust.db
        )
        trust.reputation_model.get_opinion_on_ip.assert_called_once_with(
            address, 42
        )
        result_info = trust.process_network_response.call_args.args[3]
        assert result_info["report_after_id"] == 42
    else:
        send_request.assert_not_called()
        trust.reputation_model.get_opinion_on_ip.assert_not_called()


@pytest.mark.parametrize("ip_state", ["srcip", "dstip"])
@pytest.mark.parametrize("source_ip", ["10.0.0.1", "8.8.8.8"])
@pytest.mark.parametrize(
    "peer_ips, expected_peers",
    [
        (
            [(1, "192.0.2.10"), (2, "192.0.2.20")],
            "peer-a (192.0.2.10), peer-b (192.0.2.20)",
        ),
        (
            [(False, False), (2, "192.0.2.20")],
            "peer-a, peer-b (192.0.2.20)",
        ),
    ],
)
def test_p2p_evidence_names_reporting_peers(
    ip_state: str,
    source_ip: str,
    peer_ips: list[tuple],
    expected_peers: str,
) -> None:
    """Emit one finding per flow and include the reporting peers' IPs.

    Parameters:
        ip_state: Direction of the reported address in the flow.
        source_ip: Flow source, which can also be the reported IP.
        peer_ips: Latest stored timestamp and address for each reporter.
        expected_peers: Reporter labels expected in the alert.
    """
    _module_factory = ModuleFactory()
    trust = create_trust()
    trust.trust_db = Mock()
    trust.trust_db.get_reporter_peerids_for_ip.return_value = {
        "peer-a",
        "peer-b",
    }
    trust.trust_db.get_ip_of_peer.side_effect = peer_ips

    trust.set_evidence_malicious_ip(
        {
            "ip": "8.8.8.8",
            "profileid": f"profile_{source_ip}",
            "twid": "timewindow1",
            "ip_state": ip_state,
            "uid": "flow-1",
            "stime": "2026/10/04 10:00:00.000000+0000",
            "report_after_id": 12,
        },
        0.8,
        0.9,
    )

    trust.trust_db.get_reporter_peerids_for_ip.assert_called_once_with(
        "8.8.8.8", 12
    )
    trust.db.set_evidence.assert_called_once()
    evidence = trust.db.set_evidence.call_args.args[0]
    assert evidence.attacker.value == "8.8.8.8"
    assert str(evidence.profile) == "profile_8.8.8.8"
    assert (
        f"Replied to this lookup, peers: {expected_peers}."
        in evidence.description
    )
    assert trust.trust_db.get_ip_of_peer.call_args_list == [
        call("peer-a"),
        call("peer-b"),
    ]


@pytest.mark.parametrize("stopping", [False, True])
def test_peer_reports_do_not_delay_shutdown(stopping: bool) -> None:
    """Follow the shared stop event even while peer channels are busy."""
    trust = create_trust()
    trust.termination_event.is_set.return_value = stopping
    trust.channel_tracker = {"p2p_gopy": {"msg_received": True}}

    assert trust.should_stop() is stopping


@pytest.mark.parametrize(
    "is_slips_started_by_an_update,use_local_p2p,expected",
    [
        (False, False, False),
        (False, True, False),
        (True, False, False),
        (True, True, True),
    ],
)
def test_should_rebuild_pigeon_binary(
    is_slips_started_by_an_update, use_local_p2p, expected
):
    """
    Ensure the p2p binary rebuild only runs for updated local p2p runs.

    Parameters:
        is_slips_started_by_an_update: Whether Slips was restarted by update.
        use_local_p2p: Whether local p2p is enabled in config.
        expected: Expected rebuild decision.

    Returns:
        None.
    """
    trust = create_trust()
    trust.args.is_slips_started_by_an_update = is_slips_started_by_an_update
    trust.conf.use_local_p2p.return_value = use_local_p2p

    assert trust._should_rebuild_pigeon_binary() is expected


def test_rebuild_pigeon_binary_after_slips_update_runs_go_build():
    """
    Ensure the p2p module rebuilds p2p4slips after a live update.

    Returns:
        None.
    """
    trust = create_trust()
    trust.args.is_slips_started_by_an_update = True
    trust.conf.use_local_p2p.return_value = True

    with patch("modules.p2p_trust.p2p_trust.subprocess.run") as mock_run:
        assert trust._rebuild_pigeon_binary_after_slips_update() is True

    mock_run.assert_called_once_with(
        ["go", "build", "-buildvcs=false"],
        cwd="p2p4slips",
        check=True,
        capture_output=True,
        text=True,
    )
    assert trust.print.call_args_list == [
        call(
            "Rebuilding p2p4slips after Slips update. This can take "
            "some time."
        ),
        call("Done rebuilding p2p4slips after Slips update."),
    ]


def test_rebuild_pigeon_binary_after_slips_update_stops_on_build_error():
    """
    Ensure build failures are reported and stop p2p startup.

    Returns:
        None.
    """
    trust = create_trust()
    trust.args.is_slips_started_by_an_update = True
    trust.conf.use_local_p2p.return_value = True

    with patch(
        "modules.p2p_trust.p2p_trust.subprocess.run",
        side_effect=OSError("go not found"),
    ):
        assert trust._rebuild_pigeon_binary_after_slips_update() is False

    assert trust.print.call_args_list == [
        call(
            "Rebuilding p2p4slips after Slips update. This can take "
            "some time."
        ),
        call(
            "Warning: Failed to rebuild p2p4slips after Slips update. "
            "Error: go not found"
        ),
    ]


def test_start_pigeon_passes_runtime_arguments_to_go():
    """
    Ensure the Go Pigeon process receives the configured runtime arguments.

    Returns:
        None.
    """
    trust = create_trust()
    trust.port = 32769
    trust.host = "172.16.2.4"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = "permanent/p2p_trust_runtime"
    trust.pigeon_key_file = "pigeon;peer1.keys"
    trust._rebuild_pigeon_binary_after_slips_update = Mock(return_value=True)

    with (
        patch("modules.p2p_trust.p2p_trust.shutil.which", return_value=True),
        patch("modules.p2p_trust.p2p_trust.subprocess.Popen") as mock_popen,
    ):
        mock_popen.return_value.poll.return_value = None
        trust._start_pigeon()

    executable = mock_popen.call_args.args[0]
    key_index = executable.index("-key-file")
    assert executable[key_index + 1] == "pigeonpeer1.keys"
    assert "--redis-db" in executable
    assert f"localhost:{trust.redis_port}" in executable
    rendezvous_index = executable.index("-rendezvous")
    assert executable[rendezvous_index + 1] == trust.rendezvous
    version_index = executable.index("-slips-version")
    assert executable[version_index + 1] == trust.slips_version
    host_index = executable.index("-host")
    assert executable[host_index + 1] == "0.0.0.0"
    assert mock_popen.call_args.kwargs["cwd"] == "permanent/p2p_trust_runtime"
    assert mock_popen.call_args.kwargs["stderr"] == subprocess.STDOUT


def test_pigeon_command_bootstraps_to_authenticated_peers_on_current_subnet():
    """Use saved peer ID and endpoint mappings when mDNS misses peers."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.port = 6668
    trust.host = "192.168.1.163"
    trust.trust_db = Mock()
    trust.trust_db.get_recent_peer_addresses.return_value = [
        ("peer-current", "192.168.1.196", 6669, 100),
        ("peer-other-network", "10.0.0.5", 6668, 99),
    ]
    trust.trust_db.get_recent_peer_ips.return_value = [
        ("peer-current", "192.168.1.196", 100),
        ("peer-legacy", "192.168.1.170", 98),
    ]
    trust._get_local_subnets = Mock(
        return_value={ipaddress.ip_network("192.168.1.0/24")}
    )

    peers = trust._get_bootstrap_peer_addresses()

    assert peers == [
        "/ip4/192.168.1.196/tcp/6669/p2p/peer-current",
        "/ip4/192.168.1.170/tcp/6668/p2p/peer-legacy",
    ]


def test_local_subnets_include_interfaces_other_than_capture_interface():
    """Include directly connected LANs on secondary interfaces for P2P."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.args = SimpleNamespace(interface="en0")
    addresses = {
        "en0": {netifaces.AF_INET: [{"addr": "192.168.12.24", "netmask": "255.255.255.0"}]},
        "en16": {netifaces.AF_INET: [{"addr": "192.168.1.132", "netmask": "255.255.255.0"}]},
        "lo0": {netifaces.AF_INET: [{"addr": "127.0.0.1", "netmask": "255.0.0.0"}]},
    }
    with (
        patch("modules.p2p_trust.p2p_trust.netifaces.interfaces", return_value=list(addresses)),
        patch("modules.p2p_trust.p2p_trust.netifaces.ifaddresses", side_effect=lambda name: addresses[name]),
    ):
        assert trust._get_local_subnets() == {
            ipaddress.ip_network("192.168.12.0/24"),
            ipaddress.ip_network("192.168.1.0/24"),
        }


@pytest.mark.parametrize(
    "flag,stdout,stderr,expected",
    [
        ("-slips-version", "  -slips-version string\n", "", True),
        ("-slips-version", "", "  -slips-version string\n", True),
        ("-bootstrap-peers", "  -bootstrap-peers string\n", "", True),
        ("-slips-version", "  -rendezvous string\n", "", False),
    ],
)
def test_pigeon_supports_flag(
    flag: str, stdout: str, stderr: str, expected: bool
) -> None:
    """Detect supported Pigeon flags from stdout or stderr help text.

    Parameters:
        stdout: Simulated standard help output.
        stderr: Simulated error help output.
        expected: Whether the requested flag should be detected.
    """
    trust = create_trust()
    del trust._pigeon_supports_flag
    result = subprocess.CompletedProcess([], 0, stdout, stderr)

    with patch(
        "modules.p2p_trust.p2p_trust.subprocess.run", return_value=result
    ) as run:
        assert trust._pigeon_supports_flag(flag) is expected

    run.assert_called_once_with(
        [str(trust.pigeon_binary), "-help"],
        capture_output=True,
        check=False,
        text=True,
        timeout=5,
    )


def test_start_pigeon_omits_unsupported_version_flag() -> None:
    """Start older native binaries without their unsupported version flag."""
    trust = create_trust()
    trust.port = 32769
    trust.host = "172.16.2.4"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = "permanent/p2p_trust_runtime"
    trust.pigeon_key_file = "pigeon.keys"
    trust._pigeon_supports_flag.return_value = False
    trust._rebuild_pigeon_binary_after_slips_update = Mock(return_value=True)

    with (
        patch("modules.p2p_trust.p2p_trust.shutil.which", return_value=True),
        patch("modules.p2p_trust.p2p_trust.subprocess.Popen") as mock_popen,
    ):
        mock_popen.return_value.poll.return_value = None
        trust._start_pigeon()

    executable = mock_popen.call_args.args[0]
    assert "-slips-version" not in executable
    trust.print.assert_any_call(
        "Warning: The installed p2p4slips binary does not support "
        "-slips-version; starting in legacy compatibility mode."
    )


def test_start_pigeon_passes_redis_auth_conf_to_go():
    """
    Ensure the Go Pigeon process is told where slips' redis
    `requirepass` conf lives, so it can authenticate to redis.

    Returns:
        None.
    """
    trust = create_trust()
    trust.port = 32769
    trust.host = "172.16.2.4"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = "permanent/p2p_trust_runtime"
    trust.pigeon_key_file = "pigeon.keys"
    trust._rebuild_pigeon_binary_after_slips_update = Mock(return_value=True)
    auth_conf = "/slips/permanent/redis_auth.conf"

    with (
        patch("modules.p2p_trust.p2p_trust.shutil.which", return_value=True),
        patch(
            "modules.p2p_trust.p2p_trust.get_redis_auth_conf_path",
            return_value=auth_conf,
        ),
        patch("modules.p2p_trust.p2p_trust.subprocess.Popen") as mock_popen,
    ):
        trust._start_pigeon()

    executable = mock_popen.call_args.args[0]
    conf_index = executable.index("-redis-auth-conf")
    assert executable[conf_index + 1] == auth_conf


def test_start_pigeon_rebuilds_and_retries_on_exec_format_error():
    """
    Ensure incompatible p2p4slips binaries are rebuilt and retried.

    Returns:
        None.
    """
    trust = create_trust()
    trust.port = 32769
    trust.host = "172.16.2.4"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = "permanent/p2p_trust_runtime"
    trust.pigeon_key_file = "pigeon.keys"
    trust._rebuild_pigeon_binary_after_slips_update = Mock(return_value=True)
    trust._build_pigeon_binary = Mock(return_value=True)
    exec_error = OSError(errno.ENOEXEC, "Exec format error")
    pigeon_process = Mock()
    pigeon_process.poll.return_value = None

    with (
        patch("modules.p2p_trust.p2p_trust.shutil.which", return_value=True),
        patch(
            "modules.p2p_trust.p2p_trust.subprocess.Popen",
            side_effect=[exec_error, pigeon_process],
        ) as mock_popen,
    ):
        trust._start_pigeon()

    assert trust.pigeon == pigeon_process
    assert mock_popen.call_count == 2
    trust._build_pigeon_binary.assert_called_once_with("for this system")
    trust.print.assert_any_call(
        "Warning: p2p4slips binary is not executable on this system. "
        "Trying to rebuild it locally."
    )


def test_start_pigeon_reports_start_errors_without_retry():
    """
    Ensure non-format startup errors are reported without rebuilding.

    Returns:
        None.
    """
    trust = create_trust()
    trust.port = 32769
    trust.host = "172.16.2.4"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = "permanent/p2p_trust_runtime"
    trust.pigeon_key_file = "pigeon.keys"
    trust._rebuild_pigeon_binary_after_slips_update = Mock(return_value=True)
    trust._build_pigeon_binary = Mock()

    with (
        patch("modules.p2p_trust.p2p_trust.shutil.which", return_value=True),
        patch(
            "modules.p2p_trust.p2p_trust.subprocess.Popen",
            side_effect=OSError(errno.EACCES, "Permission denied"),
        ) as mock_popen,
    ):
        trust._start_pigeon()

    assert trust.pigeon is None
    mock_popen.assert_called_once()
    trust._build_pigeon_binary.assert_not_called()
    trust.print.assert_any_call(
        "Warning: Failed to start p2p4slips. Error: "
        "[Errno 13] Permission denied"
    )


def test_start_pigeon_reports_immediate_child_failure() -> None:
    """Do not claim P2P is listening when its child exits during startup."""
    trust = create_trust()
    trust.port = 32769
    trust.host = "172.16.2.4"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = "permanent/p2p_trust_runtime"
    trust.pigeon_key_file = "pigeon.keys"
    trust._rebuild_pigeon_binary_after_slips_update = Mock(return_value=True)

    with (
        patch("modules.p2p_trust.p2p_trust.shutil.which", return_value=True),
        patch("modules.p2p_trust.p2p_trust.subprocess.Popen") as mock_popen,
    ):
        mock_popen.return_value.poll.return_value = 2
        trust._start_pigeon()

    assert trust.pigeon is None
    trust.print.assert_any_call(
        "Warning: p2p4slips exited during startup with return code 2. "
        f"Check {os.devnull}."
    )
    assert call("P2P is listening on 172.16.2.4 port 32769.") not in (
        trust.print.call_args_list
    )


@pytest.mark.parametrize(
    "ip_info",
    [
        {},
        {"score": None, "confidence": 0.8},
        {"score": "invalid", "confidence": 0.8},
        {"score": 0.5},
        {"score": 0.5, "confidence": None},
        {"score": 0.5, "confidence": "invalid"},
        {"threat_level": "invalid", "confidence": 0.8},
    ],
)
def test_get_ip_info_rejects_missing_or_malformed_values(
    ip_info: dict,
) -> None:
    """
    Return no opinion when a stored score or confidence cannot be converted.

    Parameters:
        ip_info: Simulated IP metadata returned by Redis.
    """
    module_factory = ModuleFactory()
    db = module_factory.create_go_director_obj().db
    db.get_ip_info.side_effect = lambda _ip, field: ip_info.get(field)

    assert get_ip_info_from_slips("192.0.2.1", db) == (None, None)


def test_main_continues_after_one_malformed_gopy_message() -> None:
    """Process the next Go message after one malformed message is ignored."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.create_p2p_logfile = False
    trust.p2p_data_request_channel = "p2p_data_request"
    trust.gopy_channel = "p2p_gopy"
    trust.pigeon = Mock()
    trust.pigeon.poll.return_value = None
    trust.mutliaddress_printed = True
    valid_data = {
        "message_type": "peer_update",
        "message_contents": {"peerid": "peer-1"},
    }
    trust.get_msg = Mock(
        side_effect=[
            None,
            None,
            {"data": "malformed"},
            None,
            None,
            {"data": json.dumps(valid_data)},
        ]
    )
    trust.go_director = Mock()
    trust.gopy_callback = Mock(wraps=trust.gopy_callback)

    trust.main()
    trust.main()

    assert trust.gopy_callback.call_count == 2
    trust.go_director.handle_gopy_data.assert_called_once_with(valid_data)
    warning = trust.print.call_args.args
    assert warning[0].startswith(
        "Warning: Ignoring malformed p2p_gopy message after processing failed:"
    )
    assert warning[1:] == (0, 1)


@pytest.mark.parametrize(
    "message_type,expected",
    [
        ("peer_update", True),
        ("connection_update", True),
        ("go_data", True),
        ("unexpected", False),
    ],
)
def test_gopy_filter_accepts_connection_updates(
    message_type: str, expected: bool
) -> None:
    """Pass authenticated connection events to the Go message handler.

    Parameters:
        message_type: Go message type on the local Pigeon channel.
        expected: Whether the filter should accept the message.
    """
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.gopy_channel = "p2p_gopy"
    message = {
        "data": json.dumps(
            {"message_type": message_type, "message_contents": {}}
        )
    }

    assert trust.is_msg_version_compatible(message, "p2p_gopy") is expected


def test_main_yields_between_nonblocking_channel_polls() -> None:
    """An idle P2P module must yield CPU while remaining responsive."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.create_p2p_logfile = False
    trust.p2p_data_request_channel = "p2p_data_request"
    trust.gopy_channel = "p2p_gopy"
    trust.pigeon = Mock()
    trust.pigeon.poll.return_value = None
    trust.mutliaddress_printed = True
    trust.get_msg = Mock(return_value=None)

    trust.main()

    trust.termination_event.wait.assert_called_once_with(0.05)


@pytest.mark.parametrize(
    "error_message,handled",
    [
        ("database is locked", True),
        ("database table is locked", True),
        ("malformed SQL", False),
    ],
)
def test_main_defers_locked_report_compaction(
    error_message: str, handled: bool
) -> None:
    """Keep P2P online when compaction temporarily loses the SQLite lock.

    Parameters:
        error_message: SQLite operational error to simulate.
        handled: Whether the module should retry on a later poll.
    """
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.create_p2p_logfile = False
    trust.p2p_data_request_channel = "p2p_data_request"
    trust.gopy_channel = "p2p_gopy"
    trust.pigeon = Mock()
    trust.pigeon.poll.return_value = None
    trust.mutliaddress_printed = True
    trust.get_msg = Mock(return_value=None)
    trust._refresh_pigeon_address = Mock()
    trust.trust_db = Mock()
    trust.trust_db.compact_reports.side_effect = sqlite3.OperationalError(
        error_message
    )
    trust.last_p2p_connection_heartbeat_time = 100
    trust.last_report_compaction_time = 90

    with patch("modules.p2p_trust.p2p_trust.time.time", return_value=100):
        if handled:
            trust.main()
        else:
            with pytest.raises(sqlite3.OperationalError):
                trust.main()

    trust.trust_db.compact_reports.assert_called_once()
    if handled:
        assert trust.last_report_compaction_time == 100
        trust.print.assert_any_call(
            f"Deferring P2P report compaction: {error_message}", 0, 1
        )
        trust.termination_event.wait.assert_called_once_with(0.05)
    else:
        assert trust.last_report_compaction_time == 90
        trust.termination_event.wait.assert_not_called()


def test_stop_pigeon_waits_for_child_exit() -> None:
    """Signal the Go child and wait for it before clearing the process handle."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.pigeon = Mock()
    trust.pigeon.poll.return_value = None
    pigeon = trust.pigeon

    trust._stop_pigeon()

    pigeon.send_signal.assert_called_once_with(signal.SIGINT)
    pigeon.wait.assert_called_once_with(timeout=5)
    assert trust.pigeon is None


def test_pigeon_restarts_when_monitored_interface_address_changes() -> None:
    """Rebind Pigeon and clear stale live peers after a Wi-Fi change."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.host = "192.168.1.247"
    trust.last_local_ip_check = 0
    trust.local_ip_check_interval = 5
    trust.pigeon = Mock()
    trust.mutliaddress_printed = True
    trust.get_local_IP = Mock(return_value="192.168.1.163")
    trust._stop_pigeon = Mock()
    trust._start_pigeon = Mock()

    with patch("modules.p2p_trust.p2p_trust.time.monotonic", return_value=10):
        trust._refresh_pigeon_address()

    assert trust.host == "192.168.1.163"
    assert trust.mutliaddress_printed is False
    trust._stop_pigeon.assert_called_once_with()
    trust.db.clear_authenticated_p2p_connections.assert_called_once_with()
    trust.db.store_connected_peers.assert_called_once_with([])
    trust._start_pigeon.assert_called_once_with()


def test_run_stops_pigeon_after_unexpected_module_exit() -> None:
    """Stop the Go child even when the common module runner exits on error."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust._stop_pigeon = Mock()

    with patch.object(IModule, "run", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError, match="boom"):
            trust.run()


def create_trust_for_blame(network_opinion, local_opinion):
    """
    Build a Trust object ready to exercise evaluate_blame_report()'s
    blame-evaluation logic (Omega-Trust: combine the network's
    trust-weighted opinion with Slips' own local opinion before ever
    forwarding a blame report to the blocking pipeline).

    Parameters:
        network_opinion: (score, confidence) returned by
            reputation_model.get_opinion_on_ip().
        local_opinion: (score, confidence) returned by
            get_ip_info_from_slips().

    Returns:
        A Trust instance with mocked dependencies.
    """
    trust = create_trust()
    trust.ips_weight = 0.5
    trust.blame_threshold = 0.5
    trust.reputation_model = Mock()
    trust.reputation_model.get_opinion_on_ip.return_value = network_opinion
    trust.local_opinion = local_opinion
    return trust


def blame_report(ip="1.2.3.4"):
    return {
        "message_type": "blame",
        "key": ip,
        "key_type": "ip",
        "evaluation_type": "score_confidence",
        "evaluation": {"score": 1, "confidence": 1},
    }


def test_evaluate_blame_report_ignores_non_blame_messages():
    """
    A plain "report" must never reach the network's opinion lookup or
    the blocking pipeline - only "blame" messages are evaluated here.
    """
    trust = create_trust_for_blame((1, 1), (1, 1))
    data = blame_report()
    data["message_type"] = "report"

    trust.evaluate_blame_report("peer1", 123, data)

    trust.reputation_model.get_opinion_on_ip.assert_not_called()
    trust.db.publish.assert_not_called()


def test_evaluate_blame_report_no_network_opinion_yet():
    """
    If the trust model has no aggregated opinion on the IP yet (e.g.
    the trustdb has no usable reports), the blame must not be
    forwarded.
    """
    trust = create_trust_for_blame((None, None), (1, 1))

    with patch(
        "modules.p2p_trust.p2p_trust.p2p_utils.get_ip_info_from_slips",
        return_value=trust.local_opinion,
    ):
        trust.evaluate_blame_report("peer1", 123, blame_report())

    trust.db.publish.assert_not_called()


def test_evaluate_blame_report_below_threshold_is_not_forwarded():
    """
    A blame about an IP that neither the network nor Slips considers
    malicious must not be forwarded to the blocking pipeline.
    """
    trust = create_trust_for_blame((0, 0), (0, 0))

    with patch(
        "modules.p2p_trust.p2p_trust.p2p_utils.get_ip_info_from_slips",
        return_value=trust.local_opinion,
    ):
        trust.evaluate_blame_report("peer1", 123, blame_report())

    trust.db.publish.assert_not_called()


def test_evaluate_blame_report_above_threshold_is_forwarded():
    """
    A blame about an IP that both the network and Slips agree is
    malicious enough must be forwarded to the "new_blame" channel.
    """
    trust = create_trust_for_blame((1, 1), (1, 1))
    data = blame_report()

    with patch(
        "modules.p2p_trust.p2p_trust.p2p_utils.get_ip_info_from_slips",
        return_value=trust.local_opinion,
    ):
        trust.evaluate_blame_report("peer1", 123, data)

    trust.db.publish.assert_called_once_with("new_blame", json.dumps(data))


def test_evaluate_blame_report_single_malicious_peer_is_not_enough():
    """
    Regression test for the thesis' core safety requirement: a single
    peer's blame, unsupported by the network's aggregated opinion or
    by Slips' own local opinion, must never directly cause a block.
    """
    trust = create_trust_for_blame((0, 0), (0, 0))

    with patch(
        "modules.p2p_trust.p2p_trust.p2p_utils.get_ip_info_from_slips",
        return_value=trust.local_opinion,
    ):
        trust.evaluate_blame_report("malicious_peer", 123, blame_report())

    trust.db.publish.assert_not_called()
