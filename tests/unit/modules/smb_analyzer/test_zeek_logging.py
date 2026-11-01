"""Exercise the actual Zeek logging policies without retaining data chunks."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("enabled", [True, False])
def test_zeek_limits_file_write_logging_and_authentication_commands(
    tmp_path: Path, enabled: bool
) -> None:
    """Repeated chunks produce one write record; interim authentication is excluded.

    :param tmp_path: Isolated Zeek log directory.
    :param enabled: Whether additional SMB logging is enabled.
    """
    factory = ModuleFactory()
    assert factory is not None
    zeek = shutil.which("zeek")
    if not zeek:
        pytest.skip("Zeek is not installed")
    # Invoke the real SMB logger with metadata records. No file content is involved.
    script = """
    event zeek_init() &priority=-10 {
        local id: conn_id = [$orig_h=192.168.1.120, $orig_p=50000/tcp, $resp_h=10.0.0.1, $resp_p=445/tcp];
        local f = SMB::FileInfo($uid="Csmb", $id=id, $name="test.exe", $action=SMB::FILE_WRITE);
        local state = SMB::State($current_file=f);
        for (i in vector(1,2,3,4,5,6,7,8,9,10))
            SMB::write_file_log(state);
        f$action = SMB::FILE_CLOSE;
        f$size = 200000000;
        SMB::write_file_log(state);
        local cmd = SMB::CmdInfo($ts=network_time(), $uid="Csmb", $id=id, $command="SESSION_SETUP_ANDX", $status="LOGON_FAILURE", $version="SMB1");
        Log::write(SMB::CMD_LOG, cmd);
        cmd$status = "SUCCESS";
        Log::write(SMB::CMD_LOG, cmd);
        cmd$status = "MORE_PROCESSING_REQUIRED";
        Log::write(SMB::CMD_LOG, cmd);
    }
    """
    result = subprocess.run(
        [
            zeek,
            "zeek-scripts/smb-behavior.zeek",
            "LogAscii::use_json=T",
            "-e",
            f'redef Log::default_logdir = "{tmp_path}"; redef SMB::slips_log_file_operations={"T" if enabled else "F"}; '
            f'redef SMB::slips_log_authentication_failures={"T" if enabled else "F"}; '
            + script,
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    files = tmp_path / "smb_files.log"
    rows = (
        [json.loads(line) for line in files.read_text().splitlines()]
        if files.exists()
        else []
    )
    assert len(rows) == (2 if enabled else 0)
    if enabled:
        assert [r["action"] for r in rows] == [
            "SMB::FILE_WRITE",
            "SMB::FILE_CLOSE",
        ]
        assert all(r["slips_write_seen"] for r in rows)
        assert all("slips_event_ts" in r for r in rows)
        assert rows[-1]["size"] == 200000000
    commands = tmp_path / "smb_cmd.log"
    rows = (
        [json.loads(line) for line in commands.read_text().splitlines()]
        if commands.exists()
        else []
    )
    assert len(rows) == int(enabled)
    if enabled:
        assert rows[0]["status"] == "LOGON_FAILURE"
