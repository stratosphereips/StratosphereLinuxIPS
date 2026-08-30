"""Integration coverage for the Python-to-Go Pigeon startup contract."""

import shutil
import subprocess
from unittest.mock import patch

import pytest

from modules.p2p_trust.p2p_trust import Trust
from tests.module_factory import ModuleFactory


def test_python_pigeon_arguments_are_accepted_by_go_binary(tmp_path) -> None:
    """Build Pigeon and verify that Go accepts every argument Python supplies."""
    _module_factory = ModuleFactory()
    go_executable = shutil.which("go")
    if go_executable is None:
        pytest.skip("Go is required for the Python-to-Pigeon contract test")

    pigeon_binary = tmp_path / "p2p4slips"
    build = subprocess.run(
        [
            go_executable,
            "build",
            "-buildvcs=false",
            "-o",
            str(pigeon_binary),
            ".",
        ],
        cwd="p2p4slips",
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )
    assert build.returncode == 0, build.stdout + build.stderr

    trust = Trust.__new__(Trust)
    trust.start_pigeon = True
    trust.pigeon_binary = str(pigeon_binary)
    trust.pigeon_binary_dir = "p2p4slips"
    trust.port = 32769
    trust.host = "127.0.0.1"
    trust.pigeon_key_file = "pigeon.keys"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.slips_version = "contract-test"
    trust.p2p_connection_ttl = 30
    trust.p2p_handshake_pending_seconds = 2
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = str(tmp_path)
    trust._rebuild_pigeon_binary_after_slips_update = lambda: True
    trust.print = lambda *args, **kwargs: None

    with patch("modules.p2p_trust.p2p_trust.subprocess.Popen") as popen:
        trust._start_pigeon()

    command = list(popen.call_args.args[0]) + ["-help"]
    result = subprocess.run(
        command,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 0, output
    assert "flag provided but not defined" not in output
