"""Verify independent file analyses without copying live configuration files."""

from copy import deepcopy
from pathlib import Path
import sys

import pytest
import yaml

from slips_files.common.parsers.analysis_config import (
    isolated_analysis_config, isolated_analysis_output,
    prepare_analysis_files, validate_analysis_paths,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.database.redis_db import redis_auth
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("arguments, expected", [
    (["-m", "-f", "test.pcap", "-o", "output/test"], "output/test"),
    (["--multiinstance", "--filepath=logs", "--output=output/logs"], "output/logs"),
    (["-mfake"], None),
    (["-m", "-i", "eth0", "-o", "output/live"], None),
    (["-f", "test.pcap", "-o", "output/test"], None),
    (["-m", "-f", "test.pcap"], None),
    (["-m", "-f", "test.pcap", "-o", "output/test", "-g", "logs"], None),
    (["--list-instances"], None),
])
def test_isolated_analysis_selection(arguments: list[str], expected: str | None) -> None:
    """Enable automatic file isolation only for the complete CLI combination.

    Parameters:
        arguments: Arguments supplied by the main process or a worker.
        expected: Independent output path, or None for other run types.
    """
    _factory = ModuleFactory()
    assert isolated_analysis_output(arguments) == expected


@pytest.mark.parametrize("extra", [["--clearcache"], ["--keep-history"], ["-P", "6379"]])
def test_isolated_analysis_rejects_shared_cache_operations(extra: list[str]) -> None:
    """Reject shared destructive operations before configuration has side effects.

    Parameters:
        extra: Options incompatible with independent file analysis.
    """
    _factory = ModuleFactory()
    with pytest.raises(SystemExit) as error:
        isolated_analysis_output(["-m", "-f", "test.pcap", "-o", "output/test", *extra])
    assert error.value.code == 2


def test_isolated_configuration_preserves_detection_settings(tmp_path: Path) -> None:
    """Keep detection parameters and read models while separating writable state.

    Parameters:
        tmp_path: Separate analysis output.
    """
    _factory = ModuleFactory()
    source = {"parameters": {"permanent_dir": "live", "time_window_width": 120},
              "beaconing": {"min_flows": 7}, "web_interface": {"bind": "interface", "port": 55000},
              "update": {"auto_update_slips": True},
              "ml_online_model": {"model_load_path": "trained/model.bin", "model_store_path": "live/model.bin"}}
    before = deepcopy(source)
    output = tmp_path / "analysis"
    effective = isolated_analysis_config(source, str(output))
    assert source == before
    assert effective["parameters"]["permanent_dir"] == str(output / "permanent")
    assert effective["parameters"]["time_window_width"] == 120
    assert effective["parameters"]["store_zeek_files_in_the_output_dir"] is True
    assert effective["parameters"]["metadata_dir"] is True
    assert effective["beaconing"] == source["beaconing"]
    assert effective["web_interface"] == {"bind": "localhost", "port": 55000}
    assert effective["update"]["auto_update_slips"] is False
    assert effective["ml_online_model"]["model_load_path"] == "trained/model.bin"
    assert Path(effective["ml_online_model"]["model_store_path"]).is_relative_to(output)


@pytest.mark.parametrize("credentials_exist", [False, True])
def test_analysis_files_copy_only_credentials_and_whitelist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, credentials_exist: bool,
) -> None:
    """Share cache credentials while keeping rules and learned data independent.

    Parameters:
        tmp_path: Source state and separate output.
        monkeypatch: Password cache isolation.
        credentials_exist: Whether credentials already exist for a live run.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr(redis_auth, "_cached_password", None)
    original = tmp_path / "live"
    original.mkdir()
    if credentials_exist:
        (original / "redis_auth.conf").write_text("requirepass unit-test-password\n")
        (original / "web_auth.json").write_text('{"hash": "existing-login"}')
    (original / "hosts.sqlite").write_bytes(b"live identities")
    whitelist = tmp_path / "whitelist.conf"
    whitelist.write_text("ip,192.0.2.10,src,alerts\n")
    source = {"parameters": {"permanent_dir": str(original)},
              "whitelists": {"local_whitelist_path": str(whitelist)}}
    effective = isolated_analysis_config(source, str(tmp_path / "analysis"))
    prepare_analysis_files(source, effective)
    destination = Path(effective["parameters"]["permanent_dir"])
    for name in ("redis_auth.conf", "web_auth.json"):
        if (original / name).exists():
            assert (destination / name).read_bytes() == (original / name).read_bytes()
            assert (destination / name).stat().st_mode & 0o777 == 0o600
            assert (destination / name).stat().st_ino != (original / name).stat().st_ino
    assert not (destination / "hosts.sqlite").exists()
    copied = Path(effective["whitelists"]["local_whitelist_path"])
    assert copied.read_text() == whitelist.read_text()
    copied.write_text("changed only for analysis\n")
    assert whitelist.read_text() == "ip,192.0.2.10,src,alerts\n"
    assert redis_auth.ensure_redis_password(str(original / "redis_auth.conf"))


@pytest.mark.parametrize("output", [".", "live", "live/nested", "config", "input", "input/nested", "rules", "analysis"])
def test_analysis_paths_protect_original_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str) -> None:
    """Reject destructive output relationships before creating any files.

    Parameters:
        tmp_path: Source configuration, input and state paths.
        monkeypatch: Relative path resolution inside the fixture.
        output: Requested output directory.
    """
    _factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    Path("input").mkdir()
    source = {"parameters": {"permanent_dir": "live"},
              "whitelists": {"local_whitelist_path": "rules/whitelist.conf"}}
    if output == "analysis":
        validate_analysis_paths(source, output, "config/slips.yaml", "input")
    else:
        with pytest.raises(SystemExit, match="independent -o"):
            validate_analysis_paths(source, output, "config/slips.yaml", "input")
    assert sorted(path.name for path in tmp_path.iterdir()) == ["input"]


def test_each_process_reconstructs_same_analysis_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reconstruct the same private paths without rewriting argv or source YAML.

    Parameters:
        tmp_path: Reused source configuration and selected output.
        monkeypatch: Command line and configuration singleton isolation.
    """
    _factory = ModuleFactory()
    source = tmp_path / "slips.yaml"
    original = {"parameters": {"permanent_dir": "permanent"}, "beaconing": {"min_flows": 7}}
    source.write_text(yaml.safe_dump(original))
    arguments = ["slips.py", "-c", str(source), "-m", "-f", "capture.pcap",
                 "-o", str(tmp_path / "analysis"), "--web-port", "55012"]
    monkeypatch.setattr(sys, "argv", arguments)
    configurations = []
    for _ in range(2):
        monkeypatch.setattr(ConfigParser, "_instance", None)
        conf = ConfigParser()
        configurations.append(conf.config)
        assert conf.isolated_analysis
        assert conf.web_interface_port == 55012
        assert conf.get_args().config == str(source)
    assert configurations[0] == configurations[1]
    assert yaml.safe_load(source.read_text()) == original
    assert sys.argv == arguments
