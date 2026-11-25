"""Tests for isolated file analyses: runs on a file that keep their own data."""

from copy import deepcopy
from pathlib import Path
import sys

import pytest
import yaml

from slips_files.common.parsers.analysis_config import (
    build_isolated_analysis_config, get_isolated_analysis_output_dir,
    validate_analysis_paths,
)
from slips_files.common.parsers.config_parser import ConfigParser
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
    """A run is isolated only if it has all of -m, -f and -o and no -i or -g.

    Parameters:
        arguments: The command-line arguments of the run.
        expected: The output directory, or None if the run is not isolated.
    """
    _factory = ModuleFactory()
    assert get_isolated_analysis_output_dir(arguments) == expected


@pytest.mark.parametrize("extra", [["--clearcache"], ["--keep-history"], ["-P", "6379"]])
def test_isolated_analysis_rejects_shared_cache_operations(extra: list[str]) -> None:
    """Options that touch shared data are rejected in an isolated analysis.

    Parameters:
        extra: The option that can't be used with an isolated analysis.
    """
    _factory = ModuleFactory()
    with pytest.raises(SystemExit) as error:
        get_isolated_analysis_output_dir(["-m", "-f", "test.pcap", "-o", "output/test", *extra])
    assert error.value.code == 2


def test_isolated_configuration_preserves_detection_settings(tmp_path: Path) -> None:
    """Detection settings stay as they are; only the data locations change.

    Parameters:
        tmp_path: Output folder of the analysis.
    """
    _factory = ModuleFactory()
    source = {"parameters": {"permanent_dir": "live", "time_window_width": 120},
              "beaconing": {"min_flows": 7}, "web_interface": {"bind": "interface", "port": 55000},
              "update": {"auto_update_slips": True},
              "ml_online_model": {"model_load_path": "trained/model.bin"}}
    before = deepcopy(source)
    output = tmp_path / "analysis"
    effective = build_isolated_analysis_config(source, str(output))
    assert source == before
    assert effective["parameters"]["permanent_dir"] == "live"
    assert effective["parameters"]["time_window_width"] == 120
    assert effective["parameters"]["store_zeek_files_in_the_output_dir"] is True
    assert effective["parameters"]["metadata_dir"] is True
    assert effective["beaconing"] == source["beaconing"]
    assert effective["web_interface"] == {"bind": "localhost", "port": 55000}
    assert effective["update"]["auto_update_slips"] is False
    assert effective["ml_online_model"] == source["ml_online_model"]


def test_isolated_configuration_never_creates_a_permanent_dir(tmp_path: Path) -> None:
    """The permanent dir, whitelist and feed download paths are left as configured.

    Parameters:
        tmp_path: Output folder of the analysis.
    """
    _factory = ModuleFactory()
    source = {"parameters": {"permanent_dir": "live"},
              "whitelists": {"local_whitelist_path": "rules/whitelist.conf"},
              "threatintelligence": {"download_path_for_remote_threat_intelligence": "feeds/"}}
    output = tmp_path / "analysis"
    effective = build_isolated_analysis_config(source, str(output))
    assert effective["parameters"]["permanent_dir"] == "live"
    assert effective["whitelists"] == source["whitelists"]
    assert effective["threatintelligence"] == source["threatintelligence"]
    assert str(output) not in str(
        {k: v for k, v in effective.items()
         if k in ("parameters", "whitelists", "threatintelligence")}
    )
    assert not output.exists()


@pytest.mark.parametrize("output", [".", "live", "live/nested", "config", "input", "input/nested", "rules", "analysis"])
def test_analysis_paths_protect_original_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str) -> None:
    """An output dir that could delete source data is rejected, and nothing is created.

    Parameters:
        tmp_path: Folder holding the config, input and permanent dir.
        monkeypatch: Used to make relative paths resolve inside tmp_path.
        output: The output directory the user asked for.
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
    """Every process reads the same config, without changing argv or slips.yaml.

    Parameters:
        tmp_path: Folder holding the config file and the output dir.
        monkeypatch: Used to set the command line and reset ConfigParser.
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
        # the config only has what slips.yaml says; runtime values live in Redis
        assert conf.config == original
        assert not hasattr(conf, "isolated_analysis")
        assert conf.web_interface_port == 55012
        assert conf.get_args().config == str(source)
    assert configurations[0] == configurations[1]
    assert yaml.safe_load(source.read_text()) == original
    assert sys.argv == arguments


def test_remote_feeds_default_to_a_dir_inside_permanent() -> None:
    """Feeds are downloaded into the permanent dir unless a path is configured."""
    _factory = ModuleFactory()
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = {"parameters": {"permanent_dir": "live"}}
    assert parser.remote_ti_data_path() == "live/remote_data_files"
    parser.config["threatintelligence"] = {
        "download_path_for_remote_threat_intelligence": "feeds/"
    }
    assert parser.remote_ti_data_path() == "feeds/"


def test_isolated_configuration_leaves_store_settings_untouched(tmp_path: Path) -> None:
    """The store settings are not changed; the modules pick their own paths.

    Parameters:
        tmp_path: Output folder of the analysis.
    """
    _factory = ModuleFactory()
    source = {"regex_generator": {"persistent_store_dir": "databases/regex_store"},
              "t_cell": {"persistent_store_dir": "t_cell"}}
    effective = build_isolated_analysis_config(source, str(tmp_path / "analysis"))
    assert effective["regex_generator"] == source["regex_generator"]
    assert effective["t_cell"] == source["t_cell"]


@pytest.mark.parametrize("isolated", [False, True])
@pytest.mark.parametrize("storage_class", ["regex", "t_cell"])
def test_file_analysis_ignores_the_persistent_store(tmp_path: Path, isolated: bool, storage_class: str) -> None:
    """A file analysis must not write into the permanent dir of live runs.

    Parameters:
        tmp_path: Output folder of the analysis.
        isolated: Whether the run is an isolated file analysis.
        storage_class: Which store to test.
    """
    from unittest.mock import Mock
    from slips_files.core.database.sqlite_db.regex_generator_db import (
        RegexGeneratorStorage,
    )
    from slips_files.core.database.sqlite_db.t_cell_db import TCellStorage

    _factory = ModuleFactory()
    cls, prefix = (RegexGeneratorStorage, "regex_generator") if storage_class == "regex" else (TCellStorage, "t_cell")
    storage = cls.__new__(cls)
    storage.output_dir = str(tmp_path)
    storage.conf = Mock()
    setattr(storage.conf, f"{prefix}_persistent_store_dir", Mock(return_value="stable_store"))
    setattr(storage.conf, f"{prefix}_store_dir", Mock(return_value=f"output/{prefix}"))
    raw, persistent = storage._read_store_dir(allow_persistent=not isolated)
    if isolated:
        assert (raw, persistent) == (f"output/{prefix}", False)
    else:
        assert (raw, persistent) == ("stable_store", True)
