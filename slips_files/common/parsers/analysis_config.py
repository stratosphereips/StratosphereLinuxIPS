"""Keep offline multi-instance analyses separate from live runtime data."""

import argparse
from copy import deepcopy
from pathlib import Path
import shutil

from modules.supported_module_names import Modules


def isolated_analysis_output(arguments: list[str] | None = None) -> str | None:
    """Identify an offline analysis with its own output and Redis instance.

    Parameters:
        arguments: CLI arguments, or None to read the current process arguments.

    Returns:
        Output directory for an isolated analysis, or None for other runs.
    """
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("-m", "--multiinstance", action="store_true")
    parser.add_argument("-f", "--filepath")
    parser.add_argument("-o", "--output")
    parser.add_argument("-i", "--interface")
    parser.add_argument("-g", "--growing")
    parser.add_argument("-P", "--port")
    parser.add_argument("-c", "--config")
    parser.add_argument("-cc", "--clearcache", action="store_true")
    parser.add_argument("--keep-history", action="store_true")
    options, _ = parser.parse_known_args(arguments)
    if not (
        options.multiinstance
        and options.filepath
        and options.output
        and not options.interface
        and not options.growing
    ):
        return None
    if options.clearcache or options.keep_history or options.port == "6379":
        parser.error(
            "An isolated file analysis cannot use --clearcache, "
            "--keep-history or Redis port 6379"
        )
    return str(Path(options.output))


def isolated_analysis_config(config: dict, output: str) -> dict:
    """Override writable paths for one analysis without editing its source.

    Parameters:
        config: Source configuration to reuse.
        output: Independent analysis output directory.

    Returns:
        Configuration with private runtime data and a localhost web listener.
    """
    result = deepcopy(config)
    permanent = Path(output) / "permanent"
    overrides = {
        "parameters": {
            "permanent_dir": str(permanent),
            "metadata_dir": True,
            "store_zeek_files_in_the_output_dir": True,
        },
        "whitelists": {
            "local_whitelist_path": str(permanent / "whitelist.conf")
        },
        "web_interface": {"bind": "localhost"},
        "update": {"auto_update_slips": False},
        Modules.REGEX_GENERATOR.value: {
            "persistent_store_dir": "databases/regex_store"
        },
        Modules.T_CELL.value: {"persistent_store_dir": ""},
        "threatintelligence": {
            "download_path_for_remote_threat_intelligence": str(
                permanent / "remote_ti"
            )
        },
    }
    for module in (Modules.ML_LINEAR_MODEL, Modules.ML_ONLINE_MODEL):
        directory = permanent / module.value
        overrides[module.value] = {
            "model_store_path": str(directory / "model.bin"),
            "preprocess_store_path": str(directory / "preprocess.bin"),
        }
    for section, values in overrides.items():
        result[section] = {**(result.get(section) or {}), **values}
    return result


def validate_analysis_paths(
    config: dict, output: str, config_path: str, input_path: str
) -> None:
    """Reject outputs whose normal cleanup could damage source data.

    Parameters:
        config: Original configuration containing shared source paths.
        output: Directory that startup will reset.
        config_path: Configuration file being reused.
        input_path: Capture or log directory being analyzed.
    """
    destination = Path(output).resolve()
    permanent = Path(
        (config.get("parameters") or {}).get("permanent_dir") or "permanent"
    ).resolve()
    whitelist = (config.get("whitelists") or {}).get(
        "local_whitelist_path"
    ) or "config/whitelist.conf"
    sources = [
        permanent,
        Path(whitelist).resolve(),
        Path(config_path).resolve(),
        Path(input_path).resolve(),
    ]
    input_directory = Path(input_path)
    if (
        destination.is_relative_to(permanent)
        or any(source.is_relative_to(destination) for source in sources)
        or (
            input_directory.is_dir()
            and destination.is_relative_to(input_directory.resolve())
        )
    ):
        raise SystemExit(
            "Choose an independent -o directory outside the source "
            "configuration, input and permanent data paths."
        )


def prepare_analysis_files(source: dict, effective: dict) -> None:
    """Copy credentials and whitelist rules into a freshly prepared analysis.

    Parameters:
        source: Original configuration with credential and whitelist paths.
        effective: Run configuration with independent writable paths.
    """
    from slips_files.core.database.redis_db.redis_auth import (
        ensure_redis_password,
    )

    original = Path(
        (source.get("parameters") or {}).get("permanent_dir") or "permanent"
    )
    original.mkdir(parents=True, exist_ok=True)
    ensure_redis_password(str(original / "redis_auth.conf"))
    destination = Path(effective["parameters"]["permanent_dir"])
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.chmod(0o700)
    for name in ("redis_auth.conf", "web_auth.json"):
        path = original / name
        if path.is_file():
            target = destination / name
            shutil.copyfile(path, target)
            target.chmod(0o600)
    whitelist = Path(
        (source.get("whitelists") or {}).get("local_whitelist_path")
        or "config/whitelist.conf"
    )
    if whitelist.is_file():
        shutil.copyfile(
            whitelist, effective["whitelists"]["local_whitelist_path"]
        )
