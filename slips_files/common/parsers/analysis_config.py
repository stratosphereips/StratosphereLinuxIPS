"""Keep offline multi-instance analyses separate from live runtime data."""

import argparse
from copy import deepcopy
from pathlib import Path


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
    """Build the settings an isolated analysis actually runs with.

    ConfigParser keeps only what slips.yaml says. Code that reads one of
    the settings below checks db.is_running_non_stop() and applies the
    same override for file analyses; this function only records them in
    the metadata dir. Keep both in sync. Every path setting
    (permanent dir, whitelist, feed downloads, persistent stores) is left as
    configured; modules that must not write into the live permanent dir
    during a file analysis choose their own output-dir path in code.

    Parameters:
        config: Source configuration to reuse.
        output: Independent analysis output directory.

    Returns:
        Configuration with private runtime data and a localhost web listener.
    """
    result = deepcopy(config)
    overrides = {
        "parameters": {
            "metadata_dir": True,
            "store_zeek_files_in_the_output_dir": True,
        },
        "web_interface": {"bind": "localhost"},
        "update": {"auto_update_slips": False},
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
