"""Keep analyses of files, run next to other Slips instances, from mixing
with the data of live runs."""

from copy import deepcopy
from pathlib import Path

from slips_files.common.parsers.arg_parser import (
    create_isolated_analysis_parser,
)


def get_isolated_analysis_output_dir(
    arguments: list[str] | None = None,
) -> str | None:
    """Check if this is an isolated file analysis, and get its output directory.

    An isolated analysis reads a file (not an interface), is started with
    --multiinstance and its own output directory, and gets its own Redis
    server so it doesn't share data with other runs.

    Parameters:
        arguments: Command-line arguments. If None, the arguments of the
            current process are used.

    Returns:
        The output directory, or None if this isn't an isolated analysis.
    """
    parser = create_isolated_analysis_parser()
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


def build_isolated_analysis_config(config: dict, output: str) -> dict:
    """Build the config that an isolated analysis runs with.

    ConfigParser only reads slips.yaml, so it doesn't know about the
    overrides below. The code that reads these settings checks
    db.is_running_non_stop() and applies the same override for file
    analyses. This function only records them in the metadata dir, so
    keep both in sync.

    Path settings (permanent dir, whitelist, feed downloads, persistent
    stores) are left as configured. Modules that must not write into the
    live permanent dir during a file analysis pick their own output
    directory in code.

    Parameters:
        config: The config to copy.
        output: The output directory of the analysis.

    Returns:
        A copy of the config that keeps its runtime data in the output
        directory and serves the web interface on localhost only.
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
    """Stop the run if its output directory could end up deleting source data.

    Slips empties the output directory when it starts, so it must not
    contain (or be inside) the config, the input or the permanent data.

    Parameters:
        config: The config, used to find the permanent dir and whitelist.
        output: The output directory that Slips will empty.
        config_path: The config file in use.
        input_path: The file or directory being analyzed.
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
