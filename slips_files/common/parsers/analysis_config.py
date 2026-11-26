"""Keep analyses of files, run next to other Slips instances, from mixing
with the data of live runs."""

from argparse import Namespace
from copy import deepcopy
from pathlib import Path

from slips_files.common.parsers.arg_parser import (
    create_isolated_analysis_parser,
)


def _is_isolated_file_analysis(options: Namespace) -> bool:
    """Check if the parsed options describe an isolated file analysis.
    isolated runs require -f -i and -m together.

    Parameters:
        options: The parsed command-line options.
    """
    return bool(
        options.multiinstance
        and options.filepath
        and options.output
        and not options.interface
        and not options.growing
    )


def is_isolated_run(arguments: list[str] | None = None) -> bool:
    """Check if a Slips run is isolated.

    An isolated run analyzes a file while another instance can be analyzing
    an interface, so it must not share that instance's data. It needs -m
    , -o  AND -f, and no -i or -g.

    Parameters:
        arguments: Command-line arguments. If None, the arguments of the
            current process are used.

    Returns:
        True if the run is isolated.
    """
    parser = create_isolated_analysis_parser()
    options, _ = parser.parse_known_args(arguments)
    return _is_isolated_file_analysis(options)


def build_isolated_analysis_config(config: dict, output: str) -> dict:
    """Build the config to record for an isolated analysis.

    ConfigParser only reads slips.yaml, so it doesn't know about the
    overrides below. This function doesn't apply them, its result is only
    recorded in the metadata dir. The code that reads these settings applies
    them to isolated runs, so keep both in sync. auto_update_slips needs no
    extra check, since Slips only updates itself on non-stop runs.

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
