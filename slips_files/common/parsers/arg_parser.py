# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Customize --help in argparse.

import os
import sys
import argparse
import textwrap


def parse_web_port(value: str) -> int:
    """Check that the web port given on the command line is valid.

    Parameters:
        value: The port the user typed.

    Returns:
        The port as a number from 1 to 65535. Anything else is an argparse error.
    """
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "web port must be an integer from 1 to 65535"
        ) from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            "web port must be an integer from 1 to 65535"
        )
    return port


def get_web_port_override(arguments: list[str] | None = None) -> int | None:
    """Read --web-port from the command line, ignoring all other arguments.

    Parameters:
        arguments: Command-line arguments, or None to read sys.argv.

    Returns:
        The web port, or None if --web-port wasn't given.
    """
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--web-port", type=parse_web_port)
    return parser.parse_known_args(arguments)[0].web_port


def add_instance_arguments(parser: argparse.ArgumentParser) -> None:
    """Add --list-instances, --stop and --restart to a parser.

    Only one of the three can be used at a time.

    Parameters:
        parser: The parser to add the options to.
    """
    commands = parser.add_mutually_exclusive_group()
    commands.add_argument(
        "--list-instances",
        action="store_true",
        help="List running Slips instances from this Slips folder without "
        "starting a run or connecting to Redis.",
    )
    commands.add_argument(
        "--stop",
        nargs="?",
        const="auto",
        metavar="PID|all",
        help="Gracefully stop a Slips instance in any mode from this Slips folder. "
        "Omit PID when only one is running, or use all to stop every instance.",
    )
    commands.add_argument(
        "--restart",
        nargs="?",
        const="auto",
        metavar="PID",
        help="Stop a running daemon and relaunch it with its original "
        "arguments. Omit PID when only one daemon is running. Use the same "
        "Python environment that started it.",
    )


def create_instance_parser() -> argparse.ArgumentParser:
    """Build a small parser that only knows --list-instances, --stop and
    --restart. It is used before Slips opens any database.

    Returns:
        The parser.
    """
    parser = argparse.ArgumentParser(prog="slips.py", allow_abbrev=False)
    add_instance_arguments(parser)
    return parser


def create_launch_parser() -> argparse.ArgumentParser:
    """Build a parser that knows every option of slips.py.

    It is only used to look up how each option can be spelled when reading
    the command line of other Slips processes, never to parse our own.

    Returns:
        The parser.
    """
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("-D", "--daemon", action="store_true")
    parser.add_argument("-i", "--interface")
    parser.add_argument("-f", "--filepath")
    parser.add_argument("-g", "--growing")
    parser.add_argument("-o", "--output")
    parser.add_argument("--view")
    parser.add_argument("-k", "--killall", action="store_true")
    parser.add_argument("-V", "--version", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument(
        "-S", "--stopdaemon", dest="stop_daemon", action="store_true"
    )
    add_instance_arguments(parser)
    return parser


def create_web_server_parser() -> argparse.ArgumentParser:
    """Build a parser that knows the options of the web interface server.

    It is used to read the command line of a running web server.

    Returns:
        The parser.
    """
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--output-dir")
    return parser


def create_isolated_analysis_parser() -> argparse.ArgumentParser:
    """Build a parser that knows only the options that decide if a run is an
    isolated file analysis.

    An isolated run analyzes a file next to an instance that analyzes an
    interface. It needs -m and -o together (with -f); without -m it isn't
    isolated.

    Returns:
        The parser.
    """
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("-m", "--multiinstance", action="store_true")
    parser.add_argument("-f", "--filepath")
    parser.add_argument("-o", "--output")
    parser.add_argument("-i", "--interface")
    parser.add_argument("-g", "--growing")
    return parser


def create_run_conflict_parser() -> argparse.ArgumentParser:
    """Build a parser that reads the options another run shares with us
    (Redis port, output dir, web port...).

    Returns:
        The parser. It raises argparse.ArgumentError instead of exiting.
    """
    parser = argparse.ArgumentParser(
        add_help=False, allow_abbrev=False, exit_on_error=False
    )
    parser.add_argument("-m", "--multiinstance", action="store_true")
    parser.add_argument("-P", "--port")
    parser.add_argument("-o", "--output")
    parser.add_argument("-c", "--config", default="config/slips.yaml")
    parser.add_argument("-cc", "--clearcache", action="store_true")
    parser.add_argument("-w", "--webinterface", action="store_true")
    parser.add_argument("--web-port", type=int)
    return parser


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        self.options = []
        super(ArgumentParser, self).__init__(*args, **kwargs)
        self.program = {key: kwargs[key] for key in kwargs}

    def add_argument(self, *args, **kwargs):
        super(ArgumentParser, self).add_argument(*args, **kwargs)
        if kwargs.get("help") == argparse.SUPPRESS:
            return
        option = {"flags": list(args)}
        for key in kwargs:
            option[key] = kwargs[key]
        self.options.append(option)

    def print_help(self):
        wrapper = textwrap.TextWrapper(width=160)

        # Print description
        if "description" in self.program:
            print(self.program["description"])
            print()

        # Print usage
        if "usage" in self.program:
            print(f"Usage: {self.program['usage']}")
        else:
            usage = []
            for option in self.options:
                usage += [
                    (
                        f"[{item}|{option['metavar']}]"
                        if "metavar" in option
                        else (
                            f"[{item}|{option['dest'].upper()}]"
                            if "dest" in option
                            else f"[{item}]"
                        )
                    )
                    for item in option["flags"]
                ]
            wrapper.initial_indent = "Usage: %s " % os.path.basename(
                sys.argv[0]
            )
            wrapper.subsequent_indent = len(wrapper.initial_indent) * " "
            output = str.join(" ", usage)
            output = wrapper.fill(output)
            print(output)
        print()

        # Print options
        print("Options:")
        maxlen = 0
        for option in self.options:
            option["flags2"] = " ".join(
                [
                    "|".join(list(option["flags"])),
                    option["metavar"] if "metavar" in option else "",
                ]
            )

            if len(option["flags2"]) > maxlen:
                maxlen = len(option["flags2"])
        for option in self.options:
            template = f" %-{str(maxlen)}s  | "
            wrapper.initial_indent = template % option["flags2"]
            wrapper.subsequent_indent = len(wrapper.initial_indent) * " "
            if "help" in option and "default" in option:
                output = option["help"]
                # do not print th default value of help arg
                if "-h" not in option["flags"]:
                    output += f" (default: '{option['default']})"
                output = wrapper.fill(output)
            elif "help" in option:
                output = option["help"]
                output = wrapper.fill(output)
            elif "default" in option:
                output = (
                    f"Default: '{option['default']}'"
                    if isinstance(option["default"], str)
                    else f"Default: {str(option['default'])}"
                )
                output = wrapper.fill(output)
            else:
                output = wrapper.initial_indent
            print(output)

    def get_configfile(self):
        slips_conf_path = os.path.join(os.getcwd(), "config/slips.yaml")
        self.add_argument(
            "-cc",
            "--clearcache",
            action="store_true",
            required=False,
            help="Clear the cache database.",
        )
        self.add_argument(
            "-c",
            "--config",
            metavar="<configfile>",
            action="store",
            required=False,
            default=slips_conf_path,
            help="Path to the Slips config file.",
        )
        return self.parse_known_args()[0].config

    def parse_arguments(self):
        # Parse the parameters
        slips_conf_path = os.path.join(os.getcwd(), "config/slips.yaml")
        self.add_argument(
            "-c",
            "--config",
            metavar="<configfile>",
            action="store",
            required=False,
            default=slips_conf_path,
            help="Path to the Slips config file.",
        )
        self.add_argument(
            "-v",
            "--verbose",
            metavar="<verbositylevel>",
            action="store",
            required=False,
            type=int,
            help="Verbosity level. This logs more info about Slips.",
        )
        self.add_argument(
            "-e",
            "--debug",
            metavar="<debuglevel>",
            action="store",
            required=False,
            type=int,
            help="Debugging level. This shows more detailed errors.",
        )
        self.add_argument(
            "-f",
            "--filepath",
            metavar="<file>",
            action="store",
            required=False,
            help="Read a Zeek dir with all logs, "
            "a Zeek conn.log file (tab-separated or JSON), "
            "a Suricata JSON file, an Argus binetflow file, a PCAP file or a nfdump file. "
            'The word "zeek" is used to read from zeek lines from stdin. ',
        )
        self.add_argument(
            "-i",
            "--interface",
            metavar="<interface>",
            action="store",
            required=False,
            help="Read packets from an interface.",
        )
        self.add_argument(
            "-ap",
            "--access-point",
            action="store",
            required=False,
            help="Read packets from two interfaces when Slips is running as "
            "an access point. the wifi interface should come first (e.g -ap wlan0,eth0).",
        )
        self.add_argument(
            "-F",
            "--pcapfilter",
            action="store",
            required=False,
            type=str,
            help="Packet filter for Zeek. BPF style.",
        )
        self.add_argument(
            "-cc",
            "--clearcache",
            action="store_true",
            required=False,
            help="Clear the cache database.",
        )
        self.add_argument(
            "-p",
            "--blocking",
            help="Allow Slips to block malicious IPs. Requires root access. "
            "Supported only on Linux.",
            required=False,
            default=False,
            action="store_true",
        )
        self.add_argument(
            "--clearblocking",
            help="Flush and delete slipsBlocking iptables chain",
            required=False,
            default=False,
            action="store_true",
        )
        self.add_argument(
            "-o",
            "--output",
            action="store",
            metavar="<dir>",
            required=False,
            help="Store Slips logs in the given folder.",
        )
        self.add_argument(
            "-d",
            "--db",
            action="store",
            metavar="<redis .rdb file>",
            required=False,
            help="Read an analysed file (rdb) from disk.",
        )
        self.add_argument(
            "-D",
            "--daemon",
            required=False,
            default=False,
            action="store_true",
            help="Run slips in daemon mode",
        )
        self.add_argument(
            "-k",
            "--killall",
            action="store_true",
            required=False,
            help="Kill all unused redis servers",
        )
        add_instance_arguments(self)
        self.add_argument(
            "-m",
            "--multiinstance",
            action="store_true",
            required=False,
            help="Run multiple instances of slips, don't overwrite the old "
            "one. This option run redis using a random unused port "
            "instead of the default one (6379). With -f and -o, also isolate "
            "runtime data and copy the whitelist and credentials automatically "
            "under the output directory; reuse the same -c file.",
        )
        self.add_argument(
            "-P",
            "--port",
            metavar="<port_number>",
            action="store",
            required=False,
            help="The redis-server port to use",
        )
        self.add_argument(
            "--keep-history",
            action="store_true",
            required=False,
            help="Keep detections and flows from a previous live run in the "
            "same output directory, or start fresh if none exist. "
            "Requires -i and -o; concurrent runs "
            "need separate data directories and ports.",
        )
        self.add_argument(
            "-t",
            "--testing",
            action="store_true",
            required=False,
            help="used for testing slips",
        )
        self.add_argument(
            "-g",
            "--growing",
            action="store",
            metavar="<zeek_dir>",
            required=False,
            help="Treat the given zeek directory as growing. eg. "
            "Zeek dirs generated when running on an interface",
        )
        self.add_argument(
            "-w",
            "--webinterface",
            action="store_true",
            required=False,
            help="Enable the local web interface for this Slips run",
        )
        self.add_argument(
            "--web-port",
            type=parse_web_port,
            metavar="PORT",
            help="Override web_interface.port for this run (1-65535). "
            "Enable the web interface with -w or in the configuration.",
        )
        self.add_argument(
            "-V",
            "--version",
            action="store_true",
            required=False,
            help="Print Slips Version",
        )
        self.add_argument(
            "-im",
            "--input-module",
            action="store",
            metavar="<module_name>",
            required=False,
            help="Read flows from a module other than input process.",
        )
        self.add_argument(
            "--no-recurse",
            action="store_true",
            help="Internal use only, prevents infinite recursion for cpu profiler dev mode multiprocess tracking",
        )
        # Internal flag used when Slips starts a newer version of itself.
        self.add_argument(
            "-u",
            dest="is_slips_started_by_an_update",
            action="store_true",
            default=False,
            help=argparse.SUPPRESS,
        )
        try:
            self.add_argument(
                "-h",
                "--help",
                action="store_true",
                help="command line help",
            )
        except argparse.ArgumentError:
            pass
        return self.parse_args()
