# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import json
import multiprocessing
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from distutils.dir_util import copy_tree
from typing import Set
import logging

from managers.host_ip_manager import HostIPManager
from managers.metadata_manager import MetadataManager
from managers.process_manager import ProcessManager
from managers.profilers_manager import ProfilersManager
from managers.redis_manager import RedisManager
from managers.ui_manager import UIManager
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.printer import Printer
from slips_files.common.slips_utils import utils
from slips_files.common.style import green
from slips_files.core.database.database_manager import DBManager
from slips_files.core.helpers.checker import Checker


logging.basicConfig(level=logging.WARNING)

DAEMONIZED_MODE = "daemonized"


class Main:
    def __init__(self, testing=False):
        self.name = "Main"
        self.alerts_default_path = "output/"
        self.mode = "interactive"
        # objects to manage various functionality
        self.checker = Checker(self)
        self.redis_man = RedisManager(self)
        self.conf = ConfigParser()
        self.metadata_man = MetadataManager(self)
        self.ui_man = UIManager(self)
        self.version = utils.get_slips_version()
        # will be filled later
        self.commit = "None"
        self.branch = "None"
        self.last_updated_stats_time = datetime.now()
        self.input_type = False
        self.proc_man = ProcessManager(self)
        # in testing mode we manually set the following params
        # TODO use mocks instead of this testing param
        if not testing:
            self.args = self.conf.get_args()
            self.profilers_manager = ProfilersManager(self)
            self.pid = os.getpid()
            self.checker.check_given_flags()

            if not self.args.stopdaemon:
                # Check the type of input
                (
                    self.input_type,
                    self.input_information,
                    self.line_type,
                ) = self.checker.check_input_type()
                # If we need zeek (bro), test if we can run it.
                self.check_zeek_or_bro()
                self.prepare_output_dir()
                # this is the zeek dir slips will be using
                self.prepare_zeek_output_dir()
                self.twid_width = self.conf.get_tw_width()
                # should be initialised after self.input_type is set
                self.host_ip_man = HostIPManager(self)

    def check_zeek_or_bro(self):
        """
        Check if we have zeek or bro
        """
        self.zeek_bro = None
        if self.input_type not in ("pcap", "interface"):
            return False

        if shutil.which("zeek"):
            self.zeek_bro = "zeek"
        elif shutil.which("bro"):
            self.zeek_bro = "bro"
        else:
            print("Error. No zeek or bro binary found.")
            self.terminate_slips()
            return False

        return self.zeek_bro

    def prepare_zeek_output_dir(self):
        from pathlib import Path

        without_ext = Path(self.input_information).stem
        if self.conf.store_zeek_files_in_the_output_dir():
            self.zeek_dir = os.path.join(self.args.output, "zeek_files")
        else:
            self.zeek_dir = f"zeek_files_{without_ext}/"

    def terminate_slips(self):
        """
        Shutdown slips, is called when stopping slips before
        starting all modules. for example using -cb
        """
        if self.mode == DAEMONIZED_MODE:
            self.daemon.stop()
        if not self.conf.get_cpu_profiler_enable():
            sys.exit(0)

    def save_the_db(self):
        # save the db to the output dir of this analysis
        # backups_dir = os.path.join(os.getcwd(), 'redis_backups/')
        # try:
        #     os.mkdir(backups_dir)
        # except FileExistsError:
        #     pass
        backups_dir = self.args.output
        # The name of the interface/pcap/nfdump/binetflow used is in self.input_information
        # if the input is a zeek dir, remove the / at the end
        if self.input_information.endswith("/"):
            self.input_information = self.input_information[:-1]
        # remove the path
        self.input_information = os.path.basename(self.input_information)
        # Remove the extension from the filename
        with contextlib.suppress(ValueError):
            self.input_information = self.input_information[
                : self.input_information.index(".")
            ]
        # Give the exact path to save(), this is where our saved .rdb backup will be
        rdb_filepath = os.path.join(backups_dir, self.input_information)
        self.db.save(rdb_filepath)
        # info will be lost only if you're out of space and redis
        # can't write to dump.self.rdb, otherwise you're fine
        print(
            "[Main] [Warning] stop-writes-on-bgsave-error is set to no, "
            "information may be lost in the redis backup file."
        )

    def was_running_zeek(self) -> bool:
        """returns true if zeek was used in this run"""
        return self.db.is_running_non_stop() or self.db.get_input_type() in (
            "pcap",
            "interface",
        )

    def store_zeek_dir_copy(self):
        store_a_copy_of_zeek_files = self.conf.store_a_copy_of_zeek_files()
        was_running_zeek = self.was_running_zeek()
        if store_a_copy_of_zeek_files and was_running_zeek:
            # this is where the copy will be stored
            dest_zeek_dir = os.path.join(self.args.output, "zeek_files")
            copy_tree(self.zeek_dir, dest_zeek_dir)
            print(f"[Main] Stored a copy of zeek files to {dest_zeek_dir}")

    def delete_zeek_files(self):
        if self.conf.delete_zeek_files():
            shutil.rmtree(self.zeek_dir)

    def prepare_output_dir(self):
        """
        Clears the output dir if it already exists , or creates a
        new one if it doesn't exist
        Log dirs are stored in output/<input>_%Y-%m-%d_%H:%M:%S
        @return: None
        """
        # default output/
        if "-o" in sys.argv:
            # -o is given
            # delete all old files in the output dir
            if os.path.exists(self.args.output):
                for file in os.listdir(self.args.output):
                    # in integration tests, slips redirects its
                    # output to slips_output.txt,
                    # don't delete that file
                    if self.args.testing and "slips_output.txt" in file:
                        continue

                    file_path = os.path.join(self.args.output, file)
                    with contextlib.suppress(Exception):
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
            else:
                os.makedirs(self.args.output)
            return

        # self.args.output is the same as self.alerts_default_path
        self.input_information = os.path.normpath(self.input_information)
        # now that slips can run several instances,
        # each created dir will be named after the instance
        # that created it
        # it should be output/wlp3s0
        self.args.output = os.path.join(
            self.alerts_default_path,
            os.path.basename(
                self.input_information
            ),  # get pcap name from path
        )
        # add timestamp to avoid conflicts wlp3s0_2022-03-1_03:55
        ts = utils.convert_format(datetime.now(), "%Y-%m-%d_%H:%M:%S")
        self.args.output += f"_{ts}/"

        os.makedirs(self.args.output)

    def set_mode(self, mode, daemon=""):
        """
        Slips has 2 modes, daemonized and interactive, this function
        sets up the mode so that slips knows in which mode it's operating
        :param mode: daemonized of interavtive
        :param daemon: Daemon() instance
        """
        self.mode = mode
        self.daemon = daemon

    def log(self, txt):
        """
        Is used instead of print for daemon debugging
        """
        with open(self.daemon.stdout, "a") as f:
            f.write(f"{txt}\n")

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def handle_flows_from_stdin(self, input_information):
        """
        Make sure the stdin line type is valid (argus, suricata, or zeek)
        when using -f stdin-type
        """
        if input_information.lower() not in (
            "argus",
            "suricata",
            "zeek",
        ):
            print(f"[Main] Invalid file path {input_information}. Stopping.")
            sys.exit(-1)

        if self.mode == DAEMONIZED_MODE:
            print(
                "Can't read input from stdin in daemonized mode. " "Stopping"
            )
            sys.exit(-1)
        line_type = input_information
        input_type = "stdin"
        return input_type, line_type.lower()

    def is_binetflow_line(self, line: str) -> bool:
        return "->" in line or "StartTime" in line

    def get_input_file_type(self, given_path):
        """
        given_path: given file
        returns binetflow, pcap, nfdump, zeek_folder, suricata, etc.
        """
        # default value
        input_type = "file"
        # Get the type of file
        cmd_result = subprocess.run(
            ["file", given_path], stdout=subprocess.PIPE
        )
        # Get command output
        cmd_result = cmd_result.stdout.decode("utf-8")
        if (
            "pcap capture file" in cmd_result
            or "pcapng capture file" in cmd_result
        ) and os.path.isfile(given_path):
            input_type = "pcap"
        elif (
            "dBase" in cmd_result
            or "nfcap" in given_path
            or "nfdump" in given_path
        ) and os.path.isfile(given_path):
            input_type = "nfdump"
            if shutil.which("nfdump") is None:
                # If we do not have nfdump, terminate Slips.
                print("nfdump is not installed. terminating slips.")
                self.terminate_slips()
        elif "CSV" in cmd_result and os.path.isfile(given_path):
            input_type = "binetflow"
        elif "directory" in cmd_result and os.path.isdir(given_path):
            for log_file in os.listdir(given_path):
                # if there is at least 1 supported log file inside the
                # given directory, start slips normally
                # otherwise, stop slips
                if not utils.is_ignored_zeek_log_file(log_file):
                    input_type = "zeek_folder"
                    break
            else:
                print(
                    f"Log files in {given_path} are not supported \n"
                    f"Make sure all log files inside the given "
                    f"directory end with .log or .log.labeled .. Stopping."
                )
                sys.exit(-1)
        else:
            # is it a zeek log file or suricata, binetflow tabs,
            # or binetflow comma separated file?
            # use first line to determine
            with open(given_path, "r") as f:
                while True:
                    # get the first line that isn't a comment
                    first_line = f.readline().replace("\n", "")
                    if not first_line.startswith("#"):
                        break
            if "flow_id" in first_line:
                input_type = "suricata"
            else:
                # this is a text file, it can be binetflow or zeek_log_file
                try:
                    # is it a json log file
                    json.loads(first_line)
                    input_type = "zeek_log_file"
                except json.decoder.JSONDecodeError:
                    # this is a tab separated file
                    # is it zeek log file or binetflow file?

                    # zeek tab files are separated by several spaces or tabs
                    sequential_spaces_found = re.search(
                        r"\s{1,}-\s{1,}", first_line
                    )
                    tabs_found = re.search("\t{1,}", first_line)
                    commas_found = re.search(",{1,}", first_line)
                    if sequential_spaces_found or tabs_found:
                        if self.is_binetflow_line(first_line):
                            # tab separated files are usually binetflow tab files
                            input_type = "binetflow-tabs"
                        else:
                            input_type = "zeek_log_file"
                    elif commas_found and self.is_binetflow_line(first_line):
                        # sometimes modified binetflow files aren't CSV,
                        # and the file command return ASCII text, this is
                        # probably the case
                        return "binetflow"
        return input_type

    def setup_print_levels(self):
        """
        setup debug and verbose levels
        """
        # Any verbosity passed as parameter overrides
        # the configuration. Only check its value
        if self.args.verbose is None:
            self.args.verbose = self.conf.verbose()

        # Limit any verbosity to > 0
        self.args.verbose = max(self.args.verbose, 1)
        # Any debug passed as parameter overrides the
        # configuration. Only check its value
        if self.args.debug is None:
            self.args.debug = self.conf.debug()

        # Debug levels must be > 0
        self.args.debug = max(self.args.debug, 0)

    def print_version(self):
        slips_version = f"Slips Version: {green(self.version)}"
        branch_info = utils.get_branch_info()
        if branch_info is not False:
            # it's false when we're in docker because there's no .git/ there
            self.commit, self.branch = branch_info
            slips_version += f" ({self.commit[:8]})"
        slips_version.replace("\n", "")
        print(slips_version)

    def update_stats(self):
        """
        updates the statistics printed every 5s
        """
        if not self.mode == "interactive":
            return

        # only update the stats every 5s
        now = datetime.now()
        if (
            utils.get_time_diff(self.last_updated_stats_time, now, "seconds")
            < 5
        ):
            return

        self.last_updated_stats_time = now
        now = utils.convert_format(now, "%Y/%m/%d %H:%M:%S")
        modified_ips_in_the_last_tw = self.db.get_modified_ips_in_the_last_tw()
        profiles_len = self.db.get_profiles_len()
        evidence_number = self.db.get_evidence_number() or 0
        flow_per_min = self.db.get_flows_analyzed_per_minute()
        stats = (
            f"\r[{now}] Total analyzed IPs: {green(profiles_len)}. "
            f"{self.get_analyzed_flows_percentage()}"
            f"Evidence: {green(evidence_number)}. "
            f"Number of IPs seen in the last ({self.twid_width}):"
            f" {green(modified_ips_in_the_last_tw)}. "
            f"Analyzed {flow_per_min} flows/min."
        )
        self.print(stats)
        sys.stdout.flush()  # Make sure the output is displayed immediately

    def get_analyzed_flows_percentage(self) -> str:
        """
        returns a str with the percentage of analyzed flows so far to be
        logged in the stats
        """
        if self.is_total_flows_unknown():
            return ""

        if not hasattr(self, "total_flows"):
            self.total_flows = self.db.get_total_flows()

        flows_percentage = int(
            (self.db.get_processed_flows_so_far() / self.total_flows) * 100
        )
        return f"Analyzed Flows: {green(flows_percentage)}{green('%')}. "

    def is_total_flows_unknown(self) -> bool:
        """
        Determines if slips knows the total flows it's gonna be
        reading beforehand or not
        for example, we dont know the total flows when running on an interface,
         a pcap, an input module like cyst, etc.
        """
        return (
            self.args.input_module
            or self.args.growing
            or self.input_type in ("stdin", "pcap", "interface")
        )

    def get_slips_logfile(self) -> str:
        if self.mode == "daemonized":
            return self.daemon.stdout
        elif self.mode == "interactive":
            return os.path.join(self.args.output, "slips.log")

    def get_slips_error_file(self) -> str:
        if self.mode == "daemonized":
            return self.daemon.stderr
        elif self.mode == "interactive":
            return os.path.join(self.args.output, "errors.log")

    def start(self):
        """Main Slips Function"""
        try:
            self.print_version()
            print("https://stratosphereips.org")
            print("-" * 27)
            self.setup_print_levels()
            stderr: str = self.get_slips_error_file()
            slips_logfile: str = self.get_slips_logfile()
            # if stdout is redirected to a file,
            # tell output.py to redirect it's output as well
            self.logger = self.proc_man.start_output_process(
                stderr, slips_logfile
            )
            self.printer = Printer(self.logger, self.name)
            self.print(f"Storing Slips logs in {self.args.output}")
            self.redis_port: int = self.redis_man.get_redis_port()
            # dont start the redis server if it's already started
            start_redis_server = not utils.is_port_in_use(self.redis_port)
            try:
                self.db = DBManager(
                    self.logger,
                    self.args.output,
                    self.redis_port,
                    start_redis_server=start_redis_server,
                )
            except RuntimeError as e:
                self.print(str(e), 1, 1)
                self.terminate_slips()

            self.db.set_input_metadata(
                {
                    "output_dir": self.args.output,
                    "commit": self.commit,
                    "branch": self.branch,
                    # we need to set this in the db because some modules use
                    # it as soon as they start
                    "input_type": self.input_type,
                }
            )
            # this line should happen as soon as we start the db
            # to be able to use the host IP as analyzer IP in alerts.json
            # should be after setting the input metadata with "input_type"
            # TLDR; dont change the order of this line
            host_ip = self.host_ip_man.store_host_ip()

            self.print(
                f"Using redis server on port: {green(self.redis_port)}",
                1,
                0,
            )
            self.print(
                f'Started {green("Main")} process '
                f"[PID"
                f" {green(self.pid)}]",
                1,
                0,
            )
            self.profilers_manager.cpu_profiler_init()
            self.profilers_manager.memory_profiler_init()

            if self.args.growing:
                if self.input_type != "zeek_folder":
                    self.print(
                        f"Parameter -g should be used with "
                        f"-f <dirname> not a {self.input_type} file. "
                        f"Ignoring -g. Analyzing {self.input_information} "
                        f"instead.",
                        verbose=1,
                        debug=3,
                    )
                else:
                    self.print(
                        f"Running on a growing zeek dir: {self.input_information}"
                    )
                    self.db.set_growing_zeek_dir()

            # log the PID of the started redis-server
            # should be here after we're sure that the server was started
            redis_pid = self.redis_man.get_pid_of_redis_server(self.redis_port)
            self.redis_man.log_redis_server_pid(self.redis_port, redis_pid)

            self.db.set_slips_mode(self.mode)

            if self.mode == DAEMONIZED_MODE:
                std_files = {
                    "stderr": self.daemon.stderr,
                    "stdout": self.daemon.stdout,
                    "stdin": self.daemon.stdin,
                    "pidfile": self.daemon.pidfile,
                    "logsfile": self.daemon.logsfile,
                }
            else:
                std_files = {
                    "stderr": stderr,
                    "stdout": slips_logfile,
                }

            self.db.store_std_file(**std_files)

            # if slips is given a .rdb file, don't load the
            # modules as we don't need them
            if not self.args.db:
                # update local files before starting modules
                # if wait_for_TI_to_finish is set to true in the config file,
                # slips will wait untill all TI files are updated before
                # starting the rest of the modules
                self.proc_man.start_update_manager(
                    local_files=True,
                    ti_feeds=self.conf.wait_for_TI_to_finish(),
                )
                self.print("Starting modules", 1, 0)
                self.proc_man.load_modules()
                # give outputprocess time to print all the started modules
                time.sleep(0.5)
                self.proc_man.print_disabled_modules()

            if self.args.webinterface:
                self.ui_man.start_webinterface()

            # call shutdown_gracefully on sigterm
            def sig_handler(sig, frame):
                self.proc_man.shutdown_gracefully()

            # The signals SIGKILL and SIGSTOP cannot be caught,
            # blocked, or ignored.
            signal.signal(signal.SIGTERM, sig_handler)

            self.proc_man.start_evidence_process()
            self.proc_man.start_profiler_process()

            self.c1 = self.db.subscribe("control_channel")

            self.metadata_man.add_metadata_if_enabled()

            self.input_process = self.proc_man.start_input_process()

            # obtain the list of active processes
            self.proc_man.processes = multiprocessing.active_children()

            self.db.store_pid("slips.py", int(self.pid))
            self.metadata_man.set_input_metadata()

            # warn about unused open redis servers
            open_servers = len(self.redis_man.get_open_redis_servers())
            if open_servers > 1:
                self.print(
                    f"Warning: You have {open_servers} "
                    f"redis servers running. "
                    f"Run Slips with --killall to stop them."
                )

            self.print(
                "Warning: Slips may generate a large amount "
                "of traffic by querying TI sites."
            )

            # Don't try to stop slips if it's capturing from
            # an interface or a growing zeek dir
            self.is_interface: bool = self.db.is_running_non_stop()

            while not self.proc_man.stop_slips():
                # Sleep some time to do routine checks and give time for
                # more traffic to come
                time.sleep(5)

                # if you remove the below logic anywhere before the
                # above sleep() statement, it will try to get the return
                # value very quickly before
                # the webinterface thread sets it. so don't:D
                self.ui_man.check_if_webinterface_started()

                self.update_stats()

                self.db.check_tw_to_close()

                modified_profiles: Set[str] = (
                    self.metadata_man.update_slips_stats_in_the_db()[1]
                )

                self.host_ip_man.update_host_ip(host_ip, modified_profiles)

        except KeyboardInterrupt:
            # the EINTR error code happens if a signal occurred while
            # the system call was in progress
            # comes here if zeek terminates while slips is still working
            pass

        self.proc_man.shutdown_gracefully()
