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

from managers.metadata_manager import MetadataManager
from managers.process_manager import ProcessManager
from managers.redis_manager import RedisManager
from managers.ui_manager import UIManager
from slips_files.common.abstracts.observer import IObservable
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.performance_profilers.cpu_profiler import CPUProfiler
from slips_files.common.performance_profilers.memory_profiler import MemoryProfiler
from slips_files.common.slips_utils import utils
from slips_files.common.style import green
from slips_files.core.database.database_manager import DBManager
from slips_files.core.helpers.checker import Checker


class Main(IObservable):
    def __init__(self, testing=False):
        IObservable.__init__(self)
        self.name = "Main"
        self.alerts_default_path = "output/"
        self.mode = "interactive"
        # objects to manage various functionality
        self.checker = Checker(self)
        self.redis_man = RedisManager(self)
        self.ui_man = UIManager(self)
        self.metadata_man = MetadataManager(self)
        self.proc_man = ProcessManager(self)
        self.conf = ConfigParser()
        self.version = self.get_slips_version()
        # will be filled later
        self.commit = "None"
        self.branch = "None"
        self.last_updated_stats_time = datetime.now()
        self.input_type = False
        # in testing mode we manually set the following params
        if not testing:
            self.args = self.conf.get_args()
            self.pid = os.getpid()
            self.checker.check_given_flags()

            if not self.args.stopdaemon:
                # Check the type of input
                self.input_type, self.input_information, self.line_type = (
                    self.checker.check_input_type()
                )
                # If we need zeek (bro), test if we can run it.
                self.check_zeek_or_bro()
                self.prepare_output_dir()
                # this is the zeek dir slips will be using
                self.prepare_zeek_output_dir()
                self.twid_width = self.conf.get_tw_width()

    def cpu_profiler_init(self):
        self.cpuProfilerEnabled = self.conf.get_cpu_profiler_enable() == "yes"
        self.cpuProfilerMode = self.conf.get_cpu_profiler_mode()
        self.cpuProfilerMultiprocess = (
            self.conf.get_cpu_profiler_multiprocess() == "yes"
        )
        if self.cpuProfilerEnabled:
            try:
                if self.cpuProfilerMultiprocess and self.cpuProfilerMode == "dev":
                    args = sys.argv
                    if args[-1] != "--no-recurse":
                        tracer_entries = str(
                            self.conf.get_cpu_profiler_dev_mode_entries()
                        )
                        viz_args = [
                            "viztracer",
                            "--tracer_entries",
                            tracer_entries,
                            "--max_stack_depth",
                            "10",
                            "-o",
                            str(
                                os.path.join(
                                    self.args.output, "cpu_profiling_result.json"
                                )
                            ),
                        ]
                        viz_args.extend(args)
                        viz_args.append("--no-recurse")
                        print("Starting multiprocess profiling recursive subprocess")
                        subprocess.run(viz_args)
                        exit(0)
                else:
                    self.cpuProfiler = CPUProfiler(
                        db=self.db,
                        output=self.args.output,
                        mode=self.conf.get_cpu_profiler_mode(),
                        limit=self.conf.get_cpu_profiler_output_limit(),
                        interval=self.conf.get_cpu_profiler_sampling_interval(),
                    )
                    self.cpuProfiler.start()
            except Exception as e:
                print(e)
                self.cpuProfilerEnabled = False

    def cpu_profiler_release(self):
        if hasattr(self, "cpuProfilerEnabled"):
            if self.cpuProfilerEnabled and not self.cpuProfilerMultiprocess:
                self.cpuProfiler.stop()
                self.cpuProfiler.print()

    def memory_profiler_init(self):
        self.memoryProfilerEnabled = self.conf.get_memory_profiler_enable() == "yes"
        memoryProfilerMode = self.conf.get_memory_profiler_mode()
        memoryProfilerMultiprocess = (
            self.conf.get_memory_profiler_multiprocess() == "yes"
        )
        if self.memoryProfilerEnabled:
            output_dir = os.path.join(self.args.output, "memoryprofile/")
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            output_file = os.path.join(output_dir, "memory_profile.bin")
            self.memoryProfiler = MemoryProfiler(
                output_file,
                db=self.db,
                mode=memoryProfilerMode,
                multiprocess=memoryProfilerMultiprocess,
            )
            self.memoryProfiler.start()

    def memory_profiler_release(self):
        if hasattr(self, "memoryProfilerEnabled") and self.memoryProfilerEnabled:
            self.memoryProfiler.stop()

    def memory_profiler_multiproc_test(self):
        def target_function():
            print("Target function started")
            time.sleep(5)

        def mem_function():
            print("Mem function started")
            while True:
                time.sleep(1)
                array = []
                for i in range(1000000):
                    array.append(i)

        processes = []
        num_processes = 3

        for _ in range(num_processes):
            process = multiprocessing.Process(
                target=target_function if _ % 2 else mem_function
            )
            process.start()
            processes.append(process)

        # Message passing
        self.db.publish("memory_profile", processes[1].pid)  # successful
        # target_function will timeout and tracker will be cleared
        time.sleep(5)
        # end but maybe don't start
        self.db.publish("memory_profile", processes[0].pid)
        time.sleep(5)  # mem_function will get tracker started
        # start successfully
        self.db.publish("memory_profile", processes[0].pid)
        input()

    def get_slips_version(self):
        version_file = "VERSION"
        with open(version_file, "r") as f:
            version = f.read()
        return version

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
        if self.mode == "daemonized":
            self.daemon.stop()
        if self.conf.get_cpu_profiler_enable() != "yes":
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
        # We need to separate it from the path
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
        """returns true if zeek wa sused in this run"""
        return (
            self.db.get_input_type() in ("pcap", "interface")
            or self.db.is_growing_zeek_dir()
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
            os.path.basename(self.input_information),  # get pcap name from path
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

    def print(self, text, verbose=1, debug=0, log_to_logfiles_only=False):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by
        taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like f'Test {here}'
        """
        self.notify_observers(
            {
                "from": self.name,
                "txt": text,
                "verbose": verbose,
                "debug": debug,
                "log_to_logfiles_only": log_to_logfiles_only,
            }
        )

    def handle_flows_from_stdin(self, input_information):
        """
        Make sure the stdin line type is valid (argus, suricata, or zeek)
        """
        if input_information.lower() not in (
            "argus",
            "suricata",
            "zeek",
        ):
            print(f"[Main] Invalid file path {input_information}. Stopping.")
            sys.exit(-1)

        if self.mode == "daemonized":
            print("Can't read input from stdin in daemonized mode. " "Stopping")
            sys.exit(-1)
        line_type = input_information
        input_type = "stdin"
        return input_type, line_type.lower()

    def get_input_file_type(self, given_path):
        """
        given_path: given file
        returns binetflow, pcap, nfdump, zeek_folder, suricata, etc.
        """
        # default value
        input_type = "file"
        # Get the type of file
        cmd_result = subprocess.run(["file", given_path], stdout=subprocess.PIPE)
        # Get command output
        cmd_result = cmd_result.stdout.decode("utf-8")
        if (
            "pcap capture file" in cmd_result or "pcapng capture file" in cmd_result
        ) and os.path.isfile(given_path):
            input_type = "pcap"
        elif (
            "dBase" in cmd_result or "nfcap" in given_path or "nfdump" in given_path
        ) and os.path.isfile(given_path):
            input_type = "nfdump"
            if shutil.which("nfdump") is None:
                # If we do not have nfdump, terminate Slips.
                print("nfdump is not installed. terminating slips.")
                self.terminate_slips()
        elif "CSV" in cmd_result and os.path.isfile(given_path):
            input_type = "binetflow"
        elif "directory" in cmd_result and os.path.isdir(given_path):
            from slips_files.core.input import SUPPORTED_LOGFILES

            for log_file in os.listdir(given_path):
                # if there is at least 1 supported log file inside the
                # given directory, start slips normally
                # otherwise, stop slips
                if log_file.replace(".log", "") in SUPPORTED_LOGFILES:
                    input_type = "zeek_folder"
                    break
            else:
                # zeek dir filled with unsupported logs
                # or .labeled logs that slips can't read.
                print(
                    f"Log files in {given_path} are not supported \n"
                    f"Make sure all log files inside the given "
                    f"directory end with .log .. Stopping."
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
            if "flow_id" in first_line and os.path.isfile(given_path):
                input_type = "suricata"
            elif os.path.isfile(given_path):
                # this is a text file, it can be binetflow or zeek_log_file
                try:
                    # is it a json log file
                    json.loads(first_line)
                    input_type = "zeek_log_file"
                except json.decoder.JSONDecodeError:
                    # this is a tab separated file
                    # is it zeek log file or binetflow file?

                    # zeek tab files are separated by several spaces or tabs
                    sequential_spaces_found = re.search("\s{1,}-\s{1,}", first_line)
                    tabs_found = re.search("\t{1,}", first_line)

                    if "->" in first_line or "StartTime" in first_line:
                        # tab separated files are usually binetflow tab files
                        input_type = "binetflow-tabs"
                    elif sequential_spaces_found or tabs_found:
                        input_type = "zeek_log_file"

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

        # Limit any debuggisity to > 0
        self.args.debug = max(self.args.debug, 0)

    def print_version(self):
        slips_version = f"Slips. Version {green(self.version)}"
        branch_info = utils.get_branch_info()
        if branch_info is not False:
            # it's false when we're in docker because there's no .git/ there
            self.commit, self.branch = branch_info
            slips_version += f" ({self.commit[:8]})"
        print(slips_version)

    def update_stats(self):
        """
        updates the statistics shown next to the progress bar
         or shown in a new line
        """
        # for input of type : pcap, interface and growing
        # zeek directories, we prin the stats using slips.py
        # for other files, we print a progress bar +
        # the stats using outputprocess
        if not self.mode == "interactive":
            return

        # only update the stats every 5s
        now = datetime.now()
        if utils.get_time_diff(self.last_updated_stats_time, now, "seconds") < 5:
            return

        self.last_updated_stats_time = now
        now = utils.convert_format(now, "%Y/%m/%d %H:%M:%S")
        modified_ips_in_the_last_tw = self.db.get_modified_ips_in_the_last_tw()
        profilesLen = self.db.get_profiles_len()
        evidence_number = self.db.get_evidence_number() or 0
        msg = (
            f"Total analyzed IPs so far: "
            f"{green(profilesLen)}. "
            f"Evidence Added: {green(evidence_number)}. "
            f"IPs sending traffic in the last "
            f"{self.twid_width}: {green(modified_ips_in_the_last_tw)}. "
            f"({now})"
        )
        self.print(msg)

    def update_host_ip(self, hostIP: str, modified_profiles: Set[str]) -> str:
        """
        when running on an interface we keep track of the host IP.
        If there was no  modified TWs in the host IP, we check if the
        network was changed.
        """
        if self.is_interface and hostIP not in modified_profiles:
            if hostIP := self.metadata_man.get_host_ip():
                self.db.set_host_ip(hostIP)
        return hostIP

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

    def start(self):
        """Main Slips Function"""
        try:

            self.print_version()
            print("https://stratosphereips.org")
            print("-" * 27)

            self.setup_print_levels()

            # if stdout is redirected to a file,
            # tell output.py to redirect it's output as well
            current_stdout, stderr, slips_logfile = (
                self.checker.check_output_redirection()
            )
            self.stdout = current_stdout
            self.logger = self.proc_man.start_output_process(
                current_stdout, stderr, slips_logfile
            )
            self.add_observer(self.logger)

            # get the port that is going to be used for this instance of slips
            if self.args.port:
                self.redis_port = int(self.args.port)
                # close slips if port is in use
                self.redis_man.check_if_port_is_in_use(self.redis_port)
            elif self.args.multiinstance:
                self.redis_port = self.redis_man.get_random_redis_port()
                if not self.redis_port:
                    # all ports are unavailable
                    inp = input("Press Enter to close all ports.\n")
                    if inp == "":
                        self.redis_man.close_all_ports()
                    self.terminate_slips()
            else:
                # even if this port is in use, it will be overwritten by slips
                self.redis_port = 6379

            self.db = DBManager(self.logger, self.args.output, self.redis_port)
            self.db.set_input_metadata(
                {
                    "output_dir": self.args.output,
                    "commit": self.commit,
                    "branch": self.branch,
                }
            )

            self.cpu_profiler_init()
            self.memory_profiler_init()

            if self.args.growing:
                if self.input_type != "zeek_folder":
                    self.print(
                        f"Parameter -g should be using with "
                        f"-f <dirname> not a {self.input_type}. "
                        f"Ignoring -g"
                    )
                else:
                    self.print(
                        f"Running on a growing zeek dir:" f" {self.input_information}"
                    )
                    self.db.set_growing_zeek_dir()

            # log the PID of the started redis-server
            # should be here after we're sure that the server was started
            redis_pid = self.redis_man.get_pid_of_redis_server(self.redis_port)
            self.redis_man.log_redis_server_pid(self.redis_port, redis_pid)

            self.db.set_slips_mode(self.mode)

            if self.mode == "daemonized":
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

            self.print(
                f"Using redis server on " f"port: {green(self.redis_port)}", 1, 0
            )
            self.print(
                f'Started {green("Main")} process ' f"[PID {green(self.pid)}]", 1, 0
            )
            self.print("Starting modules", 1, 0)

            # if slips is given a .rdb file, don't load the
            # modules as we don't need them
            if not self.args.db:
                # update local files before starting modules
                # if wait_for_TI_to_finish is set to true in the config file,
                # slips will wait untill all TI files are updated before
                # starting the rest of the modules
                self.proc_man.start_update_manager(
                    local_files=True, TI_feeds=self.conf.wait_for_TI_to_finish()
                )
                self.proc_man.load_modules()

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

            self.metadata_man.enable_metadata()

            self.input_process = self.proc_man.start_input_process()

            # obtain the list of active processes
            self.proc_man.processes = multiprocessing.active_children()

            self.db.store_process_PID("slips.py", int(self.pid))
            self.metadata_man.set_input_metadata()

            if self.conf.use_p2p() and not self.args.interface:
                self.print(
                    "Warning: P2P is only supported using "
                    "an interface. Disabled P2P."
                )

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

            hostIP = self.metadata_man.store_host_ip()

            # Don't try to stop slips if it's capturing from
            # an interface or a growing zeek dir
            self.is_interface: bool = (
                self.args.interface or self.db.is_growing_zeek_dir()
            )

            while (
                not self.proc_man.should_stop()
                and not self.proc_man.slips_is_done_receiving_new_flows()
            ):
                # Sleep some time to do routine checks and give time for
                # more traffic to come
                time.sleep(5)

                # if you remove the below logic anywhere before the
                # above sleep() statement, it will try to get the return
                # value very quickly before
                # the webinterface thread sets it. so don't
                self.ui_man.check_if_webinterface_started()

                # update the text we show in the cli
                self.update_stats()

                # Check if we need to close any TWs
                self.db.check_TW_to_close()

                modified_profiles: Set[str] = (
                    self.metadata_man.update_slips_running_stats()[1]
                )
                hostIP: str = self.update_host_ip(hostIP, modified_profiles)

                # don't move this line up because we still need to print the
                # stats and check tws anyway
                if self.proc_man.should_run_non_stop():
                    continue

                self.db.check_health()

        except KeyboardInterrupt:
            # the EINTR error code happens if a signal occurred while
            # the system call was in progress
            # comes here if zeek terminates while slips is still working
            pass

        self.proc_man.shutdown_gracefully()
