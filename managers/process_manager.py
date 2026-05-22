# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import importlib
import inspect
import os
import pkgutil
import signal
import sys
import time
import traceback
from collections import OrderedDict
from datetime import datetime
from multiprocessing import (
    Queue,
    Event,
    Process,
    Semaphore,
)
from multiprocessing.process import BaseProcess
from typing import (
    List,
    Tuple,
    Callable,
)

from exclusiveprocess import (
    Lock,
    CannotAcquireLock,
)
import multiprocessing


import modules
from managers.update_manager import UpdateManager
from modules.feeds_update_manager.feeds_update_manager import (
    FeedsUpdateManager,
)
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import (
    IModule,
)
from slips_files.common.plotter import Plotter

from slips_files.common.style import green
from slips_files.common.input_type import InputType
from slips_files.core.evidence_handler import EvidenceHandler
from slips_files.core.helpers.bloom_filters_manager import BFManager
from slips_files.core.input import Input
from slips_files.core.output import Output
from slips_files.core.profiler import Profiler


class ProcessManager:
    """
    Responsible for starting and stopping all the slips processes and modules.
    Here's how the stopping of input.py and profiler.py works
    input.py
      -> realizes that no more flows are arriving
      -> puts "stop" in the profiler_queue
      -> is_input_done_event.set()
      -> waits on is_profiler_done_event

    profiler.py
      <- recvs is_input_done_event for normal input completion
      <- recvs is_input_failed_event for abnormal input failure
      -> waits/join() profiler workers

    profiler workers
      <- recvs the "stop" from the  profiler_queue
      -> exit

    profiler.py
      <- realizes that all workers exited
      -> is_profiler_done_semaphore.release()
      -> is_profiler_done_event.set()

    input.py
      <- is_profiler_done_event
      -> is_input_done.release()

    process_manager
      <- is_input_done
      <- is_profiler_done_semaphore
      -> Slips can finish shutdown

    """

    def __init__(self, main):
        self.main = main
        # Can be used by signal handlers before startup finishes.
        self.processes: List[Process] = []

        # this is the queue that will be used by the input process
        # to pass flows to the profiler
        # this max size is decided based on the avg size of each flow (650
        # bytes), and the max memory that this queue is allowed to
        # use (1GB), so 1321528 bytes will be 2033 flows in queue at max
        self.profiler_queue = Queue(maxsize=1321528)
        self.termination_event = Event()
        # to make sure we only warn the user once about
        # the pending modules
        self.warning_printed_once = False
        # this one has its own termination event because we want it to
        # shutdown at the very end of all other slips modules.
        self.evidence_handler_termination_event = Event()
        self.stopped_modules = []
        # used to stop slips when these 2 are done
        # since the semaphore count is zero, slips.py will wait until another
        # thread (input and profiler)
        # release the semaphore. Once having the semaphore, then slips.py can
        # terminate slips.
        self.is_input_done = Semaphore(0)
        # when profiler is done processing, it releases this semaphore,
        self.is_profiler_done_semaphore = Semaphore(0)
        # is set by the profiler process to indicate that it's done so
        # input can shutdown no issue
        # now without this event, input process doesn't know that profiler
        # is still waiting for the queue to stop
        # and inout stops and renders the profiler queue useless and profiler
        # cant get more lines any more!
        self.is_profiler_done_event = Event()
        self.is_profiler_done_starting_initial_workers_event = Event()
        # is set by the input process to indicate no more flows are coming
        # so profiler can safely begin shutdown/joins.
        self.is_input_done_event = Event()
        # is set by the input process when it stops because of a failure.
        self.is_input_failed_event = Event()
        self.is_slips_live_updating_event = Event()
        self.user_disabled_modules: List[str] = []
        self.slips_disabled_modules: List[str] = []
        self.read_config()
        self.all_children_started = False
        self.core_module_failure = False

    def read_config(self):
        self.bootstrapping_modules = self.main.conf.get_bootstrapping_modules()
        self.bootstrapping_node = self.main.conf.read_configuration(
            "global_p2p", "bootstrapping_node", False
        )
        self.use_global_p2p = self.main.conf.read_configuration(
            "global_p2p", "use_global_p2p", False
        )

    def _reading_flows_from_cyst(self) -> bool:
        """
        Check whether the selected input module is CYST.

        Returns:
            True when CYST is configured as the input module.
        """
        custom_flows = self.main.args.input_module
        return "cyst" in str(custom_flows)

    def get_disabled_modules(self) -> Tuple[List[str], List[str]]:
        """
        Get user-disabled modules and Slips-disabled modules.

        Returns:
            A tuple containing user-disabled modules and modules disabled by
            Slips runtime rules.
        """
        user_disabled_modules: List[str] = self.main.conf.read_configuration(
            "modules", "disable", ["template"]
        )
        user_disabled_modules = [
            module.strip() for module in user_disabled_modules
        ]

        is_running_non_stop = self.main.db.is_running_non_stop()

        slips_disabled_modules: List[str] = []

        if not self._is_exporting_module_enabled():
            slips_disabled_modules.append("exporting_alerts")

        use_p2p = self.main.conf.use_local_p2p()
        if not (use_p2p and is_running_non_stop):
            slips_disabled_modules.append("p2p_trust")

        use_global_p2p = self.main.conf.use_global_p2p()
        if not (use_global_p2p and is_running_non_stop):
            slips_disabled_modules.extend(("fides", "iris"))

        if not (
            self.main.conf.send_to_warden()
            or self.main.conf.receive_from_warden()
        ):
            slips_disabled_modules.append("cesnet")

        if not (self.main.args.clearblocking or self.main.args.blocking):
            slips_disabled_modules.extend(("blocking", "arp_poisoner"))

        if self.main.input_type != InputType.PCAP:
            slips_disabled_modules.append("leak_detector")

        if not self._reading_flows_from_cyst():
            slips_disabled_modules.append("cyst")

        for module in self.slips_disabled_modules:
            if module not in slips_disabled_modules:
                slips_disabled_modules.append(module)

        return user_disabled_modules, slips_disabled_modules

    def _is_exporting_module_enabled(self) -> bool:
        """
        Check whether alert exporting is configured.

        Returns:
            True when at least one supported alert exporter is enabled.
        """
        export_to = self.main.conf.export_to()
        return "stix" in export_to or "slack" in export_to

    def get_all_disabled_modules(self) -> List[str]:
        """
        Get all disabled modules as a single list.

        Returns:
            User-disabled modules followed by Slips-disabled modules.
        """
        return self.user_disabled_modules + self.slips_disabled_modules

    def declare_that_slips_done_starting_all_children(self):
        self.all_children_started = True

    def start_slips_update_manager(self):
        return UpdateManager(
            database=self.main.db,
            is_slips_live_updating_event=self.is_slips_live_updating_event,
            print_func=self.main.print,
        )

    def start_output_process(self, stderr, slips_logfile, stdout=""):
        output_process = Output(
            stdout=stdout,
            stderr=stderr,
            slips_logfile=slips_logfile,
            verbose=self.main.args.verbose or 0,
            debug=self.main.args.debug,
            input_type=self.main.input_type,
            create_logfiles=False if self.main.args.stopdaemon else True,
            slips_args=self.main.args,
        )
        self.slips_logfile = output_process.slips_logfile
        return output_process

    def start_profiler_process(self):
        profiler_process = Profiler(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
            self.main.args,
            self.main.conf,
            self.main.pid,
            self.main.bloom_filters_man,
            is_profiler_done_semaphore=self.is_profiler_done_semaphore,
            profiler_queue=self.profiler_queue,
            is_profiler_done_event=self.is_profiler_done_event,
            is_input_done_event=self.is_input_done_event,
            is_input_failed_event=self.is_input_failed_event,
            is_profiler_done_starting_initial_workers_event=self.is_profiler_done_starting_initial_workers_event,
        )
        profiler_process.start()
        self.main.print(
            f'Started {green("Profiler Process")} '
            f"[PID {green(profiler_process.pid)}]",
            1,
            0,
        )
        self.main.db.store_pid("Profiler", int(profiler_process.pid))
        # Interface input starts profiler workers before the input process
        # sends any flows. File-like inputs need the input process to send the
        # first message before the profiler can choose the input handler.
        if self.main.input_type == InputType.INTERFACE:
            self.is_profiler_done_starting_initial_workers_event.wait(30)
        self.profiler_process = profiler_process
        return profiler_process

    def start_evidence_process(self):
        evidence_process = EvidenceHandler(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.evidence_handler_termination_event,
            self.main.args,
            self.main.conf,
            self.main.pid,
            self.main.bloom_filters_man,
        )
        evidence_process.start()
        self.main.print(
            f'Started {green("Evidence Process")} '
            f"[PID {green(evidence_process.pid)}]",
            1,
            0,
        )
        self.main.db.store_pid("evidence_handler", int(evidence_process.pid))
        self.evidence_process = evidence_process
        return evidence_process

    def start_input_process(self):
        input_process = Input(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
            self.main.args,
            self.main.conf,
            self.main.pid,
            self.main.bloom_filters_man,
            is_input_done=self.is_input_done,
            profiler_queue=self.profiler_queue,
            input_type=self.main.input_type,
            input_information=self.main.input_information,
            cli_packet_filter=self.main.args.pcapfilter,
            zeek_or_bro=self.main.zeek_bro,
            line_type=self.main.line_type,
            is_profiler_done_event=self.is_profiler_done_event,
            is_input_done_event=self.is_input_done_event,
            is_input_failed_event=self.is_input_failed_event,
            is_slips_live_updating_event=self.is_slips_live_updating_event,
        )
        input_process.start()
        self.main.print(
            f'Started {green("Input Process")} '
            f"[PID {green(input_process.pid)}]",
            1,
            0,
        )
        self.main.db.store_pid("Input", int(input_process.pid))
        self.input_process = input_process
        return input_process

    def kill_process_tree(self, pid: int):
        try:
            # Send SIGKILL signal to the process
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass  # Ignore if the process doesn't exist or cannot be killed

        # Get the child processes of the current process
        try:
            process_list = os.popen(f"pgrep -P {pid}").read().splitlines()
        except Exception:
            process_list = []

        # Recursively kill the child processes
        for child_pid in process_list:
            self.kill_process_tree(int(child_pid))

    def kill_all_children(self):
        """
        kills all processes that are not done
        in self.processes and prints the name of stopped ones
        """
        for process in self.children:
            process: Process
            module_name: str = self.main.db.get_name_of_module_at(process.pid)
            if not module_name:
                # if it's a thread started by one of the modules or
                # by slips.py, we don't have it stored in
                # the db so just skip it
                continue
            if module_name in self.stopped_modules:
                # already stopped
                continue

            process.join(3)
            self.kill_process_tree(process.pid)
            self.print_stopped_module(module_name)

    def is_disabled_module(self, module_name: str) -> bool:
        """
        returns true if the given module is disabled by the user or by
        slips runtime
        """
        for ignored_module in self.get_all_disabled_modules():
            ignored_module = (
                ignored_module.replace(" ", "")
                .replace("_", "")
                .replace("-", "")
                .lower()
            )
            # this version of the module name wont contain
            # _ or spaces so we can
            # easily match it with the ignored module name
            curr_module_name = (
                module_name.replace("_", "").replace("-", "").lower()
            )
            if curr_module_name.__contains__(ignored_module):
                return True
        return False

    def is_bootstrapping_module(self, module_name: str) -> bool:
        m1 = (
            module_name.replace(" ", "")
            .replace("_", "")
            .replace("-", "")
            .lower()
        )
        for bootstrap_module in self.bootstrapping_modules:
            m2 = (
                bootstrap_module.replace(" ", "")
                .replace("_", "")
                .replace("-", "")
                .lower()
            )

            if m1.__contains__(m2):
                return True
        disabled_module = module_name.split(".")[-1]
        if disabled_module not in self.slips_disabled_modules:
            self.slips_disabled_modules.append(disabled_module)
        return False

    def is_bootstrapping_node(self) -> bool:
        """
        Check whether this Slips instance should run as a P2P bootstrap node.

        Returns:
            True when both bootstrapping and global P2P are enabled.
        """
        if not self.main.db.is_running_non_stop():
            return False

        return self.bootstrapping_node and self.use_global_p2p

    def is_abstract_module(self, obj) -> bool:
        return obj.name in ("imodule", "iasync_module")

    def get_modules(self):
        """
        get modules to load from the modules/ dir and ignore the ones in
        the disable param in the config file.
        Starts the blocking module only if --clearblocking in given
        and returns a list of modules to load in the correct order if
        applicable.
        """
        (
            self.user_disabled_modules,
            self.slips_disabled_modules,
        ) = self.get_disabled_modules()

        plugins = {}
        failed_to_load_modules = 0
        for module_name in self._discover_module_names():
            if not self._should_load_module(module_name):
                continue

            module = self._import_module(module_name)
            if not module:
                failed_to_load_modules += 1
                continue

            plugins = self._load_valid_classes_from_module(module, plugins)

        plugins = self._reorder_modules(plugins)
        return plugins, failed_to_load_modules

    def _reorder_modules(self, plugins):
        plugins = self._prioritize_blocking_modules(plugins)
        plugins = self._change_cyst_module_order(plugins)
        return plugins

    def _discover_module_names(self):
        """
        walk recursively through all modules and packages found in modules/
        """
        # __path__ is the current path of this python program
        look_for_modules_in = modules.__path__
        prefix = f"{modules.__name__}."

        for loader, module_name, ispkg in pkgutil.walk_packages(
            look_for_modules_in, prefix
        ):
            if ispkg:
                continue  # skip if current item is a package

            dir_name, file_name = module_name.split(".")[1:3]

            # to avoid loading everything in the dir,
            # only load modules that have the same name as the dir name
            if dir_name == file_name:
                yield module_name

    def _should_load_module(self, module_name: str) -> bool:
        if self.is_bootstrapping_node():
            # in this node slips only runs bootstrapping-necessary modules,
            # no detection modules are started.
            if not self.is_bootstrapping_module(module_name):
                return False
        else:
            if self.is_disabled_module(module_name):
                return False
        return True

    def _import_module(self, module_name):
        # try to import the module, otherwise return None
        try:
            # "level" specifies how importlib should resolve the module
            return importlib.import_module(module_name)
        except ImportError as e:
            print(
                f"Something wrong happened while importing the module"
                f" {module_name}: {e}"
            )
            print(traceback.format_exc())
            return None

    def _load_valid_classes_from_module(self, module, plugins):
        # walk through all members of the given module
        for member_name, member_object in inspect.getmembers(module):
            if inspect.isclass(member_object):
                if issubclass(
                    member_object, IModule
                ) and not self.is_abstract_module(member_object):
                    plugins[member_object.name] = {
                        "obj": member_object,
                        "description": member_object.description,
                    }
        return plugins

    def _prioritize_blocking_modules(self, plugins):
        """
        Changes the order of the blocking modules (`arp_poisoner` and
        `blocking`) to load them before the rest of the modules
        so they can receive msgs sent from other modules
        """
        blocking_modules = ("blocking", "arp_poisoner")

        at_least_one_blocking_module_is_loaded = False
        for module in blocking_modules:
            if module in plugins:
                at_least_one_blocking_module_is_loaded = True
                break
        if not at_least_one_blocking_module_is_loaded:
            return plugins

        # put the blocking modules at the top to start first
        ordered = OrderedDict(plugins)
        for module in blocking_modules:
            if module in plugins:
                # last=False to move to the beginning of the dict
                ordered.move_to_end(module, last=False)

        plugins.clear()
        plugins.update(ordered)
        return plugins

    def _change_cyst_module_order(self, plugins):
        # when cyst starts first, as soon as slips connects to cyst,
        # cyst sends slips the flows,
        # but the inputprocess didn't even start yet so the flows are lost
        # to fix this, change the order of the CYST module (load it last)
        if "cyst" not in plugins:
            return plugins

        ordered = OrderedDict(plugins)
        ordered.move_to_end(
            "cyst", last=True
        )  # last=True to move to the end of the dict
        plugins.clear()
        plugins.update(ordered)
        return plugins

    def print_disabled_modules(self):
        print("-" * 27)
        self.main.print(
            f"Disabled Modules: " f"{self.get_all_disabled_modules()}",
            1,
            0,
        )

    def load_modules(self):
        """responsible for starting all the modules in the modules/ dir"""
        modules_to_call = self.get_modules()[0]
        for module_name in modules_to_call:
            module_class = modules_to_call[module_name]["obj"]
            module = module_class(
                self.main.logger,
                self.main.args.output,
                self.main.redis_port,
                self.termination_event,
                self.main.args,
                self.main.conf,
                self.main.pid,
                self.main.bloom_filters_man,
            )
            module.start()
            self.main.db.store_pid(module_name, int(module.pid))
            self.print_started_module(
                module_name,
                module.pid,
                modules_to_call[module_name]["description"],
            )

    def print_started_module(
        self, module_name: str, module_pid: int, module_description: str
    ) -> None:
        self.main.print(
            f"\t\tStarting {green(module_name)} module "
            f"({module_description}) "
            f"[PID {green(module_pid)}]",
            1,
            0,
        )

    def print_stopped_module(self, module):
        self.stopped_modules.append(module)

        modules_left = len(self.children) - len(self.stopped_modules)

        # to vertically align them when printing
        module += " " * (20 - len(module))
        self.main.print(
            f"\t{green(module)} \tStopped. " f"" f"{green(modules_left)} left."
        )

    def init_bloom_filters_manager(self):
        """this instance is shared accross all slips IModule instances,
        because we dont wanna re-create the filters once for each process,
        this way is more memory efficient"""
        return BFManager(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.main.conf,
            self.main.pid,
        )

    def start_update_manager(self, local_files=False, ti_feeds=False):
        """
        starts the update manager process
        PS; this function is blocking, slips.py will not start the rest of the
         module unless this function's done
        :kwarg local_files: if true, updates the local ports and
                org files from disk
        :kwarg ti_feeds: if true, updates the remote TI feeds.
            PS: this takes time.
        """
        try:
            bloom_filters_man = getattr(self.main, "bloom_filters_man", None)
            # only one instance of slips should be able to update ports
            # and orgs at a time
            # so this function will only be allowed to run from 1 slips
            # instance.
            with Lock(name="slips_ports_and_orgs"):
                # pass a dummy termination event for update manager to
                # update orgs and ports info
                update_manager = FeedsUpdateManager(
                    self.main.logger,
                    self.main.args.output,
                    self.main.redis_port,
                    multiprocessing.Event(),
                    self.main.args,
                    self.main.conf,
                    self.main.pid,
                    bloom_filters_man,
                )

                if local_files:
                    update_manager.update_ports_info()
                    update_manager.update_org_files()
                    update_manager.update_local_whitelist()

                if ti_feeds:
                    update_manager.print("Updating TI feeds")
                    asyncio.run(update_manager.update_ti_files())

        except CannotAcquireLock:
            # another instance of slips is updating ports and orgs
            return

    def warn_about_pending_modules(self, pending_modules: List[Process]):
        """
        Prints the names of the modules that are not finished yet.
        :param pending_modules: List of active/pending process that aren't
        killed or stopped yet
        """
        if self.warning_printed_once:
            return

        pending_module_names: List[str] = [
            proc.name for proc in pending_modules
        ]
        self.main.print(
            f"The following modules are busy working on your data."
            f"\n\n{pending_module_names}\n\n"
            "You can wait for them to finish, or you can "
            "press CTRL-C again to force-kill.\n"
        )

        # check if update manager is still alive
        if "feeds_update_manager" in pending_module_names:
            self.main.print(
                "feeds_update_manager may take several minutes "
                "to finish updating 45+ TI files."
            )

        self.warning_printed_once = True
        return True

    def get_hitlist_in_order(self) -> Tuple[List[Process], List[Process]]:
        """
        returns a list of PIDs that slips should terminate first,
         and pids that should be killed last
        """
        # all modules that deal with evidence, blocking and alerts should
        # be killed last
        # so we don't miss exporting or blocking any malicious IoC
        # input and profiler are not in this list because they
        # indicate that they're done processing using a semaphore
        # slips won't reach this function unless they are done already.
        # so no need to kill them last
        pids_to_kill_last = [
            self.main.db.get_pid_of("evidence_handler"),
        ]

        if self.main.args.blocking:
            pids_to_kill_last.append(self.main.db.get_pid_of("blocking"))
            pids_to_kill_last.append(self.main.db.get_pid_of("arp_poisoner"))

        if "exporting_alerts" not in self.main.db.get_disabled_modules():
            pids_to_kill_last.append(
                self.main.db.get_pid_of("exporting_alerts")
            )
        # remove all None PIDs. this happens when a module in that list
        # isnt started in the current run. e.g. virustotal module starts then
        # stops immediately if no API is found. so its pid will be None.
        pids_to_kill_last: List[int] = [
            pid for pid in pids_to_kill_last if pid is not None
        ]

        # now get the process obj of each pid
        to_kill_first: List[Process] = []
        to_kill_last: List[Process] = []
        for process in self.children:
            if process.pid in pids_to_kill_last:
                to_kill_last.append(process)
            else:
                to_kill_first.append(process)

        return to_kill_first, to_kill_last

    def wait_for_processes_to_finish(
        self, processes_to_wait_for: List[Process]
    ) -> List[Process]:
        """
        :param processes_to_wait_for: list of PIDs to wait for
        :return: list of PIDs that still are not done yet
        """
        alive_processes: List[Process] = []
        # go through all processes to kill and see which
        # of them still need time
        for process in processes_to_wait_for:
            # wait 3s for it to stop
            process.join(3)

            if process.is_alive():
                # reached timeout
                alive_processes.append(process)
            else:
                self.print_stopped_module(process.name)

        return alive_processes

    def get_analysis_time(self) -> Tuple[float, str]:
        """
        Returns how long slips took to analyze the given file
        returns analysis_time in minutes and slips end_time as a date
        """
        start_time = self.main.db.get_slips_start_time()
        end_time = utils.convert_ts_format(datetime.now(), "unixtimestamp")
        return (
            utils.get_time_diff(start_time, end_time, return_type="minutes"),
            end_time,
        )

    def should_stop_slips(self) -> bool:
        """
        determines whether slips should stop
        based on the following:
        1. is slips still receiving new flows? (checks input.py and
        profiler.py)
        2. did the control channel recv the stop_slips
        3. is a debugger present?

        This function NEVER returns True if the input and profiler are
        still processing.
        """
        if self.is_slips_live_updating_event.is_set():
            # slips is auto updating this version of slips should stop and
            # the updated one will start soon
            return True

        if not self.all_children_started:
            # to avoid race conditions that happen when the input file is
            # very fast, that slips decides to stop before even all the
            # modules are up and running.
            # happens in dataset/test4-malicious.binetflow
            return False

        if self._did_a_core_module_fail():
            self.core_module_failure = True
            return True

        if self.is_stop_msg_received() or self.is_done_receiving_new_flows():
            return True

        return False

    def _did_a_core_module_fail(self) -> bool:
        """
        if one of the core modules crash or gets killed by the OS,
        then slips should stop immediately
        """

        input_exit_code = self.input_process.exitcode
        profiler_exit_code = self.profiler_process.exitcode
        evidence_exit_code = self.evidence_process.exitcode

        input_running = input_exit_code is None
        profiler_running = profiler_exit_code is None
        evidence_running = evidence_exit_code is None

        failed_modules: list[tuple[str, int | None]] = []

        if self.main.db.is_running_non_stop():
            # Slips is continuously receiving flows,
            # none of these modules should stop or "finish"
            if not input_running:
                failed_modules.append(("input", input_exit_code))
            if not profiler_running:
                failed_modules.append(("profiler", profiler_exit_code))
            if not evidence_running:
                failed_modules.append(("evidence", evidence_exit_code))
        else:
            # input can stop before the profiler  if it's done recving new
            # flows from the file it's reading.
            # but the profiler should never stop without the input. if it
            # did then something went wrong.
            if not profiler_running and input_running:
                failed_modules.append(("profiler", profiler_exit_code))

            if not evidence_running:
                failed_modules.append(("evidence", evidence_exit_code))

        for module_name, exit_code in failed_modules:
            self.main.print(
                f"Stopping Slips because a core module failed: "
                f"{module_name}, exit code: {exit_code}."
            )

        return bool(failed_modules)

    def is_stop_msg_received(self) -> bool:
        """
        returns true if the control_channel channel received the
        'stop_slips' msg
        This control channel is used by CYST or the filemanager to tell
        slips that zeek terminated (useful when running slips with -g)
        """
        message = self.main.c1.get_message(timeout=0.01)
        if not message:
            return False

        return (
            utils.is_msg_intended_for(message, "control_channel")
            and utils.get_msg_payload(message) == "stop_slips"
        )

    def is_debugger_active(self) -> bool:
        """Returns true if the debugger is currently active"""
        gettrace = getattr(sys, "gettrace", lambda: None)
        return gettrace() is not None

    def should_run_non_stop(self) -> bool:
        """
        determines if slips shouldn't terminate because by default,
        it terminates when there's no more incoming flows
        """
        # these are the cases where slips should be running non-stop
        # when slips is reading from a special module other than the input process
        # this module should handle the stopping of slips
        return self.is_debugger_active() or self.main.db.is_running_non_stop()

    def shutdown_interactive(
        self, to_kill_first, to_kill_last
    ) -> Tuple[List[Process], List[Process]]:
        """
        Shuts down modules in interactive mode only.
        it won't work with the daemon's -S because the
        processes aren't technically the children of the daemon
        returns 2 lists of alive children
        """
        # wait for the processes to be killed first as long as they want
        # maximum time to wait is timeout_seconds
        alive_processes = self.wait_for_processes_to_finish(to_kill_first)
        if alive_processes:
            # update the list of processes to kill first with only the ones
            # that are still alive
            to_kill_first: List[Process] = alive_processes

            # the 2 lists combined are all the children that are still alive
            # here to_kill_last are considered alive because we haven't tried
            # to join() em yet
            self.warn_about_pending_modules(alive_processes + to_kill_last)
            return to_kill_first, to_kill_last
        else:
            # all of them are killed
            to_kill_first = []
            # tell evidence to stop since all the modules are done
            self.evidence_handler_termination_event.set()

        alive_processes = self.wait_for_processes_to_finish(to_kill_last)
        if alive_processes:
            # update the list of processes to kill last with only the ones
            # that are still alive
            to_kill_last: List[Process] = alive_processes
            # the 2 lists combined are all the children that are still alive
            self.warn_about_pending_modules(alive_processes)
            return to_kill_first, to_kill_last

        # all of them are killed
        return None, None

    def can_acquire_semaphore(self, semaphore) -> bool:
        """
        return True if the given semaphore can be aquired
        """
        if semaphore.acquire(block=False):
            # ok why are we releasing after aquiring?
            # because once the module release the semaphore, this process
            # needs to be able to acquire it as many times as it wants,
            # not just once (which is what happens if we dont release)
            semaphore.release()
            return True
        return False

    def is_done_receiving_new_flows(self) -> bool:
        """
        Determines if slips is still receiving new flows.
        this method will return True when the input and profiler release
        the semaphores signaling that they're done
        If they're still processing (we can't acquire the semaphore),
        it will return False
        """
        # the goal of using can_acquire_semaphore()
        # is to avoid the race condition that happens when
        # one of the 2 semaphores (input and profiler) is released and
        # the other isnt
        input_done_processing: bool = self.can_acquire_semaphore(
            self.is_input_done
        )
        profiler_done_processing: bool = self.can_acquire_semaphore(
            self.is_profiler_done_semaphore
        )
        return input_done_processing and profiler_done_processing

    def kill_daemon_children(self):
        """
        kills the processes started by the daemon
        """
        # this method doesn't deal with self.processes bc they
        # aren't the daemon's children,
        # they are the children of the slips.py that ran using -D
        # (so they started on a previous run)
        # and we only have access to the PIDs
        children = self.main.db.get_pids().items()
        for module_name, pid in children:
            if "thread" in module_name.lower():
                # skip threads, they'll be  handled by their parent process
                continue
            self.kill_process_tree(int(pid))
            self.print_stopped_module(module_name)

    def get_print_function(self):
        """
        returns the print() function to use based on the curr slips mode
        because the daemon's print isn't the same as the normal slips' print()
        """
        if self.main.mode == "daemonized":
            return self.main.daemon.print
        else:
            return self.main.print

    def _generate_plots(self):
        if self.is_slips_live_updating_event:
            # slips is updating and will start a new instance, plots
            # should be done when slips is actually shutting down at the
            # very end of the analysis.
            return

        if self.main.conf.generate_performance_plots() is True:
            self.plotter = Plotter(self.main.args.output, print)
            self.plotter.plot_latency_csv()
            self.plotter.plot_profiler_latency_csvs()
            self.plotter.plot_throughput_csv()
            self.plotter.write_throughput_metrics()
            self.plotter.plot_flows_from_conn_log()

    def _print_shutdown_stats(
        self,
        graceful_shutdown: bool,
        analysis_time: float,
        reason: str,
        print: Callable,
    ) -> None:
        """
        Print the shutdown summary.

        Parameters:
            graceful_shutdown: Whether Slips finished without forcing modules.
            analysis_time: Analysis duration in minutes.
            reason: Explanation when shutdown was not graceful.
            print: Print function for the current Slips mode.

        Return value:
            None.
        """
        print(
            f"Analysis of {self.main.input_information} "
            f"finished in {analysis_time:.2f} minutes"
        )

        if graceful_shutdown:
            if self.is_slips_live_updating_event.is_set():
                print(
                    "[Process Manager] Slips is live updating, "
                    "Stopping this instance and starting the new "
                    "instance now.\n",
                    log_to_logfiles_only=True,
                )

            print(
                "[Process Manager] Slips shutdown gracefully\n",
                log_to_logfiles_only=True,
            )
        else:
            print(
                f"[Process Manager] Slips didn't "
                f"shutdown gracefully - {reason}\n",
                log_to_logfiles_only=True,
            )

    def shutdown_gracefully(self):
        """
        Waits for all modules to confirm that they're done processing
        or kills them after 15 mins
        """
        try:
            print = self.get_print_function()

            self._generate_plots()

            if not self.main.args.stopdaemon:
                print("\n" + "-" * 27)
            print("Stopping Slips")

            self.children: List[BaseProcess] = (
                multiprocessing.active_children()
            )
            method_start_time = time.time()

            # how long to wait for modules to finish in minutes before
            # killing them
            timeout: float = self.main.conf.wait_for_modules_to_finish()
            # convert to seconds
            timeout *= 60

            # dont close tws if we're updating, the next slips will continue
            # from where this slips left off.
            if not self.is_slips_live_updating_event.is_set():
                # close all tws
                self.main.db.check_tw_to_close(close_all=True)

            graceful_shutdown = True
            reason = ""
            if self.main.mode == "daemonized":
                self.kill_daemon_children()
                profiles_len: int = self.main.db.get_profiles_len()
                self.main.daemon.print(f"Total analyzed IPs: {profiles_len}.")
                self.main.daemon.delete_pidfile()

            else:
                flows_count: int = self.main.db.get_flows_count()
                print(
                    f"Total flows read (without altflows): " f"{flows_count}",
                    log_to_logfiles_only=True,
                )

                to_kill_first: List[Process]
                to_kill_last: List[Process]
                to_kill_first, to_kill_last = self.get_hitlist_in_order()

                self.termination_event.set()

                try:
                    if self.core_module_failure:
                        # dont wait for failed core modules to stop
                        self.kill_all_children()
                        reason = "Core module failure."
                        graceful_shutdown = False
                    else:
                        # Wait timeout_seconds for all the processes to finish
                        while time.time() - method_start_time < timeout:
                            (
                                to_kill_first,
                                to_kill_last,
                            ) = self.shutdown_interactive(
                                to_kill_first, to_kill_last
                            )
                            if not to_kill_first and not to_kill_last:
                                # all modules are done
                                break
                except KeyboardInterrupt:
                    # either the user wants to kill the remaining modules
                    # (pressed ctrl +c again)
                    # or slips was stuck looping for too long that the OS
                    # sent an automatic sigint to kill slips
                    # pass to kill the remaining modules
                    reason = "User pressed ctr+c or Slips was killed by the OS"
                    graceful_shutdown = False

                if time.time() - method_start_time >= timeout:
                    # getting here means we're killing them bc of the timeout
                    # not getting here means we're killing them bc of double
                    # ctr+c OR they terminated successfully
                    reason = (
                        f"Killing modules that took more than {timeout}"
                        f" mins to finish."
                    )
                    print(reason)
                    graceful_shutdown = False

                self.kill_all_children()

            if not self.is_slips_live_updating_event.is_set():
                if self.main.args.save:
                    self.main.save_the_db()
                if self.main.redis_man.should_save_redis_db_after_analysis():
                    self.main.redis_man.save_redis_db()
                if self.main.conf.export_labeled_flows():
                    format_ = self.main.conf.export_labeled_flows_to().lower()
                    self.main.db.export_labeled_flows(format_)

                # if store_a_copy_of_zeek_files is set to yes in slips.yaml
                # copy the whole zeek_files dir to the output dir
                self.main.store_zeek_dir_copy()
                # if delete_zeek_files is set to yes in slips.yaml,
                # delete zeek_files/ dir
                self.main.delete_zeek_files()

            analysis_time, end_date = self.get_analysis_time()
            self.main.metadata_man.set_analysis_end_date(end_date)

            self.main.profilers_manager.cpu_profiler_release()
            self.main.profilers_manager.memory_profiler_release()

            self.main.db.close_all_dbs()
            if not self.is_slips_live_updating_event.is_set():
                self.main.redis_man.stop_redis_server_after_analysis()

            self._print_shutdown_stats(
                graceful_shutdown, analysis_time, reason, print
            )

        except KeyboardInterrupt:
            return False
