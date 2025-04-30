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
from typing import (
    List,
    Tuple,
    Dict,
)

from exclusiveprocess import (
    Lock,
    CannotAcquireLock,
)
import multiprocessing


import modules
from modules.update_manager.update_manager import UpdateManager
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import (
    IModule,
)

from slips_files.common.style import green
from slips_files.core.evidence_handler import EvidenceHandler
from slips_files.core.input import Input
from slips_files.core.output import Output
from slips_files.core.profiler import Profiler


class ProcessManager:
    def __init__(self, main):
        self.main = main
        # this will be set by main.py if slips is not daemonized,
        # it'll be set to the children of main.py
        self.processes: Dict[str, Process]
        # this is the queue that will be used by the input proces
        # to pass flows to the profiler
        self.profiler_queue = Queue()
        self.termination_event: Event = Event()
        # to make sure we only warn the user once about
        # the pending modules
        self.warning_printed_once = False
        # this one has its own termination event because we want it to
        # shutdown at the very end of all other slips modules.
        self.evidence_handler_termination_event: Event = Event()
        self.stopped_modules = []
        # used to stop slips when these 2 are done
        # since the semaphore count is zero, slips.py will wait until another
        # thread (input and profiler)
        # release the semaphore. Once having the semaphore, then slips.py can
        # terminate slips.
        self.is_input_done = Semaphore(0)
        self.is_profiler_done = Semaphore(0)
        # is set by the profiler process to indicate that it's done so
        # input can shutdown no issue
        # now without this event, input process doesn't know that profiler
        # is still waiting for the queue to stop
        # and inout stops and renders the profiler queue useless and profiler
        # cant get more lines anymore!
        self.is_profiler_done_event = Event()
        self.read_config()

    def read_config(self):
        self.modules_to_ignore: list = self.main.conf.get_disabled_modules(
            self.main.input_type
        )
        self.bootstrap_p2p = self.main.conf.is_bootstrapping_node()
        self.bootstrapping_modules = self.main.conf.get_bootstrapping_modules()
        # self.bootstrap_p2p, self.boootstrapping_modules = self.main.conf.get_bootstrapping_setting()

    def start_output_process(self, stderr, slips_logfile, stdout=""):
        output_process = Output(
            stdout=stdout,
            stderr=stderr,
            slips_logfile=slips_logfile,
            verbose=self.main.args.verbose or 0,
            debug=self.main.args.debug,
            input_type=self.main.input_type,
            create_logfiles=False if self.main.args.stopdaemon else True,
        )
        self.slips_logfile = output_process.slips_logfile
        return output_process

    def start_profiler_process(self):
        profiler_process = Profiler(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
            is_profiler_done=self.is_profiler_done,
            profiler_queue=self.profiler_queue,
            is_profiler_done_event=self.is_profiler_done_event,
        )
        profiler_process.start()
        self.main.print(
            f'Started {green("Profiler Process")} '
            f"[PID {green(profiler_process.pid)}]",
            1,
            0,
        )
        self.main.db.store_pid("Profiler", int(profiler_process.pid))
        return profiler_process

    def start_evidence_process(self):
        evidence_process = EvidenceHandler(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.evidence_handler_termination_event,
        )
        evidence_process.start()
        self.main.print(
            f'Started {green("Evidence Process")} '
            f"[PID {green(evidence_process.pid)}]",
            1,
            0,
        )
        self.main.db.store_pid("EvidenceHandler", int(evidence_process.pid))
        return evidence_process

    def start_input_process(self):
        input_process = Input(
            self.main.logger,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
            is_input_done=self.is_input_done,
            profiler_queue=self.profiler_queue,
            input_type=self.main.input_type,
            input_information=self.main.input_information,
            cli_packet_filter=self.main.args.pcapfilter,
            zeek_or_bro=self.main.zeek_bro,
            zeek_dir=self.main.zeek_dir,
            line_type=self.main.line_type,
            is_profiler_done_event=self.is_profiler_done_event,
        )
        input_process.start()
        self.main.print(
            f'Started {green("Input Process")} '
            f"[PID {green(input_process.pid)}]",
            1,
            0,
        )
        self.main.db.store_pid("Input", int(input_process.pid))
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
        for process in self.processes:
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

    def is_ignored_module(self, module_name: str) -> bool:
        for ignored_module in self.modules_to_ignore:
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
        self.modules_to_ignore.append(module_name.split(".")[-1])
        return False

    def is_abstract_module(self, obj) -> bool:
        return obj.name in ("IModule", "AsyncModule")

    def get_modules(self):
        """
        Get modules from the 'modules' folder.
        """
        # This plugins import will automatically load the modules
        # and put them in the __modules__ variable
        plugins = {}
        failed_to_load_modules = 0

        # __path__ is the current path of this python program
        look_for_modules_in = modules.__path__
        prefix = f"{modules.__name__}."
        # Walk recursively through all modules and packages found on the .
        # folder.
        for loader, module_name, ispkg in pkgutil.walk_packages(
            look_for_modules_in, prefix
        ):
            # If current item is a package, skip.
            if ispkg:
                continue

            # to avoid loading everything in the dir,
            # only load modules that have the same name as the dir name
            dir_name = module_name.split(".")[1]
            file_name = module_name.split(".")[2]
            if dir_name != file_name:
                continue

            if self.bootstrap_p2p:  # if bootstrapping the p2p network
                if not self.is_bootstrapping_module(
                    module_name
                ):  # keep only the bootstrapping-necessary modules
                    continue
            else:  # if not bootstrappig mode
                if self.is_ignored_module(
                    module_name
                ):  # ignore blacklisted modules
                    continue

            # Try to import the module, otherwise skip.
            try:
                # "level specifies whether to use absolute or relative imports.
                # The default is -1 which
                # indicates both absolute and relative imports will
                # be attempted.
                # 0 means only perform absolute imports.
                # Positive values for level indicate the number of parent
                # directories to search relative to the directory of the
                # module calling __import__()."
                module = importlib.import_module(module_name)
            except ImportError as e:
                print(
                    f"Something wrong happened while "
                    f"importing the module {module_name}: {e}"
                )
                print(traceback.format_exc())
                failed_to_load_modules += 1
                continue

            # Walk through all members of currently imported modules.
            for member_name, member_object in inspect.getmembers(module):
                # Check if current member is a class.
                if inspect.isclass(member_object) and (
                    issubclass(member_object, IModule)
                    and not self.is_abstract_module(member_object)
                ):
                    plugins[member_object.name] = dict(
                        obj=member_object,
                        description=member_object.description,
                    )

        # Change the order of the blocking module(load it first)
        # so it can receive msgs sent from other modules
        if "Blocking" in plugins:
            plugins = OrderedDict(plugins)
            # last=False to move to the beginning of the dict
            plugins.move_to_end("Blocking", last=False)

        # when cyst starts first, as soon as slips connects to cyst,
        # cyst sends slips the flows,
        # but the inputprocess didn't even start yet so the flows are lost
        # to fix this, change the order of the CYST module(load it last)
        if "cyst" in plugins:
            plugins = OrderedDict(plugins)
            # last=False to move to the beginning of the dict
            plugins.move_to_end("cyst", last=True)

        return plugins, failed_to_load_modules

    def print_disabled_modules(self):
        print("-" * 27)
        self.main.print(f"Disabled Modules: {self.modules_to_ignore}", 1, 0)

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
            f"\t\tStarting the module {green(module_name)} "
            f"({module_description}) "
            f"[PID {green(module_pid)}]",
            1,
            0,
        )

    def print_stopped_module(self, module):
        self.stopped_modules.append(module)

        modules_left = len(self.processes) - len(self.stopped_modules)

        # to vertically align them when printing
        module += " " * (20 - len(module))
        self.main.print(
            f"\t{green(module)} \tStopped. " f"" f"{green(modules_left)} left."
        )

    def start_update_manager(self, local_files=False, ti_feeds=False):
        """
        starts the update manager process
        PS; this function is blocking, slips.py will not start the rest of the
         module unless this functionis done
        :kwarg local_files: if true, updates the local ports and
                org files from disk
        :kwarg ti_feeds: if true, updates the remote TI feeds.
            PS: this takes time.
        """
        try:
            # only one instance of slips should be able to update ports
            # and orgs at a time
            # so this function will only be allowed to run from 1 slips
            # instance.
            with Lock(name="slips_ports_and_orgs"):
                # pass a dummy termination event for update manager to
                # update orgs and ports info
                update_manager = UpdateManager(
                    self.main.logger,
                    self.main.args.output,
                    self.main.redis_port,
                    multiprocessing.Event(),
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
        if "Update Manager" in pending_module_names:
            self.main.print(
                "Update Manager may take several minutes "
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
            self.main.db.get_pid_of("EvidenceHandler"),
        ]

        if self.main.args.blocking:
            pids_to_kill_last.append(self.main.db.get_pid_of("Blocking"))

        if "exporting_alerts" not in self.main.db.get_disabled_modules():
            pids_to_kill_last.append(
                self.main.db.get_pid_of("Exporting Alerts")
            )

        # remove all None PIDs. this happens when a module in that list
        # isnt started in the current run.
        pids_to_kill_last: List[int] = [
            pid for pid in pids_to_kill_last if pid is not None
        ]

        # now get the process obj of each pid
        to_kill_first: List[Process] = []
        to_kill_last: List[Process] = []
        for process in self.processes:
            if process.pid in pids_to_kill_last:
                to_kill_last.append(process)
            elif isinstance(process, multiprocessing.context.ForkProcess):
                # skips the context manager of output.py, will close
                # it manually later
                # once all processes are closed
                continue
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

    def get_analysis_time(self) -> Tuple[str, str]:
        """
        Returns how long slips took to analyze the given file
        returns analysis_time in minutes and slips end_time as a date
        """
        start_time = self.main.db.get_slips_start_time()
        end_time = utils.convert_format(datetime.now(), "unixtimestamp")
        return (
            utils.get_time_diff(start_time, end_time, return_type="minutes"),
            end_time,
        )

    def stop_slips(self) -> bool:
        """
        determines whether slips should stop
        based on the following:
        1. is slips still receiving new flows? (checks input.py and
        profiler.py)
        2. did slips the control channel recv the stop_slips
        3. is a debugger present?
        """
        if self.should_run_non_stop():
            return False

        return (
            self.is_stop_msg_received() or self.is_done_receiving_new_flows()
        )

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
            and message["data"] == "stop_slips"
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
        return (
            self.is_debugger_active()
            or self.main.input_type in ("stdin", "cyst")
            or self.main.is_interface
        )

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
            self.is_profiler_done
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

    def shutdown_gracefully(self):
        """
        Wait for all modules to confirm that they're done processing
        or kill them after 15 mins
        """
        try:
            print = self.get_print_function()

            if not self.main.args.stopdaemon:
                print("\n" + "-" * 27)
            print("Stopping Slips")

            # by default, max 15 mins (taken from wait_for_modules_to_finish)
            # from this time, all modules should be killed
            method_start_time = time.time()

            # how long to wait for modules to finish in minutes
            timeout: float = self.main.conf.wait_for_modules_to_finish()
            # convert to seconds
            timeout *= 60

            # close all tws
            self.main.db.check_tw_to_close(close_all=True)

            graceful_shutdown = True
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

            if self.main.args.save:
                self.main.save_the_db()

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

            print(
                f"Analysis of {self.main.input_information} "
                f"finished in {analysis_time:.2f} minutes"
            )

            self.main.profilers_manager.cpu_profiler_release()
            self.main.profilers_manager.memory_profiler_release()

            self.main.db.close_redis_and_sqlite()
            if graceful_shutdown:
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

        except KeyboardInterrupt:
            return False
