# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# ShutdownMixin groups termination decisions, waiting, process ordering,
# and final cleanup for ProcessManager.
import multiprocessing
import os
import signal
import sys
import time
from datetime import datetime
from multiprocessing import Process
from multiprocessing.process import BaseProcess
from typing import List, Optional, Tuple

from modules.supported_module_names import Modules
from slips_files.common.plotter import Plotter
from slips_files.common.slips_utils import utils
from slips_files.common.style import print_separator


class ShutdownMixin:
    """Provide shutdown orchestration and process cleanup helpers."""

    def kill_process_tree(self, pid: int) -> None:
        """
        Kill a process and its descendants.

        Parameters:
            pid: PID at the root of the process tree.
        """
        # Get descendants before killing their parent so they do not get
        # reparented and disappear from pgrep's results.
        try:
            process_list = os.popen(f"pgrep -P {pid}").read().splitlines()
        except Exception:
            process_list = []

        for child_pid in process_list:
            self.kill_process_tree(int(child_pid))

        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    def kill_all_children(self) -> None:
        """
        Kills all slips child processes.
        """
        for process in self.children:
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

    def warn_about_pending_modules(
        self, pending_modules: List[Process]
    ) -> Optional[bool]:
        """
        Print the names of modules that have not finished yet.

        Parameters:
            pending_modules: Active processes that are still pending.

        Returns:
            True when the warning was printed, otherwise None.
        """
        if self.warning_printed_once:
            return None

        pending_module_names: List[str] = [
            proc.name for proc in pending_modules
        ]
        self.main.print(
            "The following modules are busy working on your data."
            f"\n\n{pending_module_names}\n\n"
            "You can wait for them to finish, or you can "
            "press CTRL-C again to force-kill.\n"
        )

        self.warning_printed_once = True
        return True

    def get_hitlist_in_order(self) -> Tuple[List[Process], List[Process]]:
        """
        Get the process shutdown order.

        Returns:
            Processes to terminate first and processes to terminate last.
        """
        # all modules that deal with evidence, blocking and alerts should
        # be killed last
        # so we don't miss exporting or blocking any malicious IoC
        # input and profiler are not in this list because they
        # indicate that they're done processing using a semaphore
        # slips won't reach this function unless they are done already.
        # so no need to kill them last
        pids_to_kill_last = [self.main.db.get_pid_of("evidence_handler")]

        if self.main.args.blocking:
            pids_to_kill_last.append(self.main.db.get_pid_of(Modules.BLOCKING))
            pids_to_kill_last.append(
                self.main.db.get_pid_of(Modules.ARP_POISONER)
            )

        if Modules.EXPORTING_ALERTS not in self.main.db.get_disabled_modules():
            pids_to_kill_last.append(
                self.main.db.get_pid_of(Modules.EXPORTING_ALERTS)
            )
        # remove all None PIDs. this happens when a module in that list
        # isnt started in the current run. e.g. virustotal module starts then
        # stops immediately if no API is found. so its pid will be None.
        pids_to_kill_last = [
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
        Wait briefly for processes to exit.

        Parameters:
            processes_to_wait_for: Processes to wait for.

        Returns:
            Processes that remained alive after waiting.
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
        Get the elapsed analysis time and the end timestamp.

        Returns:
            Analysis time in minutes and end time as a date string.
        """
        start_time = self.main.db.get_slips_start_time()
        end_time = utils.convert_ts_format(datetime.now(), "unixtimestamp")
        return (
            utils.get_time_diff(start_time, end_time, return_type="minutes"),
            end_time,
        )

    def should_stop_slips(self) -> bool:
        """
        Determine whether Slips should stop.

        Returns:
            True when shutdown should begin.
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
        Check whether a core process has failed unexpectedly.

        Returns:
            True when any core module failure was detected.
        """
        input_exit_code = self.input_process.exitcode
        profiler_exit_code = self.profiler_process.exitcode
        evidence_exit_code = self.evidence_process.exitcode

        input_running = input_exit_code is None
        profiler_running = profiler_exit_code is None
        evidence_running = evidence_exit_code is None

        failed_modules: List[Tuple[str, Optional[int]]] = []

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
            # input can stop before the profiler if it's done receiving new
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
        Check whether a stop message was received on the control channel.

        Returns:
            True when the control channel requested shutdown.
        """
        message = self.main.c1.get_message(timeout=0.01)
        if not message:
            return False

        return (
            utils.is_msg_intended_for(message, "control_channel")
            and utils.get_msg_payload(message) == "stop_slips"
        )

    def is_debugger_active(self) -> bool:
        """
        Check whether a debugger is currently active.

        Returns:
            True when a debugger is attached.
        """
        gettrace = getattr(sys, "gettrace", lambda: None)
        return gettrace() is not None

    def should_run_non_stop(self) -> bool:
        """
        Determine whether Slips should keep running continuously.

        Returns:
            True when Slips should run non-stop.
        """
        # these are the cases where slips should be running non-stop
        # when slips is reading from a special module other than the input
        # process this module should handle the stopping of slips
        return self.is_debugger_active() or self.main.db.is_running_non_stop()

    def shutdown_interactive(
        self, to_kill_first: List[Process], to_kill_last: List[Process]
    ) -> Tuple[Optional[List[Process]], Optional[List[Process]]]:
        """
        Shut down children in interactive mode.

        Parameters:
            to_kill_first: Processes to stop before the final group.
            to_kill_last: Processes that should stop after the first group.

        Returns:
            Remaining first-group and last-group processes, or None values
            when all processes have stopped.
        """
        # wait for the processes to be killed first as long as they want
        # maximum time to wait is timeout_seconds
        alive_processes = self.wait_for_processes_to_finish(to_kill_first)
        if alive_processes:
            # the 2 lists combined are all the children that are still alive
            self.warn_about_pending_modules(alive_processes + to_kill_last)
            return alive_processes, to_kill_last

        to_kill_first = []
        # tell evidence to stop since all the modules are done
        self.evidence_handler_termination_event.set()

        alive_processes = self.wait_for_processes_to_finish(to_kill_last)
        if alive_processes:
            self.warn_about_pending_modules(alive_processes)
            return to_kill_first, alive_processes

        return None, None

    def _stop_llm_stack_if_llm_module_stopped(self):
        """
        Stop modules that depend on the shared LLM proxy after it dies.
        """
        if self.termination_event.is_set() or not self.main.conf.llm_enabled():
            # other parts of slips will take care of stopping the llm stack
            # now
            return

        llm_pid = self.main.db.get_pid_of(Modules.LLM_PROXY)
        if llm_pid is None:
            return

        try:
            # non distructive signal, checks if the pid is up
            os.kill(llm_pid, 0)
            # llm modules is up, dont shutdown stack.
            return
        except PermissionError:
            return
        except (ProcessLookupError, OSError):
            pass

        impacted_modules: List[Modules] = []
        stopped_modules = {Modules.LLM_PROXY}

        while True:
            modules_with_stopped_dependencies: List[Modules] = []
            for module_that_has_a_dependency in self.module_dependencies:
                if module_that_has_a_dependency in stopped_modules:
                    continue

                dependencies = self.get_module_dependencies(
                    module_that_has_a_dependency
                )
                # did any of the module's dependencies stop?
                if any(
                    dependency in stopped_modules
                    for dependency in dependencies
                ):
                    modules_with_stopped_dependencies.append(
                        module_that_has_a_dependency
                    )

            if not modules_with_stopped_dependencies:
                break

            for (
                module_that_has_a_stopped_dependency
            ) in modules_with_stopped_dependencies:
                stopped_modules.add(module_that_has_a_stopped_dependency)
                impacted_modules.append(module_that_has_a_stopped_dependency)

        # now actually stop the modules that have stopped dependencies
        stopped_module_names: List[str] = []
        for module_that_has_a_dependency in impacted_modules:
            if module_that_has_a_dependency.casefold() in (
                stopped_module.casefold()
                for stopped_module in self.stopped_modules
            ):
                continue

            module_pid = self.main.db.get_pid_of(module_that_has_a_dependency)
            if module_pid is None:
                continue

            self.kill_process_tree(module_pid)
            self.stopped_modules.append(str(module_that_has_a_dependency))
            stopped_module_names.append(str(module_that_has_a_dependency))

        if not stopped_module_names:
            return

        self.stopped_modules.append(str(Modules.LLM_PROXY))
        self.main.print(
            "Stopping modules because llm_proxy stopped: "
            f"{stopped_module_names}"
        )

    def health_check_modules(self):
        """checks for modules that should be stopped due to different
        conditions"""
        self._stop_llm_stack_if_llm_module_stopped()

    def can_acquire_semaphore(self, semaphore: object) -> bool:
        """
        Check whether a semaphore can be acquired without blocking.

        Parameters:
            semaphore: Semaphore object to probe.

        Returns:
            True when the semaphore can be acquired.
        """
        if semaphore.acquire(block=False):
            # ok why are we releasing after acquiring?
            # because once the module releases the semaphore, this process
            # needs to be able to acquire it as many times as it wants,
            # not just once (which is what happens if we dont release)
            semaphore.release()
            return True
        return False

    def is_done_receiving_new_flows(self) -> bool:
        """
        Determine whether input and profiler finished processing.

        Returns:
            True when both semaphores indicate processing is done.
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

    def kill_daemon_children(self) -> None:
        """
        Kill processes that were started by the daemon.
        """
        # this method doesn't deal with self.processes bc they
        # aren't the daemon's children,
        # they are the children of the slips.py that ran using -D
        # (so they started on a previous run)
        # and we only have access to the PIDs
        children = [
            (module_name, pid)
            for module_name, pid in self.main.db.get_pids().items()
            if "thread" not in module_name.lower()
        ]
        for module_name, pid in children:
            self.kill_process_tree(int(pid))
            self.print_stopped_module(module_name, total_modules=len(children))

    def _generate_plots(self) -> None:
        """
        Generate performance plots after analysis finishes.
        """
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

    def shutdown_gracefully(self) -> Optional[bool]:
        """
        Wait for modules to finish or kill them after the timeout.

        Returns:
            False when interrupted during shutdown, otherwise None.
        """
        try:
            print = self.get_print_function()

            self._generate_plots()

            if not self.main.args.stopdaemon:
                print_separator()

            print("Stopping Slips")

            self.children: List[BaseProcess] = (
                multiprocessing.active_children()
            )
            method_start_time = time.time()
            timeout: float = self.main.conf.wait_for_modules_to_finish()
            # convert to seconds
            timeout *= 60

            if not self.is_slips_live_updating_event.is_set():
                # close all tws
                self.main.db.check_tw_to_close(close_all=True)

            graceful_shutdown = True
            shutdown_reason = ""
            if self.main.mode == "daemonized":
                self.kill_daemon_children()
                profiles_len: int = self.main.db.get_profiles_len()
                self.main.daemon.print(f"Total analyzed IPs: {profiles_len}.")
                self.main.daemon.delete_pidfile()
            else:
                flows_count: int = self.main.db.get_flows_count()
                print(
                    f"Total flows read (without altflows): {flows_count}",
                    log_to_logfiles_only=True,
                )

                to_kill_first, to_kill_last = self.get_hitlist_in_order()
                self.termination_event.set()

                try:
                    if self.core_module_failure:
                        # dont wait for failed core modules to stop
                        self.kill_all_children()
                        shutdown_reason = "Core module failure."
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
                                break
                except KeyboardInterrupt:
                    # either the user wants to kill the remaining modules
                    # (pressed ctrl +c again)
                    # or slips was stuck looping for too long that the OS
                    # sent an automatic sigint to kill slips
                    # pass to kill the remaining modules
                    shutdown_reason = (
                        "User pressed ctr+c or Slips was killed by the OS"
                    )
                    graceful_shutdown = False

                if time.time() - method_start_time >= timeout:
                    # getting here means we're killing them bc of the timeout
                    # not getting here means we're killing them bc of double
                    # ctr+c OR they terminated successfully
                    shutdown_reason = (
                        f"Killing modules that took more than {timeout}"
                        f" mins to finish."
                    )
                    print(shutdown_reason)
                    graceful_shutdown = False

                self.kill_all_children()

            if not self.is_slips_live_updating_event.is_set():
                self.main.redis_man.decide_on_saving_and_killing_the_redis_db()

                if self.main.conf.export_labeled_flows():
                    format_ = self.main.conf.export_labeled_flows_to().lower()
                    self.main.db.export_labeled_flows(format_)

                self.main.store_zeek_dir_copy()
                self.main.delete_zeek_files()

            analysis_time, end_date = self.get_analysis_time()
            self.main.metadata_man.set_analysis_end_date(end_date)

            self.main.profilers_manager.cpu_profiler_release()
            self.main.profilers_manager.memory_profiler_release()

            self.main.db.close_all_dbs()
            if not self.is_slips_live_updating_event.is_set():
                self.main.redis_man.stop_redis_server_after_analysis()

            self._print_shutdown_stats(
                graceful_shutdown, analysis_time, shutdown_reason, print
            )
        except KeyboardInterrupt:
            return False
        return None
