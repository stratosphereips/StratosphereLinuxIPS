# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# ShutdownMixin groups termination decisions, waiting, process ordering,
# and final cleanup for ProcessManager.
import multiprocessing
import os
import select
import signal
import sys
import threading
import time
from datetime import datetime
from multiprocessing import Process
from multiprocessing.process import BaseProcess
from typing import Callable, List, Optional, Tuple

from modules.supported_module_names import Modules
from managers.process_manager.owned_processes import OwnedProcesses
from slips_files.common.input_type import InputType
from slips_files.common.plotter import Plotter
from slips_files.common.slips_utils import utils
from slips_files.common.style import print_separator

try:
    # the blocking module isn't shipped in every build (e.g. the light
    # Docker image), in which case there are no firewall rules to manage
    from modules.blocking.recovery import clear_firewall_recovery_state
    from modules.blocking.slips_chain_manager import (
        del_slips_blocking_chain,
        has_slips_firewall_rules,
    )
except ImportError:
    clear_firewall_recovery_state = None
    del_slips_blocking_chain = None
    has_slips_firewall_rules = None


class ShutdownMixin:
    """Provide shutdown orchestration and process cleanup helpers."""

    INTERRUPT_SHUTDOWN_GRACE_SECONDS = 30

    def _close_queues_owned_by_main(self) -> None:
        """
        Close the queues the main process created, once the workers that
        read from them have stopped. Anything still unread is dropped so
        that closing never blocks shutdown.
        """
        for queue in (
            self.profiler_queue,
            self.aid_queue,
            self.evidence_worker_queue,
            self.evidence_logger_q,
            self.main.logger._startup_queue,
        ):
            queue.cancel_join_thread()
            queue.close()

    def cleanup_failed_startup(self) -> None:
        """Stop and reap this run's workers after an incomplete startup."""
        self.children = multiprocessing.active_children()
        self._track_children_and_descendants()
        self._kill_tracked_processes()
        for process in self.children:
            process.join(1)

    def _set_stop_event_within_deadline(
        self, event: object, deadline: float
    ) -> bool:
        """
        Set a stop event to tell workers to stop, giving up at the deadline.

        event.set() can block forever when a worker died while holding the
        event's lock, so it runs in a helper thread that main only waits
        on until the deadline. Calling this again for the same event waits
        on the same thread instead of starting another one.

        Parameters:
            event: Stop event of the modules or of the evidence handler.
            deadline: Monotonic time at which the shutdown wait ends.

        Returns:
            True when the event was set before the deadline.
        """
        # event id -> (thread setting that event, errors it raised)
        setter_threads = getattr(self, "_stop_event_setter_threads", None)
        if setter_threads is None:
            setter_threads = self._stop_event_setter_threads = {}
        event_id = id(event)
        if event_id not in setter_threads:
            errors = []

            def set_event() -> None:
                """Set the event and keep any error for the main thread."""
                try:
                    event.set()
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(
                target=set_event,
                daemon=True,
                name=f"stop_event_setter_{len(setter_threads)}",
            )
            setter_threads[event_id] = (thread, errors)
            utils.start_thread(thread, self.main.db)
        thread, errors = setter_threads[event_id]
        thread.join(max(0.0, deadline - time.monotonic()))
        if thread.is_alive() or errors:
            self.main.print(
                "Could not deliver the stop signal before the shutdown deadline; "
                "terminating the remaining workers.",
                0,
                1,
            )
            return False
        return True

    def kill_process_tree(self, pid: int) -> None:
        """
        Kill a process and its descendants.

        Parameters:
            pid: PID at the root of the process tree.
        """
        process_tree = OwnedProcesses()
        process_tree.track(pid)
        process_tree.kill_all()

    def _track_children_and_descendants(self) -> None:
        """
        Record the PIDs of all Slips children and of every subprocess they
        started (e.g. zeek, the web server), so that
        _kill_tracked_processes() can still find them later.

        A subprocess whose module exits is handed over to init, after
        which it can't be reached through that module anymore. So this is
        called before waiting on the modules, and again on every round of
        the wait to pick up subprocesses started in the meantime.
        """
        if not hasattr(self, "_tracked_processes"):
            self._tracked_processes = OwnedProcesses()
        for process in [*self.processes, *getattr(self, "children", [])]:
            if isinstance(process.pid, int):
                self._tracked_processes.track(process.pid)
        self._tracked_processes.track_new_descendants()

    def _kill_tracked_processes(
        self, keep_web_interface: bool = False
    ) -> None:
        """
        Kill every process recorded by _track_children_and_descendants()
        that is still running, and check that none survived.

        This is what catches subprocesses left behind by a module that
        already exited. CTRL-C is ignored while it runs, so the user can't
        interrupt it halfway and leave processes behind.

        Parameters:
            keep_web_interface: Leave the web interface server running,
                because the user is asked later whether to stop it.
        """
        tracked_processes = getattr(self, "_tracked_processes", None)
        if tracked_processes is None:
            return
        web_server_pid = (
            self.main.db.get_pid_of("Web Interface")
            if keep_web_interface
            else None
        )
        pids_to_keep = (
            frozenset({web_server_pid})
            if isinstance(web_server_pid, int)
            else frozenset()
        )
        previous_sigint_handler = None
        if threading.current_thread() is threading.main_thread():
            previous_sigint_handler = signal.signal(
                signal.SIGINT, signal.SIG_IGN
            )
        try:
            tracked_processes.kill_all(pids_to_keep)
        finally:
            if previous_sigint_handler is not None:
                signal.signal(signal.SIGINT, previous_sigint_handler)

    def kill_all_children(self, force: bool = False) -> None:
        """
        Kill remaining Slips children, skipping another wait after timeout.

        Parameters:
            force: Kill living children immediately after the grace period.
        """
        self._track_children_and_descendants()
        self._kill_tracked_processes(keep_web_interface=True)
        for process in self.children:
            module_name = process.name
            # its "stopped" message was already printed or is delayed
            already_handled = (
                module_name in self.stopped_modules
                or module_name in self.modules_with_delayed_stopped_msg
            )
            if already_handled and not process.is_alive():
                continue

            if not force:
                process.join(3)
            if process.is_alive():
                self.kill_process_tree(process.pid)
                process.join(1 if force else 3)
            if already_handled:
                continue
            if self._should_delay_web_interface_stopped_msg(module_name):
                self.modules_with_delayed_stopped_msg.add(module_name)
                continue
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

        if Modules.FEEDS_UPDATE_MANAGER in pending_module_names:
            self.main.print(
                f"{Modules.FEEDS_UPDATE_MANAGER} may take a few minutes "
                "to finish updating TI feeds before it can stop."
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
        self,
        processes_to_wait_for: List[Process],
        deadline: Optional[float] = None,
    ) -> List[Process]:
        """
        Wait briefly for processes to exit.

        Parameters:
            processes_to_wait_for: Processes to wait for.
            deadline: Monotonic deadline for an interrupt-driven shutdown.

        Returns:
            Processes that remained alive after waiting.
        """
        alive_processes: List[Process] = []
        # go through all processes to kill and see which
        # of them still need time
        for process in processes_to_wait_for:
            seconds_to_wait = (
                3
                if deadline is None
                else max(0, min(0.25, deadline - time.monotonic()))
            )
            process.join(seconds_to_wait)

            if process.is_alive():
                # reached timeout
                alive_processes.append(process)
            elif self._should_delay_web_interface_stopped_msg(process.name):
                self.modules_with_delayed_stopped_msg.add(str(process.name))
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
            self.shutdown_cause = "live_update"
            return True

        if not self.all_children_started:
            # to avoid race conditions that happen when the input file is
            # very fast, that slips decides to stop before even all the
            # modules are up and running.
            # happens in dataset/test4-malicious.binetflow
            return False

        if self._did_a_core_module_fail():
            self.core_module_failure = True
            self.shutdown_cause = "core_failure"
            return True

        if self.is_stop_msg_received():
            self.shutdown_cause = "control"
            return True

        if self.is_done_receiving_new_flows():
            self.shutdown_cause = "natural"
            return True

        return False

    def install_shutdown_signal_handlers(self) -> None:
        """
        Install handlers for SIGTERM, SIGHUP, and SIGQUIT so Slips starts
        a graceful shutdown instead of dying immediately.
        """
        main_pid = self.main.pid

        def sig_handler(sig: int, frame: object) -> None:
            """
            Record a termination signal for forced shutdown.

            Parameters:
                sig: Numeric signal received by the main process.
                frame: Interpreter frame active when the signal arrived.
            """
            if os.getpid() != main_pid:
                # Children created after this handler is installed inherit
                # it, but only the main process coordinates shutdown.
                return

            if self.shutdown_signal_received:
                return

            self.shutdown_signal_received = True
            self.sigterm_received = sig == signal.SIGTERM
            signal_name = signal.Signals(sig).name
            self.main.print(f"{signal_name} received, shutting down Slips.")
            self.main.print(
                "Slips is stopping without completing the analysis.",
                0,
                1,
            )

        for handled_signal in (
            signal.SIGTERM,
            signal.SIGHUP,
            signal.SIGQUIT,
        ):
            signal.signal(handled_signal, sig_handler)

    def handle_keyboard_interrupt(self) -> None:
        """
        Record that shutdown was triggered by an interactive Ctrl-C in
        the main loop.
        """
        self.keyboard_interrupt_received = True
        self.shutdown_signal_received = True
        self.main.print("Interrupt received, shutting down Slips.")

    def _did_slips_finish_normally(self) -> bool:
        """
        Decide whether analysis finished on its own, without a shutdown
        signal (Ctrl-C, SIGTERM, SIGHUP, SIGQUIT) cutting it short.

        Returns:
            True when the finite input ran to completion undisturbed.
        """
        return (
            not self.shutdown_signal_received
            and self.shutdown_cause == "natural"
        )

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

        stdin_finished = (
            self.main.input_type == InputType.STDIN
            and self.is_input_done_event.is_set()
        )
        if self.main.db.is_running_non_stop() and not stdin_finished:
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
        stdin_finished = (
            self.main.input_type == InputType.STDIN
            and self.is_input_done_event.is_set()
        )
        return self.is_debugger_active() or (
            self.main.db.is_running_non_stop() and not stdin_finished
        )

    def shutdown_interactive(
        self,
        to_kill_first: List[Process],
        to_kill_last: List[Process],
        deadline: Optional[float] = None,
    ) -> Tuple[Optional[List[Process]], Optional[List[Process]]]:
        """
        Shut down children in interactive mode.

        Parameters:
            to_kill_first: Processes to stop before the final group.
            to_kill_last: Processes that should stop after the first group.
            deadline: Monotonic deadline for an interrupt-driven shutdown.

        Returns:
            Remaining first-group and last-group processes, or None values
            when all processes have stopped.
        """
        # wait for the processes to be killed first as long as they want
        # maximum time to wait is timeout_seconds
        alive_processes = self.wait_for_processes_to_finish(
            to_kill_first, deadline
        )
        if alive_processes:
            # the 2 lists combined are all the children that are still alive
            self.warn_about_pending_modules(alive_processes + to_kill_last)
            return alive_processes, to_kill_last

        to_kill_first = []
        # tell evidence to stop since all the modules are done
        stop_event_deadline = (
            deadline
            if deadline is not None
            else time.monotonic() + self.INTERRUPT_SHUTDOWN_GRACE_SECONDS
        )
        if not self._set_stop_event_within_deadline(
            self.evidence_handler_termination_event, stop_event_deadline
        ):
            return to_kill_first, to_kill_last

        alive_processes = self.wait_for_processes_to_finish(
            to_kill_last, deadline
        )
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
            f"Stopping modules because llm_proxy stopped: {stopped_module_names}"
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

    def _ask_to_keep_firewall_rules(self) -> bool:
        """Ask whether managed firewall rules should survive Slips shutdown.

        Returns:
            True when rules should remain installed, false when deleted.
        """
        if not sys.stdin or not sys.stdin.isatty():
            self.main.print(
                "No interactive console is available; keeping Slips "
                "firewall rules."
            )
            return True
        print(
            "Slips is stopping. Keep the installed firewall rules? [Y/n] ",
            end="",
            flush=True,
        )
        while not self.shutdown_signal_received:
            try:
                readable, _, _ = select.select([sys.stdin], [], [], 0.25)
            except (OSError, ValueError):
                return True
            if not readable:
                continue
            response = sys.stdin.readline()
            if response == "":
                return True
            return response.strip().lower() not in {"n", "no", "d", "delete"}
        return True

    def is_forced_shutdown(self) -> bool:
        """
        Whether shutdown must proceed without any interactive prompts
        (e.g. keep firewall rules? keep the web interface running?).

        Returns:
            True on an unattended SIGTERM, or when the user forced an
            immediate shutdown with a second Ctrl-C.
        """
        return self.force_shutdown_requested or self.sigterm_received

    def _handle_firewall_after_analysis(self) -> None:
        """Keep or remove managed firewall rules after an interactive run."""
        if has_slips_firewall_rules is None or not has_slips_firewall_rules():
            return

        cant_ask_user = (
            self.main.mode == "daemonized" or self.is_forced_shutdown()
        )
        if cant_ask_user:
            self.main.print(
                "Slips firewall rules remain installed after forced shutdown."
            )
            return

        # The first Ctrl-C initiated graceful shutdown and must not cancel this
        # explicit keep/delete decision.
        self.shutdown_signal_received = False
        if self._ask_to_keep_firewall_rules():
            self.main.print("Keeping Slips firewall rules after shutdown.")
            return

        if not del_slips_blocking_chain():
            self.main.print("Unable to delete the Slips firewall rules.", 0, 1)
            return

        clear_firewall_recovery_state(self.main.db)
        self.main.print("Deleted Slips firewall rules and recovery state.")

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

    def _get_module_shutdown_timeout(self) -> float:
        """
        Get how long shutdown waits for modules to stop. A shutdown started
        by a signal (e.g. CTRL-C) never waits more than
        INTERRUPT_SHUTDOWN_GRACE_SECONDS, even if the configured wait is
        longer.

        Returns:
            Maximum seconds to wait for the modules to stop.
        """
        configured = float(self.main.conf.wait_for_modules_to_finish()) * 60
        if self.shutdown_signal_received:
            return min(configured, self.INTERRUPT_SHUTDOWN_GRACE_SECONDS)
        return configured

    def _wait_for_modules_to_stop(
        self,
        to_kill_first: List[Process],
        to_kill_last: List[Process],
        deadline: float,
    ) -> None:
        """
        Keep waiting for the modules to stop until the deadline passes.

        Parameters:
            to_kill_first: Processes to stop before the final group.
            to_kill_last: Processes that should stop after the first group.
            deadline: Monotonic time at which the shutdown wait ends.
        """
        while time.monotonic() < deadline:
            self._track_children_and_descendants()
            to_kill_first, to_kill_last = self.shutdown_interactive(
                to_kill_first, to_kill_last, deadline
            )
            if not to_kill_first and not to_kill_last:
                break

    def _stop_modules_within_deadline(
        self, deadline: float, timeout: float, print: Callable
    ) -> str:
        """
        Tell the modules to stop and wait for them until the deadline.

        Parameters:
            deadline: Monotonic time at which the shutdown wait ends.
            timeout: Seconds the modules were given to stop.
            print: Print function for the current Slips mode.

        Returns:
            Why the remaining modules have to be killed, or an empty
            string when they all stopped in time.
        """
        shutdown_reason = ""
        to_kill_first, to_kill_last = self.get_hitlist_in_order()
        stop_event_was_set = self._set_stop_event_within_deadline(
            self.termination_event, deadline
        )
        try:
            if self.core_module_failure or not stop_event_was_set:
                # dont wait for failed core modules to stop
                self.kill_all_children(force=True)
                shutdown_reason = (
                    "Core module failure."
                    if self.core_module_failure
                    else "Worker stop notification failed."
                )
                self.force_shutdown_requested = True
            else:
                self._wait_for_modules_to_stop(
                    to_kill_first, to_kill_last, deadline
                )
        except KeyboardInterrupt:
            # either the user wants to kill the remaining modules
            # (pressed ctrl +c again)
            # or slips was stuck looping for too long that the OS
            # sent an automatic sigint to kill slips
            # pass to kill the remaining modules
            shutdown_reason = (
                "User pressed ctr+c or Slips was killed by the OS"
            )
            self.shutdown_signal_received = True
            self.force_shutdown_requested = True
        if time.monotonic() >= deadline:
            # getting here means we're killing them bc of the timeout
            # not getting here means we're killing them bc of double
            # ctr+c OR they terminated successfully
            shutdown_reason = (
                f"Killing modules that did not stop within "
                f"{timeout:g} seconds."
            )
            print(shutdown_reason)
            self.force_shutdown_requested = True
        return shutdown_reason

    def _wrap_up_analysis(self, normal_completion: bool) -> float:
        """
        Store the results and release what the analysis used, once the
        modules are stopped.

        Parameters:
            normal_completion: Whether Slips finished without being forced.

        Returns:
            Analysis duration in minutes.
        """
        analysis_time, end_date = self.get_analysis_time()
        self.main.metadata_man.set_analysis_end_date(end_date)
        self._handle_firewall_after_analysis()
        self._handle_web_interface_after_analysis(normal_completion)

        if not self.is_slips_live_updating_event.is_set():
            self.main.redis_man.decide_on_saving_and_killing_the_redis_db()

            if self.main.conf.export_labeled_flows():
                format_ = self.main.conf.export_labeled_flows_to().lower()
                self.main.db.export_labeled_flows(format_)

            self.main.store_zeek_dir_copy()
            self.main.delete_zeek_files()

        self.main.profilers_manager.cpu_profiler_release()
        self.main.profilers_manager.memory_profiler_release()

        self.main.db.close_all_dbs()
        if not self.is_slips_live_updating_event.is_set():
            self.main.redis_man.stop_redis_server_after_analysis()
        return analysis_time

    def _force_stop_after_interrupted_shutdown(self) -> None:
        """Kill the workers and the web interface when shutdown is cut short."""
        self.shutdown_signal_received = True
        self.force_shutdown_requested = True
        self.children = multiprocessing.active_children()
        self.kill_all_children(force=True)
        if self._is_web_interface_enabled():
            port = int(self.main.conf.web_interface_port)
            self._stop_web_interface(port)

    def shutdown_gracefully(self) -> Optional[bool]:
        """
        Wait for modules to finish or kill them after the timeout.

        Returns:
            False when interrupted during shutdown, otherwise None.
        """
        normal_completion = self._did_slips_finish_normally()
        try:
            self.children = multiprocessing.active_children()
            self._track_children_and_descendants()
            print = self.get_print_function()
            self.main.logger._flush_startup_queue()

            self._generate_plots()

            print_separator()

            print("Stopping Slips")

            self.main.flow_cleanup_man.shutdown()
            self.main.log_rotation_man.shutdown()

            self.children: List[BaseProcess] = (
                multiprocessing.active_children()
            )
            method_start_time = time.monotonic()
            timeout = self._get_module_shutdown_timeout()
            if self.shutdown_signal_received:
                print(
                    f"Waiting up to {timeout:g} seconds for modules to stop. "
                    "Press CTRL-C again to force an immediate stop."
                )
            deadline = method_start_time + timeout

            if not self.is_slips_live_updating_event.is_set():
                # close all tws
                self.main.db.check_tw_to_close(close_all=True)

            flows_count: int = self.main.db.get_flows_count()
            print(
                f"Total flows read (without altflows): {flows_count}",
                log_to_logfiles_only=True,
            )

            shutdown_reason = self._stop_modules_within_deadline(
                deadline, timeout, print
            )
            graceful_shutdown = not shutdown_reason
            normal_completion = normal_completion and graceful_shutdown

            self.kill_all_children(force=not graceful_shutdown)
            if self.main.mode == "daemonized":
                self.main.daemon.delete_pidfile()

            analysis_time = self._wrap_up_analysis(normal_completion)
            self._print_shutdown_stats(
                graceful_shutdown, analysis_time, shutdown_reason, print
            )
        except KeyboardInterrupt:
            self._force_stop_after_interrupted_shutdown()
            return False
        finally:
            self._kill_tracked_processes()
            # These queues are owned by the main process. Close them after
            # children have stopped so their pipe handles do not survive
            # until interpreter shutdown.
            self._close_queues_owned_by_main()
        return None
