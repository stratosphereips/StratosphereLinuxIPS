# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# ReportingMixin groups user-facing and log-facing output helpers used by
# ProcessManager during startup and shutdown.
from typing import Callable, Optional, Set

from modules.supported_module_names import Modules
from slips_files.common.startup_report import format_started_line
from slips_files.common.style import green, grey

# core processes get their own color in the startup progress report,
# to visually distinguish them from detection modules
CORE_PROCESSES = {
    Modules.MAIN,
    Modules.PROFILER,
    Modules.EVIDENCE_HANDLER,
    Modules.INPUT,
}


class ReportingMixin:
    """Provide printing and shutdown-report helpers."""

    disabled_modules_printed = False

    def print_disabled_modules(self) -> None:
        """
        Print the current disabled module list.
        """
        if self.disabled_modules_printed:
            return
        disabled_modules: Set[str | Modules] = (
            self.get_user_and_runtime_disabled_modules()
        )
        if not disabled_modules:
            return

        printable_modules = sorted(
            module.value if isinstance(module, Modules) else str(module)
            for module in disabled_modules
        )
        self.main.print(
            f"Disabled Modules: {grey(', '.join(printable_modules))}"
        )
        self.disabled_modules_printed = True

    def print_started_module(
        self,
        module_name: Modules,
        module_pid: int,
        module_description: str,
        started_count: int,
        total_modules: int,
    ) -> None:
        """
        Print a module startup message.

        Parameters:
            module_name: Module name.
            module_pid: Started module PID.
            module_description: Human-readable module description.
            started_count: How many modules have finished starting so
                far, including this one.
            total_modules: Total number of modules slips is starting.
        """
        category = "core" if module_name in CORE_PROCESSES else "module"
        line = format_started_line(
            module_name.value,
            started_count,
            total_modules,
            module_pid,
            module_description,
            category=category,
        )
        self.main.print(
            line,
            1,
            0,
            suppress_sender=True,
            is_final_startup_announcement=started_count >= total_modules,
        )

    def announce_started(
        self,
        module_name: Modules,
        pid: int,
        description: str,
        db,
    ) -> None:
        """
        Bump the shared startup counter and print this module/process's
        startup line. Used by detection modules and core processes
        (main, evidence handler, profiler, input) alike, so they all
        share one running "x/total" count.

        Parameters:
            module_name: Module or core process name.
            pid: Started process/module PID.
            description: Human-readable description.
            db: DB connection to increment the shared counter through.
                Must be a connection local to the calling process -
                each detection module has its own, since it runs in
                its own forked process.
        """
        started_count = db.increment_modules_started_count()
        self.print_started_module(
            module_name,
            pid,
            description,
            started_count,
            self.total_processes_to_start,
        )

    def print_stopped_module(
        self, module: Modules, total_modules: Optional[int] = None
    ) -> None:
        """
        Log that a module stopped and report the number still running.

        Parameters:
            module: Name of the stopped module.
            total_modules: Number of modules being stopped. Uses active
                children when omitted.
        """
        module_name = str(module)
        if module_name.casefold() in (
            stopped_module.casefold()
            for stopped_module in self.stopped_modules
        ):
            return

        self.stopped_modules.append(module_name)
        total_modules = (
            len(self.children) if total_modules is None else total_modules
        )
        modules_left = total_modules - len(self.stopped_modules)
        # to vertically align them when printing
        module_name += " " * (20 - len(module_name))
        self.main.print(
            f"\t{green(module_name)} \tStopped. {green(modules_left)} left."
        )

    def get_print_function(self) -> Callable:
        """
        Get the print function for the current Slips mode.

        Returns:
            Print function appropriate for the current mode.
        """
        if self.main.mode == "daemonized":
            return self.main.daemon.print
        return self.main.print

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
            return

        print(
            f"[Process Manager] Slips didn't shutdown gracefully - "
            f"{reason}\n",
            log_to_logfiles_only=True,
        )
