# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# ReportingMixin groups user-facing and log-facing output helpers used by
# ProcessManager during startup and shutdown.
from typing import Callable, Optional, Set

from modules.supported_module_names import Modules
from slips_files.common.style import green


class ReportingMixin:
    """Provide printing and shutdown-report helpers."""

    def print_disabled_modules(self) -> None:
        """
        Print the current disabled module list.
        """
        disabled_modules: Set[Modules] = (
            self.get_user_and_runtime_disabled_modules()
        )
        printable_modules = [module.value for module in disabled_modules]
        print("-" * 27)
        self.main.print(
            f"Disabled Modules: {printable_modules}",
            1,
            0,
        )

    def print_started_module(
        self,
        module_name: Modules,
        module_pid: int,
        module_description: str,
    ) -> None:
        """
        Print a module startup message.

        Parameters:
            module_name: Module name.
            module_pid: Started module PID.
            module_description: Human-readable module description.
        """
        self.main.print(
            f"\t\tStarting {green(module_name)} module "
            f"({module_description}) "
            f"[PID {green(module_pid)}]",
            1,
            0,
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
