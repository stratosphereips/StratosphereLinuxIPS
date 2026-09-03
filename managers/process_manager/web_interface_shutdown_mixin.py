# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# WebInterfaceShutdownMixin groups the decisions, prompts, and cleanup
# needed to stop the local Slips web interface for ProcessManager.
import select
import sys
import time

from modules.supported_module_names import Modules
from modules.web_interface.web_interface import WebInterface
from slips_files.common.slips_utils import utils


class WebInterfaceShutdownMixin:
    """Provide web interface shutdown orchestration helpers."""

    def _is_web_interface_enabled(self) -> bool:
        """
        Check whether CLI or configuration enabled the local web interface.

        Returns:
            True when this run started the local web interface.
        """
        if getattr(self.main.args, "webinterface", False) is True:
            return True

        return self.main.conf.web_interface_enabled()

    def _should_defer_web_interface_stopped_message(
        self, module_name: object
    ) -> bool:
        """Defer the launcher status while its HTTP server remains available.

        Parameters:
            module_name: Name of the child process that exited.

        Returns:
            True when the detached web server is still running.
        """
        if str(module_name).casefold() != Modules.WEB_INTERFACE.value:
            return False
        if not self._is_web_interface_enabled():
            return False
        if self.main.web_interface_shutdown:
            return False
        port = int(self.main.conf.web_interface_port)
        return WebInterface.is_verified_server_running(port)

    def _report_web_interface_stopped(self) -> None:
        """Report the web interface only after its HTTP server has stopped."""
        self.deferred_stopped_modules.discard(Modules.WEB_INTERFACE.value)
        total_modules = max(
            len(getattr(self, "children", [])), len(self.stopped_modules) + 1
        )
        self.print_stopped_module(
            Modules.WEB_INTERFACE.value,
            total_modules=total_modules,
        )

    def _ask_to_stop_web_interface(self) -> bool:
        """
        Ask whether to stop the local web interface after analysis stops.

        Returns:
            True when the server should stop immediately.
        """
        if not sys.stdin or not sys.stdin.isatty():
            self.main.print(
                "No interactive console is available; stopping the web interface."
            )
            return True

        print(
            "Slips analysis has stopped. Stop the web interface? [y/N] ",
            end="",
            flush=True,
        )
        while not self.main.shutdown_signal_received:
            try:
                readable, _, _ = select.select([sys.stdin], [], [], 0.25)
            except (OSError, ValueError):
                return True
            if not readable:
                continue
            response = sys.stdin.readline()
            if response == "":
                return True
            return response.strip().lower() in {"y", "yes"}
        return True

    def _stop_web_interface(self, port: int) -> None:
        """
        Stop only the verified Slips web server on the configured port.

        Parameters:
            port: Configured HTTP port.
        """
        if WebInterface.stop_verified_server(port):
            self.main.web_interface_shutdown = True
            self._report_web_interface_stopped()
            return
        self.main.print(
            f"Could not stop the verified web interface on port {port}.",
            0,
            1,
        )

    def _should_force_stop_web_interface(
        self, natural_completion: bool
    ) -> bool:
        """
        Decide whether the web interface must stop without prompting.

        Parameters:
            natural_completion: Whether finite input completed without a stop signal.

        Returns:
            True when a forced or non-graceful shutdown requires an
            immediate stop.
        """
        keep_web_interface_available = (
            natural_completion or self.main.keyboard_interrupt_received
        )
        return (
            self.main.force_shutdown_requested
            or self.main.sigterm_received
            or not keep_web_interface_available
        )

    def _get_web_interface_display_host(self) -> str:
        """
        Resolve the host to show in the web interface's shutdown message.

        Returns:
            The bound interface's IP, or "localhost" when not bound to one.
        """
        bind_mode = getattr(self.main.conf, "web_interface_bind", "localhost")
        if not isinstance(bind_mode, str):
            bind_mode = "localhost"
        if bind_mode != "interface":
            return "localhost"
        for interface in utils.get_all_interfaces(self.main.args):
            candidate = self.main.db.get_host_ip(interface)
            if isinstance(candidate, str) and candidate:
                return candidate
        return "localhost"

    def _wait_until_web_interface_should_stop(self, port: int) -> None:
        """
        Block until the web server stops or a shutdown signal arrives.

        Parameters:
            port: Configured HTTP port.
        """
        try:
            while (
                WebInterface.is_verified_server_running(port)
                and not self.main.shutdown_signal_received
            ):
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.main.shutdown_signal_received = True

    def _handle_web_interface_after_analysis(
        self, natural_completion: bool
    ) -> None:
        """
        Prompt and wait after normal completion, or stop on forced shutdown.

        Parameters:
            natural_completion: Whether finite input completed without a stop signal.
        """
        if not self._is_web_interface_enabled():
            return
        port = int(self.main.conf.web_interface_port)
        if not WebInterface.is_verified_server_running(port):
            self.main.web_interface_shutdown = True
            self._report_web_interface_stopped()
            return

        if self._should_force_stop_web_interface(natural_completion):
            self._stop_web_interface(port)
            return

        # The first Ctrl-C stopped the analysis. It must not also cancel the
        # web-interface prompt; a later Ctrl-C remains a forced shutdown.
        self.main.shutdown_signal_received = False
        if self._ask_to_stop_web_interface():
            self._stop_web_interface(port)
            return

        display_host = self._get_web_interface_display_host()
        self.main.print(
            f"Web interface remains available at "
            f"http://{display_host}:{port}/. "
            "Press CTRL-C to stop it and exit Slips."
        )
        self._wait_until_web_interface_should_stop(port)
        self._stop_web_interface(port)
