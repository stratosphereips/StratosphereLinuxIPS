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
        accessor = getattr(self.main.conf, "web_interface_enabled", None)
        return callable(accessor) and accessor() is True

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
        if getattr(self.main, "web_interface_shutdown", False):
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
        while not getattr(self.main, "shutdown_signal_received", False):
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
        keep_web_interface_available = natural_completion or getattr(
            self.main, "keyboard_interrupt_received", False
        )
        if (
            getattr(self.main, "force_shutdown_requested", False) is True
            or getattr(self.main, "sigterm_received", False) is True
            or not keep_web_interface_available
        ):
            self._stop_web_interface(port)
            return

        # The first Ctrl-C stopped the analysis. It must not also cancel the
        # web-interface prompt; a later Ctrl-C remains a forced shutdown.
        self.main.shutdown_signal_received = False
        if self._ask_to_stop_web_interface():
            self._stop_web_interface(port)
            return

        bind_mode = getattr(self.main.conf, "web_interface_bind", "localhost")
        if not isinstance(bind_mode, str):
            bind_mode = "localhost"
        display_host = "localhost"
        if bind_mode == "interface":
            for interface in utils.get_all_interfaces(self.main.args):
                candidate = self.main.db.get_host_ip(interface)
                if isinstance(candidate, str) and candidate:
                    display_host = candidate
                    break
        self.main.print(
            f"Web interface remains available at "
            f"http://{display_host}:{port}/. "
            "Press CTRL-C to stop it and exit Slips."
        )
        try:
            while WebInterface.is_verified_server_running(
                port
            ) and not getattr(self.main, "shutdown_signal_received", False):
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.main.shutdown_signal_received = True
        self._stop_web_interface(port)
