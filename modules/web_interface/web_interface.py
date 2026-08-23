# SPDX-License-Identifier: GPL-2.0-only
"""Launch the local web interface for the current Slips run."""

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import IO, Optional

import psutil
import redis

from modules.web_interface.history import HistoryCollector
from slips_files.common.abstracts.imodule import IModule
from slips_files.common.slips_utils import utils


class WebInterface(IModule):
    """Keep a run-scoped local dashboard available during and after analysis."""

    name = "web_interface"
    description = "Local technical web interface for the current Slips run"
    authors = ["Stratosphere Laboratory"]

    def init(self, **kwargs: object) -> None:
        """Initialize launcher and history collector state."""
        self.server_process: Optional[subprocess.Popen] = None
        self.server_log: Optional[IO[str]] = None
        self.history_collector: Optional[HistoryCollector] = None
        self.history_thread: Optional[threading.Thread] = None
        self.backfill_thread: Optional[threading.Thread] = None
        self.history_stop = threading.Event()

    def subscribe_to_channels(self) -> None:
        """Declare that the launcher does not consume Redis channels."""
        self.channels = {}

    @staticmethod
    def _port_is_available(port: int) -> bool:
        """
        Check whether the configured loopback port can be bound.

        Parameters:
            port: TCP port to check.

        Returns:
            True when a new server can bind the port.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind(("127.0.0.1", port))
            except OSError:
                return False
        return True

    @staticmethod
    def _listener_pid(port: int) -> Optional[int]:
        """
        Find the process listening on a loopback port.

        Parameters:
            port: Local TCP port.

        Returns:
            Listener PID when visible.
        """
        try:
            connections = psutil.net_connections(kind="tcp")
        except psutil.Error:
            return None
        for connection in connections:
            if (
                connection.status == psutil.CONN_LISTEN
                and connection.laddr
                and connection.laddr.port == port
                and connection.laddr.ip in {"127.0.0.1", "::1"}
            ):
                return connection.pid
        return None

    @staticmethod
    def _is_owned_web_server(process: psutil.Process, port: int) -> bool:
        """
        Verify a listener is this user's Slips web server.

        Parameters:
            process: Candidate listener.
            port: Expected configured port.

        Returns:
            True only for the expected module command and effective user.
        """
        try:
            command = process.cmdline()
            process_uid = process.uids().effective
        except (psutil.Error, AttributeError):
            return False
        module_marker = "modules.web_interface.server"
        has_port = any(
            value == "--port"
            and index + 1 < len(command)
            and command[index + 1] == str(port)
            for index, value in enumerate(command)
        )
        return process_uid == os.geteuid() and module_marker in command and has_port

    def _replace_stale_server(self, port: int) -> bool:
        """
        Stop a verified previous Slips server occupying the configured port.

        Parameters:
            port: Configured HTTP port.

        Returns:
            True when the port is available after replacement.
        """
        if self._port_is_available(port):
            return True
        pid = self._listener_pid(port)
        if not pid:
            return False
        try:
            process = psutil.Process(pid)
        except psutil.Error:
            return False
        if not self._is_owned_web_server(process, port):
            return False
        try:
            process.terminate()
            process.wait(timeout=3)
        except psutil.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=2)
            except psutil.Error:
                return False
        except psutil.NoSuchProcess:
            pass
        except psutil.Error:
            return False
        return self._port_is_available(port)

    def _collect_history(self) -> None:
        """Collect one bounded history batch each second."""
        while not self.history_stop.is_set():
            started = time.monotonic()
            try:
                if self.history_collector:
                    self.history_collector.collect_once()
            except Exception as error:
                self.print(f"History collector error: {error}", 0, 1)
            elapsed = time.monotonic() - started
            self.history_stop.wait(max(1.0 - elapsed, 0.05))

    def _backfill_history(self) -> None:
        """Recover durable detection history without blocking live data."""
        while not self.history_stop.is_set():
            try:
                if self.history_collector:
                    self.history_collector.backfill_detections()
            except Exception as error:
                self.print(f"Detection backfill error: {error}", 0, 1)
            self.history_stop.wait(30)

    def pre_main(self) -> bool:
        """
        Start the run-specific history collector and loopback HTTP server.

        Returns:
            True when startup failed and the module should stop.
        """
        utils.drop_root_privs_permanently()
        port = self.conf.web_interface_port
        if not self._replace_stale_server(port):
            self.print(
                f"Cannot start the web interface: localhost port {port} "
                "belongs to another process.",
                0,
                1,
            )
            return True

        history_path = Path(self.get_module_specific_output_path("history.sqlite"))
        redis_client = redis.Redis(
            host="127.0.0.1",
            port=self.redis_port,
            db=0,
            decode_responses=True,
            socket_timeout=2,
        )
        self.history_collector = HistoryCollector(
            self.parent_output_dir,
            history_path,
            redis_client,
            self.ppid,
        )
        # Publish live hosts before the HTTP server accepts requests. Detection
        # backfill runs separately so it cannot delay live host refreshes.
        self.history_collector.snapshot_hosts()
        self.history_thread = threading.Thread(
            target=self._collect_history,
            daemon=True,
            name="web_interface_history",
        )
        utils.start_thread(self.history_thread, self.db)
        log_path = self.get_module_specific_output_path("server.log")
        self.server_log = open(log_path, "a", encoding="utf-8")
        command = [
            sys.executable,
            "-m",
            "modules.web_interface.server",
            "--port",
            str(port),
            "--redis-port",
            str(self.redis_port),
            "--output-dir",
            self.parent_output_dir,
        ]
        self.server_process = subprocess.Popen(
            command,
            cwd=Path.cwd(),
            stdin=subprocess.DEVNULL,
            stdout=self.server_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.db.store_pid("Web Interface", self.server_process.pid)
        self.backfill_thread = threading.Thread(
            target=self._backfill_history,
            daemon=True,
            name="web_interface_detection_backfill",
        )
        utils.start_thread(self.backfill_thread, self.db)
        self.print(
            f"Web interface available at http://localhost:{port}/ "
            f"[PID {self.server_process.pid}]"
        )
        return False

    def main(self) -> bool:
        """
        Monitor whether the detached HTTP server is still running.

        Returns:
            True when the server exited and the launcher should stop.
        """
        time.sleep(1)
        if not self.server_process:
            return True
        if self.server_process.poll() is None:
            return False
        self.print(
            f"Web interface stopped with exit code "
            f"{self.server_process.returncode}. See server.log.",
            0,
            1,
        )
        return True

    def shutdown_gracefully(self) -> None:
        """Stop collection while leaving completed-run HTTP access alive."""
        self.history_stop.set()
        if self.history_thread:
            self.history_thread.join(timeout=2)
        if self.backfill_thread:
            self.backfill_thread.join(timeout=2)
        if self.history_collector:
            try:
                self.history_collector.collect_once()
            except Exception as error:
                self.print(f"Final history collection error: {error}", 0, 1)
        if self.server_log:
            self.server_log.close()
            self.server_log = None
