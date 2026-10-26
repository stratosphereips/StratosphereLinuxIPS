# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import json
import select
import sys
import time
from signal import SIGTERM
from pathlib import Path
from typing import Tuple, Optional
from exclusiveprocess import (
    Lock,
    CannotAcquireLock,
)
import psutil

from managers.process_manager.instance_control import (
    inspect_instance,
    stop_instances,
)


class Daemon:
    description = "This module runs when slips is in daemonized mode"
    name = "daemon"

    def __init__(self, slips):
        # to use read_configurations defined in Main
        self.slips = slips
        # tell Main class that we're running in daemonized mode
        self.slips.set_mode("daemonized", daemon=self)
        # this is a conf file used to store the pid of the daemon and
        # is deleted when the daemon stops
        self.pidfile_dir = self.slips.conf.permanent_dir()
        self.daemon_start_lock = "slips_daemon_start"
        self.daemon_stop_lock = "slips_daemon_stop"
        self.pidfile = os.path.join(self.pidfile_dir, "slips_daemon.lock")
        self._startup_write_fd: Optional[int] = None
        self.read_configuration()
        if not self.slips.args.stopdaemon:
            self.prepare_output_dir()
        self.pid = self.read_pidfile()

    def read_pidfile(self) -> Optional[int]:
        # Get the pid from pidfile
        try:
            with open(self.pidfile) as pidfile:
                pid = int(pidfile.read().strip())
                return pid if pid > 0 else None
        except (IOError, ValueError):
            return None

    def is_pid_running(self, pid: Optional[int] = None) -> bool:
        """
        Check whether a daemon PID is still running.

        Parameters:
            pid: PID to validate. Uses the current daemon PID when omitted.

        Returns:
            True when the PID exists, otherwise False.
        """
        pid = self.pid if pid is None else pid
        if pid is None:
            return False

        try:
            os.kill(int(pid), 0)
        except (ProcessLookupError, TypeError, ValueError):
            return False
        except PermissionError:
            return True
        return True

    def print(self, text, **kwargs):
        """Prints output to logsfile specified in slips.yaml"""
        with open(self.logsfile, "a") as f:
            f.write(f"{text}\n")

    def create_std_streams(self):
        """Create daemon log streams without truncating saved run history."""
        if self.slips.args.is_slips_started_by_an_update:
            return

        std_streams = dict.fromkeys([self.stderr, self.stdout, self.logsfile])
        for file in std_streams:
            os.makedirs(os.path.dirname(file) or ".", exist_ok=True)
            open(file, "a").close()

    def prepare_std_streams(self, output_dir):
        """
        prepare the path of stderr, stdout, logsfile
        """
        self.stderr = os.path.join(output_dir, self.stderr)
        self.stdout = os.path.join(output_dir, self.stdout)
        self.logsfile = os.path.join(output_dir, self.logsfile)

    def read_configuration(self):
        conf = self.slips.conf
        self.logsfile = conf.logs_file()
        self.stdout = conf.stdout()
        self.stderr = conf.stderr()
        # we don't use it anyway
        self.stdin = "/dev/null"

    def prepare_output_dir(self):
        self.prepare_std_streams(self.slips.args.output)

        self.create_std_streams()

        # when stopping the daemon don't log this info again
        if "-S" not in sys.argv:
            self.print(
                f"Logsfile: {self.logsfile}\n"
                f"pidfile: {self.pidfile}\n"
                f"stdin : {self.stdin}\n"
                f"stdout: {self.stdout}\n"
                f"stderr: {self.stderr}\n"
            )

            self.print("Done reading configuration and setting up files.\n")

    def delete_pidfile(self):
        """Deletes the pidfile to mark the daemon as closed"""

        # self.print('Deleting pidfile...')
        # dont write logs when stopping the daemon,
        # because we don't know the output dir
        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)
            self.print("pidfile deleted.")
        else:
            self.print(f"Can't delete pidfile, {self.pidfile} doesn't exist.")
            # if an error happened it will be written in logsfile
            self.print("Either Daemon stopped normally or an error occurred.")

    def _report_startup(self, status: str, message: str) -> None:
        """Send bounded startup status to the original terminal process.

        Parameters:
            status: Starting, ready, or error status.
            message: PID or short failure description for the terminal.
        """
        if self._startup_write_fd is None:
            return
        try:
            os.write(
                self._startup_write_fd,
                (
                    json.dumps({"status": status, "message": message[:2000]})
                    + "\n"
                ).encode(),
            )
        except BrokenPipeError:
            pass
        finally:
            if status != "starting":
                os.close(self._startup_write_fd)
                self._startup_write_fd = None

    def notify_started(self) -> None:
        """Tell the terminal that the daemon has started its core workers."""
        self._report_startup("ready", str(os.getpid()))

    def _wait_for_startup(self, descriptor: int) -> int:
        """Wait for startup feedback without mistaking a fork for success.

        Parameters:
            descriptor: Read end of the daemon startup pipe.

        Returns:
            Terminal command exit status; a live slow startup returns zero.
        """
        deadline = time.monotonic() + 30
        pending = b""
        pid = None
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select(
                    [descriptor], [], [], max(0, deadline - time.monotonic())
                )
                if not ready:
                    break
                chunk = os.read(descriptor, 4096)
                if not chunk:
                    print(
                        f"Slips daemon exited before startup completed. See {self.stderr}",
                        file=sys.stderr,
                        flush=True,
                    )
                    return 1
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    result = json.loads(line)
                    if result["status"] == "starting":
                        pid = int(result["message"])
                    elif result["status"] == "ready":
                        print(
                            f"Slips daemon started. [PID {result['message']}] Logs: {self.logsfile}",
                            flush=True,
                        )
                        return 0
                    else:
                        print(
                            f"Slips daemon startup failed: {result['message']}. See {self.stderr}",
                            file=sys.stderr,
                            flush=True,
                        )
                        return 1
            if pid and self.is_pid_running(pid):
                print(
                    f"Slips daemon PID {pid} is still starting. Check {self.logsfile} and {self.stderr}.",
                    flush=True,
                )
                return 0
            print(
                f"Slips daemon exited before startup completed. See {self.stderr}",
                file=sys.stderr,
                flush=True,
            )
            return 1
        finally:
            os.close(descriptor)

    def daemonize(self):
        """
        Does the Unix double-fork to create a daemon
        """
        # double fork explaination
        # https://stackoverflow.com/questions/881388/what-is-the-reason-for-performing-a-double-fork-when-creating-a-daemon

        sys.stdout.flush()
        sys.stderr.flush()
        read_fd, self._startup_write_fd = os.pipe()
        try:
            self.pid = os.fork()
            if self.pid > 0:
                os.close(self._startup_write_fd)
                self._startup_write_fd = None
                status = self._wait_for_startup(read_fd)
                # Python finalizers would unlink semaphore names still needed
                # by spawn workers in the surviving daemon.
                os._exit(status)
        except OSError as e:
            os.close(read_fd)
            os.close(self._startup_write_fd)
            self._startup_write_fd = None
            sys.stderr.write(f"Fork #1 failed: {e.errno} {e.strerror}\n")
            self.print(f"Fork #1 failed: {e.errno} {e.strerror}\n")
            sys.exit(1)
        os.close(read_fd)

        # os.chdir("/")
        # dissociate the daemon from its controlling terminal.
        # calling setsid means that this child will be the session leader of the new session
        # aka detaches this process from the terminal.
        os.setsid()
        # a daemon should not keep whatever restrictive mask the launching
        # shell or service manager happened to have
        #  after umask(0), files and directories the daemon creates later get
        #  the permissions requested by the code, instead of being silently
        #  reduced by the parent process’s umask
        os.umask(0)

        # If you want to prevent a process from acquiring a tty, the process shouldn't be the session leader
        # fork again so that the second child is no longer a session leader
        try:
            self.pid = os.fork()
            if self.pid > 0:
                os._exit(0)
        except OSError as e:
            self._report_startup("error", f"Second fork failed: {e}")
            sys.stderr.write(f"Fork #2 failed: {e.errno} {e.strerror}\n")
            self.print(f"Fork #2 failed: {e.errno} {e.strerror}\n")
            sys.exit(1)

        # Now this code is run from the daemon
        # A daemon must close it's input and output file descriptors otherwise, it would still
        # be attached to the terminal it was started in.
        sys.stdout.flush()
        sys.stderr.flush()

        # redirect standard file descriptors
        with open(self.stdin, "r") as stdin, open(
            self.stdout, "a+"
        ) as stdout, open(self.stderr, "a+") as stderr:
            os.dup2(stdin.fileno(), sys.stdin.fileno())
            os.dup2(stdout.fileno(), sys.stdout.fileno())
            os.dup2(stderr.fileno(), sys.stderr.fileno())

        # write the pid of the daemon to a file so we can
        # check if it's already opened before re-opening
        os.makedirs(self.pidfile_dir, mode=0o700, exist_ok=True)

        # remember that we are writing this pid to a file
        # because the parent and the first fork, already exited, so this pid is the daemon pid which is slips.py pid
        self.pid = str(os.getpid())
        with open(self.pidfile, "w+") as pidfile:
            pidfile.write(self.pid)
        self._report_startup("starting", self.pid)

        # Register a function to be executed if sys.exit()
        # is called or the main module’s execution completes
        # atexit.register(self.terminate)

    def start(self):
        """
        Main function
        Starts the daemon and starts slips normally.
        """
        try:
            with Lock(name=self.daemon_start_lock):
                if self.pid is not None:
                    if not self.is_pid_running():
                        self.delete_pidfile()
                        self.pid = None
                    else:
                        to_print = (
                            f"pidfile {self.pidfile} already exists. "
                            f"Daemon already running?"
                        )
                        # to cli and to log file
                        self.print(to_print)
                        print(to_print)
                        return

                self.print("Daemon starting...")
                # Starts the daemon
                self.daemonize()
                self.slips.pid = os.getpid()
                self.slips.proc_man.adopt_daemon_ipc()

                # any code run after daemonizing will be run inside
                # the daemon and have the same PID as slips.py
                self.print(f"Slips Daemon is running. [PID {self.pid}]\n")
                self.slips.start()
                self._report_startup(
                    "error", "Daemon stopped before startup completed"
                )
        except CannotAcquireLock:
            # another instance of slips daemon is running
            return
        except BaseException as error:
            self._report_startup("error", f"{type(error).__name__}: {error}")
            self.slips.proc_man.cleanup_failed_startup()
            raise
        finally:
            if (
                self.pid == str(os.getpid())
                and self.read_pidfile() == os.getpid()
            ):
                self.delete_pidfile()

    def get_last_opened_daemon_info(self) -> Optional[Tuple[str]]:
        """
        get information about the last opened slips daemon from
         running_slips_info.txt
        """
        try:
            with open(self.slips.redis_man.running_logfile, "r") as f:
                # read the lines in reverse order to get the
                # last opened daemon
                for line in f.read().splitlines()[::-1]:
                    # skip comments
                    if (
                        line.startswith("#")
                        or line.startswith("Date")
                        or len(line) < 3
                    ):
                        continue
                    line = line.split(",")
                    is_daemon = bool(line[7])
                    if not is_daemon:
                        continue
                    port, output_dir, slips_pid = line[2], line[5], line[6]
                    return port, output_dir, slips_pid
        except FileNotFoundError:
            # file removed after daemon started
            self.print(
                f"Warning: {self.slips.redis_man.running_logfile} is not found. Can't get daemon info."
                f" Slips won't be completely killed."
            )

    def _kill_self(self):
        """Kill the daemon process only (aka slips.py)"""

        # sending SIGINT to self.pid will only kill slips.py
        # and the rest of its children will be zombies

        # sending SIGKILL to self.pid will only kill slips.py and the rest of
        # it's children will stay open in memory (not even zombies)
        try:
            os.kill(int(self.pid), SIGTERM)
        except ProcessLookupError:
            # daemon was killed manually
            pass

    def _is_running(self) -> bool:
        """
        returns true if the daemon lock is released
         and the daemon pidfile is deleted
        """
        if not self.pid:
            return False

        if not self.is_pid_running():
            self.delete_pidfile()
            return False

        try:
            with Lock(name=self.daemon_start_lock):
                pass
        except CannotAcquireLock:
            # another instance of slips daemon is running
            pass
        return True

    def stop(self) -> dict[str, object]:
        """Stop the verified daemon through the shared instance controller.

        Returns:
            Whether the daemon and its observed workers stopped, or an error.
        """
        try:
            with Lock(name=self.daemon_stop_lock):
                if not self._is_running():
                    return {
                        "stopped": False,
                        "error": "Daemon is not running.",
                    }
                if int(self.pid) == os.getpid():
                    self.slips.proc_man.cleanup_failed_startup()
                    self.delete_pidfile()
                    return {"stopped": True, "error": None}
                entrypoint = Path(__file__).parent.parent / "slips.py"
                process = psutil.Process(int(self.pid))
                instance = inspect_instance(process, entrypoint)
                if instance is None or not {"-D", "--daemon"}.intersection(
                    instance.arguments
                ):
                    return {
                        "stopped": False,
                        "error": "The PID file does not identify this checkout's Slips daemon.",
                    }
                stopped = stop_instances([instance], entrypoint) == 0
                if stopped and self.read_pidfile() == instance.pid:
                    self.delete_pidfile()
                return {
                    "stopped": stopped,
                    "error": (
                        None
                        if stopped
                        else "Daemon shutdown did not finish; check errors.log."
                    ),
                }
        except psutil.NoSuchProcess:
            self.delete_pidfile()
            return {"stopped": False, "error": "Daemon is not running."}
        except psutil.AccessDenied:
            return {
                "stopped": False,
                "error": "Permission denied for this daemon.",
            }
        except CannotAcquireLock:
            return {
                "stopped": False,
                "error": "Another daemon stop command is already running.",
            }
