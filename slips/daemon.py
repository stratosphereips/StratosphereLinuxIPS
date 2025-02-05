# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import sys
from signal import SIGTERM
from typing import Tuple, Optional
from exclusiveprocess import (
    Lock,
    CannotAcquireLock,
)

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.printer import Printer
from slips_files.core.database.database_manager import DBManager


class Daemon:
    description = "This module runs when slips is in daemonized mode"
    name = "Daemon"

    def __init__(self, slips):
        # to use read_configurations defined in Main
        self.slips = slips
        # tell Main class that we're running in daemonized mode
        self.slips.set_mode("daemonized", daemon=self)
        # this is a conf file used to store the pid of the daemon and
        # is deleted when the daemon stops
        self.pidfile_dir = "/var/lock"
        self.daemon_start_lock = "slips_daemon_start"
        self.daemon_stop_lock = "slips_daemon_stop"
        self.pidfile = os.path.join(self.pidfile_dir, "slips_daemon.lock")
        self.read_configuration()
        if not self.slips.args.stopdaemon:
            self.prepare_output_dir()
        self.pid = self.read_pidfile()

    def read_pidfile(self) -> Optional[int]:
        # Get the pid from pidfile
        try:
            with open(self.pidfile) as pidfile:
                return int(pidfile.read().strip())
        except (IOError, FileNotFoundError):
            return None

    def print(self, text, **kwargs):
        """Prints output to logsfile specified in slips.yaml"""
        with open(self.logsfile, "a") as f:
            f.write(f"{text}\n")

    def create_std_streams(self):
        """Create standard steam files and dirs and clear them"""

        std_streams = [self.stderr, self.stdout, self.logsfile]
        for file in std_streams:
            # we don't want to clear the stdout or the logsfile when we stop
            # the daemon using -S
            if "-S" in sys.argv and file != self.stderr:
                continue
            # create the file if it doesn't exist or clear it if it exists
            try:
                open(file, "w").close()
            except (FileNotFoundError, NotADirectoryError):
                os.mkdir(os.path.dirname(file))
                open(file, "w").close()

    def prepare_std_streams(self, output_dir):
        """
        prepare the path of stderr, stdout, logsfile
        """
        self.stderr = os.path.join(output_dir, self.stderr)
        self.stdout = os.path.join(output_dir, self.stdout)
        self.logsfile = os.path.join(output_dir, self.logsfile)

    def read_configuration(self):
        conf = ConfigParser()
        self.logsfile = conf.logsfile()
        self.stdout = conf.stdout()
        self.stderr = conf.stderr()
        # we don't use it anyway
        self.stdin = "/dev/null"

    def prepare_output_dir(self):
        if "-o" in sys.argv:
            self.prepare_std_streams(self.slips.args.output)
        else:
            # if we have acess to '/var/log/slips/' store the logfiles there,
            # if not , store it in the output/ dir
            try:
                output_dir = "/var/log/slips/"
                try:
                    os.mkdir(output_dir)
                except FileExistsError:
                    pass
                # see if we have write permission to that dir or not
                tmpfile = os.path.join(output_dir, "tmp")
                open(tmpfile, "w").close()
                os.remove(tmpfile)

                # we have permission, append the path to each logfile
                self.prepare_std_streams(output_dir)
                #  set it as the default output dir
                self.slips.args.output = output_dir
            except PermissionError:
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

    def daemonize(self):
        """
        Does the Unix double-fork to create a daemon
        """
        # double fork explaination
        # https://stackoverflow.com/questions/881388/what-is-the-reason-for-performing-a-double-fork-when-creating-a-daemon

        try:
            self.pid = os.fork()
            if self.pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #1 failed: {e.errno} {e.strerror}\n")
            self.print(f"Fork #1 failed: {e.errno} {e.strerror}\n")
            sys.exit(1)

        # os.chdir("/")
        # dissociate the daemon from its controlling terminal.
        # calling setsid means that this child will be the session leader of the new session
        os.setsid()
        os.umask(0)

        # If you want to prevent a process from acquiring a tty, the process shouldn't be the session leader
        # fork again so that the second child is no longer a session leader
        try:
            self.pid = os.fork()
            if self.pid > 0:
                # exit from second parent (aka first child)
                sys.exit(0)
        except OSError as e:
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
        if not os.path.exists(self.pidfile_dir):
            os.mkdir(self.pidfile_dir)

        # remember that we are writing this pid to a file
        # because the parent and the first fork, already exited, so this pid is the daemon pid which is slips.py pid
        self.pid = str(os.getpid())
        with open(self.pidfile, "w+") as pidfile:
            pidfile.write(self.pid)

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
                    self.print(
                        "pidfile already exists. Daemon already " "running?"
                    )
                    return

                self.print("Daemon starting...")

                # Starts the daemon
                self.daemonize()

                # any code run after daemonizing will be run inside
                # the daemon and have the same PID as slips.py
                self.print(f"Slips Daemon is running. [PID {self.pid}]\n")
                self.slips.start()
        except CannotAcquireLock:
            # another instance of slips daemon is running
            return

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

    def killdaemon(self):
        """Kill the damon process only (aka slips.py)"""
        # sending SIGINT to self.pid will only kill slips.py
        # and the rest of it's children will be zombies
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
        try:
            with Lock(name=self.daemon_start_lock):
                if not self.pid:
                    return False
        except CannotAcquireLock:
            # another instance of slips daemon is running
            pass
        return True

    def stop(self):
        """Stops the daemon"""
        try:
            with Lock(name=self.daemon_stop_lock):

                if not self._is_running():
                    return {
                        "stopped": False,
                        "error": "Daemon is not running.",
                    }

                self.killdaemon()

                info: Tuple[str] = self.get_last_opened_daemon_info()
                if not info:
                    return {
                        "stopped": False,
                        "error": "Can't get the info of the last opened "
                        "Slips daemon.",
                    }

                port, output_dir, self.pid = info

                self.stderr = "errors.log"
                self.stdout = "slips.log"
                self.logsfile = "slips.log"
                self.prepare_std_streams(output_dir)
                self.logger = self.slips.proc_man.start_output_process(
                    self.stderr, self.logsfile, stdout=self.stdout
                )
                self.db = DBManager(
                    self.logger,
                    output_dir,
                    port,
                    start_sqlite=False,
                    flush_db=False,
                )
                self.slips.printer = Printer(self.logger, self.name)
                self.db.set_slips_mode("daemonized")
                self.slips.set_mode("daemonized", daemon=self)
                # used in shutdown gracefully to print the name of the
                # stopped file in slips.log
                self.slips.input_information = self.db.get_input_file()
                self.slips.args = self.slips.conf.get_args()
                self.slips.db = self.db
                self.slips.proc_man.slips_logfile = self.logsfile

                # WARNING: this function shouldn't call shutdown gracefully.
                # it should send sigint to the opened daemon, and the
                # opened daemon should call shutdown gracefully
                return {
                    "stopped": True,
                    "error": None,
                }
        except CannotAcquireLock:
            # another instance of slips daemon is running
            pass
