# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz
import multiprocessing
import sys
import time
from pathlib import Path
from datetime import datetime
from queue import Empty
import os

from slips_files.common.abstracts.iobserver import IObserver
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.style import red, yellow, print_separator


class Output(IObserver):
    """
    A class to process and output all text to cli and to slips log files.
    If any Slips module or process needs to print or log anything to screen,
     or logs, it should use The printer that uses this process.
    """

    name = "output"
    # Output is instantiated once in the main process before any of
    # slips' child processes are forked, so these multiprocessing locks
    # are inherited by every child and actually serialize writes to the
    # shared stdout/logfiles across processes. threading.Lock() would not
    # do that, since each forked process gets its own independent copy of
    # it, letting concurrent prints from different processes interleave
    # and corrupt each other's output (e.g. a partial in-place \r update
    # from one process landing in the middle of another process' line).
    slips_logfile_lock = multiprocessing.Lock()
    errors_logfile_lock = multiprocessing.Lock()
    cli_lock = multiprocessing.Lock()
    # set while a single-line, in-place-refreshing status line (e.g. the
    # "Total analyzed IPs" summary) is left on screen without a trailing
    # newline. shared across all forked processes so that any of them
    # printing a normal line first closes it out with a newline instead
    # of overwriting/merging with it.
    _cli_has_dangling_line = multiprocessing.Value("b", False)

    # While slips' processes/modules are still announcing their startup
    # (see begin_startup_announcements()), every OTHER printed message
    # is held here instead of going straight to the cli/logfiles, so it
    # can't land in the middle of the startup progress report and break
    # up its lines. Nothing is delayed except the printing itself - the
    # code that queued the message keeps running normally. Queued
    # messages are flushed, in the order they arrived, as soon as the
    # last process/module announces itself.
    _startup_queue = multiprocessing.Queue()
    _startup_in_progress = multiprocessing.Value("b", False)
    _startup_queue_lock = multiprocessing.Lock()
    # monotonic-clock deadline after which queued messages are
    # force-flushed even if the expected total was never reached - a
    # safety net for the case where a module dies/errors out before
    # announcing itself, which would otherwise stall all cli/logfile
    # output for the rest of the run
    _startup_deadline = multiprocessing.Value("d", 0.0)
    STARTUP_QUEUE_TIMEOUT_SECS = 120

    def __init__(
        self,
        verbose=1,
        debug=0,
        stderr="errors.log",
        slips_logfile="slips.log",
        input_type=False,
        create_logfiles: bool = True,
        stdout="",
        slips_args=None,
    ):
        super().__init__()
        # a fresh Output() means a fresh run for whichever process
        # constructed it - no startup announcements are in progress yet
        self._startup_in_progress.value = False
        # when running slips using -e , this var is set and we only
        # print all msgs with debug lvl less than it
        self.verbose = verbose
        self.debug = debug
        self.stdout = stdout
        self.input_type = input_type
        self.errors_logfile = stderr
        self.slips_logfile = slips_logfile
        self.args = slips_args

        if self.verbose > 2:
            print(f"Verbosity: {self.verbose}. Debugging: {self.debug}")

        # when we're using -S, no need to init all the logfiles
        # we just need an instance of this class to be able
        # to start the db from the daemon class
        if create_logfiles:
            # to create worl-writable files, so that when a module drops
            # root privs, it can still write to the logfiles created by
            # root (if slips was started by root)
            os.umask(0)
            self._read_configuration()
            if self.create_logfile(self.errors_logfile):
                self.log_branch_info(self.errors_logfile)
            if self.create_logfile(self.slips_logfile):
                self.log_branch_info(self.slips_logfile)

            utils.change_logfiles_ownership(
                self.errors_logfile, self.UID, self.GID
            )
            utils.change_logfiles_ownership(
                self.slips_logfile, self.UID, self.GID
            )

    def _read_configuration(self):
        conf = ConfigParser()
        self.printable_twid_width = conf.get_tw_width()
        self.GID = conf.get_GID()
        self.UID = conf.get_UID()

    def log_branch_info(self, logfile: str):
        """
        logs the branch and commit to the given logfile
        """
        # both will be False when we're in docker because there's no .git/ there
        branch_info = utils.get_branch_info()
        if not branch_info:
            return
        commit, branch = branch_info

        git_info = ""
        if branch:
            git_info += branch
        if commit:
            git_info += f" ({commit})"

        now = datetime.now()
        with open(logfile, "a") as f:
            f.write(f"Using {git_info} - {now}\n\n")

    def create_logfile(self, path):
        """
        creates slips.log and errors.log if they don't exist
        :return: True if the file was initialized, False otherwise.
        """
        if getattr(self.args, "is_slips_started_by_an_update", False) is True:
            return False

        try:
            open(path, "a").close()
            return True
        except FileNotFoundError:
            p = Path(os.path.dirname(path))
            p.mkdir(parents=True, exist_ok=True)
            return utils.initialize_logfile(
                path, False, create_parent_dirs=False
            )

    def log_line(self, msg: dict):
        """
        Logs line to slips.log
        """

        # don't log in daemon mode, all printed
        # lines are redirected to slips.log by default
        if "-D" in sys.argv:
            return

        sender, msg = msg["from"], msg["txt"]

        date_time = utils.get_human_readable_datetime()

        self.slips_logfile_lock.acquire()
        with open(self.slips_logfile, "a") as slips_logfile:
            slips_logfile.write(f"{date_time} [{sender}] {msg}\n")
        self.slips_logfile_lock.release()

    def print(self, sender: str, txt: str, end="\n"):
        """
        prints the given txt whether using tqdm or using print()
        """
        self.cli_lock.acquire()
        try:
            if sender:
                to_print = f"[{sender}] {txt}"
            else:
                to_print = txt

            if end == "\r":
                # in-place status line: go back to the start of the line,
                # print, then clear anything left over from a longer
                # previous status line, and remember it's left dangling
                # (no trailing newline) so the next unrelated line closes
                # it out instead of overwriting/merging with it
                print(f"\r{to_print}\033[K", end="")
                self._cli_has_dangling_line.value = True
            else:
                if self._cli_has_dangling_line.value:
                    print()
                    self._cli_has_dangling_line.value = False
                print(to_print, end=end)
            # flush while still holding the lock, so this write is fully
            # on screen before another process is allowed to print,
            # instead of risking a delayed buffered flush interleaving
            # with the next process' output
            sys.stdout.flush()

        except Exception as e:
            print(f"Problem printing {txt}. {e}")

        self.cli_lock.release()

    def log_error(self, msg: dict):
        """
        Log error line to errors.log
        """
        date_time = utils.get_human_readable_datetime()

        self.errors_logfile_lock.acquire()
        with open(self.errors_logfile, "a") as errors_logfile:
            errors_logfile.write(f'{date_time} [{msg["from"]}] {msg["txt"]}\n')
        self.errors_logfile_lock.release()

    def enough_verbose(self, verbose: int):
        """
        checks if the given verbose level is enough to print
        """
        return 0 < verbose <= 3 and verbose <= self.verbose

    def enough_debug(self, debug: int):
        """
        checks if the given debug level is enough to print
        """
        return 0 < debug <= 3 and debug <= self.debug

    def output_line_to_cli_and_logfiles(self, msg: dict):
        """
        Prints to terminal and logfiles depending on the debug and verbose
        levels
        """
        verbose = msg.get("verbose", self.verbose)
        debug = msg.get("debug", self.debug)
        end = msg.get("end", "\n")
        sender, txt = msg["from"], str(msg["txt"])

        # if debug level is 3 make it red
        if debug == 3:
            txt = red(txt)
        if "Warning" in txt:
            txt = yellow(txt)

        # the periodically-updated "Total analyzed IPs" summary refreshes
        # in place on a single unprefixed cli line instead of scrolling
        if "analyzed IPs" in txt:
            sender = ""
            end = "\r"

        # There should be a level 0 that we never print. So its >, and not >=
        if self.enough_verbose(verbose) or self.enough_debug(debug):
            # when printing started processes, don't print a sender
            if "Start" in txt or msg.get("suppress_sender", False):
                sender = ""
            self.print(sender, txt, end=end)
            self.log_line(msg)

        # if the line is an error and we're running slips without -e 1 ,
        # we should log the error to output/errors.log
        # make sure the msg is an error. debug_level==1 is the one printing
        # errors
        if debug == 1:
            self.log_error(msg)

    def begin_startup_announcements(self) -> None:
        """
        Marks the start of slips' startup progress report. Called once,
        as soon as the total number of processes/modules to start is
        known, and before any of them are forked. Until the last one
        announces itself (or the safety-net timeout below elapses),
        every other printed message is queued instead of interleaving
        with the startup progress lines.
        """
        self._startup_deadline.value = (
            time.monotonic() + self.STARTUP_QUEUE_TIMEOUT_SECS
        )
        self._startup_in_progress.value = True

    def _dispatch(self, msg: dict) -> None:
        """
        Actually prints/logs a message - the part of update() that
        queueing defers.
        """
        if msg.get("log_to_logfiles_only", False):
            self.log_line(msg)
        else:
            self.output_line_to_cli_and_logfiles(msg)

    def _flush_startup_queue(self) -> None:
        """
        Prints every message queued since begin_startup_announcements(),
        in order, then lets new messages print immediately again.
        """
        with self._startup_queue_lock:
            if not self._startup_in_progress.value:
                # another process already flushed it
                return

            print_separator()

            # a multiprocessing.Queue delivers items to get() slightly
            # after put() returns on another process - a short grace
            # period avoids treating a message that was queued a
            # moment ago, but isn't visible yet, as if it never was
            consecutive_empty_checks = 0
            while consecutive_empty_checks < 3:
                try:
                    queued_msg = self._startup_queue.get(timeout=0.05)
                except Empty:
                    consecutive_empty_checks += 1
                    continue
                consecutive_empty_checks = 0
                self._dispatch(queued_msg)
            self._startup_in_progress.value = False

    def update(self, msg: dict):
        """
        is called whenever any module need to print something using the
        Printer.notify_observers()
        each msg should be in the following format
        {
            log_to_logfiles_only: bool that indicates whether we
            wanna log the text to all logfiles or the cli only?
            txt: text to log to the logfiles and/or the cli
        }
        """
        # startup progress lines are never queued - they're what the
        # queueing is protecting in the first place
        if msg.get("suppress_sender", False):
            self._dispatch(msg)
            if msg.get("is_final_startup_announcement", False):
                self._flush_startup_queue()
            return

        if self._startup_in_progress.value:
            if time.monotonic() >= self._startup_deadline.value:
                # a module/worker likely died before announcing itself,
                # so the expected total was never reached. stop
                # queueing instead of holding all future output forever
                self._flush_startup_queue()
            else:
                with self._startup_queue_lock:
                    # re-check now that we hold the lock: startup may
                    # have finished between the check above and here
                    if self._startup_in_progress.value:
                        self._startup_queue.put(msg)
                        return

        self._dispatch(msg)
