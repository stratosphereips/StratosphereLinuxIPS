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
from threading import Lock
import sys
from pathlib import Path
from datetime import datetime
import os

from slips_files.common.abstracts.observer import IObserver
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.style import red, yellow


class Output(IObserver):
    """
    A class to process and output all text to cli and to slips log files.
    If any Slips module or process needs to print or log anything to screen,
     or logs, it should use The printer that uses this process.
    """

    name = "Output"
    slips_logfile_lock = Lock()
    errors_logfile_lock = Lock()
    cli_lock = Lock()

    def __init__(
        self,
        verbose=1,
        debug=0,
        stderr="output/errors.log",
        slips_logfile="output/slips.log",
        input_type=False,
        create_logfiles: bool = True,
        stdout="",
    ):
        super().__init__()
        # when running slips using -e , this var is set and we only
        # print all msgs with debug lvl less than it
        self.verbose = verbose
        self.debug = debug
        self.stdout = stdout
        self.input_type = input_type
        self.errors_logfile = stderr
        self.slips_logfile = slips_logfile

        if self.verbose > 2:
            print(f"Verbosity: {self.verbose}. Debugging: {self.debug}")

        # when we're using -S, no need to init all the logfiles
        # we just need an instance of this class to be able
        # to start the db from the daemon class
        if create_logfiles:
            self._read_configuration()
            self.create_logfile(self.errors_logfile)
            self.log_branch_info(self.errors_logfile)
            self.create_logfile(self.slips_logfile)
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
        """
        try:
            open(path, "a").close()
        except FileNotFoundError:
            p = Path(os.path.dirname(path))
            p.mkdir(parents=True, exist_ok=True)
            open(path, "w").close()

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

            print(to_print, end=end)

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
        if "analyzed IPs" in txt:
            self.print("", txt, end="\r")
            return

        # There should be a level 0 that we never print. So its >, and not >=
        if self.enough_verbose(verbose) or self.enough_debug(debug):
            # when printing started processes, don't print a sender
            if "Start" in txt:
                sender = ""
            self.print(sender, txt, end=end)
            self.log_line(msg)

        # if the line is an error and we're running slips without -e 1 ,
        # we should log the error to output/errors.log
        # make sure the msg is an error. debug_level==1 is the one printing
        # errors
        if debug == 1:
            self.log_error(msg)

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
        # output to terminal and logs or logs only?
        if msg.get("log_to_logfiles_only", False):
            self.log_line(msg)
        else:
            self.output_line_to_cli_and_logfiles(msg)
