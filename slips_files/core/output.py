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
from slips_files.common.imports import *
import sys
import io
from pathlib import Path
from datetime import datetime
import os
from tqdm.auto import tqdm
from slips_files.common.abstracts.observer import IObserver
from slips_files.common.style import green
from threading import Lock

class Output(IObserver):
    """
    A class to process the output of everything Slips need. Manages all the output
    If any Slips module or process needs to output anything to screen, or logs,
    it should use always the output queue. Then this output class will handle how to deal with it
    """

    name = 'Output'
    obj = None
    slips_logfile_lock = Lock()
    errors_logfile_lock = Lock()
    cli_lock = Lock()


    def __new__(
        cls,
        verbose=None,
        debug=None,
        stdout='',
        stderr='output/errors.log',
        slips_logfile='output/slips.log',
        slips_mode='interactive',
    ):
        if not cls.obj:
            cls.obj = super().__new__(cls)
            # when running slips using -e , this var is set and we only print all msgs with debug lvl less than it
            cls.verbose = verbose
            cls.debug = debug
            ####### create the log files
            cls._read_configuration()
            cls.errors_logfile = stderr
            cls.slips_logfile = slips_logfile
            cls.create_logfile(cls.errors_logfile)
            cls.create_logfile(cls.slips_logfile)
            utils.change_logfiles_ownership(cls.errors_logfile, cls.UID, cls.GID)
            utils.change_logfiles_ownership(cls.slips_logfile, cls.UID, cls.GID)

            cls.stdout = stdout
            if stdout != '':
                cls.change_stdout()
            if cls.verbose > 2:
                print(f'Verbosity: {cls.verbose}. Debugging: {cls.debug}')
            cls.done_reading_flows = False
            # we update the stats printed by slips every 5seconds
            # this is the last time the stats was printed
            cls.last_updated_stats_time = float("-inf")
            #TODO test this when daemonized
            cls.slips_mode = slips_mode

        return cls.obj


    @classmethod
    def _read_configuration(cls):
        conf = ConfigParser()
        cls.printable_twid_width = conf.get_tw_width()
        cls.GID = conf.get_GID()
        cls.UID = conf.get_UID()

    @classmethod
    def log_branch_info(cls, logfile: str):
        """
        logs the branch and commit to the given logfile
        """
        # both will be False when we're in docker because there's no .git/ there
        branch_info = utils.get_branch_info()
        if not branch_info:
            return
        commit, branch = branch_info


        git_info = ''
        if branch:
            git_info += branch
        if commit:
            git_info += f' ({commit})'

        now = datetime.now()
        with open(logfile, 'a') as f:
            f.write(f'Using {git_info} - {now}\n\n')

    @classmethod
    def create_logfile(cls, path):
        """
        creates slips.log and errors.log if they don't exist
        """
        try:
            open(path, 'a').close()
        except FileNotFoundError:
            p = Path(os.path.dirname(path))
            p.mkdir(parents=True, exist_ok=True)
            open(path, 'w').close()
        cls.log_branch_info(path)


    def log_line(self, msg: dict):
        """
        Logs line to slips.log
        """
        sender, msg = msg['from'], msg['txt']
        # don't log in daemon mode, all printed
        # lines are redirected to slips.log by default
        if "-D" in sys.argv and 'update'.lower() not in sender and 'stopping' not in sender:
            # if the sender is the update manager, always log
            return

        date_time = datetime.now()
        date_time = utils.convert_format(date_time, utils.alerts_format)

        self.slips_logfile_lock.acquire()
        with open(self.slips_logfile, 'a') as slips_logfile:
            slips_logfile.write(f'{date_time} [{sender}] {msg}\n')
        self.slips_logfile_lock.release()


    @classmethod
    def change_stdout(cls):
        # io.TextIOWrapper creates a file object of this file
        # Pass 0 to open() to switch output buffering off (only allowed in binary mode)
        # write_through= True, to flush the buffer to disk, from there the file can read it.
        # without it, the file writer keeps the information in a local buffer that's not accessible to the file.
        sys.stdout = io.TextIOWrapper(
            open(cls.stdout, 'wb', 0),
            write_through=True
        )
        return

    def print(self, sender: str, txt: str):
        """
        prints the given txt whether using tqdm or using print()
        """
        self.cli_lock.acquire()
        # when the pbar reaches 100% aka we're done_reading_flows
        # we print alerts at the very botttom of the screen using print
        # instead of printing alerts at the top of the pbar using tqdm
        if hasattr(self, 'done_reading_flows') and self.done_reading_flows:
            print(f'[{green(sender)}] {txt}')
        else:
            tqdm.write(f'[{sender}] {txt}')
        self.cli_lock.release()


    def log_error(self, msg: dict):
        """
        Log error line to errors.log
        """
        date_time = datetime.now()
        date_time = utils.convert_format(date_time, utils.alerts_format)

        self.errors_logfile_lock.acquire()
        with open(self.errors_logfile, 'a') as errors_logfile:
            errors_logfile.write(f'{date_time} {msg["from"]}{msg["txt"]}\n')
        self.errors_logfile_lock.release()

    def has_pbar(self):
        """returns false when pbar wasnt initialised or is done 100%"""
        if hasattr(self, 'done_reading_flows') and self.done_reading_flows:
            return False
        elif hasattr(self, 'progress_bar'):
            return True

    def handle_printing_stats(self, stats: str):
        # if we're done reading flows, aka pbar reached 100%
        # we print the stats in a new line, instead of next to the pbar
        if not self.has_pbar():
            print(stats, end='\r')
        else:
            # print the stats next to the bar
            self.progress_bar.set_postfix_str(
                stats,
                refresh=True
            )

    def output_line(self, msg: dict):
        """
        Prints to terminal and logfiles depending on the debug and verbose levels
        """
        verbose, debug = msg.get('verbose', self.verbose), msg.get('debug', self.debug)
        sender, txt = msg['from'], msg['txt']

        # if verbosity level is 3 make it red
        if debug == 3:
            msg = f'\033[0;35;40m{msg}\033[00m'

        if 'analyzed IPs' in txt:
            self.handle_printing_stats(txt)
            return


        # There should be a level 0 that we never print. So its >, and not >=
        if ((
                0 < verbose <= 3
                and verbose <= self.verbose
        ) or (
                0 < debug <= 3
                and debug <= self.debug
        )):
            if 'Start' in txt:
                # we use tqdm.write() instead of print() to make sure we
                # don't get progress bar duplicates in the cli
                tqdm.write(f'{txt}')
                return

            self.print(sender, txt)
            self.log_line(msg)

        # if the line is an error and we're running slips without -e 1 , we should log the error to output/errors.log
        # make sure the msg is an error. debug_level==1 is the one printing errors
        if debug == 1:
            self.log_error(msg)

    def unknown_total_flows(self, input_type: str) -> bool:
        """
        When running on a pcap, interface, or taking flows from an
        external module, the total amount of flows is unknown
        """


        # whenever any of those is present, slips won't be able to get the
        # total flows when starting, nor init the progress bar
        params = ('-g', '--growing', '-im', '--input_module')
        for param in params:
            if param in sys.argv:
                return True

    def init_progress_bar(self, bar: dict):
        """
        initializes the progress bar when slips is runnning on a file or a zeek dir
        ignores pcaps, interface and dirs given to slips if -g is enabled
        :param bar: dict with input type, total_flows, etc.
        """
        if self.unknown_total_flows(bar['input_type']):
            # we don't know how to get the total number of flows slips is going to process,
            # because they're growing
            return

        if self.stdout != '':
            # this means that stdout was redirected to a file,
            # no need to print the progress bar
            return

        self.total_flows = int(bar['total_flows'])
        # the bar_format arg is to disable ETA and unit display
        # dont use ncols so tqdm will adjust the bar size according to the terminal size
        self.progress_bar = tqdm(
            total=self.total_flows,
            leave=True,
            colour="green",
            desc="Flows read",
            mininterval=0, # defines how long to wait between each refresh.
            unit=' flow',
            smoothing=1,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}{postfix}",
            position=0,
            initial=0, #initial value of the flows processed
            file=sys.stdout
        )

    def update_progress_bar(self):
        """
        wrapper for tqdm.update()
        adds 1 to the number of flows processed
        """
        if not hasattr(self, 'progress_bar'):
            # this module wont have the progress_bar set if it's running on pcap or interface
            return

        if self.slips_mode == 'daemonized':
            return

        self.progress_bar.update(1)
        if self.progress_bar.n == self.total_flows:
            self.remove_stats_from_progress_bar()
            print(f"Done reading all flows. Slips is now processing them.")
            # remove it from the bar because we'll be prining it in a new line
            self.done_reading_flows = True
        # self.progress_bar.refresh()

    def shutdown_gracefully(self):
        self.log_line(
            {
                'from': self.name,
                'txt': 'Stopping output process. '
                       'Further evidence may be missing. '
                       'Check alerts.log for full evidence list.'
            }
        )

    def remove_stats_from_progress_bar(self):
        # remove the stats from the progress bar
        self.progress_bar.set_postfix_str(
            '',
            refresh=True
        )



    def update(self, msg: dict):
        """
        gets called whenever any module need to print something
        each msg shhould be in the following format
        {
            bar: 'update' or 'init'
            log_to_logfiles_only: bool that indicates wheteher we wanna log the text to all logfiles or the cli only?
            txt: text to log to the logfiles and/or the cli
            bar_info: {
                input_type: only given when we send bar:'init', specifies the type of the input file given to slips
                    eg zeek, argus, etc
                total_flows: int,
        }
        """
        if 'init' in msg.get('bar',''):
            self.init_progress_bar(msg['bar_info'])

        elif 'update' in msg.get('bar', ''):
            self.update_progress_bar()

        else:
            # output to terminal and logs or logs only?
            if msg.get('log_to_logfiles_only', False):
                self.log_line(msg)
            else:
                # output to terminal
                self.output_line(msg)

