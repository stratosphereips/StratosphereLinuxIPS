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
from slips_files.common.abstracts.observer import IObserver
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.helpers.progress_bar import PBar
from slips_files.common.slips_utils import utils
from slips_files.common.style import red
from threading import Lock
import sys
import io
import time
from pathlib import Path
from datetime import datetime
import os
from multiprocessing import Pipe, Manager



class Output(IObserver):
    """
    A class to process the output of everything Slips need. Manages all the output
    If any Slips module or process needs to output anything to screen, or logs,
    it should use always the output queue. Then this output class will handle how to deal with it
    """

    name = 'Output'
    _obj = None
    slips_logfile_lock = Lock()
    errors_logfile_lock = Lock()
    cli_lock = Lock()
    has_pbar = False

    def __new__(
        cls,
        verbose=1,
        debug=0,
        stdout='',
        stderr='output/errors.log',
        slips_logfile='output/slips.log',
        slips_mode='interactive',
    ):
        if not cls._obj:
            cls._obj = super().__new__(cls)
            # when running slips using -e , this var is set and we only
            # print all msgs with debug lvl less than it
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

            # todo handle how we'll close this proc if pbar
            #  is supported or not supported
            # todo handle closing the pipe
            # false means the pipe is unidirectional.
            # only msgs can go from output -> pbar and not vice versa
            # recv_pipe used only for receiving,
            # send_pipe use donly for sending
            recv_pipe, cls.send_pipe = Pipe(False)
            # using mp manager to be able to change this value
            # from the PBar class and have it changed here
            cls.manager = Manager()
            cls.has_bar = cls.manager.Value("has_pbar", False)
            pbar = PBar(recv_pipe, cls.has_bar, cls.stdout)
            pbar.start()

            if cls.verbose > 2:
                print(f'Verbosity: {cls.verbose}. Debugging: {cls.debug}')


            cls.done_reading_flows = False
            # we update the stats printed by slips every 5seconds
            # this is the last time the stats was printed
            cls.last_updated_stats_time = float("-inf")

            #TODO test this when daemonized
            cls.slips_mode = slips_mode

        return cls._obj


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

        # don't log in daemon mode, all printed
        # lines are redirected to slips.log by default
        if "-D" in sys.argv:
            return

        sender, msg = msg['from'], msg['txt']

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

    def print(self, sender: str, txt: str, end='\n'):
        """
        prints the given txt whether using tqdm or using print()
        """
        self.cli_lock.acquire()
        # when the pbar reaches 100% aka we're done_reading_flows
        # we print alerts at the very botttom of the screen using print
        # instead of printing alerts at the top of the pbar using tqdm
        if sender:
            to_print = f'[{sender}] {txt}'
        else:
            to_print = txt

        if self.has_pbar:
            self.tell_pbar({
                'event': 'print',
                'txt': to_print
            })
        else:
            print(to_print, end=end)
        self.cli_lock.release()


    def log_error(self, msg: dict):
        """
        Log error line to errors.log
        """
        date_time = datetime.now()
        date_time = utils.convert_format(date_time, utils.alerts_format)

        self.errors_logfile_lock.acquire()
        with open(self.errors_logfile, 'a') as errors_logfile:
            errors_logfile.write(f'{date_time} [{msg["from"]}] {msg["txt"]}\n')
        self.errors_logfile_lock.release()


    def handle_printing_stats(self, stats: str):
        """
        slips prints the stats as a pbar postfix,
        or in a separate line if pbar isn't supported
        this method handles the 2 cases depending on the availability of the pbar
        """
        # if we're done reading flows, aka pbar reached 100% or we dont have a pbar
        # we print the stats in a new line, instead of next to the pbar
        if self.has_pbar:
            self.tell_pbar({
                'event': 'update_stats',
                'txt': stats
            })
        else:
            # print the stats with no sender
            self.print('', stats, end="\r")



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

    def output_line(self, msg: dict):
        """
        Prints to terminal and logfiles depending on the debug and verbose levels
        """
        verbose, debug = msg.get('verbose', self.verbose), msg.get('debug', self.debug)
        sender, txt = msg['from'], msg['txt']

        # if debug level is 3 make it red
        if debug == 3:
            msg = red(msg)

        if 'analyzed IPs' in txt:
            self.handle_printing_stats(txt)
            return


        # There should be a level 0 that we never print. So its >, and not >=
        if self.enough_verbose(verbose) or self.enough_debug(debug):
            if 'Start' in txt:
                # we use tqdm.write() instead of print() to make sure we
                # don't get progress bar duplicates in the cli
                self.tell_pbar({
                    'event': 'print',
                    'txt': txt
                })
                return

            self.print(sender, txt)
            self.log_line(msg)

        # if the line is an error and we're running slips without -e 1 ,
        # we should log the error to output/errors.log
        # make sure the msg is an error. debug_level==1 is the one printing errors
        if debug == 1:
            self.log_error(msg)

    def shutdown_gracefully(self):
        self.manager.shutdown()

        self.log_line(
            {
                'from': self.name,
                'txt': 'Stopping output process. '
                       'Further evidence may be missing. '
                       'Check alerts.log for full evidence list.'
            }
        )



    def tell_pbar(self, msg: dict):
        """
        writes to the pbar pipe. anything sent by this method
        will be received by the pbar class
        """
        self.send_pipe.send(msg)


    def update(self, msg: dict):
        """
        gets called whenever any module need to print something
        each msg shhould be in the following format
        {
            bar: 'update' or 'init'
            log_to_logfiles_only: bool that indicates wheteher we
            wanna log the text to all logfiles or the cli only?
            txt: text to log to the logfiles and/or the cli
            bar_info: {
                input_type: only given when we send bar:'init', specifies the type of the input file given to slips
                    eg zeek, argus, etc
                total_flows: int,
        }
        """
        if 'init' in msg.get('bar', ''):
            self.has_pbar = True
            self.tell_pbar({
                'event': 'init',
                'total_flows': msg['bar_info']['total_flows'],
            })

        elif 'update' in msg.get('bar', ''):
            # if pbar wasn't supported, inputproc won't send update msgs
            self.tell_pbar({
                'event': 'update',
            })

        else:
            # output to terminal and logs or logs only?
            if msg.get('log_to_logfiles_only', False):
                self.log_line(msg)
            else:
                # output to terminal
                self.output_line(msg)

