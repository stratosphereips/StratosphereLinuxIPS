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
import traceback
from tqdm.auto import tqdm
from slips_files.common.abstracts import Core

class OutputProcess(Core):
    """
    A class to process the output of everything Slips need. Manages all the output
    If any Slips module or process needs to output anything to screen, or logs,
    it should use always the output queue. Then this output class will handle how to deal with it
    """

    name = 'Output'

    def init(
        self,
        verbose=None,
        debug=None,
        stdout='',
        stderr='output/errors.log',
        slips_logfile='output/slips.log'
    ):
        self.verbose = verbose
        self.debug = debug
        ####### create the log files
        self.read_configuration()
        self.errors_logfile = stderr
        self.slips_logfile = slips_logfile

        # set in the Core interface
        self.queue = self.output_queue

        self.create_logfile(self.errors_logfile)
        self.create_logfile(self.slips_logfile)
        utils.change_logfiles_ownership(self.errors_logfile, self.UID, self.GID)
        utils.change_logfiles_ownership(self.slips_logfile, self.UID, self.GID)

        # self.quiet manages if we should really print stuff or not
        self.quiet = False

        self.stdout = stdout
        if stdout != '':
            self.change_stdout(self.stdout)
        if self.verbose > 2:
            print(
                f'Verbosity: {str(self.verbose)}. Debugging: {str(self.debug)}'
            )
        self.done_reading_flows = False
        # are we in daemon of interactive mode
        self.slips_mode = self.db.get_slips_mode()
        # we update the stats printed by slips every 5seconds
        # this is the last time the stats was printed
        self.last_updated_stats_time = float("-inf")


    def read_configuration(self):
        conf = ConfigParser()
        self.printable_twid_width = conf.get_tw_width()
        self.GID = conf.get_GID()
        self.UID = conf.get_UID()

    def log_branch_info(self, logfile):
        # both will be False when we're in docker because there's no .git/ there
        branch = self.db.get_branch()
        commit = self.db.get_commit()
        if branch == 'None' and commit == 'None':
            return

        branch_info = ''
        if branch:
            branch_info += branch
        if commit:
            branch_info += f' ({commit})'

        now = datetime.now()
        with open(logfile, 'a') as f:
            f.write(f'Using {branch_info} - {now}\n\n')

    def create_logfile(self, path):
        """
        creates slips.log and errors.log if they don't exist
        """
        try:
            open(path, 'a').close()
        except FileNotFoundError:
            p = Path(os.path.dirname(path))
            p.mkdir(parents=True, exist_ok=True)
            open(path, 'w').close()

        self.log_branch_info(path)


    def log_line(self, sender, msg):
        """
        Log error line to slips.log
        """
        # don't log in daemon mode, all printed
        # lines are redirected to slips.log by default
        if "-D" in sys.argv and 'update'.lower() not in sender and 'stopping' not in sender:
            # if the sender is the update manager, always log
            return

        with open(self.slips_logfile, 'a') as slips_logfile:
            date_time = datetime.now()
            date_time = utils.convert_format(date_time, utils.alerts_format)
            slips_logfile.write(f'{date_time} {sender}{msg}\n')



    def change_stdout(self, file):
        # io.TextIOWrapper creates a file object of this file
        # Pass 0 to open() to switch output buffering off (only allowed in binary mode)
        # write_through= True, to flush the buffer to disk, from there the file can read it.
        # without it, the file writer keeps the information in a local buffer that's not accessible to the file.
        sys.stdout = io.TextIOWrapper(open(file, 'wb', 0), write_through=True)
        return

    def process_line(self, line):
        """
        Extract the verbosity level, the sender and the message from the line.
        The line is separated by | and the fields are:
        1. The level. It means the importance/verbosity we should be. The lower the less important
            The level is a two digit number
            first digit: verbosity level
            second digit: debug level
            both levels range from 0 to 3

            verbosity:
                0 - don't print
                1 - basic operation/proof of work
                2 - log I/O operations and filenames
                3 - log database/profile/timewindow changes

            debug:
                0 - don't print
                1 - print exceptions
                2 - unsupported and unhandled types (cases that may cause errors)
                3 - red warnings that needs examination - developer warnings

            Messages should be about verbosity or debugging, but not both simultaneously
        2. The sender
        3. The message

        The level is always an integer from 0 to 10
        """
        try:
            try:
                level = line.split('|')[0]
                if int(level) < 0 or int(level) >= 100 or len(level) < 2:
                    level = '00'
            except TypeError:
                print('Error in the level sent to the Output Process')
            except KeyError:
                level = '00'
                print(
                    'The level passed to OutputProcess was wrongly formated.'
                )
            except ValueError as inst:
                # We probably received some text instead of an int()
                print(
                    'Error receiving a text to output. '
                    'Check that you are sending the format of the msg correctly: level|msg'
                )
                print(inst)
                sys.exit(-1)

            try:
                sender = f"[{line.split('|')[1]}] "
            except KeyError:
                sender = ''
                print(
                    'The sender passed to OutputProcess was wrongly formatted.'
                )
                sys.exit(-1)

            try:
                # If there are more | inside the msg, we don't care, just print them
                msg = ''.join(line.split('|')[2:])
            except KeyError:
                msg = ''
                print(
                    'The message passed to OutputProcess was wrongly formatted.'
                )
                sys.exit(-1)
            return (level, sender, msg)

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            print(
                f'\tProblem with process line in OutputProcess() line '
                f'{exception_line}'
            )
            self.print(traceback.print_exc(), 0, 1)
            sys.exit(1)

    def log_error(self, sender, msg):
        """
        Log error line to errors.log
        """
        with open(self.errors_logfile, 'a') as errors_logfile:
            date_time = datetime.now()
            date_time = utils.convert_format(date_time, utils.alerts_format)
            errors_logfile.write(f'{date_time} {sender}{msg}\n')

    def output_line(self, level, sender, msg):
        """
        Print depending on the debug and verbose levels
        """
        # (level, sender, msg) = self.process_line(line)
        verbose_level, debug_level = int(level[0]), int(level[1])
        # if verbosity level is 3 make it red
        if debug_level == 3:
            msg = f'\033[0;35;40m{msg}\033[00m'

        # There should be a level 0 that we never print. So its >, and not >=
        if ((
            verbose_level > 0 and verbose_level <= 3
            and verbose_level <= self.verbose
        ) or (
            debug_level > 0 and debug_level <= 3
            and debug_level <= self.debug
        )):
            if 'Start' in msg:
                # we use tqdm.write() instead of print() to make sure we
                # don't get progress bar duplicates in the cli
                tqdm.write(f'{msg}')
                return

            # when the pbar reaches 100% aka we're done_reading_flows
            # we print alerts at the very botttom of the screen using print
            # instead of printing alerts at the top of the pbar using tqdm
            if hasattr(self, 'done_reading_flows') and self.done_reading_flows:
                print(f'{sender}{msg}')
            else:
                tqdm.write(f'{sender}{msg}')

            # print(f'{sender}{msg}')
            self.log_line(sender, msg)

        # if the line is an error and we're running slips without -e 1 , we should log the error to output/errors.log
        # make sure the msg is an error. debug_level==1 is the one printing errors
        if debug_level == 1:
            self.log_error(sender, msg)

    def unknown_total_flows(self) -> bool:
        """
        When running on a pcap, interface, or taking flows from an
        external module, the total amount of flows are unknown
        """
        if self.db.get_input_type() in ('pcap', 'interface', 'stdin'):
            return True

        # whenever any of those is present, slips won't be able to get the
        # total flows when starting, nor init the progress bar
        params = ('-g', '--growing', '-im', '--input_module')
        for param in params:
            if param in sys.argv:
                return True

    def init_progress_bar(self):
        """
        initializes the progress bar when slips is runnning on a file or a zeek dir
        ignores pcaps, interface and dirs given to slips if -g is enabled
        """
        if self.unknown_total_flows():
            # we don't know how to get the total number of flows slips is going to process,
            # because they're growing
            return

        if self.stdout != '':
            # this means that stdout was redirected to a file,
            # no need to print the progress bar
            return

        self.total_flows = int(self.db.get_total_flows())
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

        # todo profile slips with and without the bar !
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
        self.log_line('[Output Process]', ' Stopping output process. '
                                        'Further evidence may be missing. '
                                        'Check alerts.log for full evidence list.')

    def remove_stats_from_progress_bar(self):
        # remove the stats from the progress bar
        self.progress_bar.set_postfix_str(
            '',
            refresh=True
        )

    def update_stats(self):
        """
        updates the statistics shown next to the progress bar or shown in a new line
        """
        if not hasattr(self, 'progress_bar'):
            return

        now = datetime.now()
        if utils.get_time_diff(self.last_updated_stats_time, now, 'seconds') < 5:
            return

        # only update the stats if 5 seconds passed
        self.last_updated_stats_time = now
        now = utils.convert_format(now, '%Y/%m/%d %H:%M:%S')
        modified_ips_in_the_last_tw = self.db.get_modified_ips_in_the_last_tw()
        profilesLen = self.db.get_profiles_len()
        evidence_number = self.db.get_evidence_number() or 0
        msg = f'Analyzed IPs: ' \
              f'{profilesLen}. ' \
              f'Evidence Added: {evidence_number} ' \
              f'IPs sending traffic in the last ' \
              f'{self.printable_twid_width}: {modified_ips_in_the_last_tw}. ' \
              f'({now})'
        # if we're done reading flows, aka pbar reached 100%
        # we print the stats in a new line, instead of next to the pbar
        if hasattr(self, 'done_reading_flows') and self.done_reading_flows:
            print(msg, end='\r')
        else:
            # print the stats in a the bar
            self.progress_bar.set_postfix_str(
                msg,
                refresh=True
            )

    def main(self):
        while not self.should_stop():
            self.update_stats()
            line = self.queue.get()
            if line == 'quiet':
                self.quiet = True
            elif 'initialize progress bar' in line:
                self.init_progress_bar()
            elif 'update progress bar' in line:
                self.update_progress_bar()
            elif 'stop_process' in line or line == 'stop':
                self.shutdown_gracefully()
                return True
            elif not self.quiet:
                # output to terminal and logs or logs only?

                if 'log-only' in line:
                    line = line.replace('log-only', '')
                    (level, sender, msg) = self.process_line(line)
                    self.log_line(sender, msg)
                else:
                    (level, sender, msg) = self.process_line(line)
                    # output to terminal
                    self.output_line(level, sender, msg)

            else:
                # Here we should still print the lines coming in
                # the input for a while after receiving a 'stop'.
                # We don't know how to do it.
                print('Stopping the output process')
                self.shutdown_gracefully()
                return True

        self.shutdown_gracefully()
        return True