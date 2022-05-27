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
import io
from .database import __database__
from slips_files.common.slips_utils import utils
from datetime import datetime
import os

# Output Process
class OutputProcess(multiprocessing.Process):
    """A class process to output everything we need. Manages all the output"""

    def __init__(
        self,
        inputqueue,
        verbose,
        debug,
        config,
        redis_port,
        stdout='',
        stderr='output/errors.log',
        slips_logfile='output/slips.log'
    ):
        multiprocessing.Process.__init__(self)
        self.verbose = verbose
        self.debug = debug
        ####### create the log files
        self.errors_logfile = stderr
        self.slips_logfile = slips_logfile
        self.create_logfile(self.errors_logfile)
        self.create_logfile(self.slips_logfile)
        #######
        self.name = 'OutputProcess'
        self.queue = inputqueue
        self.config = config
        # self.quiet manages if we should really print stuff or not
        self.quiet = False
        if stdout != '':
            self.change_stdout(stdout)
        if self.verbose > 2:
            print(
                f'Verbosity: {str(self.verbose)}. Debugging: {str(self.debug)}'
            )
        # Start the DB
        __database__.start(self.config, redis_port)


    def log_branch_info(self, logfile):
        branch_info = utils.get_branch_info()
        if branch_info:
            # it's false when we're in docker because there's no .git/ there
            commit, branch = branch_info[0], branch_info[1]
            now = datetime.now()
            with open(logfile, 'w') as f:
                f.write(f'Using {branch} - {commit} - {now}\n\n')

    def create_logfile(self, path):
        """
        creates slips.log and errors.log
        """
        try:
            open(path, 'w').close()
        except FileNotFoundError:
            os.mkdir(os.path.dirname(path))
            self.create_logfile(path)

        self.log_branch_info(path)


    def log_line(self, sender, msg):
        """
        Log error line to slips.log
        """
        with open(self.slips_logfile, 'a') as slips_logfile:
            date_time = datetime.now().strftime('%d/%m/%Y-%H:%M:%S')
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
                    'Error receiving a text to output. Check that you are sending the format of the msg correctly: level|msg'
                )
                print(inst)
                sys.exit(-1)
            try:
                sender = f"[{line.split('|')[1]}] "
            except KeyError:
                sender = ''
                print(
                    'The sender passed to OutputProcess was wrongly formated.'
                )
                sys.exit(-1)
            try:
                # If there are more | inside the msg, we don't care, just print them
                msg = ''.join(line.split('|')[2:])
            except KeyError:
                msg = ''
                print(
                    'The message passed to OutputProcess was wrongly formated.'
                )
                sys.exit(-1)
            return (level, sender, msg)

        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            print(
                f'\tProblem with process line in OutputProcess() line '
                f'{exception_line}', 0, 1,
            )
            print(type(inst), 0, 1)
            print(inst.args, 0, 1)
            print(inst, 0, 1)
            sys.exit(1)

    def log_error(self, sender, msg):
        """
        Log error line to errors.log
        """
        with open(self.errors_logfile, 'a') as errors_logfile:
            date_time = datetime.now().strftime('%d/%m/%Y-%H:%M:%S')
            errors_logfile.write(f'{date_time} {sender}{msg}\n')

    def output_line(self, line):
        """
        Extract the level, sender and msg from line and format it and
        print
        """
        (level, sender, msg) = self.process_line(line)
        verbose_level, debug_level = int(level[0]), int(level[1])
        # if verbosity level is 3 make it red
        if debug_level == 3:
            msg = f'\033[0;35;40m{msg}\033[00m'

        # There should be a level 0 that we never print. So its >, and not >=
        if (
                verbose_level > 0
                and verbose_level <= 3
                and verbose_level <= self.verbose
        ):
            self.log_line(sender, msg)
            if 'Start' in msg:
                print(f'{msg}')
                return
            print(f'{sender}{msg}')
        elif (
                debug_level > 0
                and debug_level <= 3
                and debug_level <= self.debug
        ):
            self.log_line(sender, msg)
            if 'Start' in msg:
                print(f'{msg}')
                return
            # For now print DEBUG, then we can use colors or something
            print(f'{sender}{msg}')

        # if the line is an error and we're running slips without -e 1 , we should log the error to output/errors.log
        # make sure thee msg is an error. debug_level==1 is the one printing errors
        if debug_level == 1:
            self.log_line(sender, msg)
            # it's an error. we should log it
            self.log_error(sender, msg)

    def shutdown_gracefully(self):
        __database__.publish('finished_modules', self.name)

    def run(self):
        utils.drop_root_privs()
        while True:
            try:
                line = self.queue.get()
                if line == 'quiet':
                    self.quiet = True
                elif 'stop_process' in line:
                    self.shutdown_gracefully()
                    return True
                elif line != 'stop':
                    if not self.quiet:
                        self.output_line(line)
                else:
                    # Here we should still print the lines coming in
                    # the input for a while after receiving a 'stop'. We don't know how to do it.
                    print('Stopping the output thread')
                    self.shutdown_gracefully()
                    return True

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                print(
                    f'\tProblem with OutputProcess() line {exception_line}',
                    0,
                    1,
                )
                print(type(inst), 0, 1)
                print(inst.args, 0, 1)
                print(inst, 0, 1)
                return True
