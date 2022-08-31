# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
import sys

# Your imports
import asyncio
import configparser
from modules.update_manager.timer_manager import InfiniteTimer
from modules.update_manager.update_file_manager import UpdateFileManager


class UpdateManager(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'UpdateManager'
    description = 'Update Threat Intelligence files'
    authors = ['Kamila Babayeva']

    def __init__(self, outputqueue, config, redis_port):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Read the conf
        self.read_configuration()
        # Start the DB
        self.redis_port = redis_port
        __database__.start(self.config, self.redis_port)
        self.c1 = __database__.subscribe('core_messages')
        # Update file manager
        self.update_manager = UpdateFileManager(
            self.outputqueue, config, redis_port
        )
        # Timer to update the ThreatIntelligence files
        self.timer_manager = InfiniteTimer(
            self.update_period, self.update_ti_files
        )
        self.timeout = 0.000001

    def read_configuration(self):
        """Read the configuration file for what we need"""
        try:
            # update period
            self.update_period = self.config.get(
                'threatintelligence', 'malicious_data_update_period'
            )
            self.update_period = float(self.update_period)
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
        ):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.update_period = 86400

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f'{levels}|{self.name}|{text}')


    def shutdown_gracefully(self):
        # terminating the timer for the process to be killed
        self.timer_manager.cancel()
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)
        return True

    async def update_ti_files(self):
        """
        Update TI files and store them in database before slips starts
        """
        # create_task is used to run update() function concurrently instead of serially
        update_finished = asyncio.create_task(self.update_manager.update())
        # wait for UpdateFileManager to finish before starting all the modules
        await update_finished

    def run(self):
        utils.drop_root_privs()
        try:
            asyncio.run(self.update_ti_files())
            # Starting timer to update files
            self.timer_manager.start()
        except KeyboardInterrupt:
            self.shutdown_gracefully()
            return True
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on the run() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True

        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
