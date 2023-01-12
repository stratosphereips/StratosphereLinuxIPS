from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
from slips_files.common.config_parser import ConfigParser
import sys
import traceback
import asyncio
from exclusiveprocess import Lock, CannotAcquireLock
from modules.update_manager.timer_manager import InfiniteTimer
from modules.update_manager.update_file_manager import UpdateFileManager


class UpdateManager(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'Update Manager'
    description = 'Update Threat Intelligence files'
    authors = ['Kamila Babayeva', 'Alya Gomaa']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        self.read_configuration()
        # Start the DB
        self.redis_port = redis_port
        __database__.start(self.redis_port)
        self.c1 = __database__.subscribe('core_messages')
        # Update file manager
        self.update_manager = UpdateFileManager(
            self.outputqueue, redis_port
        )
        # Timer to update the ThreatIntelligence files
        self.timer_manager = InfiniteTimer(
            self.update_period, self.update_ti_files
        )
        # Timer to update the MAC db
        # when update_ti_files is called, it decides what exactly to update, the mac db,
        # online whitelist OT online ti files.
        self.mac_db_update_manager = InfiniteTimer(
            self.mac_db_update_period, self.update_ti_files
        )
        self.online_whitelist_update_timer = InfiniteTimer(
            self.online_whitelist_update_period, self.update_ti_files
        )

    def read_configuration(self):
        conf = ConfigParser()
        self.update_period = conf.update_period()
        self.mac_db_update_period = conf.mac_db_update_period()
        self.online_whitelist_update_period = conf.online_whitelist_update_period()


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
        self.mac_db_update_manager.cancel()
        self.online_whitelist_update_timer.cancel()
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
        self.print(f'{__database__.get_loaded_ti_files()} TI files successfully loaded.')

    def run(self):
        utils.drop_root_privs()
        try:
            # only one instance of slips should be able to update TI files at a time
            # so this function will only be allowed to run from 1 slips instance.
            with Lock(name="slips_macdb_and_whitelist_and_TI_files_update"):
                asyncio.run(self.update_ti_files())
                # Starting timer to update files
                self.timer_manager.start()
                self.mac_db_update_manager.start()
                self.online_whitelist_update_timer.start()
        except CannotAcquireLock:
            # another instance of slips is updating TI files, tranco whitelists and mac db
            return
        except KeyboardInterrupt:
            self.shutdown_gracefully()
            return True
        except Exception as ex:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on the run() line {exception_line}', 0, 1)
            self.print(traceback, 0, 1)
            return True

        # Main loop function
        while True:
            try:
                message = __database__.get_message(self.c1)
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
                self.print(traceback.format_exc(), 0, 1)
                return True
