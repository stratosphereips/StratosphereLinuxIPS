# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
import sys

# Your imports
from ..CESNET.warden_client import Client, Error, read_cfg, format_timestamp
import os

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'CESNET'
    description = 'Send and receive alerts from warden servers.'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.read_configuration()
        self.c1 = __database__.subscribe('new_ip')
        self.timeout = 0.0000001

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
        self.outputqueue.put(f"{levels}|{self.name}|{text}")


    def read_configuration(self):
        """ Read importing/exporting preferences from slips.conf """

        self.send_to_warden = self.config.get('CESNET', 'send_alerts').lower()
        if self.send_to_warden == 'yes':
            # how often should we push to the server?
            try:
                self.push_delay = int(self.config.get('CESNET', 'push_delay'))
            except ValueError:
                # By default push every 1 day
                self.push_delay = 86400

        self.receive_from_warden = self.config.get('CESNET', 'receive_alerts').lower()
        if self.receive_from_warden == 'yes':
            # how often should we get alerts from the server?
            try:
                self.receive_delay = int(self.config.get('CESNET', 'receive_delay'))
            except ValueError:
                # By default push every 1 day
                self.receive_delay = 86400

        self.configuration_file = self.config.get('CESNET', 'configuration_file')
        if not os.path.exists(self.configuration_file):
            self.print(f"Can't find warden.conf at {self.configuration_file}. Stopping module.")
            self.stop_module = True


    def run(self):
        # Stop module if the configuration file is invalid or not found
        if self.stop_module:
            return False

