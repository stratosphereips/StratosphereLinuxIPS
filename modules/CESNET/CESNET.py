# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
import sys

# Your imports
from ..CESNET.warden_client import Client, read_cfg, Error, format_timestamp
import os
import json
import time

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
        self.stop_module = False

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
        if 'yes' in self.send_to_warden:
            # how often should we push to the server?
            try:
                self.push_delay = int(self.config.get('CESNET', 'push_delay'))
            except ValueError:
                # By default push every 1 day
                self.push_delay = 86400
            # get the output dir, this is where the alerts we want to push are stored
            self.output_dir = 'output/'
            if '-o' in sys.argv:
                self.output_dir = sys.argv[sys.argv.index('-o')+1]


        self.receive_from_warden = self.config.get('CESNET', 'receive_alerts').lower()
        if 'yes' in self.receive_from_warden:
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




    def export_alerts(self):
        alerts_path = os.path.join(self.output_dir, 'alerts.json')
        # Get the data that we want to send
        while True:
            try:
                with open(alerts_path, 'r') as f:
                    line = f.readline()
                    json_alert  = ''
                    while line not in ('\n',''):
                        json_alert += line
                        if json_alert.endswith('}\n'):
                            # reached the end of 1 alert
                            # convert all single quotes to double quotes to be able to convert to json
                            json_alert = json_alert.replace("'",'"')
                            json_alert = json.loads(json_alert)
                              # todo when exporting to warden server, this should be added
                            #      "Node": [
                           #    {
                           #       "Name": "cz.cesnet.kippo-honey",
                           #       "Type": ["Protocol", "Honeypot"],
                           #       "SW": ["Kippo"],
                           #       "AggrWin": "00:05:00"
                           #    }
                           # ]
                            return True
                        line = f.readline()
            except FileNotFoundError:
                # no alerts.json yet, wail 10 secs and try again
                time.sleep(10)
                continue


    def run(self):
        # Stop module if the configuration file is invalid or not found
        if self.stop_module:
            return False
        # create the warden client
        wclient = Client(**read_cfg(self.configuration_file))

        info = wclient.getDebug()
        # All methods return something.
        # If you want to catch possible errors (for example implement some
        # form of persistent retry, or save failed events for later, you may
        # check for Error instance and act based on contained info.
        # If you want just to be informed, this is not necessary, just
        # configure logging correctly and check logs.
        if isinstance(info, Error):
            self.print(info, 0, 1)

        info = wclient.getInfo()
        self.print(info, 0, 1)

        if 'yes' in self.send_to_warden:
            self.export_alerts()



