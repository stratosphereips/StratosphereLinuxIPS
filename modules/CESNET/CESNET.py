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


    def export_alerts(self, wclient):

        # [1] read all alerts from alerts.json
        alerts_path = os.path.join(self.output_dir, 'alerts.json')
        # this will contain a list of dicts, each dict is an alert in the IDEA format
        # and each dict will contain node information
        alerts_list = []

        alert= ''
        # Get the data that we want to send
        with open(alerts_path, 'r') as f:
            for line in f:
                alert += line
                if line.endswith('}\n'):
                    # reached the end of 1 alert
                    # convert all single quotes to double quotes to be able to convert to json
                    alert = alert.replace("'",'"')

                    # convert to dict to be able to add node name
                    json_alert = json.loads(alert)
                    # add Node info to the alert
                    json_alert.update({"Node": self.node_info})

                    #todo for now we can only send test category
                    json_alert.update({"Category": ['Test']})

                    alerts_list.append(json_alert)
                    alert = ''



        # [2] Upload to warden server
        self.print(f"Uploading {len(alerts_list)} events to warden server.")
        ret = wclient.sendEvents(alerts_list)
        self.print(ret)

    def import_alerts(self, wclient):
        pass

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

        self.node_info = [{
            "Name": wclient.name,
            "Type": ["IPS"],
            "SW": ['Slips']
        }]

        while True:
            try:
                if 'yes' in self.send_to_warden:
                    now = time.time()
                    last_update = __database__.get_last_warden_push_time()

                    # first push should be push_delay after slips starts (for example 1h after starting)
                    # so that slips has enough time to generate alerts
                    start_time  = float(__database__.get_slips_start_time().strftime('%s'))
                    first_push = now >= start_time+self.push_delay

                    # did we wait the push_delay period since last update?
                    push_period_passed = last_update + self.push_delay < now

                    if first_push and push_period_passed:
                        self.export_alerts(wclient)
                         # set last push time to now
                        __database__.set_last_warden_push_time(now)

                if 'yes' in self.receive_from_warden:
                    last_update = __database__.get_last_warden_pull_time()

                    # did we wait the pull_delay period since last pull?
                    if last_update + self.pull_delay < now:
                        self.import_alerts(wclient)

                        # set last pull time to now
                        __database__.set_last_warden_pull_time(now)

                    # start the module again when the min of the delays has passed
                    time.sleep(min(self.push_delay, self.receive_delay))

            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True



