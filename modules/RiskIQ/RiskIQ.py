# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import sys

# Your imports
import configparser
import os
import json
import sys

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'RiskIQ'
    description = 'Module to get different information from RiskIQ'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.c1 = __database__.subscribe('new_ip')
        self.timeout = 0.0000001
        self.read_configuration()


    def read_configuration(self):
        try:
            # Read the riskiq api key
            RiskIQ_credentials_path = self.config.get('threatintelligence', 'RiskIQ_credentials_path')
            with open(RiskIQ_credentials_path,'r') as f:
                self.riskiq_email = f.readline().replace('\n','')
                self.riskiq_key = f.readline().replace('\n','')
                if len(self.riskiq_key) != 64:
                    raise NameError
        except (configparser.NoOptionError, configparser.NoSectionError, NameError, FileNotFoundError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.riskiq_email = None
            self.riskiq_key = None

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


    def get_passive_dns(self, ip) -> list:
        """
        Get passive dns info abbout this ip from passive total
        """

        command = f"curl -m 25 --insecure -s -u {self.riskiq_email}:{self.riskiq_key} 'https://api.riskiq.net/pt/v2/dns/passive?query={ip}' "
        response = os.popen(command).read()
        try:
            response = json.loads(response)
            # Sort and reverse the keys
            # Store the samples in our dictionary so we can sort them
            pt_data = {}
            # the response may have results key, OR 'message' key with an error,
            # make sure we have results before processing
            results = response.get('results', False)
            if results:
                for pt_results in results:
                    pt_data[pt_results['lastSeen']] = [pt_results['firstSeen'], pt_results['resolve'], pt_results['collected']]
                # Sort them by datetime and convert to list, sort the first 10 entries only
                sorted_pt_results = sorted(pt_data.items(), reverse=True)[:10]
            else:
                sorted_pt_results = None

        except json.decoder.JSONDecodeError:
            sorted_pt_results = None

        return sorted_pt_results

    def run(self):
        if not self.riskiq_email or not self.riskiq_key:
            return False
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True

                if utils.is_msg_intended_for(message, 'new_ip'):
                    ip = message['data']
                    # Only get passive total dns data if we don't have it in the db
                    if __database__.get_passive_dns(ip) == '':
                        # we don't have it in the db , get it from passive total
                        passive_dns = self.get_passive_dns(ip)
                        if passive_dns:
                            # we found data from passive total, store it in the db
                            __database__.set_passive_dns(ip, passive_dns)

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
