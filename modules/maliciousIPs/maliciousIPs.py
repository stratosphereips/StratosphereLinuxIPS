# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder. 
#    cp modules/template/maliciousIPs.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

# Your imports
import time

class MaliciousIPs(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'maliciousIPs'
    description = 'Check if the srcIP and dst IP are in malicious list of IPs.'
    authors = authors = ['StratoTeam']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        # The options change, so the last list is on the slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        self.c1 = __database__.subscribe('new_ip')


    def load_malicious_ips(self, malicious_txt: str) -> None:
        with open(malicious_txt) as f:
            for line in f:
                if '#' in line:
                    # '#' is comment line.
                    continue
                line = line.rstrip()
                comma_index = line.find(',')
                if comma_index == -1:
                    # No description was found for the IP.
                    ip_address = line
                else:
                    try:
                        ip_description = line[comma_index + 1:]
                    except IndexError:
                        # There is the comma, but no description.
                        ip_description = None
                    ip_address = line[:comma_index]


    def print(self, text, verbose=1, debug=0):
        """ 
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')
        
        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=None)
                # Check that the message is for you. Probably unnecessary...
                if message['channel'] == 'new_ip':
                    # Example of printing the number of profiles in the Database every second
                    data = len(__database__.getProfiles())
                    self.print('Amount of profiles: {}'.format(data))

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
