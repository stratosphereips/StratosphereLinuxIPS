# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__

# Your imports
import json

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'HTTP Analyzer'
    description = 'Module to analyze HTTP zeek files.'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.c1 = __database__.subscribe('new_http')
        self.timeout = None

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by
        taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to
         be printed
         debug: is the minimum debugging level required for this text to be
         printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the
        minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                if message['data'] == 'stop_process':
                    __database__.publish('finished_modules', self.name)
                    return True
                if message['channel'] == 'new_http' and type(message['data'])== str:
                    message = json.loads(message['data'])
                    profileid = message['profileid']
                    twid = message['twid']
                    flow = json.loads(message['flow'])
# {'uid': 'CAeDWs37BipkfP21u9', 'type': 'http', 'method': 'GET', 'host': '147.32.80.7', 'uri': '/wpad.dat', 'version': '1.1', 'user_agent': '', 'request_body_len': 0, 'response_body_len': 593, 'status_code': 200, 'status_msg': 'OK', 'resp_mime_types': ['text/plain'], 'resp_fuids': ['FqhaAy4xsmJ3AR63A3']}
                    user_agent = flow['user_agent']


            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                self.print('Problem on the run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
