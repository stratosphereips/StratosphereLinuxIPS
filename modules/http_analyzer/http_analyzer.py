# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
import sys

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

    def check_suspicious_user_agents(self, flow, profileid, twid):
        '''Check unusual user agents and set evidence'''
        user_agent = flow.get('user_agent')
        suspicious_user_agents = ('httpsend', 'chm_msdn', 'pb')
        if user_agent.lower() in suspicious_user_agents:
            uid = flow['uid']
            host = flow['host']
            uri = flow['uri']
            timestamp = flow.get('stime','')
            type_detection = 'user_agent'
            detection_info = user_agent
            type_evidence = 'SuspiciousUserAgent' # todo
            threat_level = 20
            confidence = 1
            description = f'Suspicious user agent: {user_agent} from host {host}{uri}'
            if not twid:
                twid = ''
            __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level,
                                     confidence, description, timestamp, profileid=profileid, twid=twid, uid=uid)
            return True
        return False

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
                    self.check_suspicious_user_agents(flow, profileid, twid)

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
