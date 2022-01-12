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
    description = 'Analyze HTTP flows'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.c1 = __database__.subscribe('new_http')
        self.timeout = 0.0000001
        self.google_connections_counter = 0
        self.google_connections_threshold = 4

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

    def check_suspicious_user_agents(self, uid, host, uri, timestamp, user_agent, profileid, twid):
        ''' Check unusual user agents and set evidence '''

        suspicious_user_agents = ('httpsend', 'chm_msdn', 'pb', 'jndi')
        if user_agent.lower() in suspicious_user_agents:
            type_detection = 'srcip'
            source_target_tag = 'UsingSuspiciousUserAgent'
            detection_info = profileid.split("_")[1]
            type_evidence = 'SuspiciousUserAgent'
            threat_level = 'high'
            category = 'Anomaly.Behaviour'
            confidence = 1
            description = f'Suspicious user agent: {user_agent} from host {host}{uri}'
            if not twid:
                twid = ''
            __database__.setEvidence(type_evidence, type_detection, detection_info, threat_level, confidence,
                                     description, timestamp, category,source_target_tag=source_target_tag,
                                     profileid=profileid, twid=twid, uid=uid)
            return True
        return False

    def check_multiple_google_connections(self, uid, host, timestamp, request_body_len,  profileid, twid):
        """
        Detects more than 4 empty connections to google.com on port 80
        """
        # to test this wget google.com:80 twice (wget makes multiple connections instead of 1)

        if host=='google.com' and request_body_len==0:
            self.google_connections_counter +=1

        if self.google_connections_counter == self.google_connections_threshold:
            type_evidence = 'multiple_google_connections'
            type_detection = 'srcip'
            detection_info = profileid.split('_')[0]
            threat_level = 'medium'
            category = 'Anomaly.Connection'
            confidence = 1
            description = f'multiple empty HTTP connections to google.com'
            if not twid:
                twid = ''
            __database__.setEvidence(type_evidence, type_detection, detection_info,
                                     threat_level, confidence, description, timestamp,
                                     category, profileid=profileid, twid=twid, uid=uid)
            # reset the counter
            self.google_connections_counter=0
            return True
        return False

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    __database__.publish('finished_modules', self.name)
                    return True

                if __database__.is_msg_intended_for(message, 'new_http'):
                    message = json.loads(message['data'])
                    profileid = message['profileid']
                    twid = message['twid']
                    flow = json.loads(message['flow'])
                    uid = flow['uid']
                    host = flow['host']
                    uri = flow['uri']
                    timestamp = flow.get('stime','')
                    user_agent = flow.get('user_agent')
                    request_body_len = flow.get('request_body_len')
                    self.check_suspicious_user_agents(uid, host, uri, timestamp, user_agent, profileid, twid)
                    self.check_multiple_google_connections(uid, host, timestamp, request_body_len,  profileid, twid)

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
