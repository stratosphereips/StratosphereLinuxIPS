# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import sys

# Your imports
import json
import requests


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
        self.connections_counter = {}
        self.empty_connections_threshold = 4
        # this is a list of hosts known to be resolved by malware
        # to check your internet connection
        self.hosts = ['bing.com', 'google.com', 'yandex.com','yahoo.com']


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

        suspicious_user_agents = ('httpsend', 'chm_msdn', 'pb', 'jndi', 'tesseract')
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


    def check_multiple_empty_connections(self, uid, contacted_host, timestamp, request_body_len, profileid, twid):
        """
        Detects more than 4 empty connections to google, bing, yandex and yahoo on port 80
        """
        # to test this wget google.com:80 twice
        # wget makes multiple connections per command,
        # 1 to google.com and another one to www.google.com

        for host in self.hosts:
            if contacted_host== host or contacted_host==f'www.{host}' and request_body_len==0:
                try:
                    # this host has past connections, increate counter
                    self.connections_counter[host] +=1
                except KeyError:
                    # first empty connection to this host
                    self.connections_counter.update({host: 1})
                break
        else:
            # it's an http connection to a domain that isn't
            # in self.hosts, or simply not an empty connection
            # ignore it
            return False

        if self.connections_counter[host] == self.empty_connections_threshold:
            type_evidence = 'MultipleConnections'
            type_detection = 'srcip'
            detection_info = profileid.split('_')[0]
            threat_level = 'medium'
            category = 'Anomaly.Connection'
            confidence = 1
            description = f'multiple empty HTTP connections to {host}'
            if not twid:
                twid = ''
            __database__.setEvidence(type_evidence, type_detection, detection_info,
                                     threat_level, confidence, description, timestamp,
                                     category, profileid=profileid, twid=twid, uid=uid)
            # reset the counter
            self.connections_counter[host] =0
            return True
        return False


    def get_user_agent_info(self, user_agent, profileid) -> bool:
        """
        Get OS and browser info about a use agent from an online database http://useragentstring.com
        """
        # some zeek http flows don't have a user agent field
        if not user_agent: return False

        # don't make a request again if we already have a user agent associated with this profile
        if __database__.get_user_agent_from_profile(profileid) != None:
            # this profile already has a user agent
            return True

        url = f'http://useragentstring.com/?uas={user_agent}&getJSON=all'
        try:
            response = requests.get(url)
        except requests.exceptions.ConnectionError:
            return False
        if response.status_code != 200:
            return False

        # returns the following
        # {"agent_type":"Browser","agent_name":"Internet Explorer","agent_version":"8.0",
        # "os_type":"Windows","os_name":"Windows 7","os_versionName":"","os_versionNumber":"",
        # "os_producer":"","os_producerURL":"","linux_distibution":"Null","agent_language":"","agent_languageTag":""}

        json_response = json.loads(response.text)
        os_type = json_response.get('os_type', '')
        os_name = json_response.get('os_name', '')
        browser = json_response.get('agent_name', '')
        # store the ua and the info we got in one string
        # the above website returns unknown if it has no info about this UA,
        # remove the 'unknown' from the string before storing in the db
        UA_info = f'{user_agent} {os_name} {os_type} {browser}'.replace('unknown','').replace('  ','')
        # store it in the database
        __database__.add_user_agent_to_profile(profileid, UA_info)


    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    __database__.publish('finished_modules', self.name)
                    return True

                if utils.is_msg_intended_for(message, 'new_http'):
                    message = json.loads(message['data'])
                    profileid = message['profileid']
                    twid = message['twid']
                    flow = json.loads(message['flow'])
                    uid = flow['uid']
                    host = flow['host']
                    uri = flow['uri']
                    timestamp = flow.get('stime','')
                    user_agent = flow.get('user_agent', False)
                    request_body_len = flow.get('request_body_len')
                    self.check_suspicious_user_agents(uid, host, uri, timestamp, user_agent, profileid, twid)
                    self.check_multiple_empty_connections(uid, host, timestamp, request_body_len, profileid, twid)
                    self.get_user_agent_info(user_agent, profileid)

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
