# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables
# 5. The file name of the python module (template.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to ignore the module
# 7. The name of the class MUST be 'Module', do not change it.

# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
import sys
import traceback

# Your imports
import json
import queue
import datetime

class FlowList:
    def __init__(self, buffer_size = 300, threshold = 4.0):
        self.flows = {} #saddr: queue of buffer_size most recent flows
        self.buffer_size = buffer_size
        self.stats_list = [
            'dur', 'pkts', 'allbytes'
        ]
        self.stats = {} #saddr: dict of running sum of each stat in stats_list
        self.baselines = dict.fromkeys(self.stats_list, 0) #stat: per flow avg across all sources
        self.threshold = threshold
        self.nat_ips = set()
        self.most_recent_nat = None #data value gets consumed after reading once
    def add_flow(self, flow_data):
        saddr = flow_data['saddr']
        src_before = len(self.flows)
        if saddr not in self.flows:
            self.flows[saddr] = queue.Queue()
            self.stats[saddr] = dict.fromkeys(self.stats_list, 0)
        flowq = self.flows[saddr]
        while not flowq.empty() and self.flows[saddr].qsize() >= self.buffer_size:
            popped_flow = self.get_stats_list(flowq.get())
            self.update_stats(saddr,self.get_stats_list(popped_flow), multiplier=-1)
        flowq.put(flow_data)
        # each flow->update saddr average, update global average, check if current src passes threshold
        stat_deltas = self.get_stats_list(flow_data)
        stat_avg = self.get_stat_avg(saddr)
        self.update_stats(saddr, stat_deltas)
        for stat in self.stats_list:
            self.baselines[stat] = self.baselines[stat]*src_before + stat_avg[stat]
            self.baselines[stat] /= len(self.flows)
        if self.stats_above_threshold(stat_avg):
            self.nat_ips.add(saddr)
            self.most_recent_nat = saddr
    def update_stats(self, saddr, stats_dict, multiplier=1):
        for stat in self.stats_list:
            self.stats[saddr][stat] += multiplier*stats_dict[stat]
    def get_stats_list(self, flow_data):
        return {
            'dur': float(flow_data['dur']),
            'pkts': flow_data['pkts'],
            'allbytes': flow_data['allbytes']
        }
    def get_stat_avg(self, saddr):
        avg = {}
        stats = self.stats[saddr]
        num = self.flows[saddr].qsize()
        for key in self.stats_list:
            avg[key] = stats[key]/num
        return avg
    def stats_above_threshold(self, stats):
        for key in self.stats_list:
            if key not in stats:
                raise Exception('stats_exceed_threshold: parameter doesn\'t contain required keys')
            if stats[key] > self.baselines[key]*self.threshold:
                return True
        return False
    def garbage_collect_nat_ips(self):
        for saddr in self.nat_ips:
            stat_avg = self.get_stat_avg(saddr)
            if self.stats_above_threshold(stat_avg):
                self.nat_ips.add(saddr)
            else:
                self.nat_ips.discard(saddr)
    def get_nat_ips(self):
        return self.nat_ips
    def get_most_recent_nat(self):
        most_recent = self.most_recent_nat
        self.most_recent_nat = None
        return most_recent
class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'NAT Detector'
    description = 'Detect IPs running NAT'
    authors = ['Daniel Yang']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        # Remember to subscribe to this channel in database.py
        self.c1 = __database__.subscribe('new_flow')

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
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)

    def run(self):
        utils.drop_root_privs()
        # Main loop function
        flow_list = FlowList()
        last_garbage_collection = 0
        while True:
            try:
                message = __database__.get_message(self.c1)
                # Check that the message is for you. Probably unnecessary...
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if message and message['channel'] == 'new_flow':
                    try:
                        json_data = json.loads(json.loads(message['data'])['flow'])
                        key = list(json_data.keys())[0]
                        data = json.loads(json_data[key])
                        if data['ts'] - last_garbage_collection > 120:
                            flow_list.garbage_collect_nat_ips()
                            last_garbage_collection = data['ts']
                        flow_list.add_flow(data)
                        most_recent = flow_list.get_most_recent_nat()
                        #if detects NAT then displays most_recent
                        #could also periodically correct nat_ips
                        if most_recent:
                            confidence = 0.8
                            # how dangerous is this evidence? info, low, medium, high, critical?
                            threat_level = 'high'

                            # the name of your evidence, you can put any descriptive string here
                            evidence_type = 'ConnectionToLocalDevice'
                            # what is this evidence category according to IDEA categories 
                            category = 'Anomaly.Connection'
                            # which ip is the attacker here? the src or the dst?
                            attacker_direction = 'srcip'
                            # what is the ip of the attacker?
                            attacker = data['saddr']
                            # describe the evidence
                            description = f'Detected an instance of NAT {data["saddr"]}'
                            timestamp = datetime.datetime.fromtimestamp(data['ts']).strftime('%Y/%m/%d-%H:%M:%S')
                            # the crrent profile is the source ip, this comes in 
                            # the msg received in the channel
                            msg_data = json.loads(message['data'])
                            profileid = msg_data['profileid']
                            # Profiles are split into timewindows, each timewindow is 1h, 
                            # this comes in the msg received in the channel
                            twid = msg_data['twid']

                            __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                                    timestamp, category, profileid=profileid, twid=twid)
                    except Exception as e:
                        data = "parse failed"
                        self.print(e)
                    # self.print(data, 1, 0)

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True
