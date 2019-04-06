# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

# Your imports
import time
import json

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'Timeline'
    description = 'Creates a timeline of what happened in the network based on all the flows and type of data available'
    authors = ['Sebastian Garcia']

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
        self.c1 = __database__.subscribe('new_flow')
        # To store the timelines of each profileid_twid
        self.profiles_tw = {}

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

    def process_flow(self, profileid, twid, flow):
        """
        Receives a flow and it process it for this profileid and twid
        """
        try:
            stime = next(iter(flow))
            flow_dict = json.loads(flow[stime])
            
            dur = flow_dict['dur']
            saddr = flow_dict['saddr']
            sport = flow_dict['sport']
            daddr = flow_dict['daddr']
            dport = flow_dict['dport']
            proto = flow_dict['proto']
            state = flow_dict['state']
            pkts = flow_dict['pkts']
            allbytes = flow_dict['allbytes']
            spkts = flow_dict['spkts']
            sbytes = flow_dict['sbytes']
            appproto = flow_dict['appproto']

            #key = profileid + '_' + twid
            key = profileid
            #self.print('Profileid: {}, TWid: {}, Flow: {}. key: {}'.format(profileid, twid, flow, stime))

            activity = ''
            if 'udp' in proto and '53' in dport and 'est' in state.lower():
                activity = 'DNS asked to {}'.format(daddr)
            elif 'udp' in proto and '53' in dport and not 'est' in state.lower():
                activity = 'Not Established DNS asked to {}'.format(daddr)
            elif 'udp' in proto and '123' in dport and 'est' in state.lower():
                activity = 'NTP asked to {}'.format(daddr)
            elif 'tcp' in proto and '80' in dport and 'est' in state.lower():
                activity = 'HTTP asked to {}'.format(daddr)
            elif 'tcp' in proto and '80' in dport and 'est' not in state.lower():
                activity = 'Not Established HTTP asked to {}'.format(daddr)
            elif 'tcp' in proto and '443' in dport and 'est' in state.lower():
                activity = 'HTTPS asked to {}'.format(daddr)
            elif 'tcp' in proto and '443' in dport and 'est' not in state.lower():
                activity = 'Not Established HTTPS asked to {}'.format(daddr)
            elif 'tcp' in proto and '5228' in dport and 'est' in state.lower():
                activity = 'Google Playstore or Google Talk or Google Chrome Sync to {}'.format(daddr)
            else:
                activity = 'Not recognized activity on flow {}'.format(flow)

            if activity:
                # Store the activity in the DB for this profileid and twid
                __database__.add_timeline_line(profileid, twid, activity)

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on process_flow()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=None)
                # Check that the message is for you. Probably unnecessary...
                if message['channel'] == 'new_flow' and message['data'] != 1:
                    # Example of printing the number of profiles in the Database every second
                    mdata = message['data']
                    # Convert from json to dict
                    mdata = json.loads(mdata)
                    profileid = mdata['profileid']
                    twid = mdata['twid']
                    # Get flow as a json
                    flow = mdata['flow']
                    # Convert flow to a dict
                    flow = json.loads(flow)
                    # Process the flow
                    self.process_flow(profileid, twid, flow)

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
