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
        # Load the list of common known ports
        self.load_ports()

    def load_ports(self):
        """ 
        Funciton to read our special file called 'services.csv' and load the known ports from it into the database
        """
        try:
            f = open('modules/timeline/services.csv')
            for line in f:
                name = line.split(',')[0]
                port = line.split(',')[1]
                proto = line.split(',')[2]
                descr = line.split(',')[3]
                __database__.set_port_info(port+'/'+proto, name)
        except Exception as inst:
            self.print('Problem on load_ports()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True

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
            daddr_data = __database__.getIPData(daddr)
            try:
                daddr_country = daddr_data['geocountry']
            except KeyError:
                daddr_country = 'Unknown'
            try:
                daddr_asn = daddr_data['asn']
            except KeyError:
                daddr_asn = 'Unknown'
            dport = flow_dict['dport']
            proto = flow_dict['proto']
            # Here is where we see if we know this dport
            # Check the database.py code
            dport_name = __database__.get_port_info(dport+'/'+proto)
            if dport == 80 and proto == 'udp':
                print(dport_name)
            state = flow_dict['state']
            pkts = flow_dict['pkts']
            allbytes = flow_dict['allbytes']
            allbytes_human = 0.0
            if int(allbytes) < 1024:
                # In bytes
                allbytes_human = '{:.2f}{}'.format(float(allbytes),'b')
            elif int(allbytes) > 1024 and int(allbytes) < 1048576 :
                # In Kb
                allbytes_human = '{:.2f}{}'.format(float(allbytes) / 1024,'Kb')
            elif int(allbytes) > 1048576 and int(allbytes) < 1073741824:
                # In Mb
                allbytes_human = '{:.2f}{}'.format(float(allbytes) / 1024 / 1024, 'Mb')
            elif int(allbytes) > 1073741824:
                # In Bg
                allbytes_human = '{:.2f}{}'.format(float(allbytes) / 1024 / 1024 / 1024, 'Gb')
            spkts = flow_dict['spkts']
            sbytes = flow_dict['sbytes']
            appproto = flow_dict['appproto']

            key = profileid

            # Record Activity
            activity = ''
            if 'tcp' in proto or 'udp' in proto:
                if dport_name and state.lower() == 'established':
                    activity = '- {} asked to {} {}/{}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, dport, proto, allbytes_human, daddr_country, daddr_asn)
                # In here we try to capture the situation when only 1 udp packet is sent. Looks like not established, but is actually maybe ok
                elif dport_name and 'notest' in state.lower() and proto == 'udp' and allbytes == sbytes:
                    activity = '- Not answered {} asked to {} {}/{}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, dport, proto, allbytes_human, daddr_country, daddr_asn)
                elif dport_name and 'notest' in state.lower():
                    activity = '- NOT Established {} asked to {} {}/{}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, dport, proto, allbytes_human, daddr_country, daddr_asn)
                else:
                    activity = '[!!] Not recognized activity on flow {}\n'.format(flow)
            elif 'icmp' in proto:
                if '0x0008' in sport:
                    dport_name = 'PING echo'
                    activity = '- {} sent to {}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, allbytes_human, daddr_country, daddr_asn)
                elif '0x0103' in sport:
                    dport_name = 'ICMP Host Unreachable'
                    activity = '- {} sent to {}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, allbytes_human, daddr_country, daddr_asn)
                elif '0x0303' in sport:
                    dport_name = 'ICMP Port Unreachable'
                    activity = '- {} sent to {}, unreachable port is {}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, int(dport,16), allbytes_human, daddr_country, daddr_asn)
                elif '0x000b' in sport:
                    dport_name = 'ICMP Time Excedded in Transit'
                    activity = '- {} sent to {}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, allbytes_human, daddr_country, daddr_asn)
                elif '0x0003' in sport:
                    dport_name = 'ICMP Destination Net Unreachable'
                    activity = '- {} sent to {}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, allbytes_human, daddr_country, daddr_asn)
                else:
                    dport_name = 'ICMP Unknown type'
                    activity = '- {} sent to {}, Type: 0x{}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, sport, allbytes_human, daddr_country, daddr_asn)
            elif 'igmp' in proto:
                dport_name = 'IGMP'
                activity = '- {} sent to {}, Size: {}, Country: {}, ASN Org: {}\n'.format(dport_name, daddr, allbytes_human, daddr_country, daddr_asn)

            if activity:
                # Store the activity in the DB for this profileid and twid
                __database__.add_timeline_line(profileid, twid, activity)
            self.print('Activity of Profileid: {}, TWid {}: {}'.format(profileid, twid, activity), 4, 0)

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
