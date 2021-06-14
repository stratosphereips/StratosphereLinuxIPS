# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform
import traceback

# Your imports
import time
import json
import configparser
from datetime import datetime

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'timeline'
    description = 'Creates a timeline of what happened in the network based on all the flows and type of data available'
    authors = ['Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.separator = __database__.getFieldSeparator()
        # Subscribe to 'new_flow' channel
        self.c1 = __database__.subscribe('new_flow')
        # To store the timelines of each profileid_twid
        self.profiles_tw = {}
        # Load the list of common known ports
        self.load_ports()
        # Store malicious IPs. We do not make alert everytime we receive flow with thi IP but only once.
        self.alerted_malicous_ips_dict = {}
        # Read information how we should print timestamp.
        self.is_human_timestamp = bool(self.read_configuration('modules', 'timeline_human_timestamp'))
        self.analysis_direction = self.config.get('parameters', 'analysis_direction')
        # Wait a little so we give time to have something to print
        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = None
        else:
            self.timeout = None

    def read_configuration(self, section: str, name: str) -> str:
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
            conf_variable = self.config.get(section, name)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            conf_variable = None
        return conf_variable

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
                # descr = line.split(',')[3]
                __database__.set_port_info(str(port)+'/'+proto, name)
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

    def process_timestamp(self, timestamp: float) -> str:
        if self.is_human_timestamp is True:
            # human readable time
            d = datetime.fromtimestamp(timestamp)
            timestamp = '{0:04d}/{1:02d}/{2:02d} {3:02d}:{4:02d}:{5:02d}.{6:06d}'.format(d.year, d.month, d.day, d.hour, d.minute, d.second, d.microsecond)
        return str(timestamp)

    def process_flow(self, profileid, twid, flow, timestamp: float):
        """
        Receives a flow and it process it for this profileid and twid so its printed by the logprocess later
        """
        timestamp_human = self.process_timestamp(timestamp)

        try:
            # Convert the common fields to something that can be interpreted
            uid = next(iter(flow))
            flow_dict = json.loads(flow[uid])
            profile_ip = profileid.split('_')[1]
            dur = round(float(flow_dict['dur']),3)
            stime = flow_dict['ts']
            saddr = flow_dict['saddr']
            sport = flow_dict['sport']
            daddr = flow_dict['daddr']
            dport = flow_dict['dport']
            proto = flow_dict['proto'].upper()
            try:
                dport_name = flow_dict['appproto'].upper()
            except (KeyError, AttributeError):
                dport_name = ''

            # Here is where we see if we know this dport
            if not dport_name:
                dport_name = __database__.get_port_info(str(dport)+'/'+proto.lower())
                if dport_name:
                    dport_name = dport_name.upper()
            state = flow_dict['state']
            pkts = flow_dict['pkts']
            allbytes = flow_dict['allbytes']
            if type(allbytes) != int:
                allbytes = 0
            allbytes_human = 0.0

            # Convert the bytes into human readable
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
            if type(sbytes) != int:
                sbytes = 0

            # Now that we have the flow processed. Try to interpret it and create the activity line
            # Record Activity
            activity = {}
            # Change the format of timeline in the case of inbound flows for external IP, i.e direction 'all' and destination IP == profile IP.
            # If not changed, it would have printed  'IP1 https asked to IP1'.
            if self.analysis_direction == 'all' and str(daddr) == str(profile_ip):
                if 'TCP' in proto or 'UDP' in proto:
                    warning_empty = ''
                    critical_warning_dport_name = ''
                    dns_resolution = ''
                    dns_resolution = __database__.get_dns_resolution(daddr)
                    # we should take only one resolution, if there is more than 3, because otherwise it does not fit in the timeline.
                    if len(dns_resolution) > 3:
                        dns_resolution = dns_resolution[-1]

                    if not dns_resolution:
                        dns_resolution = '????'

                    # Check if the connection sent anything!
                    if not allbytes:
                        warning_empty = ', Empty!'

                    # Check if slips and zeek know dport_name!
                    if not dport_name:
                        dport_name = '????'
                        critical_warning_dport_name = 'Protocol not recognized by Slips nor Zeek.'

                    activity = {'timestamp': timestamp_human, 'dport_name': dport_name, 'preposition': 'from','dns_resolution':dns_resolution, 'saddr': saddr, 'dport/proto': str(dport)+'/'+proto, 'state': state.lower(), 'warning': warning_empty, 'Sent': sbytes, 'Recv': allbytes - sbytes, 'Tot': allbytes_human, 'Duration': dur, 'critical warning': critical_warning_dport_name}

                elif 'ICMP' in proto:
                    if type(sport) == int:
                        # zeek puts the number
                        if sport == 8:
                            dport_name = 'PING echo'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Size': allbytes_human, 'Duration': dur}
                        elif sport == 11:
                            dport_name = 'ICMP Time Excedded in Transit'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Size': allbytes_human, 'Duration': dur}
                        elif sport == 3:
                            dport_name = 'ICMP Destination Net Unreachable'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Size': allbytes_human, 'Duration': dur}
                        else:
                            dport_name = 'ICMP Unknown type'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Type':'0x'+str(sport), 'Size': allbytes_human, 'Duration': dur}
                    elif type(sport) == str:
                        # Argus puts in hex the values of the ICMP
                        if '0x0008' in sport:
                            dport_name = 'PING echo'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Size': allbytes_human, 'Duration': dur}
                        elif '0x0103' in sport:
                            dport_name = 'ICMP Host Unreachable'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Size': allbytes_human, 'Duration': dur}
                        elif '0x0303' in sport:
                            dport_name = 'ICMP Port Unreachable'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'warning': 'unreachable port is '+ str(int(dport,16)), 'Size': allbytes_human , 'Duration': dur}
                        elif '0x000b' in sport:
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Size': allbytes_human, 'Duration': dur}
                        elif '0x0003' in sport:
                            dport_name = 'ICMP Destination Net Unreachable'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Size': allbytes_human, 'Duration': dur}
                        else:
                            dport_name = 'ICMP Unknown type'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Size': allbytes_human, 'Duration': dur}
                elif 'IGMP' in proto:
                    dport_name = 'IGMP'
                    activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'from', 'saddr': saddr, 'Size': allbytes_human, 'Duration': dur}
            else:
                if 'TCP' in proto or 'UDP' in proto:
                    warning_empty = ''
                    critical_warning_dport_name = ''
                    dns_resolution = ''

                    # Check if the connection sent anything!
                    if not allbytes:
                        warning_empty = 'Empty!'

                    # Check if slips and zeek know dport_name!
                    if not dport_name:
                        dport_name = '????'
                        critical_warning_dport_name = 'Protocol not recognized by Slips nor Zeek.'
                    dns_resolution = __database__.get_dns_resolution(daddr)
                    # we should take only one resolution, if there is more than 3, because otherwise it does not fit in the timeline.
                    if len(dns_resolution) > 3:
                        dns_resolution = dns_resolution[-1]

                    if not dns_resolution:
                        dns_resolution = '????'
                    activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to','dns_resolution':dns_resolution, 'daddr': daddr, 'dport/proto': str(dport)+'/'+proto, 'state': state.lower(), 'warning': warning_empty, 'Sent': sbytes, 'Recv': allbytes - sbytes, 'Tot': allbytes_human,'Duration': dur, 'critical warning': critical_warning_dport_name}

                elif 'ICMP' in proto:
                    if type(sport) == int:
                        # zeek puts the number
                        if sport == 8:
                            dport_name = 'PING echo'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Size': allbytes_human, 'Duration': dur}
                        elif sport == 11:
                            dport_name = 'ICMP Time Excedded in Transit'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Size': allbytes_human, 'Duration': dur}
                        elif sport == 3:
                            dport_name = 'ICMP Destination Net Unreachable'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Size': allbytes_human, 'Duration': dur}
                        else:
                            dport_name = 'ICMP Unknown type'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Type': '0x' + str(sport), 'Size': allbytes_human, 'Duration': dur}

                    elif type(sport) == str:
                        # Argus puts in hex the values of the ICMP
                        if '0x0008' in sport:
                            dport_name = 'PING echo'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Size': allbytes_human, 'Duration': dur}
                        elif '0x0103' in sport:
                            dport_name = 'ICMP Host Unreachable'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Size': allbytes_human, 'Duration': dur}
                        elif '0x0303' in sport:
                            dport_name = 'ICMP Port Unreachable'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'warning':', unreachable port is'+ str(int(dport,16)),'Size': allbytes_human, 'Duration': dur}
                        elif '0x000b' in sport:
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Size': allbytes_human, 'Duration': dur}
                        elif '0x0003' in sport:
                            dport_name = 'ICMP Destination Net Unreachable'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Size': allbytes_human, 'Duration': dur}
                        else:
                            dport_name = 'ICMP Unknown type'
                            activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Size': allbytes_human, 'Duration': dur}
                elif 'IGMP' in proto:
                    dport_name = 'IGMP'
                    activity = {'timestamp': timestamp_human,'dport_name': dport_name, 'preposition': 'to', 'daddr': daddr, 'Size': allbytes_human, 'Duration': dur}

            #################################
            # Now process the alternative flows
            # Sometimes we need to wait a little to give time to Zeek to find the related flow since they are read very fast together.
            # This should be improved algorithmically probably
            time.sleep(0.05)
            alt_flow_json = __database__.get_altflow_from_uid(profileid, twid, uid)

            alt_activity ={}
            http_data = {}
            if alt_flow_json:
                alt_flow = json.loads(alt_flow_json)
                self.print('Received an altflow of type {}: {}'.format(alt_flow['type'], alt_flow), 5,0)
                if 'dns' in alt_flow['type']:
                    answer = alt_flow["answers"]
                    if 'NXDOMAIN' in alt_flow['rcode_name']:
                        answer = 'NXDOMAIN'
                    alt_activity = {'Query': alt_flow["query"], 'Answers': answer}
                elif alt_flow['type'] == 'http':
                    http_data_all = {'Request': alt_flow["method"] + ' http://'+alt_flow["host"]+alt_flow["uri"], 'Status Code': str(alt_flow["status_code"])+ '/' + alt_flow["status_msg"],'MIME':str(alt_flow["resp_mime_types"] ),'UA':alt_flow["user_agent"]}
                    # if any of fields are empty, do not include them
                    http_data = {k: v for k, v in http_data_all.items() if v is not '' and v is not '/'}
                    alt_activity = {'http_data': http_data}
                elif alt_flow['type'] == 'ssl':
                    if alt_flow['validation_status'] == 'ok':
                        validation = 'Yes'
                        resumed = 'False'
                    elif not alt_flow['validation_status'] and alt_flow['resumed'] == True:
                        # If there is no validation and it is a resumed ssl. It means that there was a previous connection with the validation data. We can not say Say it
                        validation = '??'
                        resumed = 'True'
                    else:
                        # If the validation is not ok and not empty
                        validation = 'No'
                        resumed = 'False'
                    # if there is no CN
                    if alt_flow["subject"]:
                        subject = alt_flow["subject"].split(",")[0]
                    else:
                        subject = '????'
                    # We put server_name instead of dns resolution
                    alt_activity = {'SN': subject, 'Trusted': validation, 'Resumed': resumed, 'Version': alt_flow["version"], 'dns_resolution': alt_flow['server_name']}
                elif alt_flow['type'] == 'ssh':
                    if alt_flow['auth_success']:
                        success = 'Successful'
                    else:
                        success = 'Not Successful'
                    alt_activity = {'Login': success, 'Auth attempts': alt_flow['auth_attempts'], 'Client': alt_flow['client'], 'Server': alt_flow['client']}

            elif activity:
                alt_activity = {'info': 'No extra data.'}

            # Combine the activity of normal flows and activity of alternative flows and store in the DB for this profileid and twid
            activity.update(alt_activity)
            if activity:
                __database__.add_timeline_line(profileid, twid, activity, timestamp)
            self.print('Activity of Profileid: {}, TWid {}: {}'.format(profileid, twid, activity), 4, 0)

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on process_flow()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            self.print(traceback.format_exc())
            return True

    def run(self):
        # Main loop function
        #time.sleep(10)
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                elif message['channel'] == 'new_flow' and type(message['data']) != int :
                    mdata = message['data']
                    # Convert from json to dict
                    mdata = json.loads(mdata)
                    profileid = mdata['profileid']
                    twid = mdata['twid']
                    # Get flow as a json
                    flow = mdata['flow']
                    timestamp = mdata['stime']
                    # Convert flow to a dict
                    flow = json.loads(flow)
                    # Process the flow
                    return_value = self.process_flow(profileid, twid, flow, timestamp)
            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                self.print('Problem on the run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
