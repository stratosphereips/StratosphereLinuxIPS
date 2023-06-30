# Must imports
from slips_files.common.imports import *
import traceback
import sys

# Your imports
import time
import json


class Timeline(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'Timeline'
    description = 'Creates kalipso timeline of what happened in the network based on flows and available data'
    authors = ['Sebastian Garcia']

    def init(self):
        self.separator = self.db.get_field_separator()
        # Subscribe to 'new_flow' channel
        self.c1 = self.db.subscribe('new_flow')
        self.channels = {
            'new_flow': self.c1,
        }
        # Read information how we should print timestamp.
        conf = ConfigParser()
        self.is_human_timestamp = conf.timeline_human_timestamp()
        self.analysis_direction = conf.analysis_direction()


    def process_timestamp(self, timestamp: float) -> str:
        if self.is_human_timestamp:
            timestamp = utils.convert_format(timestamp, utils.alerts_format)
        return str(timestamp)

    def process_flow(self, profileid, twid, flow, timestamp: float):
        """
        Process the received flow  for this profileid and twid
         so its printed by the logprocess later
        """
        timestamp_human = self.process_timestamp(timestamp)

        try:
            # Convert the common fields to something that can be interpreted
            uid = next(iter(flow))
            flow_dict = json.loads(flow[uid])
            profile_ip = profileid.split('_')[1]
            dur = round(float(flow_dict['dur']), 3)
            stime = flow_dict['ts']
            saddr = flow_dict['saddr']
            sport = flow_dict['sport']
            daddr = flow_dict['daddr']
            dport = flow_dict['dport']
            proto = flow_dict['proto'].upper()
            dport_name = flow_dict.get('appproto', '')
            if not dport_name:
                dport_name = self.db.get_port_info(
                    f'{str(dport)}/{proto.lower()}'
                )
                if dport_name:
                    dport_name = dport_name.upper()
            else:
                dport_name = dport_name.upper()
            state = flow_dict['state']
            pkts = flow_dict['pkts']
            allbytes = flow_dict['allbytes']
            if type(allbytes) != int:
                allbytes = 0

            # allbytes_human are sorted wrong in the interface, thus we sticked to original byte size.
            # # Convert the bytes into human readable
            # if int(allbytes) < 1024:
            #     # In bytes
            #     allbytes_human = '{:.2f}{}'.format(float(allbytes), 'b')
            # elif int(allbytes) > 1024 and int(allbytes) < 1048576:
            #     # In Kb
            #     allbytes_human = '{:.2f}{}'.format(
            #         float(allbytes) / 1024, 'Kb'
            #     )
            # elif int(allbytes) > 1048576 and int(allbytes) < 1073741824:
            #     # In Mb
            #     allbytes_human = '{:.2f}{}'.format(
            #         float(allbytes) / 1024 / 1024, 'Mb'
            #     )
            # elif int(allbytes) > 1073741824:
            #     # In Bg
            #     allbytes_human = '{:.2f}{}'.format(
            #         float(allbytes) / 1024 / 1024 / 1024, 'Gb'
            #     )

            spkts = flow_dict['spkts']
            sbytes = flow_dict['sbytes']
            if type(sbytes) != int:
                sbytes = 0

            # Now that we have the flow processed. Try to interpret it and create the activity line
            # Record Activity
            activity = {}
            # Change the format of timeline in the case of inbound
            # flows for external IP, i.e direction 'all' and destination IP == profile IP.
            # If not changed, it would have printed  'IP1 https asked to IP1'.
            if 'TCP' in proto or 'UDP' in proto:
                warning_empty = ''
                critical_warning_dport_name = ''
                if self.analysis_direction == 'all' and str(daddr) == str(
                        profile_ip
                ):
                    dns_resolution = self.db.get_dns_resolution(daddr)
                    dns_resolution = dns_resolution.get('domains', [])

                    # we should take only one resolution, if there is more than 3, because otherwise it does not fit in the timeline.
                    if len(dns_resolution) > 3:
                        dns_resolution = dns_resolution[-1]

                    if not dns_resolution:
                        dns_resolution = '????'

                    # Check if the connection sent anything!
                    if not allbytes:
                        warning_empty = 'No data exchange!'

                    # Check if slips and zeek know dport_name!
                    if not dport_name:
                        dport_name = '????'
                        critical_warning_dport_name = (
                            'Protocol not recognized by Slips nor Zeek.'
                        )

                    activity = {
                        'timestamp': timestamp_human,
                        'dport_name': dport_name,
                        'preposition': 'from',
                        'dns_resolution': dns_resolution,
                        'saddr': saddr,
                        'daddr':daddr,
                        'dport/proto': f'{str(dport)}/{proto}',
                        'state': state,
                        'warning': warning_empty,
                        'info' : '',
                        'sent': sbytes,
                        'recv': allbytes - sbytes,
                        'tot': allbytes,
                        'duration': dur,
                        'critical warning': critical_warning_dport_name
                    }


                else:
                    # Check if the connection sent anything!
                    if not allbytes:
                        warning_empty = 'No data exchange!'

                    # Check if slips and zeek know dport_name!
                    if not dport_name:
                        dport_name = '????'
                        critical_warning_dport_name = (
                            'Protocol not recognized by Slips nor Zeek.'
                        )
                    dns_resolution = self.db.get_dns_resolution(daddr)
                    dns_resolution = dns_resolution.get('domains', [])

                    # we should take only one resolution, if there is more than 3, because otherwise it does not fit in the timeline.
                    if len(dns_resolution) > 3:
                        dns_resolution = dns_resolution[-1]

                    if not dns_resolution:
                        dns_resolution = '????'
                    activity = {
                        'timestamp': timestamp_human,
                        'dport_name': dport_name,
                        'preposition': 'to',
                        'dns_resolution': dns_resolution,
                        'daddr': daddr,
                        'dport/proto': f'{str(dport)}/{proto}',
                        'state': state,
                        'warning': warning_empty,
                        'info': '',
                        'sent': sbytes,
                        'recv': allbytes - sbytes,
                        'tot': allbytes,
                        'duration': dur,
                        'critical warning': critical_warning_dport_name
                    }

            elif 'ICMP' in proto:
                extra_info = {}
                warning = ''
                if type(sport) == int:
                    # zeek puts the number
                    if sport == 11:
                        dport_name = 'ICMP Time Excedded in Transit'

                    elif sport == 3:
                        dport_name = 'ICMP Destination Net Unreachable'

                    elif sport == 8:
                        dport_name = 'PING echo'

                    else:
                        dport_name = 'ICMP Unknown type'
                        extra_info =  {
                            'type': f'0x{str(sport)}',
                        }

                elif type(sport) == str:
                    # Argus puts in hex the values of the ICMP
                    if '0x0008' in sport:
                        dport_name = 'PING echo'
                    elif '0x0103' in sport:
                        dport_name = 'ICMP Host Unreachable'
                    elif '0x0303' in sport:
                        dport_name = 'ICMP Port Unreachable'
                        warning = f'unreachable port is {int(dport, 16)}'
                    elif '0x000b' in sport:
                        dport_name = ''
                    elif '0x0003' in sport:
                        dport_name = 'ICMP Destination Net Unreachable'
                    else:
                        dport_name = 'ICMP Unknown type'

                activity = {
                            'timestamp': timestamp_human,
                            'dport_name': dport_name,
                            'preposition': 'from',
                            'saddr': saddr,
                            'size': allbytes,
                            'duration': dur,
                        }

                extra_info.update({
                     'dns_resolution':'',
                     'daddr': daddr,
                     'dport/proto': f'{sport}/ICMP',
                     'state': '',
                     'warning' : warning,
                     'sent' :'',
                     'recv' :'',
                     'tot' :'',
                     'critical warning' : '',
                })

                activity.update(extra_info)

            elif 'IGMP' in proto:
                dport_name = 'IGMP'
                activity = {
                    'timestamp': timestamp_human,
                    'dport_name': dport_name,
                    'preposition': 'from',
                    'saddr': saddr,
                    'size': allbytes,
                    'duration': dur,
                }
            #################################
            # Now process the alternative flows
            # Sometimes we need to wait a little to give time to Zeek to find the related flow since they are read very fast together.
            # This should be improved algorithmically probably
            time.sleep(0.05)
            alt_flow: dict = self.db.get_altflow_from_uid(
                profileid, twid, uid
            )

            alt_activity = {}
            http_data = {}
            if alt_flow:
                flow_type = alt_flow['type_']
                self.print(
                    f"Received an altflow of type {flow_type}: {alt_flow}",
                    3, 0
                )
                if 'dns' in flow_type:
                    answer = alt_flow['answers']
                    if 'NXDOMAIN' in alt_flow['rcode_name']:
                        answer = 'NXDOMAIN'
                    dns_activity = {
                        'query': alt_flow['query'],
                        'answers': answer
                    }
                    alt_activity = {
                        'info': dns_activity,
                        'critical warning':'',
                    }
                elif flow_type == 'http':
                    http_data_all = {
                        'Request': alt_flow['method']
                        + ' http://'
                        + alt_flow['host']
                        + alt_flow['uri'],
                        'Status Code': str(alt_flow['status_code'])
                        + '/'
                        + alt_flow['status_msg'],
                        'MIME': str(alt_flow['resp_mime_types']),
                        'UA': alt_flow['user_agent'],
                    }
                    # if any of fields are empty, do not include them
                    http_data = {
                        k: v
                        for k, v in http_data_all.items()
                        if v != '' and v != '/'
                    }
                    alt_activity = {'info': http_data}
                elif flow_type == 'ssl':
                    if alt_flow['validation_status'] == 'ok':
                        validation = 'Yes'
                        resumed = 'False'
                    elif (
                        not alt_flow['validation_status']
                        and alt_flow['resumed'] is True
                    ):
                        # If there is no validation and it is a resumed ssl.
                        # It means that there was a previous connection with
                        # the validation data. We can not say Say it
                        validation = '??'
                        resumed = 'True'
                    else:
                        # If the validation is not ok and not empty
                        validation = 'No'
                        resumed = 'False'
                    # if there is no CN
                    subject = alt_flow['subject'].split(',')[0] if alt_flow[
                        'subject'] else '????'
                    # We put server_name instead of dns resolution
                    ssl_activity = {
                        'server_name': subject,
                        'trusted': validation,
                        'resumed': resumed,
                        'version': alt_flow['version'],
                        'dns_resolution': alt_flow['server_name']
                    }
                    alt_activity = {'info': ssl_activity}
                elif flow_type == 'ssh':
                    success = 'Successful' if alt_flow[
                        'auth_success'] else 'Not Successful'
                    ssh_activity = {
                        'login': success,
                        'auth_attempts': alt_flow['auth_attempts'],
                        'client': alt_flow['client'],
                        'server': alt_flow['client'],
                    }
                    alt_activity = {'info': ssh_activity}

            elif activity:
                alt_activity = {'info': ''}

            # Combine the activity of normal flows and activity of alternative flows and store in the DB for this profileid and twid
            activity.update(alt_activity)
            if activity:
                self.db.add_timeline_line(
                    profileid, twid, activity, timestamp
                )
            self.print(
                f'Activity of Profileid: {profileid}, TWid {twid}: '
                f'{activity}', 3, 0
            )


        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'Problem on process_flow() line {exception_line}', 0, 1
            )
            self.print(traceback.print_exc(),0,1)
            return True

    def pre_main(self):
        utils.drop_root_privs()

    def main(self):
        # Main loop function
        if msg:= self.get_msg('new_flow'):
            mdata = msg['data']
            # Convert from json to dict
            mdata = json.loads(mdata)
            profileid = mdata['profileid']
            twid = mdata['twid']
            flow = mdata['flow']
            timestamp = mdata['stime']
            flow = json.loads(flow)
            self.process_flow(
                profileid, twid, flow, timestamp
            )
