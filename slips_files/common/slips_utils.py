# Your imports
import hashlib
from uuid import uuid4
from datetime import datetime, timezone, timedelta
import validators

class Utils(object):
    name = 'utils'
    description = 'Common functions used by different modules of slips.'
    authors = ['Alya Gomaa']

    def __init__(self):
        self.home_network_ranges = ('192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8')
        self.home_networks = ('192.168.0.0', '172.16.0.0', '10.0.0.0')

    def get_hash_from_file(self, filename):
        """
        Compute the sha256 hash of a file
        """
        # The size of each read from the file
        BLOCK_SIZE = 65536
        # Create the hash object, can use something other
        # than `.sha256()` if you wish
        file_hash = hashlib.sha256()
        # Open the file to read it's bytes
        with open(filename, 'rb') as f:
            # Read from the file. Take in the amount declared above
            fb = f.read(BLOCK_SIZE)
            # While there is still data being read from the file
            while len(fb) > 0:
                # Update the hash
                file_hash.update(fb)
                # Read the next block from the file
                fb = f.read(BLOCK_SIZE)
        return file_hash.hexdigest()

    def is_msg_intended_for(self, message, channel):
        """
        Function to check
            1. If the given message is intended for this channel
            2. The msg has valid data
        """

        return (message
                and type(message['data']) == str
                and message['data'] != 'stop_process'
                and message['channel'] == channel)

    def format_timestamp(self, timestamp):
        """
        Function to unify timestamps printed to log files, notification and cli.
        :param timestamp: can be float, datetime obj or strings like 2021-06-07T12:44:56.654854+0200
        returns the date and time in RFC3339 format (IDEA standard) as str by default
        """
        if timestamp and (isinstance(timestamp, datetime)):
            # The timestamp is a datetime
            timestamp = timestamp.strftime(self.get_ts_format(timestamp))
        elif timestamp and type(timestamp) == float:
            # The timestamp is a float
            timestamp = datetime.fromtimestamp(timestamp).astimezone().isoformat()
        elif ' ' in timestamp:
            # self.print(f'DATETIME: {timestamp}')
            # The timestamp is a string with spaces
            timestamp = timestamp.replace('/','-')
            #dt_string = "2020-12-18 3:11:09"
            # format of incoming ts
            try:
                newformat = "%Y-%m-%d %H:%M:%S.%f%z"
                # convert to datetime obj
                timestamp = datetime.strptime(timestamp, newformat)
            except ValueError:
                # The string did not have a time zone
                newformat = "%Y-%m-%d %H:%M:%S.%f"
                # convert to datetime obj
                timestamp = datetime.strptime(timestamp, newformat)
            # convert to iso format
            timestamp = timestamp.astimezone().isoformat()

        return timestamp

    def IDEA_format(self, srcip, type_evidence, type_detection,
                    detection_info, description,
                    confidence, category, conn_count, source_target_tag,
                    port, proto):
        """
        Function to format our evidence according to Intrusion Detection Extensible Alert (IDEA format).
        Detailed explanation of IDEA categories: https://idea.cesnet.cz/en/classifications
        """
        IDEA_dict = {'Format': 'IDEA0',
                     'ID': str(uuid4()),
                     # both times represet the time of the detection, we probably don't need flow_datetime
                     'DetectTime': datetime.now(timezone.utc).isoformat(),
                     'EventTime': datetime.now(timezone.utc).isoformat(),
                     'Category': [category],
                     'Confidence': confidence,
                     'Source': [{}]
                     }


        # is the srcip ipv4/ipv6 or mac?
        if validators.ipv4(srcip):
            IDEA_dict['Source'][0].update({'IP4': [srcip]})
        elif validators.ipv6(srcip):
            IDEA_dict['Source'][0].update({'IP6': [srcip]})
        elif validators.mac_address(srcip):
            IDEA_dict['Source'][0].update({'MAC': [srcip]})

        # update the srcip description if specified in the evidence
        if source_target_tag:
            # for example: this will be 'Botnet' in case of C&C alerts not C&C,
            # because it describes the source ip
            IDEA_dict['Source'][0].update({'Type': [source_target_tag] })


        # When someone communicates with C&C, both sides of communication are
        # sources, differentiated by the Type attribute, 'C&C' or 'Botnet'
        if type_evidence == 'Command-and-Control-channels-detection':
            # get the destination IP
            dstip = description.split('destination IP: ')[1].split(' ')[0]

            if validators.ipv4(dstip):
                ip_version = 'IP4'
            elif validators.ipv6(dstip):
                ip_version = 'IP6'

            IDEA_dict['Source'].append({
                ip_version: [dstip],
                'Type': ['CC']
            })


        # some evidence have a dst ip
        if 'dstip' in type_detection or 'dip' in type_detection:
            # is the dstip ipv4/ipv6 or mac?
            if validators.ipv4(detection_info):
                IDEA_dict['Target'] = [{'IP4': [detection_info]}]
            elif validators.ipv6(detection_info):
                IDEA_dict['Target'] = [{'IP6': [detection_info]}]
            elif validators.mac_address(detection_info):
                IDEA_dict['Target'] = [{'MAC': [detection_info]}]

            # try to extract the hostname/SNI/rDNS of the dstip form the description if available
            hostname = False
            try:
                hostname = description.split('rDNS: ')[1]
            except IndexError:
                pass
            try:
                hostname = description.split('SNI: ')[1]
            except IndexError:
                pass
            if hostname:
                IDEA_dict['Target'][0].update({'Hostname': [hostname]})
            # update the dstip description if specified in the evidence
            if source_target_tag:
                IDEA_dict['Target'][0].update({'Type': [source_target_tag] })

        elif 'domain' in type_detection:
            # the ioc is a domain
            target_info = {'Hostname': [detection_info]}
            IDEA_dict['Target'] = [target_info]

            # update the dstdomain description if specified in the evidence
            if source_target_tag:
                IDEA_dict['Target'][0].update({'Type': [source_target_tag] })

        # add the port/proto
        # for all alerts, the srcip is in IDEA_dict['Source'][0] and the dstip is in IDEA_dict['Target'][0]
        # for alert that only have a source, this is the port/proto of the source ip
        key = 'Source'
        idx = 0 # this idx is used for selecting the right dict to add port/proto

        if 'Target' in IDEA_dict:
            # if the alert has a target, add the port/proto to the target(dstip)
            key = 'Target'
            idx = 0

        # for C&C alerts IDEA_dict['Source'][0] is the Botnet aka srcip and IDEA_dict['Source'][1] is the C&C aka dstip
        if type_evidence == 'Command-and-Control-channels-detection':
            # idx of the dict containing the dstip, we'll use this to add the port and proto to this dict
            key = 'Source'
            idx = 1

        if port:
            IDEA_dict[key][idx].update({'Port': [int(port)] })
        if proto:
            IDEA_dict[key][idx].update({'Proto': [proto.lower()] })

        # add the description
        attachment = {
            'Attach': [{
                'Content': description,
                "ContentType": "text/plain",
            }]
        }
        IDEA_dict.update(attachment)

        # only evidence of type scanning have conn_count
        if conn_count: IDEA_dict.update({'ConnCount': conn_count})

        if 'MaliciousDownloadedFile' in type_evidence:
            IDEA_dict.update({
                'Attach': [
                    {
                        'Type': ["Malware"],
                        "Hash": [f'md5:{detection_info}'],
                        "Size": int(description.split("size:")[1].split("from")[0])

                    }
                ]
            })

        return IDEA_dict

utils = Utils()