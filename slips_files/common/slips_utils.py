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
        pass

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
                    detection_info, description, flow_datetime,
                    confidence, category, conn_count, source_target_tag):
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
                     'Note' : description.replace('"','\"').replace("'",'\''),
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
            IDEA_dict['Source'][0].update({'Type': [source_target_tag] })

        # extract the port/proto from the description
        for proto in ('tcp', 'udp'):
            port = description.lower().split(proto)[0].split(' ')[-1][:-1]

            # python doesn't raise an exception when splitting using a proto
            # that's not there, so manually check
            if len(port) == len(description):
                # this proto isn't in the description
                continue

            IDEA_dict['Source'][0].update({'Proto': [proto] })
            IDEA_dict['Source'][0].update({'Port': [port] })
            break

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