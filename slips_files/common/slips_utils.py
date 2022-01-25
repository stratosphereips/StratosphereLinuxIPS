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

    def IDEA_format(self, srcip, type_evidence, type_detection,
                    detection_info, description, flow_datetime,
                    confidence, category, conn_count, source_target_tag):
        """
        Function to format our evidence according to Intrusion Detection Extensible Alert (IDEA format).
        Detailed explanation of IDEA categories: https://idea.cesnet.cz/en/classifications
        """
        IDEA_dict = {'Format': 'IDEA0',
                     'ID': str(uuid4()),
                     'DetectTime': flow_datetime,
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