# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import sys

# Your imports
import yara
import base64
import binascii
import os
import subprocess
import json
import datetime

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'leak_detector'
    description = 'Detect leaks of data in the traffic'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.timeout = 0.0000001
        # this module is only loaded when a pcap is given get the pcap path
        try:
            self.pcap = sys.argv[sys.argv.index('-f')+1]
        except ValueError:
            # this error is raised when we start this module in the unit tests so there's no argv
            # ignore it
            pass
        self.yara_rules_path = 'modules/leak_detector/yara_rules/rules/'
        self.compiled_yara_rules_path = 'modules/leak_detector/yara_rules/compiled/'

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

    def get_packet_info(self, offset: int):
        """
        Parse pcap and determine the packet at this offset
        returns  a tuple with packet info (srcip, dstip, proto, sport, dport, ts) or False if not found
        """
        offset = int(offset)
        with open(self.pcap ,'rb') as f:
            # every pcap header is 24 bytes
            f.read(24)
            packet_number = 0

            packet_data_length = True
            while packet_data_length:
                # the number of the packet we're currently working with, since packets start from 1 in tshark , the first packet should be 1
                packet_number += 1
                # this offset is exactly when the packet starts
                start_offset = f.tell() + 1
                # get the Packet header, every packet header is exactly 16 bytes long
                packet_header = f.read(16)
                # get the length of the Packet Data field (the second last 4 bytes of the header), [::-1] for little endian
                packet_data_length = packet_header[8:12][::-1]
                # convert the hex into decimal
                packet_length_in_decimal = int.from_bytes(packet_data_length, "big")

                # read until the end of this packet
                f.read(packet_length_in_decimal)
                # this offset is exactly when the packet ends
                end_offset = f.tell()
                if offset <= end_offset and offset >= start_offset:
                    # print(f"Found a match. Packet number in wireshark: {packet_number+1}")
                    # use tshark to get packet info
                    command = f'tshark -r {self.pcap} -T json -Y frame.number=={packet_number}'
                    result = subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
                    json_packet = result.stdout.decode("utf-8")
                    json_packet =  json.loads(json_packet)
                    if json_packet:
                        # sometime tshark can't find the desired packet?
                        json_packet = json_packet[0]['_source']['layers']

                        # get ip family and used protocol
                        used_protocols = json_packet['frame']['frame.protocols']
                        if 'ipv6' in used_protocols:
                            ip_family = 'ipv6'
                        else:
                            ip_family = 'ip'

                        if 'tcp' in used_protocols:
                            proto='tcp'
                        elif 'udp' in used_protocols:
                            proto = 'udp'
                        else:
                            # probably ipv6.hopopt
                            continue

                        try:
                            ts = json_packet['frame']['frame.time_epoch']
                            srcip = json_packet[ip_family][f'{ip_family}.src']
                            dstip = json_packet[ip_family][f'{ip_family}.dst']
                            sport = json_packet[proto][f'{proto}.srcport']
                            dport = json_packet[proto][f'{proto}.dstport']
                        except KeyError:
                            continue

                        return  (srcip, dstip, proto, sport, dport, ts)

        return False


    def set_evidence_yara_match(self, info:dict):
        """
        This function is called when yara finds a match
        :param info: a dict with info about the matched rule, example keys 'tags', 'matches', 'rule', 'strings' etc.
        """
        rule = info.get('rule')
        meta = info.get('meta',False)
        # strings is a list of tuples containing information about the matching strings.
        # Each tuple has the form: (<offset>, <string identifier>, <string data>).
        strings = info.get('strings')
        description = meta.get('description')
        # author = meta.get('author')
        # reference = meta.get('reference')
        # organization = meta.get('organization')

        for match in strings:
            offset, string_found = match[0], match[1]
            # we now know there's a match at offset x, we need to know offset x belongs to which packet
            packet_info = self.get_packet_info(offset)
            if packet_info:
                srcip, dstip, proto, sport, dport, ts = packet_info[0], packet_info[1], \
                                                        packet_info[2],packet_info[3], \
                                                        packet_info[4],packet_info[5]
                type_detection = 'dstip'
                detection_info = dstip
                source_target_tag = 'CC'
                # TODO: this needs to be changed if add more rules to the rules/dir
                type_evidence = 'NETWORK_gps_location_leaked'
                category = 'Malware'
                confidence = 0.9
                threat_level = 'high'
                description = f"IP: {srcip} detected {rule} to destination address: {dstip} port: {dport}/{proto}"
                # generate a random uid
                uid = base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode('utf-8')
                profileid = f'profile_{srcip}'
                # make sure we have this profileid
                if __database__.hasProfile(profileid):
                    # in which tw is this ts?
                    twid = __database__.getTWofTime(profileid, ts)
                    # convert ts to a readable format
                    flow_datetime = datetime.datetime.fromtimestamp(float(ts))
                    ts = flow_datetime.strftime('%Y/%m/%d %H:%M:%S')

                    if twid:
                        twid = twid[0]
                        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                                 threat_level, confidence, description, ts,
                                                 category, source_target_tag=source_target_tag,
                                                 port=dport, proto=proto,
                                                 profileid=profileid, twid=twid, uid=uid)

    def compile_and_save_rules(self):
        """
        Compile and save all yara rules in the compiled_yara_rules_path
        """

        try:
            os.mkdir(self.compiled_yara_rules_path)
        except FileExistsError:
            pass

        for yara_rule in os.listdir(self.yara_rules_path):
            compiled_rule_path = os.path.join(self.compiled_yara_rules_path, f'{yara_rule}_compiled')
            # if we already have the rule compiled, don't compiler again
            if os.path.exists(compiled_rule_path):
                # we already have the rule compiled
                continue
            # get the complete path of the .yara rule
            rule_path = os.path.join(self.yara_rules_path, yara_rule)
            # ignore yara_rules/compiled/
            if not os.path.isfile(rule_path):
                continue
            # compile the rule
            compiled_rule = yara.compile(filepath=rule_path)
            # save the compiled rule
            compiled_rule.save(compiled_rule_path)

    def find_matches(self):
        """ Run yara rules on the given pcap and find matches"""
        for compiled_rule in os.listdir(self.compiled_yara_rules_path):
            compiled_rule_path = os.path.join(self.compiled_yara_rules_path, compiled_rule)
            # load the compiled rules
            rule = yara.load(compiled_rule_path)
            # call set_evidence_yara_match when a match is found
            matches = rule.match(self.pcap,
                                 callback=self.set_evidence_yara_match,
                                 which_callbacks=yara.CALLBACK_MATCHES)


    def run(self):
        try:
            # if we we don't have compiled rules, compile them
            self.compile_and_save_rules()
            # run the yara rules on the given pcap
            self.find_matches()
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on the run() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
