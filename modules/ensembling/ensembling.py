from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
from slips_files.common.config_parser import ConfigParser
import sys
import json
import traceback

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'Ensembling'
    description = 'The module to assign '
    authors = ['Kamila Babayeva, Sebastian Garcia']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        # Retrieve the labels
        self.normal_label = __database__.normal_label
        self.malicious_label = __database__.malicious_label
        self.c1 = __database__.subscribe('tw_closed')
        self.separator = __database__.separator

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

    def set_label_per_flow_dstip(self, profileid, twid):
        """
        Funciton to perform first and second stage of the ensembling.
        Function assigns ensembling label per each flow in this profileid and twid,
        groups the flows with same destination IP, and calculates the amount
        of normal and malicious flows per each dstip in this profileid and twid.
        : param: profileid, twid
        : return: None
        """

        flows = __database__.get_all_flows_in_profileid_twid(profileid, twid)
        dstip_labels_total = dict()
        for flow_uid, flow_data in flows.items():
            flow_data = json.loads(flow_data)
            flow_module_labels = flow_data['module_labels']
            # First stage - calculate the amount of malicious and normal labels per each flow.
            # Set the final label per flow using majority voting
            flow_labels = list(flow_module_labels.values())
            normal_label_total = flow_labels.count(self.normal_label)
            malicious_label_total = flow_labels.count(self.malicious_label)
            # initialize the amount of normal and malicious flows per dstip.
            try:
                dstip_labels_total[flow_data['daddr']]
            except KeyError as err:
                dstip_labels_total[flow_data['daddr']] = {
                    self.normal_label: 0,
                    self.malicious_label: 0,
                }

            if (
                malicious_label_total == normal_label_total == 0
                or normal_label_total > malicious_label_total
            ):
                __database__.set_first_stage_ensembling_label_to_flow(
                    profileid, twid, flow_uid, self.normal_label
                )
                # Second stage - calculate the amount of normal and malicious labels per daddr
                dstip_labels_total[flow_data['daddr']][self.normal_label] = (
                    dstip_labels_total[flow_data['daddr']].get(
                        self.normal_label, 0
                    )
                    + 1
                )
            elif malicious_label_total >= normal_label_total:
                __database__.set_first_stage_ensembling_label_to_flow(
                    profileid, twid, flow_uid, self.malicious_label
                )
                # Second stage - calculate the amount of normal and malicious labels per daddr
                dstip_labels_total[flow_data['daddr']][
                    self.malicious_label
                ] = (
                    dstip_labels_total[flow_data['daddr']].get(
                        self.malicious_label, 0
                    )
                    + 1
                )

    def run(self):
        utils.drop_root_privs()
        # Main loop function
        while True:
            try:
                message = __database__.get_message(self.c1)
                # Check that the message is for you. Probably unnecessary...
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    self.shutdown_gracefully()
                    return True
                if message and message['channel'] == 'tw_closed':
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        profileip = data.split(self.separator)[1]
                        twid = data.split(self.separator)[2]
                        profileid = 'profile' + self.separator + profileip

                        # First stage -  define the final label for each flow in profileid and twid
                        # by the majority vote of malicious and normal
                        # Second stage - group the flows with same dstip and calculate the amount of
                        # normal and malicious flows

                        self.set_label_per_flow_dstip(profileid, twid)

            except KeyboardInterrupt:
                # Confirm that the module is done processing
                self.shutdown_gracefully()
                return True

            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True
