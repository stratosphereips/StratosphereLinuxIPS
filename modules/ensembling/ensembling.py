from slips_files.common.imports import *

class Ensembling(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'Ensembling'
    description = 'The module to assign '
    authors = ['Kamila Babayeva, Sebastian Garcia']

    def init(self):
        # Retrieve the labels
        self.normal_label = self.db.get_normal_label()
        self.malicious_label = self.db.get_malicious_label()
        self.c1 = self.db.subscribe('tw_closed')
        self.channels = {
            'tw_closed': self.c1
        }
        self.separator = self.db.get_separator()


    def set_label_per_flow_dstip(self, profileid, twid):
        """
        Funciton to perform first and second stage of the ensembling.
        Function assigns ensembling label per each flow in this profileid and twid,
        groups the flows with same destination IP, and calculates the amount
        of normal and malicious flows per each dstip in this profileid and twid.
        : param: profileid, twid
        : return: None
        """

        flows = self.db.get_all_flows_in_profileid_twid(profileid, twid)
        dstip_labels_total = {}
        for flow_uid, flow_data in flows.items():
            flow_module_labels = flow_data['module_labels']
            # First stage - calculate the amount of malicious and normal labels per each flow.
            # Set the final label per flow using majority voting
            flow_labels = list(flow_module_labels.values())
            normal_label_total = flow_labels.count(self.normal_label)
            malicious_label_total = flow_labels.count(self.malicious_label)
            # initialize the amount of normal and malicious flows per dstip.
            try:
                dstip_labels_total[flow_data['daddr']]
            except KeyError:
                dstip_labels_total[flow_data['daddr']] = {
                    self.normal_label: 0,
                    self.malicious_label: 0,
                }

            if (
                malicious_label_total == normal_label_total == 0
                or normal_label_total > malicious_label_total
            ):
                # self.db.set_first_stage_ensembling_label_to_flow(
                #     profileid, twid, flow_uid, self.normal_label
                # )
                # Second stage - calculate the amount of normal and malicious labels per daddr
                dstip_labels_total[flow_data['daddr']][self.normal_label] = (
                    dstip_labels_total[flow_data['daddr']].get(
                        self.normal_label, 0
                    )
                    + 1
                )
            else:
                # self.db.set_first_stage_ensembling_label_to_flow(
                #     profileid, twid, flow_uid, self.malicious_label
                # )
                # Second stage - calculate the amount of normal and malicious labels per daddr
                dstip_labels_total[flow_data['daddr']][
                    self.malicious_label
                ] = (
                    dstip_labels_total[flow_data['daddr']].get(
                        self.malicious_label, 0
                    )
                    + 1
                )

    def pre_main(self):
        utils.drop_root_privs()

    def main(self):
        if msg := self.get_msg('tw_closed'):
            data = msg['data']
            profileip = data.split(self.separator)[1]
            twid = data.split(self.separator)[2]
            profileid = f'profile{self.separator}{profileip}'
            # First stage -  define the final label for each flow in profileid and twid
            # by the majority vote of malicious and normal
            # Second stage - group the flows with same dstip and calculate the amount of
            # normal and malicious flows
            self.set_label_per_flow_dstip(profileid, twid)
