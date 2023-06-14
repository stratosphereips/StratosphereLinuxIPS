from slips_files.common.imports import *
import sys
import traceback
import time
import ipaddress
import json
import threading

class VerticalPortscan():
    def __init__(self, db):
        self.db = db
        # We need to know that after a detection, if we receive another flow
        # that does not modify the count for the detection, we are not
        # re-detecting again only because the threshold was overcomed last time.
        self.cache_det_thresholds = {}
        # Get from the database the separator used to separate the IP and the word profile
        self.fieldseparator = self.db.get_field_separator()
        # The minimum amount of ports to scan in vertical scan
        self.port_scan_minimum_dports = 5
        # list of tuples, each tuple is the args to setevidence
        self.pending_vertical_ps_evidence = {}
        # we should alert once we find 1 vertical ps evidence then combine the rest of evidence every x seconds
        # the value of this dict will be true after the first portscan alert to th ekey ip
        # format is {ip: True/False , ...}
        self.alerted_once_vertical_ps = {}


    def combine_evidence(self):
        for key, evidence_list in self.pending_vertical_ps_evidence.items():
            # each key here is  {profileid}-{twid}-{state}-{protocol}-{dport}
            # each value here is a list of evidence that should be combined
            profileid, twid, state, protocol, dstip = key.split('-')
            final_evidence_uids = []
            final_pkts_sent = 0

            # combine all evidence that share the above key
            for evidence in evidence_list:
                # each evidence is a tuple of (timestamp, pkts_sent, uids, amount_of_dips)
                # in the final evidence, we'll be using the ts of the last evidence
                timestamp, pkts_sent, evidence_uids, amount_of_dports = evidence
                # since we're combining evidence, we want the uids of the final evidence
                # to be the sum of all the evidence we combined
                final_evidence_uids += evidence_uids
                final_pkts_sent += pkts_sent

            self.set_evidence_vertical_portscan(
                timestamp,
                final_pkts_sent,
                protocol,
                profileid,
                twid,
                final_evidence_uids,
                amount_of_dports,
                dstip
            )
        # reset the dict since we already combined
        self.pending_vertical_ps_evidence = {}

    def set_evidence_vertical_portscan(
            self,
            timestamp,
            pkts_sent,
            protocol,
            profileid,
            twid,
            uid,
            amount_of_dports,
            dstip
    ):
        attacker_direction = 'srcip'
        evidence_type = 'VerticalPortscan'
        source_target_tag = 'Recon'
        threat_level = 'medium'
        category = 'Recon.Scanning'
        srcip = profileid.split('_')[-1]
        attacker = srcip
        confidence = self.calculate_confidence(pkts_sent)
        description = (
                        f'new vertical port scan to IP {dstip} from {srcip}. '
                        f'Total {amount_of_dports} dst {protocol} ports were scanned. '
                        f'Total packets sent to all ports: {pkts_sent}. '
                        f'Confidence: {confidence}. by Slips'
                    )
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=pkts_sent,
                                 proto=protocol, profileid=profileid, twid=twid, uid=uid, victim=dstip)


    def calculate_confidence(self, pkts_sent):
        if pkts_sent > 10:
            confidence = 1
        elif pkts_sent == 0:
            return 0.3
        else:
            # Between threshold and 10 pkts compute a kind of linear grow
            confidence = pkts_sent / 10.0
        return confidence

    def check(self, profileid, twid):
        # Get the list of dstips that we connected as client using TCP not
        # established, and their ports
        direction = 'Dst'
        role = 'Client'
        type_data = 'IPs'
        # self.print('Vertical Portscan check. Amount of dports: {}.
        # Threshold=3'.format(amount_of_dports), 3, 0)
        evidence_type = 'VerticalPortscan'
        for state in ('Not Established', 'Established'):
            for protocol in ('TCP', 'UDP'):
                dstips = self.db.getDataFromProfileTW(
                    profileid, twid, direction, state, protocol, role, type_data
                )
                # For each dstip, see if the amount of ports connections is over the threshold
                for dstip in dstips.keys():
                    ### PortScan Type 1. Direction OUT
                    dstports: dict = dstips[dstip]['dstports']
                    amount_of_dports = len(dstports)
                    cache_key = f'{profileid}:{twid}:dstip:{dstip}:{evidence_type}'
                    prev_amount_dports = self.cache_det_thresholds.get(cache_key, 0)

                    # we make sure the amount of dports reported each evidence is higher than the previous one +5
                    # so the first alert will always report 5 dport, and then 10+,15+,20+ etc
                    # the goal is to never get an evidence that's 1 or 2 ports more than the previous one so we dont
                    # have so many portscan evidence
                    if (
                            amount_of_dports >= self.port_scan_minimum_dports
                            and prev_amount_dports+5 <= amount_of_dports
                    ):
                        # Get the total amount of pkts sent different ports on the same host
                        pkts_sent = sum(dstports[dport] for dport in dstports)
                        uid = dstips[dstip]['uid']
                        timestamp = dstips[dstip]['stime']

                        # Store in our local cache how many dips were there:
                        self.cache_det_thresholds[cache_key] = amount_of_dports
                        if not self.alerted_once_vertical_ps.get(cache_key, False):
                            # now from now on, we will be combining the next vertical ps evidence targetting this dport
                            self.alerted_once_vertical_ps[cache_key] = True
                            self.set_evidence_vertical_portscan(
                                timestamp,
                                pkts_sent,
                                protocol,
                                profileid,
                                twid,
                                uid,
                                amount_of_dports,
                                dstip
                            )
                        else:
                             # we will be combining further alerts to avoid alerting
                             # many times every portscan
                            evidence_details = (timestamp, pkts_sent, uid, amount_of_dports)
                            # for all the combined alerts, the following params should be equal
                            key = f'{profileid}-{twid}-{state}-{protocol}-{dstip}'
                            try:
                                self.pending_vertical_ps_evidence[key].append(evidence_details)
                            except KeyError:
                                # first time seeing this key
                                self.pending_vertical_ps_evidence[key] = [evidence_details]

                            # combine evidence every x new portscans to the same ip
                            if len(self.pending_vertical_ps_evidence[key]) == 3:
                                self.combine_evidence()
