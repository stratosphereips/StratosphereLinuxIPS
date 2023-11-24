from slips_files.common.slips_utils import utils


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
        threat_level = 'high'
        category = 'Recon.Scanning'
        srcip = profileid.split('_')[-1]
        attacker = srcip
        confidence = utils.calculate_confidence(pkts_sent)
        description = (
                        f'new vertical port scan to IP {dstip} from {srcip}. '
                        f'Total {amount_of_dports} dst {protocol} ports were scanned. '
                        f'Total packets sent to all ports: {pkts_sent}. '
                        f'Confidence: {confidence}. by Slips'
                    )
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=pkts_sent,
                                 proto=protocol, profileid=profileid, twid=twid, uid=uid, victim=dstip)




    def check(self, profileid, twid):
        """
        Here's how the detection of vertical portscans is done
        1. Slips retrieves all destination IPs of the not established flows on TCP and UDP protocols
        2. For each dst IP, slips checks the amount of destination ports we connected to
        3. The first evidence will be triggered if the amount of destination ports for 1 IP is 5+
        4. then we combine evidence 3 by 3. for example
            evidence f 10,15,20 ports scanned will be combined into 1 evidence
            evidence of 15,30,35 ports scanned will be combined into 1 evidence
            etc.
        The result of this combining of evidence is that the dst ports scanned in each evidence will be = the
        previous scanned ports +15
        this combining is done to avoid duplicate evidence
        the downide to this is that if you do more than 1 portscan in the same timewindow, all portscans starting
        from the second portscan will be ignored if they don't exceed the number of dports of the first portscan
        so as a rule, each evidence should have X ports scanned. this X should ALWAYS be the last portscan+15,
        if this X is the last portscan +14, we don't set the evidence. we keep combining.
        3. Once the timewindow stops, Slips resets all counters, we go back to step 1
        """
        # Get the list of dstips that we connected as client using TCP not
        # established, and their ports
        direction = 'Dst'
        role = 'Client'
        type_data = 'IPs'

        # if you're portscaning a port that is open it's gonna be established
        # the amount of open ports we find is gonna be so small
        # theoretically this is incorrect bc we'll be ignoring established evidence,
        # but usually open ports are very few compared to the whole range
        # so, practically this is correct to avoid FP
        state = 'Not Established'

        for protocol in ('TCP', 'UDP'):
            #  these unknowns are the info this function retrieves
            #  profileid -> unknown_dstip:unknown_dstports
            #
            # here, the profileid given is the client.
            # returns the following
            # {
            #     dst_ip: {
            #         totalflows: total flows seen by the profileid
            #         totalpkt: total packets seen by the profileid
            #         totalbytes: total bytes sent by the profileid
            #         stime: timestamp of the first flow seen from this profileid -> this dstip
            #         uid: list of uids where the given profileid was contacting the dst_ip on this dstport
            #         dstports: dst ports seen in all flows where the given profileid was srcip
            #             {
            #                 <str port>: < int spkts sent to this port>
            #             }
            #     }
            dstips: dict = self.db.get_data_from_profile_tw(
                profileid, twid, direction, state, protocol, role, type_data
            )
            # For each dstip, see if the amount of ports connections is over the threshold
            for dstip in dstips.keys():
                ### PortScan Type 1. Direction OUT
                dstports: dict = dstips[dstip]['dstports']
                amount_of_dports = len(dstports)
                cache_key = f'{profileid}:{twid}:dstip:{dstip}:VerticalPortscan'
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
