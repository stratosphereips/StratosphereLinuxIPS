from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import \
    (
        Evidence,
        ProfileID,
        TimeWindow,
        Attacker,
        ThreatLevel,
        EvidenceType,
        IoCType,
        Direction,
        IDEACategory,
        Victim,
        Proto,
        Tag
    )

class VerticalPortscan:
    """
        Here's how the detection of vertical portscans is done
        1. Slips retrieves all destination IPs of the not
        established flows on TCP and UDP protocols
        2. For each dst IP, slips checks the amount of
        destination ports we connected to
        3. The first evidence will be triggered if the amount of
        destination ports for 1 IP is 5+
        4. then we combine evidence 3 by 3. for example
            evidence f 10,15,20 ports scanned will be combined into 1 evidence
            evidence of 15,30,35 ports scanned will be combined into 1 evidence
            etc.
        The result of this combining of evidence is that the dst ports
         scanned in each evidence will be = the
        previous scanned ports +15
        this combining is done to avoid duplicate evidence
        the downside to this is that if you do more than 1 portscan
        in the same timewindow, all portscans starting
        from the second portscan will be ignored if they don't exceed
        the number of dports of the first portscan
        so as a rule, each evidence should have X ports scanned. this
        X should ALWAYS be the last portscan+15,
        if this X is the last portscan +14, we don't
        set the evidence. we keep combining.
        3. Once the timewindow stops, Slips resets
         all counters, we go back to step 1
    """

    def __init__(self, db):
        self.db = db
        # We need to know that after a detection, if we receive another flow
        # that does not modify the count for the detection, we don't
        # re-detect again
        self.cached_tw_thresholds = {}
        # Get from the database the separator used to
        # separate the IP and the word profile
        self.fieldseparator = self.db.get_field_separator()
        # The minimum amount of ports to scan in vertical scan
        self.port_scan_minimum_dports = 5
        # list of tuples, each tuple is the args to setevidence
        self.pending_vertical_ps_evidence = {}
        # we should alert once we find 1 vertical ps evidence then
        # combine the rest of evidence every x seconds
        # the value of this dict will be true after
        # the first portscan alert to th ekey ip
        # format is {ip: True/False , ...}
        self.alerted_once_vertical_ps = {}

    def combine_evidence(self):
        """
        combines all evidence in self.pending_vertical_ps_evidence into 1
        evidence and empties the dict afterwards
        """
        for key, evidence_list in self.pending_vertical_ps_evidence.items():
            # each key here is  {profileid}-{twid}-{state}-{protocol}-{dport}
            # each value here is a list of evidence that should be combined
            profileid, twid, _, protocol, dstip = key.split('-')
            final_evidence_uids = []
            final_pkts_sent = 0

            # combine all evidence that share the above key
            for evidence in evidence_list:
                # each evidence is a tuple of
                # (timestamp, pkts_sent, uids, amount_of_dips)
                # in the final evidence, we'll be
                # using the ts of the last evidence
                timestamp, pkts_sent, evidence_uids, amount_of_dports = evidence
                # since we're combining evidence,
                # we want the uids of the final evidence
                # to be the sum of all the evidence we combined
                final_evidence_uids += evidence_uids
                final_pkts_sent += pkts_sent

            evidence = {
                'timestamp': timestamp,
                'pkts_sent': final_pkts_sent,
                'protocol': protocol,
                'profileid': profileid,
                'twid': twid,
                'uid': final_evidence_uids,
                'amount_of_dports': amount_of_dports,
                'dstip': dstip,
            }

            self.set_evidence_vertical_portscan(evidence)
        # reset the dict since we already combined
        self.pending_vertical_ps_evidence = {}


    def set_evidence_vertical_portscan(self, evidence: dict):
        """Sets the vertical portscan evidence in the db"""
        threat_level = ThreatLevel.HIGH
        saddr = evidence['profileid'].split('_')[-1]
        confidence = utils.calculate_confidence(evidence['pkts_sent'])
        description = (
            f'new vertical port scan to IP {evidence["dstip"]} from {saddr}. '
            f'Total {evidence["amount_of_dports"]} '
            f'dst {evidence["protocol"]} ports '
            f'were scanned. '
            f'Total packets sent to all ports: {evidence["pkts_sent"]}. '
            f'Confidence: {confidence}. by Slips'
        )

        attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=saddr
            )
        victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value=evidence['dstip']
            )
        twid = int(evidence['twid'].replace("timewindow", ""))
        evidence = Evidence(
            evidence_type=EvidenceType.VERTICAL_PORT_SCAN,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid),
            uid=evidence['uid'],
            timestamp=evidence['timestamp'],
            category=IDEACategory.RECON_SCANNING,
            conn_count=evidence['pkts_sent'],
            proto=Proto(evidence['protocol'].lower()),
            source_target_tag=Tag.RECON,
            victim=victim
        )

        self.db.set_evidence(evidence)



    def decide_if_time_to_set_evidence_or_combine(
            self,
            evidence: dict,
            cache_key: str
        ) -> bool:
        """
        sets the evidence immediately if it was the
            first portscan evidence in this tw
            or combines past 3
            evidence and then sets an evidence.
        :return: True if evidence was set/combined,
            False if evidence was queued for combining later
        """
        if not self.alerted_once_vertical_ps.get(cache_key, False):
            # now from now on, we will be combining the next vertical
            # ps evidence targetting this dport
            self.alerted_once_vertical_ps[cache_key] = True
            self.set_evidence_vertical_portscan(evidence)
            return True

        # we will be combining further alerts to avoid alerting
        # many times every portscan
        evidence_to_combine = (
            evidence["timestamp"],
            evidence["pkts_sent"],
            evidence["uid"],
            evidence["amount_of_dports"]
            )

        # for all the combined alerts, the following params should be equal
        key = f'{evidence["profileid"]}-' \
              f'{evidence["twid"]}-' \
              f'{evidence["state"]}-' \
              f'{evidence["protocol"]}-' \
              f'{evidence["dstip"]}'
        try:
            self.pending_vertical_ps_evidence[key].append(evidence_to_combine)
        except KeyError:
            # first time seeing this key
            self.pending_vertical_ps_evidence[key] = [evidence_to_combine]

        # combine evidence every x new portscans to the same ip
        if len(self.pending_vertical_ps_evidence[key]) == 3:
            self.combine_evidence()
            return True

        return False

    def check_if_enough_dports_to_trigger_an_evidence(
            self, cache_key: str, amount_of_dports: int
            ) -> bool:
        """
        checks if the scanned sports are enough to trigger and evidence
        we make sure the amount of dports reported each evidence
        is higher than the previous one +5
        """
        prev_amount_dports: int = self.cached_tw_thresholds.get(
            cache_key,
            0
        )
        # we make sure the amount of dports reported
        # each evidence is higher than the previous one +5
        # so the first alert will always report 5
        # dport, and then 10+,15+,20+ etc
        # the goal is to never get an evidence that's
        # 1 or 2 ports more than the previous one so we dont
        # have so many portscan evidence
        if (
                amount_of_dports >= self.port_scan_minimum_dports
                and prev_amount_dports + 5 <= amount_of_dports
        ):
            # Store in our local cache how many dips were there:
            self.cached_tw_thresholds[cache_key] = amount_of_dports
            return True
        return False

    def get_not_established_dst_ips(
            self, protocol: str, state: str, profileid: str, twid: str
            ) -> dict:
        """
        Get the list of dstips that we tried to connect to (not established flows)
          these unknowns are the info this function retrieves
          profileid -> unknown_dstip:unknown_dstports

         here, the profileid given is the client.
         :return: the following dict
         {
             dst_ip: {
                 totalflows: total flows seen by the profileid
                 totalpkt: total packets seen by the profileid
                 totalbytes: total bytes sent by the profileid
                 stime: timestamp of the first flow seen from this profileid -> this dstip
                 uid: list of uids where the given profileid was
                        contacting the dst_ip on this dstport
                 dstports: dst ports seen in all flows where the given profileid was srcip
                     {
                         <str port>: < int spkts sent to this port>
                     }
             }
        """
        direction = 'Dst'
        role = 'Client'
        type_data = 'IPs'

        dstips: dict = self.db.get_data_from_profile_tw(
            profileid, twid, direction, state, protocol, role, type_data
            )
        return dstips

    def get_cache_key(self, profileid: str, twid: str, dstip: str):
        """
        returns the key that identifies this vertical portscan in thhe
        given tw
        """
        return f'{profileid}:{twid}:dstip:{dstip}:VerticalPortscan'

    def check(self, profileid, twid):
        """
        sets an evidence if a vertical portscan is detected
        """
        # if you're portscaning a port that is open it's gonna be established
        # the amount of open ports we find is gonna be so small
        # theoretically this is incorrect bc we'll be ignoring established evidence,
        # but usually open ports are very few compared to the whole range
        # so, practically this is correct to avoid FP
        state = 'Not Established'

        for protocol in ('TCP', 'UDP'):
            dstips: dict = self.get_not_established_dst_ips(
                protocol, state, profileid, twid
                )

            # For each dstip, see if the amount of ports connections is over the threshold
            for dstip in dstips.keys():

                dstports: dict = dstips[dstip]['dstports']
                # Get the total amount of pkts sent to all
                # ports on the same host
                pkts_sent = sum(dstports[dport] for dport in dstports)
                amount_of_dports = len(dstports)

                cache_key = self.get_cache_key(profileid, twid, dstip)
                if self.check_if_enough_dports_to_trigger_an_evidence(
                        cache_key, amount_of_dports
                        ):
                    evidence_details = {
                        'timestamp': dstips[dstip]['stime'],
                        'pkts_sent': pkts_sent,
                        'protocol': protocol,
                        'profileid': profileid,
                        'twid': twid,
                        'uid': dstips[dstip]['uid'],
                        'amount_of_dports': amount_of_dports,
                        'dstip': dstip,
                        'state': state,
                    }

                    self.decide_if_time_to_set_evidence_or_combine(
                        evidence_details, cache_key
                    )
