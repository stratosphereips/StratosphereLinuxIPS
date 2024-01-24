import ipaddress

from slips_files.common.imports import *
from slips_files.core.evidence_structure.evidence import \
    (
        Evidence,
        ProfileID,
        TimeWindow,
        Victim,
        Attacker,
        Proto,
        ThreatLevel,
        EvidenceType,
        IoCType,
        Direction,
        IDEACategory,
        Tag
    )


class HorizontalPortscan():
    def __init__(self, db):
        self.db = db
        # We need to know that after a detection, if we receive another flow
        # that does not modify the count for the detection, we are not
        # re-detecting again only because the threshold was overcomed last time.
        self.cached_tw_thresholds = {}
        # the separator used to separate the IP and the word profile
        self.fieldseparator = self.db.get_field_separator()

        # The minimum amount of ips to scan horizontal scan
        self.port_scan_minimum_dips = 5
        self.pending_horizontal_ps_evidence = {}
        # we should alert once we find 1 horizontal ps evidence then combine the rest of evidence every x seconds
        # format is { scanned_port: True/False , ...}
        self.alerted_once_horizontal_ps = {}

    def combine_evidence(self):
        """
        Combines all the evidence in pending_horizontal_ps_evidence into 1 evidence and calls set_evidence
        this function is called every 3 pending ev
        """
        for key, evidence_list in self.pending_horizontal_ps_evidence.items():
            # each key here is {profileid}-{twid}-{state}-{protocol}-{dport}
            # each value here is a list of evidence that should be combined
            profileid, twid, state, protocol, dport = key.split('-')
            final_evidence_uids = []
            final_pkts_sent = 0
            # combine all evidence that share the above key
            for evidence in evidence_list:
                # each evidence is a tuple of (timestamp, pkts_sent, uids, amount_of_dips)
                # in the final evidence, we'll be using the ts of the last evidence
                timestamp, pkts_sent, evidence_uids, amount_of_dips = evidence
                # since we're combining evidence, we want the uids of the final evidence
                # to be the sum of all the evidence we combined
                final_evidence_uids += evidence_uids
                final_pkts_sent += pkts_sent

            evidence = {
                        'protocol': protocol,
                        'profileid': profileid,
                        'twid': twid,
                        'uids': final_evidence_uids,
                        'dport':dport,
                        'pkts_sent': final_pkts_sent,
                        'timestamp': timestamp,
                        'state': state,
                        'amount_of_dips': amount_of_dips
                        }

            self.set_evidence_horizontal_portscan(
                evidence
            )
        # reset the dict since we already combined the evidence
        self.pending_horizontal_ps_evidence = {}

    def get_resolved_ips(self, dstips: dict) -> list:
        """
        returns the list of dstips that have dns resolution, we will discard them when checking for
        horizontal portscans
        """
        dstips_to_discard = []
        # Remove dstips that have DNS resolution already
        for dip in dstips:
            dns_resolution = self.db.get_dns_resolution(dip)
            dns_resolution = dns_resolution.get('domains', [])
            if dns_resolution:
                dstips_to_discard.append(dip)
        return dstips_to_discard

    def get_not_estab_dst_ports(self, protocol: str, state: str, profileid: str, twid: str
            ) -> dict:
        """
        Get the list of dstports that we tried to connect to (not established
        flows)
          these unknowns are the info this function retrieves
          profileid -> unknown_dstip:unknown_dstports

         here, the profileid given is the client.
         :return: the following dict
         #TODO this is wrong, fix it
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
        # Get the list of dports that we connected as client using TCP not established
        direction = 'Dst'
        role = 'Client'
        type_data = 'Ports'
        dports: dict = self.db.get_data_from_profile_tw(
                profileid, twid, direction, state, protocol, role, type_data
            )
        return dports

    def get_cache_key(self, profileid: str, twid: str, dport):
        return f'{profileid}:{twid}:dport:{dport}:HorizontalPortscan'


    def get_packets_sent(self, dstips: dict) -> int:
        """
        returns the total amount of packets sent to all dst IPs
        :param dstips: dict with info about  in the following format
        { dstip:  {
                        'pkts': src+dst packets sent to this dstip,
                       'spkts': src packets sent to this dstip,
                       'stime': timestamp of the first flow in the uid list,
                       'uid': [uids of flows to this ip]
                   }
        }
        """
        pkts_sent = 0
        for dstip in dstips:
            if 'spkts' not in dstips[dstip]:
                # In argus files there are no src pkts, only pkts.
                # So it is better to have the total pkts than to have no packets count
                pkts_sent += int(dstips[dstip]["pkts"])
            else:
                pkts_sent += int(dstips[dstip]["spkts"])
        return pkts_sent

    def check_if_enough_dstips_to_trigger_an_evidence(
        self, cache_key: str, amount_of_dips: int
        ) -> bool:
        """
        checks if the scanned dst ips are enough to trigger and
        evidence
        we make sure the amount of scammed dst ips reported each
        evidence
        is higher than the previous one +5
        """
        prev_amount_dips = self.cached_tw_thresholds.get(cache_key, 0)

        # so the first alert will always report 5 dstips,
        # and then 10+,15+,20+ etc
        # the goal is to never get an evidence that's 1 or 2 ports
        # more than the previous one so we dont
        # have so many portscan evidence
        if (
            amount_of_dips >= self.port_scan_minimum_dips
            and prev_amount_dips + 5 <= amount_of_dips
        ):
            self.cached_tw_thresholds[cache_key] = amount_of_dips
            return True
        return False


    def get_uids(self, dstips: dict):
        """
        returns all the uids of flows sent on a sigle port ti different dstination IPs
        """
        uids = []
        for dstip in dstips:
            for uid in dstips[dstip]['uid']:
                 uids.append(uid)
        return uids

    def check(self, profileid: str, twid: str):

        saddr = profileid.split(self.fieldseparator)[1]
        try:
            saddr_obj = ipaddress.ip_address(saddr)
            if saddr == '255.255.255.255' or saddr_obj.is_multicast:
                # don't report port scans on the broadcast or multicast addresses
                return False
        except ValueError:
            # it's a mac
            pass


        # if you're portscaning a port that is open it's gonna be established
        # the amount of open ports we find is gonna be so small
        # theoretically this is incorrect bc we'll be ignoring established evidence,
        # but usually open ports are very few compared to the whole range
        # so, practically this is correct to avoid FP
        state = 'Not Established'
        for protocol in ('TCP', 'UDP'):

            dports: dict = self.get_not_estab_dst_ports(
                protocol, state, profileid, twid
                )

            # For each port, see if the amount is over the threshold
            for dport in dports.keys():
                # PortScan Type 2. Direction OUT
                dstips: dict = dports[dport]['dstips']

                # remove the resolved dstips from dstips dict
                for ip in self.get_resolved_ips(dstips):
                    dstips.pop(ip)

                cache_key: str = self.get_cache_key(profileid, twid, dport)
                amount_of_dips = len(dstips)

                if self.check_if_enough_dstips_to_trigger_an_evidence(
                        cache_key, amount_of_dips
                ):
                    evidence = {
                        'protocol': protocol,
                        'profileid': profileid,
                        'twid': twid,
                        'uids': self.get_uids(dstips),
                        'dport':dport,
                        'pkts_sent':self.get_packets_sent(dstips),
                        'timestamp': next(iter(dstips.values()))['stime'],
                        'state': state,
                        'amount_of_dips': amount_of_dips
                        }

                    self.decide_if_time_to_set_evidence_or_combine(
                        evidence,
                        cache_key
                        )

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


        if not self.alerted_once_horizontal_ps.get(cache_key, False):
            self.alerted_once_horizontal_ps[cache_key] = True
            self.set_evidence_horizontal_portscan(evidence)
            #  from now on, we will be combining the next horizontal
            #  ps evidence targeting this
            # dport
            return True


        # we will be combining further alerts to avoid alerting many times every portscan
        evidence_details = (evidence["timestamp"],
                            evidence["pkts_sent"],
                            evidence["uids"],
                            evidence["amount_of_dips"])
        # for all the combined alerts, the following params should be equal
        key = f'{evidence["profileid"]}-{evidence["twid"]}-' \
              f'{evidence["state"]}-{evidence["protocol"]}-' \
              f'{evidence["dport"]}'

        try:
            self.pending_horizontal_ps_evidence[key].append(evidence_details)
        except KeyError:
            # first time seeing this key
            self.pending_horizontal_ps_evidence[key] = [evidence_details]

        # combine evidence every 3 new portscans to the same dport
        if len(self.pending_horizontal_ps_evidence[key]) == 3:
            self.combine_evidence()
            return True
        return False


    def set_evidence_horizontal_portscan(self, evidence: dict):
        threat_level = ThreatLevel.HIGH
        confidence = utils.calculate_confidence(evidence["pkts_sent"])
        srcip = evidence["profileid"].split('_')[-1]

        attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=srcip
            )
        portproto = f'{evidence["dport"]}/{evidence["protocol"]}'
        port_info = self.db.get_port_info(portproto) or ""
        description = (
            f'Horizontal port scan to port {port_info} {portproto}. '
            f'From {srcip} to {evidence["amount_of_dips"]} unique destination IPs. '
            f'Total packets sent: {evidence["pkts_sent"]}. '
            f'Threat Level: {threat_level}. '
            f'Confidence: {confidence}. by Slips'
        )

        evidence = Evidence(
            evidence_type=EvidenceType.HORIZONTAL_PORT_SCAN,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=int(evidence["twid"].replace("timewindow", ""))),
            uid=evidence["uids"],
            timestamp=evidence["timestamp"],
            category=IDEACategory.RECON_SCANNING,
            conn_count=evidence["pkts_sent"],
            proto=Proto(evidence["protocol"].lower()),
            source_target_tag=Tag.RECON,
            port=evidence["dport"]
        )

        self.db.set_evidence(evidence)
