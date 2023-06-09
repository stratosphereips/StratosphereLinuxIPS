from slips_files.common.imports import *
import ipaddress

class HorizontalPortscan():
    def __init__(self, db):
        self.db = db
        # We need to know that after a detection, if we receive another flow
        # that does not modify the count for the detection, we are not
        # re-detecting again only because the threshold was overcomed last time.
        self.cache_det_thresholds = {}
        # the separator used to separate the IP and the word profile
        self.fieldseparator = self.db.get_field_separator()

        # The minimum amount of ips to scan horizontal scan
        self.port_scan_minimum_dips = 5
        self.pending_horizontal_ps_evidence = {}
        # we should alert once we find 1 horizontal ps evidence then combine the rest of evidence every x seconds
        # format is { scanned_port: True/False , ...}
        self.alerted_once_horizontal_ps = {}

    def calculate_confidence(self, pkts_sent):
        if pkts_sent > 10:
            confidence = 1
        elif pkts_sent == 0:
            return 0.3
        else:
            # Between threshold and 10 pkts compute a kind of linear grow
            confidence = pkts_sent / 10.0
        return confidence

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

            self.set_evidence_horizontal_portscan(
                timestamp,
                final_pkts_sent,
                protocol,
                profileid,
                twid,
                final_evidence_uids,
                dport,
                amount_of_dips
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

    def check(self, profileid, twid):
        def get_uids():
            """
            returns all the uids of flows to this port
            """
            uids = []
            for dip in dstips:
                for uid in dstips[dip]['uid']:
                     uids.append(uid)
            return uids

        saddr = profileid.split(self.fieldseparator)[1]
        try:
            saddr_obj = ipaddress.ip_address(saddr)
            if saddr == '255.255.255.255' or saddr_obj.is_multicast:
                # don't report port scans on the broadcast or multicast addresses
                return False
        except ValueError:
            # it's a mac
            pass

        # Get the list of dports that we connected as client using TCP not established
        direction = 'Dst'
        role = 'Client'
        type_data = 'Ports'
        for state in ('Established', 'Not Established'):
            for protocol in ('TCP', 'UDP'):
                dports = self.db.getDataFromProfileTW(
                    profileid, twid, direction, state, protocol, role, type_data
                )

                # For each port, see if the amount is over the threshold
                for dport in dports.keys():
                    # PortScan Type 2. Direction OUT
                    dstips: dict = dports[dport]['dstips']

                    # remove the resolved dstips from dstips dict
                    for ip in self.get_resolved_ips(dstips):
                        dstips.pop(ip)

                    amount_of_dips = len(dstips)
                    # If we contacted more than 3 dst IPs on this port with not established
                    # connections, we have evidence.

                    cache_key = f'{profileid}:{twid}:dport:{dport}:HorizontalPortscan'
                    prev_amount_dips = self.cache_det_thresholds.get(cache_key, 0)
                    # We detect a scan every Threshold. So, if the threshold is 3,
                    # we detect when there are 3, 6, 9, 12, etc. dips per port.

                    # we make sure the amount of dstips reported each evidence is higher than the previous one +5
                    # so the first alert will always report 5 dstips, and then 10+,15+,20+ etc
                    # the goal is to never get an evidence that's 1 or 2 ports more than the previous one so we dont
                    # have so many portscan evidence
                    if (
                        amount_of_dips >= self.port_scan_minimum_dips
                        and prev_amount_dips + 5 <= amount_of_dips
                    ):
                        # Get the total amount of pkts sent to the same port from all IPs
                        pkts_sent = 0
                        for dip in dstips:
                            if 'spkts' not in dstips[dip]:
                                # In argus files there are no src pkts, only pkts.
                                # So it is better to have the total pkts than to have no packets count
                                pkts_sent += int(dstips[dip]["pkts"])
                            else:
                                pkts_sent += int(dstips[dip]["spkts"])

                        uids: list = get_uids()
                        timestamp = next(iter(dstips.values()))['stime']

                        self.cache_det_thresholds[cache_key] = amount_of_dips

                        if not self.alerted_once_horizontal_ps.get(cache_key, False):
                            #  from now on, we will be combining the next horizontal ps evidence targeting this
                            # dport
                            self.alerted_once_horizontal_ps[cache_key] = True
                            self.set_evidence_horizontal_portscan(
                                timestamp,
                                pkts_sent,
                                protocol,
                                profileid,
                                twid,
                                uids,
                                dport,
                                amount_of_dips
                            )
                        else:
                            # we will be combining further alerts to avoid alerting many times every portscan
                            evidence_details = (timestamp, pkts_sent, uids, amount_of_dips)
                            # for all the combined alerts, the following params should be equal
                            key = f'{profileid}-{twid}-{state}-{protocol}-{dport}'

                            try:
                                self.pending_horizontal_ps_evidence[key].append(evidence_details)
                            except KeyError:
                                # first time seeing this key
                                self.pending_horizontal_ps_evidence[key] = [evidence_details]

                            # combine evidence every 3 new portscans to the same dport
                            if len(self.pending_horizontal_ps_evidence[key]) == 3:
                                self.combine_evidence()

    def set_evidence_horizontal_portscan(
            self,
            timestamp,
            pkts_sent,
            protocol,
            profileid,
            twid,
            uid,
            dport,
            amount_of_dips
    ):
        evidence_type = 'HorizontalPortscan'
        attacker_direction = 'srcip'
        source_target_tag = 'Recon'
        srcip = profileid.split('_')[-1]
        attacker = srcip
        threat_level = 'medium'
        category = 'Recon.Scanning'
        portproto = f'{dport}/{protocol}'
        port_info = self.db.get_port_info(portproto)
        port_info = port_info or ""
        confidence = self.calculate_confidence(pkts_sent)
        description = (
            f'horizontal port scan to port {port_info} {portproto}. '
            f'From {srcip} to {amount_of_dips} unique dst IPs. '
            f'Total packets sent: {pkts_sent}. '
            f'Threat Level: {threat_level}. '
            f'Confidence: {confidence}. by Slips'
        )

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=pkts_sent,
                                 port=dport, proto=protocol, profileid=profileid, twid=twid, uid=uid)
