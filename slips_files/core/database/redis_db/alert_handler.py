import time
import json
from dataclasses import asdict
from typing import List, Tuple

from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import \
    (
        Evidence,
        EvidenceType,
        Direction
    )

class AlertHandler:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to setting and retrieving evidence and alerts in the db
    """
    name = 'DB'

    def increment_attack_counter(
            self,
            attacker: str,
            victim: str,
            evidence_type: str
        ):
        """
        increments the value of the hash profile_attacker_evidence_summary
        of the given victim
        :param attacker: is a profileid
        :param victim: IP of a victim
        :param evidence_type: e.g. MaliciousJA3, DataExfiltration, etc.
        """
        self.r.hincrby(
            f'{attacker}_evidence_sumamry',
            f"{victim}_{evidence_type}",
            1)

    def set_evidence_causing_alert(self, profileid, twid, alert_ID, evidence_IDs: list):
        """
        When we have a bunch of evidence causing an alert,
        we associate all evidence IDs with the alert ID in our database
        this function stores evidence in 'alerts' key only
        :param alert ID: the profileid_twid_ID of the last evidence causing this alert
        :param evidence_IDs: all IDs of the evidence causing this alert
        """
        old_profileid_twid_alerts: dict = self.get_profileid_twid_alerts(profileid, twid)

        alert = {
            alert_ID: json.dumps(evidence_IDs)
        }

        if old_profileid_twid_alerts:
            # update previous alerts for this profileid twid
            # add the alert we have to the old alerts of this profileid_twid
            old_profileid_twid_alerts.update(alert)
            profileid_twid_alerts = json.dumps(old_profileid_twid_alerts)
        else:
            # no previous alerts for this profileid twid
            profileid_twid_alerts = json.dumps(alert)


        self.r.hset(f'{profileid}{self.separator}{twid}',
                    'alerts',
                    profileid_twid_alerts)

        # the structure of alerts key is
        # alerts {
        #     profile_<ip>: {
        #               twid1: {
        #                   alert_ID1: [evidence_IDs],
        #                   alert_ID2: [evidence_IDs]
        #                  }
        #             }
        # }

        profile_alerts = self.r.hget('alerts', profileid)
        # alert ids look like this
        # profile_192.168.131.2_timewindow1_92a3b9c2-330b-47ab-b73e-c5380af90439
        alert_hash = alert_ID.split('_')[-1]
        alert = {
            twid: {
                alert_hash: evidence_IDs
            }
        }
        if not profile_alerts:
            # first alert in this profile
            alert = json.dumps(alert)
            self.r.hset('alerts', profileid, alert)
            return

        # the format of this dict is {twid1: {alert_hash: [evidence_IDs]},
        #                              twid2: {alert_hash: [evidence_IDs]}}
        profile_alerts:dict = json.loads(profile_alerts)

        if twid not in profile_alerts:
            # first time having an alert for this twid
            profile_alerts.update(alert)
        else:
            # we already have a twid with alerts in this profile, update it
            # the format of twid_alerts is {alert_hash: evidence_IDs}
            twid_alerts: dict = profile_alerts[twid]
            twid_alerts[alert_hash] = evidence_IDs
            profile_alerts[twid] = twid_alerts

        profile_alerts = json.dumps(profile_alerts)
        self.r.hset('alerts', profileid, profile_alerts)

    def get_evidence_causing_alert(self, profileid, twid, alert_ID) -> list:
        """
        Returns all the IDs of evidence causing this alert
        :param alert_ID: ID of alert to export to warden server
        for example profile_10.0.2.15_timewindow1_4e4e4774-cdd7-4e10-93a3-e764f73af621
        """
        if alerts := self.r.hget(f'{profileid}{self.separator}{twid}', 'alerts'):
            alerts = json.loads(alerts)
            return alerts.get(alert_ID, False)
        return False

    def get_evidence_by_ID(self, profileid, twid, ID):

        evidence = self.get_twid_evidence(profileid, twid)
        if not evidence:
            return False

        evidence: dict = json.loads(evidence)
        # loop through each evidence in this tw
        for evidence_details in evidence.values():
            evidence_details = json.loads(evidence_details)
            if evidence_details.get('ID') == ID:
                # found an evidence that has a matching ID
                return evidence_details

    def is_detection_disabled(self, evidence_type: EvidenceType):
        """
        Function to check if detection is disabled in slips.conf
        """
        return str(evidence_type) in self.disabled_detections

    def set_flow_causing_evidence(self, uids: list, evidence_ID):
        self.r.hset("flows_causing_evidence", evidence_ID, json.dumps(uids))

    def get_flows_causing_evidence(self, evidence_ID) -> list:
        uids = self.r.hget("flows_causing_evidence", evidence_ID)
        return json.loads(uids) if uids else []

    def get_victim(self, profileid, attacker):
        saddr = profileid.split("_")[-1]
        if saddr not in attacker:
            return saddr
        # if the saddr is the attacker, then the victim should be passed as a param to this function
        # there's no 1 victim in this case. for example in ARP scans, the victim is the whole network
        return ''

    def setEvidence(self, evidence: Evidence):
        """
        Set the evidence for this Profile and Timewindow.
        :param evidence: an Evidence obj (defined in
        slips_files/core/evidence_structure/evidence.py) with all the
        evidence details,
        """
        # Ignore evidence if it's disabled in the configuration file
        if self.is_detection_disabled(evidence.evidence_type):
            return False

        self.set_flow_causing_evidence(evidence.uid, evidence.id)

        # @@@@@@@@@@@@@ todo handle the new evidence format in all the
        #  receiving clients
        evidence_to_send: dict = utils.to_json_serializable(evidence)
        evidence_to_send: str = json.dumps(evidence_to_send)

        # Check if we have the current evidence stored in the DB for
        # this profileid in this twid
        # @@@@@@@@@@@@@ TODO search using redis for the id of this evidence
        #  in the profil+tw evidence in the db! it would be faster
        current_evidence: str = self.get_twid_evidence(
            str(evidence.profile),
            str(evidence.timewindow)
            )
        current_evidence: dict = json.loads(current_evidence) if \
            current_evidence else {}

        should_publish: bool = evidence.id not in current_evidence.keys()

        # update our current evidence for this profileid and twid.
        current_evidence.update({evidence.id: evidence_to_send})
        current_evidence: str = json.dumps(current_evidence)

        self.r.hset(f'{evidence.profile}_{evidence.timewindow}',
                    'Evidence',
                    current_evidence)

        self.r.hset(f'evidence{str(evidence.profile)}',
                    str(evidence.timewindow),
                    current_evidence)

        # This is done to ignore repetition of the same evidence sent.
        # note that publishing HAS TO be done after updating the 'Evidence' keys
        if should_publish:
            self.r.incr('number_of_evidence', 1)
            self.publish('evidence_added', evidence_to_send)

        # an evidence is generated for this profile
        # update the threat level of this profile
        if evidence.attacker.direction == Direction.SRC:
            # the srcip is the malicious one
            self.update_threat_level(
                str(evidence.profile),
                str(evidence.threat_level),
                evidence.confidence
                )
        elif evidence.attacker.direction == Direction.DST:
            # the dstip is the malicious one
            self.update_threat_level(
                str(evidence.attacker.profile),
                str(evidence.threat_level),
                evidence.confidence
                )
        return True


    def init_evidence_number(self):
        """used when the db starts to initialize number of evidence generated by slips """
        self.r.set('number_of_evidence', 0)

    def get_evidence_number(self):
        return self.r.get('number_of_evidence')

    def mark_evidence_as_processed(self, evidence_ID: str):
        """
        If an evidence was processed by the evidenceprocess, mark it in the db
        """
        self.r.sadd('processed_evidence', evidence_ID)

    def is_evidence_processed(self, evidence_ID: str) -> bool:
        return self.r.sismember('processed_evidence', evidence_ID)

    def set_evidence_for_profileid(self, evidence):
        """
        Set evidence for the profile in the same format as json in alerts.json
        """
        evidence = json.dumps(evidence)
        self.r.sadd('Evidence', evidence)

    def deleteEvidence(self, profileid, twid, evidence_ID: str):
        """
        Delete evidence from the database
        """
        # 1. delete evidence from 'evidence' key
        current_evidence = self.get_twid_evidence(profileid, twid)
        current_evidence = json.loads(current_evidence) if current_evidence else {}
        # Delete the key regardless of whether it is in the dictionary
        current_evidence.pop(evidence_ID, None)
        current_evidence_json = json.dumps(current_evidence)
        self.r.hset(
            profileid + self.separator + twid,
            'Evidence',
            current_evidence_json,
        )
        self.r.hset(f'evidence{profileid}', twid, current_evidence_json)
        # 2. delete evidence from 'alerts' key
        profile_alerts = self.r.hget('alerts', profileid)
        if not profile_alerts:
            # this means that this evidence wasn't a part of an alert
            # give redis time to the save the changes before calling this function again
            # removing this sleep will cause this function to be called again before
            # deleting the evidence ID from the evidence keys
            time.sleep(0.5)
            return

        profile_alerts:dict = json.loads(profile_alerts)
        try:
            # we already have a twid with alerts in this profile, update it
            # the format of twid_alerts is {alert_hash: evidence_IDs}
            twid_alerts: dict = profile_alerts[twid]
            IDs = False
            hash = False
            for alert_hash, evidence_IDs in twid_alerts.items():
                if evidence_ID in evidence_IDs:
                    IDs = evidence_IDs
                    hash = alert_hash
                break
            else:
                return

            if IDs and hash:
                evidence_IDs = IDs.remove(evidence_ID)
                alert_ID = f'{profileid}_{twid}_{hash}'
                if evidence_IDs:
                    self.set_evidence_causing_alert(
                        profileid, twid, alert_ID, evidence_IDs
                    )

        except KeyError:
            # alert not added to the 'alerts' key yet!
            # this means that this evidence wasn't a part of an alert
            return

    def cache_whitelisted_evidence_ID(self, evidence_ID:str):
        """
        Keep track of whitelisted evidence IDs to avoid showing them in alerts later
        """
        # without this function, slips gets the stored evidence id from the db,
        # before deleteEvidence is called, so we need to keep track of whitelisted evidence ids
        self.r.sadd('whitelisted_evidence', evidence_ID)

    def is_whitelisted_evidence(self, evidence_ID):
        """
        Check if we have the evidence ID as whitelisted in the db to avoid showing it in alerts
        """
        return self.r.sismember('whitelisted_evidence', evidence_ID)

    def remove_whitelisted_evidence(self, all_evidence:str) -> str:
        """
        param all_evidence serialized json dict
        returns a serialized json dict
        """
        # remove whitelisted evidence from the given evidence
        all_evidence = json.loads(all_evidence)
        tw_evidence = {}
        for ID,evidence in all_evidence.items():
            if self.is_whitelisted_evidence(ID):
                continue
            tw_evidence[ID] = evidence
        return json.dumps(tw_evidence)

    def get_profileid_twid_alerts(self, profileid, twid) -> dict:
        """
        The format for the returned dict is
            {profile123_twid1_<alert_uuid>: [ev_uuid1, ev_uuid2, ev_uuid3]}
        """
        alerts: str = self.r.hget(f'{profileid}_{twid}', 'alerts')
        if not alerts:
            return {}
        alerts: dict = json.loads(alerts)
        return alerts

    def get_twid_evidence(self, profileid: str, twid: str) -> str:
        """Get the evidence for this TW for this Profile"""
        evidence = self.r.hget(profileid + self.separator + twid, 'Evidence')
        if evidence:
            evidence: str = self.remove_whitelisted_evidence(evidence)
        return evidence

    def set_max_threat_level(self, profileid: str, threat_level: str):
        self.r.hset(profileid, 'max_threat_level', threat_level)


    def get_accumulated_threat_level(
            self,
            profileid: str,
            twid: str
        ) -> float:
        """
        returns the accumulated_threat_lvl or 0 if it's not there
        """
        accumulated_threat_lvl = self.r.zscore(
            'accumulated_threat_levels',
            f'{profileid}_{twid}')
        return accumulated_threat_lvl or 0


    def update_accumulated_threat_level(
            self,
            profileid: str,
            twid: str,
            update_val: float):
        """
        increments or decrements the accumulated threat level of the given
        profileid and
        twid by the given update_val
        :param update_val: can be +ve to increase the threat level or -ve
        to decrease
        """
        self.r.zincrby(
            'accumulated_threat_levels',
            update_val,
            f'{profileid}_{twid}',
        )

    def set_accumulated_threat_level(
            self,
            profileid: str,
            twid: str,
            accumulated_threat_lvl: float,
        ):

        self.r.zadd('accumulated_threat_levels',
                    {f'{profileid}_{twid}': accumulated_threat_lvl} )

    def update_max_threat_level(
            self, profileid: str, threat_level: str
        ) -> float:
        """
        given the current threat level of a profileid, this method sets the
        max_threaty_level value to the given val if that max is less than
        the given
        :returns: the numerical val of the max threat level
        """
        threat_level_float  = utils.threat_levels[threat_level]

        old_max_threat_level: str = self.r.hget(
            profileid,
            'max_threat_level'
        )

        if not old_max_threat_level:
            # first time setting max tl
            self.set_max_threat_level(profileid, threat_level)
            return threat_level_float

        old_max_threat_level_float = utils.threat_levels[old_max_threat_level]

        if old_max_threat_level_float < threat_level_float:
            self.set_max_threat_level(profileid, threat_level)
            return threat_level_float

        return old_max_threat_level_float


    def update_threat_level(
            self, profileid: str, threat_level: str, confidence: float
            ):
        """
        Update the threat level of a certain profile
        Updates the profileid key and the IPsInfo key with the
         new score and confidence of this profile
        :param threat_level: available options are 'low', 'medium' 'critical' etc
        """

        self.r.hset(profileid, 'threat_level', threat_level)

        now = utils.convert_format(time.time(), utils.alerts_format)
        confidence = f'confidence: {confidence}'

        # this is what we'll be storing in the db, tl, ts, and confidence
        threat_level_data = (threat_level, now, confidence)

        past_threat_levels: List[Tuple] = self.r.hget(
            profileid,
            'past_threat_levels'
        )
        if past_threat_levels:
            # get the list of ts and past threat levels
            past_threat_levels = json.loads(past_threat_levels)

            latest: Tuple = past_threat_levels[-1]
            latest_threat_level: str = latest[0]
            latest_confidence: str = latest[2]

            if (
                    latest_threat_level == threat_level
                    and latest_confidence == confidence
            ):
                # if the past threat level and confidence
                # are the same as the ones we wanna store,
                # replace the timestamp only
                past_threat_levels[-1] = threat_level_data
                # dont change the old max tl
            else:
                # add this threat level to the list of past threat levels
                past_threat_levels.append(threat_level_data)
        else:
            # first time setting a threat level for this profile
            past_threat_levels = [threat_level_data]

        past_threat_levels = json.dumps(past_threat_levels)
        self.r.hset(profileid, 'past_threat_levels', past_threat_levels)

        max_threat_lvl: float = self.update_max_threat_level(
            profileid, threat_level
            )

        score_confidence = {
            # get the numerical value of this threat level
            'score': max_threat_lvl,
            'confidence': confidence
        }
        # set the score and confidence of the given ip in the db
        # when it causes an evidence
        # these 2 values will be needed when sharing with peers
        ip = profileid.split('_')[-1]

        if cached_ip_info := self.get_ip_info(ip):
            # append the score and confidence to the already existing data
            cached_ip_info.update(score_confidence)
            score_confidence = cached_ip_info

        self.rcache.hset('IPsInfo', ip, json.dumps(score_confidence))

