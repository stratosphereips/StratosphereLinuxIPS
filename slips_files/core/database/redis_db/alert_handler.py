# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import time
import json
from typing import (
    List,
    Tuple,
    Optional,
    Dict,
    Union,
)
from slips_files.common.slips_utils import utils
from slips_files.core.structures.alerts import (
    Alert,
    alert_to_dict,
)
from slips_files.core.structures.evidence import (
    Evidence,
    EvidenceType,
    Victim,
    ProfileID,
    IoCType,
    Attacker,
)


class AlertHandler:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to setting and retrieving evidence and alerts in the db
    """

    name = "DB"

    def increment_attack_counter(
        self, attacker: str, victim: Optional[Victim], evidence_type: str
    ):
        """
        increments the value of the hash profile_attacker_evidence_summary
        of the given victim
        :param attacker: is a profileid
        :param victim: IP of a victim
        :param evidence_type: e.g. MaliciousJA3, DataExfiltration, etc.
        """
        victim = "" if not victim else victim
        self.r.hincrby(
            f"{attacker}_evidence_summary", f"{victim}_{evidence_type}", 1
        )

    def mark_profile_as_malicious(self, profileid: ProfileID):
        """keeps track of profiles that generated an alert"""
        self.r.sadd(self.constants.MALICIOUS_PROFILES, str(profileid))

    def get_malicious_profiles(self):
        """returns profiles that generated an alert"""
        return self.r.smembers(self.constants.MALICIOUS_PROFILES)

    def set_evidence_causing_alert(self, alert: Alert):
        """
        When we have a bunch of evidence causing an alert,
        we associate all evidence IDs with the alert ID in our database
        """
        old_profileid_twid_alerts: Dict[str, List[str]]

        old_profileid_twid_alerts = self.get_profileid_twid_alerts(
            str(alert.profile), str(alert.timewindow)
        )

        alert_dict = {alert.id: json.dumps(alert.correl_id)}

        if old_profileid_twid_alerts:
            # update previous alerts for this profileid twid
            # add the alert we have to the old alerts of this profileid_twid
            old_profileid_twid_alerts.update(alert_dict)
            profileid_twid_alerts = json.dumps(old_profileid_twid_alerts)
        else:
            # no previous alerts for this profileid twid
            profileid_twid_alerts = json.dumps(alert_dict)

        self.r.hset(
            f"{alert.profile}_{alert.timewindow}",
            "alerts",
            profileid_twid_alerts,
        )
        self.r.incr(self.constants.NUMBER_OF_ALERTS, 1)

    def get_number_of_alerts_so_far(self):
        return self.r.get(self.constants.NUMBER_OF_ALERTS)

    def get_evidence_causing_alert(
        self, profileid, twid, alert_id: str
    ) -> list:
        """
        Returns all the IDs of evidence causing this alert
        :param alert_ID: ID of alert to export to warden server
        for example profile_10.0.2.15_timewindow1_4e4e4774-cdd7-4e10-93a3-e764f73af621
        """
        if alerts := self.r.hget(f"{profileid}_{twid}", "alerts"):
            alerts = json.loads(alerts)
            return alerts.get(alert_id, False)
        return False

    def get_evidence_by_id(self, profileid: str, twid: str, evidence_id: str):
        evidence: Dict[str, dict] = self.get_twid_evidence(profileid, twid)
        if not evidence:
            return False

        # loop through each evidence in this tw
        for evidence_details in evidence.values():
            evidence_details = json.loads(evidence_details)
            if evidence_details.get("ID") == evidence_id:
                # found an evidence that has a matching ID
                return evidence_details

    def is_detection_disabled(self, evidence_type: EvidenceType):
        """
        Function to check if detection is disabled in slips.yaml
        """
        return str(evidence_type) in self.disabled_detections

    def set_flow_causing_evidence(self, uids: list, evidence_id):
        self.r.hset(
            self.constants.FLOWS_CAUSING_EVIDENCE,
            evidence_id,
            json.dumps(uids),
        )

    def get_flows_causing_evidence(self, evidence_id) -> list:
        uids = self.r.hget(self.constants.FLOWS_CAUSING_EVIDENCE, evidence_id)
        return json.loads(uids) if uids else []

    def get_victim(self, profileid, attacker):
        saddr = profileid.split("_")[-1]
        if saddr not in attacker:
            return saddr
        # if the saddr is the attacker, then the victim should be
        # passed as a param to this function
        # there's no 1 victim in this case. for example in ARP scans,
        # the victim is the whole network
        return ""

    def set_blocked_ip(self, ip: str):
        self.r.zadd("blocked_ips", {ip: time.time()})

    def is_ip_blocked(self, ip: str) -> Optional[float]:
        ts = self.r.zscore("blocked_ips", ip)
        if ts is not None:
            return ts
        return None

    def del_blocked_ip(self, ip: str):
        # remove ip from the blocked_ips sorted set
        self.r.zrem("blocked_ips", ip)

    def get_tw_limits(self, profileid, twid: str) -> Tuple[float, float]:
        """
        returns the timewindow start and endtime
        """
        twid_start_time: float = self.get_tw_start_time(profileid, twid)
        if not twid_start_time:
            # the given tw is in the future
            # calc the start time of the twid manually based on the first
            # twid
            first_twid_start_time: float = self.get_first_flow_time()
            given_twid: int = int(twid.replace("timewindow", ""))
            # tws in slips start from 1.
            #     tw1   tw2   tw3   tw4
            # 0 ──────┬─────┬──────┬──────
            #         │     │      │
            #         2     4      6
            twid_start_time = first_twid_start_time + (
                self.width * (given_twid - 1)
            )

        twid_end_time: float = twid_start_time + self.width
        return twid_start_time, twid_end_time

    def get_ti(self, to_lookup: Union[Victim, Attacker]) -> Optional[str]:
        """
        if the victim/attacker's ip/domain was part of a ti feed,
        this function returns the name of the feed
        """
        if isinstance(to_lookup, Victim):
            ioc_type = to_lookup.ioc_type.name
        else:
            ioc_type = to_lookup.ioc_type.name

        cases = {
            IoCType.IP.name: self.is_blacklisted_ip,
            IoCType.DOMAIN.name: self.is_blacklisted_domain,
        }
        try:
            return cases[ioc_type](to_lookup.value)["source"]
        except (KeyError, TypeError):
            return

    def _get_more_info_about_evidence(self, evidence) -> Evidence:
        """
        sets the SNI, rDNS, TI, AS of the given evidence's attacker and
        victim IPs
        """
        for entity_type in ("victim", "attacker"):
            entity: Union[Attacker, Victim]
            entity = getattr(evidence, entity_type, None)
            if not entity:
                # some evidence may not have a victim
                continue

            if entity.ioc_type == IoCType.IP:
                ip_identification: Dict[str, str]
                ip_identification = self.get_ip_identification(entity.value)
                entity.AS = ip_identification.get("AS")
                entity.TI = ip_identification.get("TI")
                entity.rDNS = ip_identification.get("rDNS")
                entity.SNI = ip_identification.get("SNI")
                # queries resolved to that ip
                entity.queries = ip_identification.get("queries")

            elif entity.ioc_type == IoCType.DOMAIN:
                domain_info: Dict[str, str]
                domain_info = self.get_domain_data(entity.value)
                if not domain_info:
                    continue

                entity.CNAME = domain_info.get("CNAME", [])
                entity.DNS_resolution = domain_info.get("IPs", [])
                entity.TI = domain_info.get("threatintelligence", {}).get(
                    "source"
                )
                # if any of the domain's ips have an asn, set it here to
                # check if it's whitelisted later
                for ip in entity.DNS_resolution:
                    entity.AS = self.get_asn_info(ip)
                    break

            setattr(evidence, entity_type, entity)
        return evidence

    def set_evidence(self, evidence: Evidence):
        """
        Set the evidence for this Profile and Timewindow.
        :param evidence: an Evidence obj (defined in
        slips_files/core/structures/evidence.py) with all the
        evidence details,
        """
        # create the profile if it doesn't exist
        self.add_profile(str(evidence.profile), evidence.timestamp)
        # normalize confidence, should range from 0 to 1
        evidence.confidence = min(evidence.confidence, 1)

        # Ignore evidence if it's disabled in the configuration file
        if self.is_detection_disabled(evidence.evidence_type):
            return False

        self.set_flow_causing_evidence(evidence.uid, evidence.id)
        evidence = self._get_more_info_about_evidence(evidence)

        evidence_to_send: dict = utils.to_dict(evidence)
        evidence_to_send: str = json.dumps(evidence_to_send)

        evidence_hash = f"{evidence.profile}_{evidence.timewindow}_evidence"
        # This is done to ignore repetition.
        evidence_exists: Optional[dict] = self.r.hget(
            evidence_hash, evidence.id
        )

        # note that publishing HAS TO be done after adding the evidence
        # to the db
        # whitelisted evidence are deleted from the db, so we need to check
        # that we're not re-adding a deleted evidence
        if (not evidence_exists) and (
            not self.is_whitelisted_evidence(evidence.id)
        ):
            self.r.hset(evidence_hash, evidence.id, evidence_to_send)
            self.r.incr(self.constants.NUMBER_OF_EVIDENCE)
            self.publish(self.channels.EVIDENCE_ADDED, evidence_to_send)
            return True

        return False

    def set_alert(self, alert: Alert):
        self.set_evidence_causing_alert(alert)
        # reset the accumulated threat level now that an alert is generated
        self._set_accumulated_threat_level(alert, 0)
        self.mark_profile_as_malicious(alert.profile)
        self.publish(self.channels.NEW_ALERT, json.dumps(alert_to_dict(alert)))

    def init_evidence_number(self):
        """used when the db starts to initialize number of
        evidence generated by slips"""
        self.r.set(self.constants.NUMBER_OF_EVIDENCE, 0)

    def get_evidence_number(self):
        return self.r.get(self.constants.NUMBER_OF_EVIDENCE)

    def mark_evidence_as_processed(self, evidence_id: str):
        """
        If an evidence was processed by the evidenceprocess, mark it in the db
        """
        self.r.sadd(self.constants.PROCESSED_EVIDENCE, evidence_id)

    def is_evidence_processed(self, evidence_id: str) -> bool:
        return self.r.sismember(self.constants.PROCESSED_EVIDENCE, evidence_id)

    def delete_evidence(self, profileid, twid, evidence_id: str):
        """
        Deletes an evidence from the database
        """
        # this is only called by evidencehandler,
        # which means that any evidence passed to this function
        # can never be a part of a past alert
        self.r.hdel(f"{profileid}_{twid}_evidence", evidence_id)
        self.r.decr(self.constants.NUMBER_OF_EVIDENCE)

    def cache_whitelisted_evidence_id(self, evidence_id: str):
        """
        Keep track of whitelisted evidence IDs to avoid showing them in
        alerts later
        """
        # without this function, slips gets the stored evidence id from the db,
        # before deleteEvidence is called, so we need to keep track of
        # whitelisted evidence ids
        self.r.sadd(self.constants.WHITELISTED_EVIDENCE, evidence_id)

    def is_whitelisted_evidence(self, evidence_id):
        """
        Check if we have the evidence ID as whitelisted in the db to
        avoid showing it in alerts
        """
        return self.r.sismember(
            self.constants.WHITELISTED_EVIDENCE, evidence_id
        )

    def remove_whitelisted_evidence(self, all_evidence: dict) -> dict:
        """
        param all_evidence serialized json dict
        returns a dict
        """
        # remove whitelisted evidence from the given evidence
        # all_evidence = json.loads(all_evidence)
        tw_evidence = {}
        for evidence_id, evidence in all_evidence.items():
            if self.is_whitelisted_evidence(evidence_id):
                continue
            tw_evidence[evidence_id] = evidence
        return tw_evidence

    def get_profileid_twid_alerts(
        self, profileid, twid
    ) -> Dict[str, List[str]]:
        """
        The format for the returned dict is
            {<alert_uuid>: [ev_uuid1, ev_uuid2, ev_uuid3]}
        """
        alerts: str = self.r.hget(f"{profileid}_{twid}", "alerts")
        if not alerts:
            return {}
        alerts: dict = json.loads(alerts)
        return alerts

    def get_twid_evidence(self, profileid: str, twid: str) -> Dict[str, dict]:
        """Get the evidence for this TW for this Profile"""
        evidence: Dict[str, dict] = self.r.hgetall(
            f"{profileid}_{twid}_evidence"
        )
        if evidence:
            evidence: Dict[str, dict] = self.remove_whitelisted_evidence(
                evidence
            )
            return evidence

        return {}

    def set_max_threat_level(self, profileid: str, threat_level: str):
        self.r.hset(profileid, "max_threat_level", threat_level)

    def get_accumulated_threat_level(self, profileid: str, twid: str) -> float:
        """
        returns the accumulated_threat_lvl or 0 if it's not there
        """
        accumulated_threat_lvl = self.r.zscore(
            self.constants.ACCUMULATED_THREAT_LEVELS, f"{profileid}_{twid}"
        )
        return accumulated_threat_lvl or 0

    def update_accumulated_threat_level(
        self, profileid: str, twid: str, update_val: float
    ):
        """
        increments or decrements the accumulated threat level of the given
        profileid and
        twid by the given update_val
        :param update_val: can be +ve to increase the threat level or -ve
        to decrease
        """

        return self.r.zincrby(
            self.constants.ACCUMULATED_THREAT_LEVELS,
            update_val,
            f"{profileid}_{twid}",
        )

    def _set_accumulated_threat_level(
        self,
        alert: Alert,
        accumulated_threat_lvl: float,
    ):
        profile_twid = f"{alert.profile}_{alert.timewindow}"
        self.r.zadd(
            self.constants.ACCUMULATED_THREAT_LEVELS,
            {profile_twid: accumulated_threat_lvl},
        )

    def update_max_threat_level(
        self, profileid: str, threat_level: str
    ) -> float:
        """
        given the current threat level of a profileid, this method sets the
        max_threat_level value to the given val if that max is less than
        the given
        :returns: the numerical val of the max threat level
        """
        threat_level_float = utils.threat_levels[threat_level]

        old_max_threat_level: str = self.r.hget(profileid, "max_threat_level")

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
        1. Update the threat level of a certain profile
        2. Updates the profileid key and the IPsInfo key with the
         new score and confidence of this profile
        2. Stores the max threat level of the given profile as the score
        in IPsInfo
        :param threat_level: available options are 'low',
         'medium' 'critical' etc
        Do not call this function directy from this class, always call it
        from dbmanager.update_threat_level() to update the trustdb too:D
        """
        self.r.hset(profileid, "threat_level", threat_level)

        max_threat_lvl: float = self.update_max_threat_level(
            profileid, threat_level
        )

        ip = profileid.split("_")[-1]
        score_confidence = {"score": max_threat_lvl, "confidence": confidence}

        self.set_ip_info(ip, score_confidence)
