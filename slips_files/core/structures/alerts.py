# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Contains alert dataclass that is used in slips
Every alert should follow this format
"""

from dataclasses import dataclass, field
from uuid import uuid4
from typing import List


from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    ProfileID,
    TimeWindow,
    Evidence,
    ThreatLevel,
    dict_to_evidence,
)


def is_valid_correl_id(correl_id: List[str]) -> bool:
    return isinstance(correl_id, list) or not all(
        isinstance(uid, str) for uid in correl_id
    )


def normalize(value: float):
    """
    normalize a single value to a range between 0 and 1.
    :param value: numerical value to normalize
    :return: normalized value
    """
    # this corresponds to the most sensitive config_threshold 0.08333333333333333
    # 0.08333333333333333*3600/60 = 5
    # but the value from the config is 0.08 for simplicity, so the min value
    # would be 4.8 instead of 5 here, to avoid negative confidence values
    min_value = 4.8
    # this corresponds to config_threshold = 26*60/3600 = 0.43
    max_value = 26
    return (value - min_value) / (max_value - min_value)


@dataclass
class Alert:
    profile: ProfileID
    # this should have the fields start_Time and end_time set #TODO force it
    timewindow: TimeWindow
    # the last evidence that triggered this alert
    last_evidence: Evidence
    # accumulated threat level of all evidence in this alert
    accumulated_threat_level: float
    # every alert should have an ID according to the IDMEF format
    id: str = field(default_factory=lambda: str(uuid4()))
    # basically the last evidence that triggered the threshold for this alert
    # list of evidence acausing this alert
    correl_id: List[str] = field(
        default=None,
        metadata={"validate": lambda x: is_valid_correl_id(x)},
    )
    last_flow_datetime: str = ""
    threat_level: ThreatLevel = ThreatLevel.CRITICAL
    confidence: float = 0

    def __post_init__(self):
        if self.correl_id:
            if not is_valid_correl_id(self.correl_id):
                raise ValueError(
                    f"correl_id must be a list of strings. {self}"
                )
            else:
                # remove duplicate uids
                self.correl_id = list(set(self.correl_id))
        else:
            self.correl_id = []

        # timestamp of the flow causing the last evidence of this alert
        if not self.last_flow_datetime:
            last_flow_timestamp: str = self.last_evidence.timestamp
            self.last_flow_datetime = utils.convert_format(
                last_flow_timestamp, "iso"
            )

        if not self.confidence:
            # convert the accumulated threat level to  a confidence value
            # ranging from 0 to 1
            # this means that the more evidence slips generates the more
            # confident it is of the alert.
            # this value is needed by fides and the global p2p
            self.confidence: float = normalize(self.accumulated_threat_level)


def dict_to_alert(alert: dict) -> Alert:
    """
    Converts a dictionary to an Alert object.
    :param alert: Dictionary with the alert details.
    returns an instance of the alerts class.
    """
    return Alert(
        profile=(
            ProfileID(alert["profile"]["ip"]) if "profile" in alert else None
        ),
        timewindow=TimeWindow(
            alert["timewindow"]["number"],
            utils.convert_format(alert["timewindow"]["start_time"], "iso"),
            utils.convert_format(alert["timewindow"]["end_time"], "iso"),
        ),
        last_evidence=dict_to_evidence(alert["last_evidence"]),
        accumulated_threat_level=alert.get("accumulated_threat_level"),
        id=alert.get("id", ""),
        correl_id=alert.get("correl_id"),
        last_flow_datetime=utils.convert_format(
            alert["last_flow_datetime"], "iso"
        ),
        threat_level=ThreatLevel[alert["threat_level"].upper()],
        confidence=alert.get("confidence"),
    )


def alert_to_dict(alert: Alert) -> dict:
    """
    converts an Alert object to a dictionary.
    """
    evidence_to_send: dict = utils.to_dict(alert.last_evidence)
    return {
        "profile": {"ip": alert.profile.ip},
        "timewindow": {
            "number": alert.timewindow.number,
            "start_time": alert.timewindow.start_time,
            "end_time": alert.timewindow.end_time,
        },
        "last_evidence": evidence_to_send,
        "accumulated_threat_level": alert.accumulated_threat_level,
        "id": alert.id,
        "correl_id": alert.correl_id,
        "last_flow_datetime": alert.last_flow_datetime,
        "threat_level": alert.threat_level.name,
        "confidence": alert.confidence,
    }
