"""
Contains alert dataclass that is used in slips
Every alert should follow this format
"""

from dataclasses import dataclass, field
from uuid import uuid4
from typing import List


from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import (
    ProfileID,
    TimeWindow,
)


def is_valid_correl_id(correl_id: List[str]) -> bool:
    return isinstance(correl_id, list) or not all(
        isinstance(uid, str) for uid in correl_id
    )


@dataclass
class Alert:
    profileid: ProfileID
    timewindow: TimeWindow
    start_time: str
    end_time: str
    # every alert should have an ID according to the IDMEF format
    id: str = field(default_factory=lambda: str(uuid4()))
    # list of evidence acausing this alert
    correl_id: List[str] = field(
        default=None,
        metadata={
            "validate": lambda x: (
                all(utils.is_valid_uuid4(uuid_) for uuid_ in x) if x else True
            )
        },
    )

    def __post_init__(self):
        if not is_valid_correl_id(self.correl_id):
            raise ValueError(f"uid must be a list of strings .. {self}")
        else:
            # remove duplicate uids
            self.correl_id = list(set(self.correl_id))


def dict_to_alert(alert: dict) -> Alert:
    """
    Converts a dictionary to an Alert object.
    :param alert: Dictionary with the alert details.
    returns an instance of the alerts class.
    """
    return Alert(
        profileid=(
            ProfileID(alert["profile"]["ip"]) if "profile" in alert else None
        ),
        timewindow=TimeWindow(alert["timewindow"]["number"]),
        start_time=alert.get("start_time"),
        end_time=alert.get("end_time"),
        id=alert.get("id", ""),
        correl_id=alert.get("correl_id"),
    )
