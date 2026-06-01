# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/flow_alerts/login.py"""

import json
from dataclasses import asdict

import pytest

from slips_files.core.flows.zeek import Login
from slips_files.core.structures.evidence import (
    Direction,
    EvidenceType,
    IoCType,
    ThreatLevel,
    dict_to_evidence,
)
from slips_files.common.slips_utils import utils
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "success, confused, expected_status",
    [
        (True, False, "successful"),
        (False, True, "confused"),
        (False, False, "failed"),
    ],
)
def test_get_login_status(success: bool, confused: bool, expected_status: str):
    """Test login status formatting."""
    login = ModuleFactory().create_login_analyzer_obj()
    flow = Login(
        starttime="1774173495.641272",
        uid="CpUMTT6FJDsiSlCre",
        saddr="147.32.80.40",
        sport="40422",
        daddr="147.32.80.37",
        dport="23",
        proto="telnet",
        success=success,
        confused=confused,
        user="root",
        client_user="",
        password="",
    )

    assert login.get_login_status(flow) == expected_status


def test_analyze_sets_info_evidence_with_attacker_and_victim():
    """Test new_login messages create info evidence."""
    login = ModuleFactory().create_login_analyzer_obj()
    flow = Login(
        starttime="1774173495.641272",
        uid="CpUMTT6FJDsiSlCre",
        saddr="147.32.80.40",
        sport="40422",
        daddr="147.32.80.37",
        dport="23",
        proto="telnet",
        success=True,
        confused=False,
        user="root",
        client_user="",
        password="",
    )
    msg = {
        "channel": "new_login",
        "data": json.dumps(
            {
                "profileid": "profile_147.32.80.40",
                "twid": "timewindow1",
                "flow": asdict(flow),
            }
        ),
    }

    assert login.analyze(msg) is True
    evidence = login.db.set_evidence.call_args[0][0]
    assert evidence.evidence_type == EvidenceType.LOGIN
    assert evidence.threat_level == ThreatLevel.INFO
    assert evidence.attacker.direction == Direction.DST
    assert evidence.attacker.ioc_type == IoCType.IP
    assert evidence.attacker.value == "147.32.80.37"
    assert evidence.victim.direction == Direction.SRC
    assert evidence.victim.ioc_type == IoCType.IP
    assert evidence.victim.value == "147.32.80.40"
    assert evidence.profile.ip == "147.32.80.40"
    assert evidence.uid == ["CpUMTT6FJDsiSlCre"]

    serialized_evidence = utils.to_dict(evidence)
    restored_evidence = dict_to_evidence(serialized_evidence)
    assert restored_evidence.attacker.value == "147.32.80.37"
    assert restored_evidence.victim.value == "147.32.80.40"
