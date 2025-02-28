# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict

import pytest
from unittest.mock import MagicMock, call
import json
from unittest.mock import ANY
from slips_files.core.structures.evidence import (
    ProfileID,
    TimeWindow,
    Evidence,
    EvidenceType,
    Attacker,
    Direction,
    IoCType,
    ThreatLevel,
)
from tests.module_factory import ModuleFactory
from slips_files.core.structures.alerts import Alert


@pytest.mark.parametrize(
    "profileid, attacker, expected_victim",
    [
        # Testcase 1: Victim is not the attacker
        ("profile_10.0.0.1", "profile_10.0.0.2", "10.0.0.1"),
        # Testcase 2: Victim is the attacker
        ("profile_10.0.0.1", "profile_10.0.0.1", ""),
    ],
)
def test_get_victim(profileid, attacker, expected_victim):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    result = alert_handler.get_victim(profileid, attacker)
    assert result == expected_victim


@pytest.mark.parametrize(
    "all_evidence, expected_result, side_effect",
    [
        # Testcase 1: All evidence is whitelisted
        (
            {"ev1": "evidence1", "ev2": "evidence2", "ev3": "evidence3"},
            {},
            [True, True, True],
        ),
        # Testcase 2: No evidence is whitelisted
        (
            {"ev1": "evidence1", "ev2": "evidence2", "ev3": "evidence3"},
            {"ev1": "evidence1", "ev2": "evidence2", "ev3": "evidence3"},
            [False, False, False],
        ),
        # Testcase 3: Some evidence is whitelisted
        (
            {"ev1": "evidence1", "ev2": "evidence2", "ev3": "evidence3"},
            {"ev2": "evidence2", "ev3": "evidence3"},
            [True, False, False],
        ),
    ],
)
def test_remove_whitelisted_evidence(
    all_evidence, expected_result, side_effect
):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.sismember.side_effect = side_effect

    result = alert_handler.remove_whitelisted_evidence(all_evidence)

    assert result == expected_result


def test_mark_profile_as_malicious():
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()

    profile_id = "profile123"
    alert_handler.mark_profile_as_malicious(profile_id)

    alert_handler.r.sadd.assert_called_once_with(
        "malicious_profiles", profile_id
    )


@pytest.mark.parametrize(
    "profile_ip, twid, alert_id, evidence_ids, "
    "expected_old_alerts, expected_new_alerts",
    [
        # Testcase 1: No previous alerts
        (
            "192.168.1.20",
            1,
            "1234",
            ["ev1", "ev2", "ev3"],
            {},
            {"1234": ["ev3", "ev2", "ev1"]},
        ),
        # Testcase 2: Update previous alerts
        (
            "192.168.1.40",
            2,
            "5678",
            ["ev4", "ev5"],
            {"old_alert_id_8987": '["ev1", "ev2"]'},
            {
                "old_alert_id_8987": ["ev1", "ev2"],
                "5678": ["ev5", "ev4"],
            },
        ),
    ],
)
def test_set_evidence_causing_alert(
    profile_ip,
    twid,
    alert_id,
    evidence_ids,
    expected_old_alerts,
    expected_new_alerts,
):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.hget.return_value = json.dumps(expected_old_alerts)
    alert = Alert(
        id=alert_id,
        profile=ProfileID(profile_ip),
        timewindow=TimeWindow(
            twid,
            start_time="2024-10-04T18:46:50+03:00",
            end_time="2024-10-04T19:46:50+03:00",
        ),
        last_evidence=Evidence(
            evidence_type=EvidenceType.ARP_SCAN,
            description="ARP scan detected",
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value="192.168.1.20",
            ),
            threat_level=ThreatLevel.INFO,
            profile=ProfileID(profile_ip),
            timewindow=TimeWindow(twid),
            uid=[],
            timestamp="1728417813.8868346",
        ),
        accumulated_threat_level=30,
        last_flow_datetime="2024/10/04 15:45:30.123456+0000",
        correl_id=evidence_ids,
    )
    alert_handler.set_evidence_causing_alert(alert)

    alert_handler.r.incr.assert_called_once_with("number_of_alerts", 1)
    alert_handler.r.hset.assert_called_once_with(
        f"profile_{profile_ip}_timewindow{twid}", "alerts", ANY
    )
    called_args, _ = alert_handler.r.hset.call_args
    alerts_added: Dict[str, str] = json.loads(called_args[2])
    for alert_id, expected_evidence_list in expected_new_alerts.items():
        assert alert_id in alerts_added
        added_evidence_list = json.loads(alerts_added[alert_id])
        assert sorted(expected_evidence_list) == sorted(added_evidence_list)


@pytest.mark.parametrize(
    "profile_ip, twid, accumulated_threat_lvl, expected_call",
    [
        # Testcase 1: Set accumulated threat level
        ("192.168.1.9", 1, 10.5, {"profile_192.168.1.9_timewindow1": 10.5}),
        # Testcase 2: Set accumulated threat level with a different value
        ("192.168.1.3", 2, 5.0, {"profile_192.168.1.3_timewindow2": 5.0}),
        # Testcase 3: Set accumulated threat level to 0
        ("192.168.1.8", 3, 0.0, {"profile_192.168.1.8_timewindow3": 0.0}),
    ],
)
def test_set_accumulated_threat_level(
    profile_ip, twid, accumulated_threat_lvl, expected_call
):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert = Alert(
        profile=ProfileID(profile_ip),
        timewindow=TimeWindow(
            twid,
            start_time="2024-10-04T18:46:50+03:00",
            end_time="2024-10-04T19:46:50+03:00",
        ),
        last_evidence=Evidence(
            evidence_type=EvidenceType.ARP_SCAN,
            description="ARP scan detected",
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value="192.168.1.20",
            ),
            threat_level=ThreatLevel.INFO,
            profile=ProfileID(profile_ip),
            timewindow=TimeWindow(twid),
            uid=[],
            timestamp="1728417813.8868346",
        ),
        accumulated_threat_level=30,
        last_flow_datetime="2024/10/04 15:45:30.123456+0000",
    )
    alert_handler._set_accumulated_threat_level(alert, accumulated_threat_lvl)

    alert_handler.r.zadd.assert_called_once_with(
        "accumulated_threat_levels", expected_call
    )


@pytest.mark.parametrize(
    "profileid, twid, update_val, expected_call",
    [
        # Testcase 1: Increment accumulated threat level
        (
            "profile1",
            "twid1",
            1.2,
            ("accumulated_threat_levels", 1.2, "profile1_twid1"),
        ),
        # Testcase 2: Decrement accumulated threat level
        (
            "profile2",
            "twid2",
            -0.5,
            ("accumulated_threat_levels", -0.5, "profile2_twid2"),
        ),
    ],
)
def test_update_accumulated_threat_level(
    profileid, twid, update_val, expected_call
):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()

    alert_handler.update_accumulated_threat_level(profileid, twid, update_val)

    alert_handler.r.zincrby.assert_called_once_with(*expected_call)


def test_delete_evidence():
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()

    profileid = "profile123"
    twid = "twid456"
    evidence_id = "evidence_123"

    alert_handler.delete_evidence(profileid, twid, evidence_id)

    alert_handler.r.hdel.assert_called_once_with(
        f"{profileid}_{twid}_evidence", evidence_id
    )


@pytest.mark.parametrize(
    "evidence_id, expected_calls",
    [
        # Testcase 1: Evidence ID is cached
        ("evidence_123", [call("whitelisted_evidence", "evidence_123")]),
        # Testcase 2: Evidence ID is already cached
        ("evidence_456", [call("whitelisted_evidence", "evidence_456")]),
    ],
)
def test_cache_whitelisted_evidence_id(evidence_id, expected_calls):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()

    alert_handler.cache_whitelisted_evidence_id(evidence_id)

    assert alert_handler.r.sadd.call_count == len(expected_calls)
    alert_handler.r.sadd.assert_has_calls(expected_calls)


@pytest.mark.parametrize(
    "profileid, max_threat_lvl, confidence, expected_ip_info",
    [
        # Testcase 1: No previous IP info
        ("profile1_10.0.0.1", 0.8, 0.9, {"score": 0.8, "confidence": 0.9}),
        # Testcase 2: Update existing IP info
        ("profile2_10.0.0.2", 0.6, 0.7, {"score": 0.6, "confidence": 0.7}),
    ],
)
def test_update_ips_info(
    profileid, max_threat_lvl, confidence, expected_ip_info
):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.rcache = MagicMock()
    alert_handler.get_ip_info = MagicMock(
        return_value={"score": 0.5, "confidence": 0.6}
    )

    alert_handler.update_ips_info(profileid, max_threat_lvl, confidence)

    alert_handler.rcache.hset.assert_called_once_with(
        "IPsInfo", profileid.split("_")[-1], json.dumps(expected_ip_info)
    )


@pytest.mark.parametrize(
    "initial_value, expected_value",
    [
        # Testcase 1: No previous value
        (None, 0),
        # Testcase 2: Previous value exists
        ("10", 0),
    ],
)
def test_init_evidence_number(initial_value, expected_value):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.get.return_value = initial_value

    alert_handler.init_evidence_number()

    alert_handler.r.set.assert_called_once_with(
        "number_of_evidence", expected_value
    )


@pytest.mark.parametrize(
    "returned_value, expected_result",
    [
        # Testcase 1: Evidence number exists
        ("100", "100"),
        # Testcase 2: Evidence number is None
        (None, None),
    ],
)
def test_get_evidence_number(returned_value, expected_result):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.get.return_value = returned_value

    result = alert_handler.get_evidence_number()

    alert_handler.r.get.assert_called_once_with("number_of_evidence")
    assert result == expected_result


@pytest.mark.parametrize(
    "profileid, threat_level, expected_call",
    [
        # Testcase 1: Set max threat level
        ("profile1", "critical", ("profile1", "max_threat_level", "critical")),
        # Testcase 2: Update max threat level
        ("profile2", "medium", ("profile2", "max_threat_level", "medium")),
    ],
)
def test_set_max_threat_level(profileid, threat_level, expected_call):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()

    alert_handler.set_max_threat_level(profileid, threat_level)

    alert_handler.r.hset.assert_called_once_with(*expected_call)


@pytest.mark.parametrize(
    "profileid, twid, expected_result",
    [
        # Testcase 1: Accumulated threat level is present
        ("profile1", "twid1", 2.5),
        # Testcase 2: Accumulated threat level is not present
        ("profile2", "twid2", 0.0),
    ],
)
def test_get_accumulated_threat_level(profileid, twid, expected_result):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.zscore.return_value = expected_result

    result = alert_handler.get_accumulated_threat_level(profileid, twid)

    assert result == expected_result
    alert_handler.r.zscore.assert_called_once_with(
        "accumulated_threat_levels", f"{profileid}_{twid}"
    )


@pytest.mark.parametrize(
    "evidence_id, sismember_return_value, expected_result",
    [
        # Testcase 1: Evidence ID is whitelisted
        ("evidence_123", True, True),
        # Testcase 2: Evidence ID is not whitelisted
        ("evidence_456", False, False),
    ],
)
def test_is_whitelisted_evidence(
    evidence_id, sismember_return_value, expected_result
):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.sismember.return_value = sismember_return_value

    result = alert_handler.is_whitelisted_evidence(evidence_id)

    assert result == expected_result
    alert_handler.r.sismember.assert_called_once_with(
        "whitelisted_evidence", evidence_id
    )


@pytest.mark.parametrize(
    "profileid, twid, stored_alerts, expected_result",
    [
        # Testcase 1: Alerts exist for the given profileid and twid
        (
            "profile123",
            "twid456",
            '{"profile123_twid456_alert1": ["ev1", "ev2", "ev3"], '
            '"profile123_twid456_alert2": ["ev4", "ev5"]}',
            {
                "profile123_twid456_alert1": ["ev1", "ev2", "ev3"],
                "profile123_twid456_alert2": ["ev4", "ev5"],
            },
        ),
        # Testcase 2: No alerts exist for the given profileid and twid
        ("profile123", "twid456", None, {}),
        # Testcase 3: Empty alerts string
        ("profile123", "twid456", "", {}),
    ],
)
def test_get_profileid_twid_alerts(
    profileid, twid, stored_alerts, expected_result
):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.hget.return_value = stored_alerts

    result = alert_handler.get_profileid_twid_alerts(profileid, twid)
    assert result == expected_result
    alert_handler.r.hget.assert_called_once_with(
        f"{profileid}_{twid}", "alerts"
    )


@pytest.mark.parametrize(
    "evidence_id, sismember_return, expected_result",
    [
        # Testcase 1: Evidence is marked as processed
        ("evidence1", True, True),
        # Testcase 2: Evidence is not marked as processed
        ("evidence2", False, False),
    ],
)
def test_is_evidence_processed(evidence_id, sismember_return, expected_result):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.sismember.return_value = sismember_return

    result = alert_handler.is_evidence_processed(evidence_id)

    alert_handler.r.sismember.assert_called_once_with(
        "processed_evidence", evidence_id
    )
    assert result == expected_result


@pytest.mark.parametrize(
    "uids, evidence_ID",
    [
        # Testcase 1: Multiple flow IDs
        (["flow1", "flow2", "flow3"], "evidence1"),
        # Testcase 2: Single flow ID
        (["flow1"], "evidence2"),
        # Testcase 3: Empty flow ID list
        ([], "evidence3"),
    ],
)
def test_set_flow_causing_evidence(uids, evidence_ID):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()

    alert_handler.set_flow_causing_evidence(uids, evidence_ID)

    alert_handler.r.hset.assert_called_once_with(
        "flows_causing_evidence", evidence_ID, json.dumps(uids)
    )


@pytest.mark.parametrize(
    "evidence_ID, returned_uids, expected_result",
    [
        # Testcase 1: Flows causing evidence exist
        (
            "evidence1",
            '["flow1", "flow2", "flow3"]',
            ["flow1", "flow2", "flow3"],
        ),
        # Testcase 2: No flows causing evidence
        ("evidence2", None, []),
    ],
)
def test_get_flows_causing_evidence(
    evidence_ID, returned_uids, expected_result
):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.hget.return_value = returned_uids

    result = alert_handler.get_flows_causing_evidence(evidence_ID)

    alert_handler.r.hget.assert_called_once_with(
        "flows_causing_evidence", evidence_ID
    )
    assert result == expected_result


@pytest.mark.parametrize(
    "profileid, twid, alert_id, expected_alert",
    [
        # Testcase 1: Alert exists in the database
        ("profile1", "twid1", "profile1_twid1_alert1", ["ev1", "ev2", "ev3"]),
        # Testcase 2: No alert exists in the database
        ("profile2", "twid2", "profile2_twid2_alert2", False),
    ],
)
def test_get_evidence_causing_alert(profileid, twid, alert_id, expected_alert):
    alert_handler = ModuleFactory().create_alert_handler_obj()
    alert_handler.r = MagicMock()
    alert_handler.r.hget.return_value = (
        '{"profile1_twid1_alert1": ["ev1", "ev2", "ev3"]}'
    )

    result = alert_handler.get_evidence_causing_alert(
        profileid, twid, alert_id
    )

    alert_handler.r.hget.assert_called_once_with(
        f"{profileid}_{twid}", "alerts"
    )
    assert result == expected_alert
