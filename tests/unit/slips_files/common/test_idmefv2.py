from unittest.mock import Mock, patch

import pytest

from slips_files.common.idmefv2 import IDMEFv2
from slips_files.core.structures.evidence import (
    Direction,
    EvidenceType,
    IoCType,
    Proto,
    ThreatLevel,
)
from tests.module_factory import ModuleFactory


class MessageStub(dict):
    """Minimal dict-like IDMEF message for converter unit tests."""

    def validate(self) -> None:
        """Skip external schema validation.

        Return:
            None.
        """
        return None


@pytest.mark.parametrize(
    "threat_level, expected_priority",
    [
        (ThreatLevel.INFO, "Info"),
        (ThreatLevel.LOW, "Low"),
        (ThreatLevel.MEDIUM, "Medium"),
        (ThreatLevel.HIGH, "High"),
        (ThreatLevel.CRITICAL, "High"),
    ],
)
def test_convert_threat_level_to_idmefv2_priority(
    threat_level: ThreatLevel, expected_priority: str
) -> None:
    """Verify Slips threat levels map to IDMEFv2 priority values.

    Parameters:
        threat_level: Slips threat level to convert.
        expected_priority: Expected IDMEFv2 priority string.

    Return:
        None.
    """
    module_factory = ModuleFactory()
    idmefv2 = IDMEFv2(module_factory.logger, Mock())

    assert (
        idmefv2.convert_threat_level_to_idmefv2_priority(threat_level)
        == expected_priority
    )


def test_convert_to_idmef_event_uses_priority_field() -> None:
    """Verify converted IDMEFv2 events use Priority instead of Severity.

    Return:
        None.
    """
    module_factory = ModuleFactory()
    db = Mock()
    db.is_running_non_stop.return_value = False
    idmefv2 = IDMEFv2(module_factory.logger, db)
    attacker = module_factory.create_attacker_obj(
        value="192.168.1.1", direction=Direction.SRC, ioc_type=IoCType.IP
    )
    victim = module_factory.create_victim_obj(
        value="192.168.1.2", direction=Direction.DST, ioc_type=IoCType.IP
    )
    evidence = module_factory.create_evidence_obj(
        evidence_type=EvidenceType.ARP_SCAN,
        description="ARP scan detected",
        attacker=attacker,
        threat_level=ThreatLevel.MEDIUM,
        victim=victim,
        profile=module_factory.create_profileid_obj(ip="192.168.1.1"),
        timewindow=module_factory.create_timewindow_obj(number=1),
        uid=["uid1"],
        timestamp="2023/10/26 10:10:10.000000+0000",
        proto=Proto.TCP,
        dst_port=80,
        id="d4afbe1a-1cb9-4db4-9fac-74f2da6f5f34",
        confidence=0.8,
    )

    with patch("slips_files.common.idmefv2.Message", MessageStub):
        event = idmefv2.convert_to_idmef_event(evidence)

    assert event["Priority"] == "Medium"
    assert "Severity" not in event
