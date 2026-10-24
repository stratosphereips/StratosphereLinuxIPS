"""Validate protocol eligibility and module settings."""

from datetime import datetime, timezone
from typing import Any

import pytest

from modules.anomaly_detection_services.models import Observation, Settings
from tests.module_factory import ModuleFactory


def flow(day: int = 0, hour: int = 10, **changes: Any) -> dict:
    """Build an original-direction Zeek connection on a known Monday.

    Parameters:
        day: Days after Monday 5 January 2026.
        hour: UTC hour of the connection.
        changes: Field overrides, including a unique UID when needed.

    Returns:
        Connection fields matching a new_flow payload.
    """
    timestamp = (
        datetime(2026, 1, 5, tzinfo=timezone.utc).timestamp()
        + day * 86400
        + hour * 3600
    )
    return {
        "type_": "conn",
        "uid": f"flow-{day}-{hour}",
        "saddr": "192.0.2.10",
        "daddr": "192.0.2.20",
        "sport": 40000,
        "dport": 22,
        "proto": "tcp",
        "dur": 120,
        "starttime": timestamp,
        "state": "SF",
        "history": "ShADadFf",
        "spkts": 10,
        "dpkts": 10,
        "interface": "eth0",
        **changes,
    }


@pytest.mark.parametrize(
    "changes,eligible,reply,accepted,complete",
    [
        ({}, True, True, True, True),
        ({"state": "S1", "history": "ShA"}, True, True, True, False),
        (
            {"state": "S0", "history": "S", "dpkts": 0},
            True,
            False,
            False,
            False,
        ),
        ({"state": "REJ", "history": "Sr"}, True, False, False, False),
        ({"state": "RSTR", "history": "Sr"}, True, False, False, False),
        ({"state": "RSTR", "history": "ShAr"}, True, True, True, False),
        ({"state": "OTH", "history": "Dd"}, False, False, False, False),
        ({"proto": "udp", "history": "Dd"}, True, True, True, False),
        ({"proto": "udp", "dpkts": 0}, True, False, False, False),
        ({"proto": "icmp"}, False, False, False, False),
        ({"daddr": "224.0.0.251"}, False, False, False, False),
        ({"daddr": "255.255.255.255"}, False, False, False, False),
        ({"daddr": "ff02::1", "saddr": "fe80::1"}, False, False, False, False),
        (
            {"daddr": "2001:db8::20", "saddr": "2001:db8::10"},
            True,
            True,
            True,
            True,
        ),
        ({"dmac": "ff:ff:ff:ff:ff:ff"}, False, False, False, False),
        ({"smac": "01:00:5e:00:00:01"}, False, False, False, False),
        ({"dport": 0}, False, False, False, False),
        ({"dur": "nan"}, False, False, False, False),
        ({"starttime": 1e30}, False, False, False, False),
        ({"starttime": -1}, False, False, False, False),
        ({"saddr": "bad"}, False, False, False, False),
        ({"type_": "ssl"}, False, False, False, False),
        ({"flow_source": "suricata"}, False, False, False, False),
    ],
)
def test_observation_eligibility(
    changes: dict, eligible: bool, reply: bool, accepted: bool, complete: bool
) -> None:
    """Distinguish observed services, attempts and measurable durations.

    Parameters:
        changes: Protocol, state or malformed-field case.
        eligible: Whether the flow has an unambiguous service direction.
        reply: Whether it proves a responding service.
        accepted: Whether it can train a normal client relationship.
        complete: Whether its duration can be compared safely.
    """
    _module = ModuleFactory().create_service_anomaly_obj()
    observation = Observation.from_zeek(flow(**changes))
    assert (observation is not None) is eligible
    if observation:
        assert (
            observation.service_reply,
            observation.accepted,
            observation.complete,
        ) == (reply, accepted, complete)


@pytest.mark.parametrize(
    "name,value",
    [
        ("mode", "wrong"),
        ("timezone", "Not/A_Timezone"),
        ("max_services", 0),
        ("max_clients", 99999999),
        ("history_days", 9999),
        ("training_hours", -1),
        ("training_hours", "nan"),
        ("duration_min_samples", 9999),
        ("adapt_known_clients", "false"),
        ("max_clients", 1.5),
        ("duration_ratio", 0),
        ("time_probability_threshold", 0),
        ("time_min_concentration", -0.1),
        ("time_min_concentration", 1.1),
    ],
)
def test_invalid_configuration_is_rejected(name: str, value: object) -> None:
    """Reject unsafe configuration before opening model files.

    Parameters:
        name: Configured setting name.
        value: Invalid setting value.
    """
    factory = ModuleFactory()
    with pytest.raises((ValueError, KeyError)):
        factory.create_service_anomaly_obj(**{name: value})


def test_default_configuration_round_trip() -> None:
    """Keep runtime defaults consistent with the shipped YAML section."""
    module = ModuleFactory().create_service_anomaly_obj()
    import yaml
    from pathlib import Path

    data = yaml.safe_load(Path("config/slips.yaml").read_text())[module.name]
    module.conf.read_configuration.side_effect = (
        lambda section, key, default: data.get(key, default)
    )
    assert Settings.from_config(module.conf) == module.settings
