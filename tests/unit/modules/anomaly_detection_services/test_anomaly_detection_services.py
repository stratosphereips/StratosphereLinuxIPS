"""Verify module wiring, identity context and ordinary evidence handling."""

import json
from unittest.mock import patch

import pytest

from slips_files.core.structures.evidence import (
    EvidenceType,
    Method,
    ThreatLevel,
)
from tests.module_factory import ModuleFactory
from tests.unit.modules.anomaly_detection_services.test_models import flow


def fit(module: object, **changes: object) -> None:
    """Pass normal messages through the real module adapter.

    Parameters:
        module: Test module with mocked external dependencies.
        changes: Captured identity or protocol overrides.
    """
    for day in range(3):
        for index in range(20):
            module.handle_flow(
                {
                    "twid": "timewindow1",
                    "flow": flow(day, uid=f"normal-{day}-{index}", **changes),
                }
            )


@pytest.mark.parametrize("accepted", [True, False])
def test_new_client_evidence_uses_original_flow(accepted: bool) -> None:
    """Keep the client as the evidence profile and link its original UID.

    Parameters:
        accepted: Whether the unusual client established a connection.
    """
    module = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    fit(module)
    module.handle_flow(
        {
            "twid": "timewindow7",
            "flow": flow(
                4,
                uid="new-b",
                interface="default",
                saddr="192.0.2.11",
                state="SF" if accepted else "S0",
                history="ShADadFf" if accepted else "S",
                dpkts=10 if accepted else 0,
            ),
        }
    )
    evidence = module.db.set_evidence.call_args.args[0]
    assert evidence.evidence_type is EvidenceType.ANOMALOUS_FLOW
    assert evidence.method is Method.STATISTICAL
    assert evidence.threat_level is ThreatLevel.LOW
    assert evidence.profile.ip == "192.0.2.11"
    assert evidence.attacker.value == "192.0.2.11"
    assert evidence.victim.value == "192.0.2.20"
    assert evidence.dst_port == 22
    assert evidence.interface == "eth0"
    assert evidence.timewindow.number == 7
    assert evidence.uid == ["new-b"]
    assert "retained baseline" in evidence.description
    assert (
        "answered connection" if accepted else "connection attempt"
    ) in evidence.description


def test_mac_identity_survives_addresses_but_not_device_replacement() -> None:
    """Keep aliases together while distinguishing a reused IP with another MAC."""
    module = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    fit(module, smac="02:00:00:00:00:10", dmac="02:00:00:00:00:20")
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(
                4,
                uid="aliases",
                saddr="192.0.2.11",
                daddr="192.0.2.21",
                smac="02:00:00:00:00:10",
                dmac="02:00:00:00:00:20",
            ),
        }
    )
    assert len(module.detector.services) == 1
    module.db.set_evidence.assert_not_called()
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(
                4,
                uid="replacement",
                smac="02:00:00:00:00:10",
                dmac="02:00:00:00:00:99",
            ),
        }
    )
    assert len(module.detector.services) == 2
    module.db.set_evidence.assert_not_called()


def test_roaming_keeps_networks_separate() -> None:
    """A second router with the same private subnet has its own baseline."""
    module = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    fit(module)
    module.db.get_network_state.return_value = {
        "gateway_mac": "02:00:00:00:00:99",
        "local_network": "192.0.2.0/24",
        "changed_at": 0,
    }
    module._networks.clear()
    module.handle_flow(
        {
            "twid": "timewindow1",
            "flow": flow(4, uid="other-network", saddr="192.0.2.11"),
        }
    )
    assert len(module.detector.services) == 2
    module.db.set_evidence.assert_not_called()


def test_old_completion_uses_recorded_network_context() -> None:
    """Do not attribute a delayed connection record to the new Wi-Fi network."""
    module = ModuleFactory().create_service_anomaly_obj()
    old = {
        "gateway_mac": "02:00:00:00:00:01",
        "local_network": "192.0.2.0/24",
        "changed_at": 0,
    }
    module.db.get_network_state.return_value = {
        "gateway_mac": "02:00:00:00:00:02",
        "local_network": "192.0.2.0/24",
        "changed_at": flow(10)["starttime"],
        "history": [old],
    }
    from modules.anomaly_detection_services.models import Observation

    scope, state, current = module._network(Observation.from_zeek(flow()))
    assert "02:00:00:00:00:01" in scope
    assert state is old
    assert not current


@pytest.mark.parametrize("ip", ["198.51.100.1", "198.51.100.2", "192.0.2.10"])
def test_gateway_mac_never_merges_hosts(ip: str) -> None:
    """Reject gateway hardware as proof of an endpoint's identity.

    Parameters:
        ip: Routed or local endpoint carrying the next-hop MAC.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    state = module.db.get_network_state.return_value
    assert (
        module._endpoint_identity(
            ip, state["gateway_mac"], "network", state, True
        )
        == f"ip:{ip}"
    )


@pytest.mark.parametrize(
    "changes", [{"daddr": "192.0.2.255"}, {"saddr": "192.0.2.0"}]
)
def test_directed_broadcasts_are_ignored(changes: dict) -> None:
    """Exclude subnet broadcast traffic before learning service models.

    Parameters:
        changes: Subnet network or broadcast endpoint.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    module.handle_flow({"twid": "timewindow1", "flow": flow(**changes)})
    assert not module.detector.services


def test_main_subscribes_drains_and_ignores_malformed_records() -> None:
    """Wire the module through new_flow without bypassing message validation."""
    module = ModuleFactory().create_service_anomaly_obj()
    module.subscribe_to_channels()
    module.db.subscribe.assert_called_once_with("new_flow")
    messages = [
        {"data": "{"},
        {"data": json.dumps([])},
        {"data": json.dumps({"flow": flow(), "twid": "bad"})},
        {"data": json.dumps({"flow": flow(), "twid": "timewindow1"})},
        None,
    ]
    with patch.object(module, "get_msg", side_effect=messages):
        module.main()
    assert len(module.detector.services) == 1
    module.db.set_evidence.assert_not_called()


@pytest.mark.parametrize("field", ["label", "ground_truth_label"])
def test_explicit_malicious_labels_cannot_fit_normal_clients(
    field: str,
) -> None:
    """Keep labeled attacks out of training while retaining anomaly detection.

    Parameters:
        field: Payload or original flow label containing the known verdict.
    """
    module = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    bad_flow = flow(uid="bad-training")
    payload = {"twid": "timewindow1", "flow": bad_flow}
    if field == "label":
        payload[field] = "Malicious"
    else:
        bad_flow[field] = "Malware"
    module.handle_flow(payload)
    assert next(iter(module.detector.services.values())).summary.count == 0
    fit(module)
    bad_flow.update(flow(4, uid="bad-client", saddr="192.0.2.11"))
    module.handle_flow(payload)
    module.db.set_evidence.assert_called_once()
    assert module.detector.client_count == 1


def test_duration_and_time_reasons_are_explained_in_one_evidence() -> None:
    """Combine dimensions into one finding instead of multiplying flow scores."""
    module = ModuleFactory().create_service_anomaly_obj()
    from modules.anomaly_detection_services.models import Observation

    module._emit(
        Observation.from_zeek(flow()),
        "timewindow1",
        [
            {
                "kind": "unusual_time",
                "baseline": "client",
                "local_time": "2026-01-05T03:00:00+00:00",
                "observed_days": 20,
            },
            {
                "kind": "unusual_duration",
                "baseline": "client",
                "direction": "long",
                "seconds": 3600,
                "usual_low_seconds": 90,
                "usual_high_seconds": 150,
                "samples": 80,
            },
        ],
    )
    evidence = module.db.set_evidence.call_args.args[0]
    assert (
        "03:00" in evidence.description and "3600.000s" in evidence.description
    )
    assert evidence.confidence <= 0.65
    module.db.set_evidence.assert_called_once()
