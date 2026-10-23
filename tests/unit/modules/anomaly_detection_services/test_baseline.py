"""Exercise learning, uncertainty, bounded state and anomaly explanations."""

from modules.anomaly_detection_services.models import Observation
from copy import deepcopy
from tests.module_factory import ModuleFactory
from tests.unit.modules.anomaly_detection_services.test_models import flow

import pytest


def train(
    module: object, days: int = 3, samples: int = 20, **changes: object
) -> None:
    """Train accepted connections over distinct days without external services.

    Parameters:
        module: Test module with a real detector.
        days: Number of distinct observation days.
        samples: Connections per day.
        changes: Flow overrides.
    """
    for day in range(days):
        for index in range(samples):
            observation = Observation.from_zeek(
                flow(day, uid=f"train-{day}-{index}", **changes)
            )
            assert (
                module.detector.process(observation, "service", "client-a")
                == []
            )


@pytest.mark.parametrize(
    "state,history,packets,accepted",
    [
        ("SF", "ShADadFf", 10, True),
        ("S0", "S", 0, False),
        ("REJ", "Sr", 1, False),
    ],
)
def test_new_client_to_trained_service(
    state: str, history: str, packets: int, accepted: bool
) -> None:
    """Detect new successful and failed clients without learning their attempts.

    Parameters:
        state: Zeek connection outcome.
        history: Observed handshake flags.
        packets: Responder packet count.
        accepted: Expected established-connection indication.
    """
    module = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    train(module)
    observation = Observation.from_zeek(
        flow(4, uid="new-b", state=state, history=history, dpkts=packets)
    )
    reasons = module.detector.process(observation, "service", "client-b")
    assert reasons == [
        {"kind": "new_client", "accepted": accepted, "known_clients": 1}
    ]
    assert "client-b" not in module.detector.services["service"].clients


def test_unanswered_and_rejected_ports_do_not_create_services() -> None:
    """A refusal or silent scan cannot establish an open service baseline."""
    module = ModuleFactory().create_service_anomaly_obj()
    for state in ("REJ", "S0"):
        observation = Observation.from_zeek(
            flow(uid=state, state=state, history="Sr", dpkts=1)
        )
        assert module.detector.process(observation, state, "client") == []
    assert not module.detector.services


def test_training_needs_distinct_days_and_ignores_older_flow_for_alerting() -> (
    None
):
    """One chatty afternoon and elapsed idle time do not establish a routine."""
    module = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    train(module, days=1, samples=100)
    observation = Observation.from_zeek(
        flow(20, uid="later", saddr="192.0.2.11")
    )
    assert module.detector.process(observation, "service", "b") == []
    assert not module.detector.services["service"].ready(
        observation.timestamp, module.settings
    )
    train(module, days=3, samples=2)
    old = Observation.from_zeek(flow(uid="old-completion"))
    assert module.detector.process(old, "service", "late-original") == []


@pytest.mark.parametrize("duration,direction", [(3600, "long"), (1, "short")])
def test_duration_anomaly_does_not_poison_training(
    duration: float, direction: str
) -> None:
    """Flag both duration tails while preserving the accepted baseline.

    Parameters:
        duration: Unusual completed-connection length.
        direction: Expected duration tail.
    """
    module = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    train(module)
    client = module.detector.services["service"].clients["client-a"]
    previous = deepcopy(client.to_dict())
    observation = Observation.from_zeek(flow(4, uid="duration", dur=duration))
    reasons = module.detector.process(observation, "service", "client-a")
    assert len(reasons) == 1
    assert reasons[0]["kind"] == "unusual_duration"
    assert reasons[0]["direction"] == direction
    assert client.count == previous["count"]
    assert client.durations == previous["durations"]
    assert client.activity == previous["activity"]


@pytest.mark.parametrize(
    "state,history,proto",
    [("S1", "ShA", "tcp"), ("REJ", "Sr", "tcp"), ("SF", "Dd", "udp")],
)
def test_incomplete_or_datagram_flows_do_not_train_session_duration(
    state: str, history: str, proto: str
) -> None:
    """Keep ambiguous completion and UDP timeout grouping out of durations.

    Parameters:
        state: Connection state.
        history: Observed direction flags.
        proto: Transport protocol.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    train(module, days=3, state=state, history=history, proto=proto)
    if "service" in module.detector.services:
        assert not module.detector.services["service"].summary.durations


def test_multimodal_training_duration_remains_normal() -> None:
    """Preserve legitimate short and long modes instead of trusting one mean."""
    module = ModuleFactory().create_service_anomaly_obj(
        mode="train", training_hours=24
    )
    train(module, dur=60)
    train(module, days=3, samples=10, dur=3600)
    # The second training pass needs independent UIDs.
    for index in range(20):
        observation = Observation.from_zeek(
            flow(4, uid=f"long-{index}", dur=3600)
        )
        module.detector.process(observation, "service", "client-a")
    module.settings.mode = "detect"
    for duration in (60, 3600):
        observation = Observation.from_zeek(
            flow(5, uid=f"normal-{duration}", dur=duration)
        )
        assert (
            module.detector.process(observation, "service", "client-a") == []
        )


@pytest.mark.parametrize("hour,expected", [(10, False), (3, True)])
def test_regular_schedule_supports_time_anomalies(
    hour: int, expected: bool
) -> None:
    """Learn a broad clock neighborhood with repeated support across weeks.

    Parameters:
        hour: New connection hour.
        expected: Whether the time lies outside the supported routine.
    """
    module = ModuleFactory().create_service_anomaly_obj(
        mode="train", min_training_connections=10
    )
    train(module, days=28, samples=1)
    module.settings.mode = "detect"
    observation = Observation.from_zeek(flow(28, hour, uid="time-check"))
    reasons = module.detector.process(observation, "service", "client-a")
    assert bool(reasons) is expected
    if expected:
        assert reasons[0]["kind"] == "unusual_time"
        assert reasons[0]["observed_days"] == 20


def test_midnight_wrap_and_irregular_humans() -> None:
    """Keep midnight continuous and refrain from policing a variable schedule."""
    module = ModuleFactory().create_service_anomaly_obj(mode="train")
    train(module, days=28, samples=1, hour=23)
    module.settings.mode = "detect"
    client = module.detector.services["service"].clients["client-a"]
    timestamp = flow(28, 0)["starttime"]
    # 23:00 and 00:00 remain neighbors in the one-hour smoothed clock.
    assert client.unusual_time(timestamp, module.settings) is None
    module.settings.mode = "train"
    for day in range(28):
        for hour in range(24):
            observation = Observation.from_zeek(
                flow(day, hour, uid=f"variable-{day}-{hour}")
            )
            module.detector.process(observation, "service", "client-a")
    assert (
        client.unusual_time(flow(28, 3)["starttime"], module.settings) is None
    )


def test_sparse_weekend_context_has_no_timing_claim() -> None:
    """Abstain on a day category without enough matching observations."""
    module = ModuleFactory().create_service_anomaly_obj(mode="train")
    for day in range(28):
        if day % 7 < 5:
            observation = Observation.from_zeek(
                flow(day, uid=f"weekday-{day}")
            )
            module.detector.process(observation, "service", "client-a")
    client = module.detector.services["service"].clients["client-a"]
    assert (
        client.unusual_time(flow(33, 3)["starttime"], module.settings) is None
    )


def test_old_schedule_or_future_observations_cannot_support_timing() -> None:
    """Require recent historical support when a client resumes after a gap."""
    module = ModuleFactory().create_service_anomaly_obj(mode="train")
    train(module, days=28, samples=1)
    client = module.detector.services["service"].clients["client-a"]
    assert (
        client.unusual_time(flow(100, 3)["starttime"], module.settings) is None
    )
    assert (
        client.unusual_time(flow(1, 3)["starttime"], module.settings) is None
    )


def test_client_limit_disables_novelty_for_incomplete_sets() -> None:
    """An admitted partial client list must not label omitted clients new."""
    module = ModuleFactory().create_service_anomaly_obj(
        mode="train", training_hours=0, max_clients=1
    )
    train(module)
    observation = Observation.from_zeek(flow(4, uid="at-cap"))
    module.detector.process(observation, "service", "b")
    module.settings.mode = "auto"
    observation = Observation.from_zeek(flow(5, uid="after-cap"))
    assert module.detector.process(observation, "service", "c") == []
    assert module.detector.client_count == 1
    assert not module.detector.services["service"].clients_complete


def test_service_capacity_pruning_and_duplicate_uid() -> None:
    """Bound model counts and prevent repeated records from inflating training."""
    module = ModuleFactory().create_service_anomaly_obj(
        max_services=1, retention_days=1
    )
    observation = Observation.from_zeek(flow(uid="same"))
    module.detector.process(observation, "a", "client")
    module.detector.process(observation, "a", "client")
    assert module.detector.services["a"].summary.count == 1
    second = Observation.from_zeek(flow(uid="capacity"))
    assert module.detector.process(second, "b", "client") == []
    assert list(module.detector.services) == ["a"]
    later = Observation.from_zeek(flow(3, uid="expire"))
    module.detector.process(later, "a", "client")
    assert module.detector.services["a"].summary.count == 1
    assert "a" not in module.detector.deleted


def test_train_detect_modes_and_rate_limits() -> None:
    """Support explicit fitting and frozen evaluation with bounded evidence."""
    module = ModuleFactory().create_service_anomaly_obj(
        mode="train", training_hours=0, max_alerts_per_service_hour=2
    )
    train(module)
    module.settings.mode = "detect"
    for index in range(5):
        observation = Observation.from_zeek(flow(4, uid=f"client-{index}"))
        reasons = module.detector.process(
            observation, "service", f"new-{index}"
        )
        assert bool(reasons) is (index < 2)
    observation = Observation.from_zeek(flow(4, uid="again"))
    assert module.detector.process(observation, "service", "new-0") == []
    assert len(module.detector.services["service"].clients) == 1
    assert len(module.detector.services["service"].recent_alerts) == 2
    assert not module.detector.process(observation, "unknown-service", "new")
    assert "unknown-service" not in module.detector.services


def test_detect_mode_keeps_active_baselines_without_refitting() -> None:
    """Retain active services while leaving their fitted distributions frozen."""
    module = ModuleFactory().create_service_anomaly_obj(
        training_hours=24, retention_days=10
    )
    train(module)
    module.settings.mode = "detect"
    for day in (4, 9, 15):
        observation = Observation.from_zeek(flow(day, uid=f"keep-{day}"))
        assert not module.detector.process(observation, "service", "client-a")
    assert module.detector.services["service"].summary.count == 60
    assert module.detector.services["service"].clients["client-a"].count == 60


def test_missing_mac_does_not_invent_a_new_client() -> None:
    """Abstain when a previously identified device temporarily loses MAC data."""
    module = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    train(module)
    service = module.detector.services["service"]
    service.clients["mac:02:00:00:00:00:10"] = service.clients.pop("client-a")
    observation = Observation.from_zeek(flow(4, uid="missing-mac"))
    assert not module.detector.process(observation, "service", "ip:192.0.2.10")
    assert len(service.clients) == 1


def test_repeated_dst_hour_is_one_observed_time_slot() -> None:
    """Use local clock bins without counting a repeated autumn hour twice."""
    module = ModuleFactory().create_service_anomaly_obj(
        mode="train", timezone="Europe/Prague"
    )
    from datetime import datetime

    for index, utc in enumerate(
        ("2026-10-25T00:30:00+00:00", "2026-10-25T01:30:00+00:00")
    ):
        observation = Observation.from_zeek(
            flow(
                uid=f"dst-{index}",
                starttime=datetime.fromisoformat(utc).timestamp(),
            )
        )
        module.detector.process(observation, "service", "client-a")
    activity = module.detector.services["service"].clients["client-a"].activity
    assert len(activity) == 1
    assert next(iter(activity.values())).bit_count() == 1
