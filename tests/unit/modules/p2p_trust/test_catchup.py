"""Exercise bounded incident history independently of live scoring and blocking."""

import json
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modules.p2p_trust.catchup import Catchup, CatchupSettings, CatchupStore
from tests.module_factory import ModuleFactory


def incident(author: str = "origin", **changes: object) -> dict:
    """Return a valid signed-record payload for author with changes applied."""
    now = time.time()
    return {
        "network": "gateway:aa",
        "author": author,
        "incident": "scan",
        "revision": 1,
        "state": "observed",
        "target": "192.0.2.50",
        "first_seen": now - 10,
        "last_seen": now - 5,
        "expires": now + 60,
        "confidence": 0.95,
        "threat": 3,
        "evidence_type": "HORIZONTAL_PORT_SCAN",
        **changes,
    }


def test_web_counts_local_storage_separately_and_prioritizes_imports(tmp_path: Path) -> None:
    """Local summaries remain shareable but cannot displace imported rows from a bounded web page."""
    _factory = ModuleFactory()
    store = CatchupStore(tmp_path / "catchup.sqlite", CatchupSettings())
    for index in range(4):
        assert store.save(incident("me", incident=f"own-{index}", threat=4))
    assert store.save(incident("other", incident="remote", threat=1), "signed", "relay")
    view = CatchupStore.view(store.path, "gateway:aa", limit=1)
    assert view["local_total"] == 4
    assert view["imported_total"] == 1
    assert view["incidents"][0]["incident"] == "remote"
    assert not view["transfers"]
    page = store.page({"network": "gateway:aa", "nonce": "a" * 32, "lane": "fresh", "since": time.time() - 3600}, "me", "requester")
    assert sum(item["record"]["author"] == "me" for item in page["items"]) == 4


@pytest.mark.parametrize("reply", [False, True])
def test_request_reply_summary_retains_contents_without_signature_envelopes(reply: bool) -> None:
    """Keep bounded exchange details for the UI without logging sealed payloads."""
    _factory = ModuleFactory()
    from modules.p2p_trust.catchup import message_summary

    message = {"message_type": "catchup_page" if reply else "catchup_request", "network": "gateway:aa", "lane": "history", "nonce": "a" * 32, "since": 123}
    if reply:
        message["items"] = [{"record": incident(description="private packet body"), "seal": "signature-envelope"} for _ in range(60)]
    summary = message_summary(message)
    assert summary["nonce"] == "a" * 32
    assert summary["since"] == 123
    assert len(summary["incidents"]) == (50 if reply else 0)
    assert "signature-envelope" not in json.dumps(summary)
    assert "private packet body" not in json.dumps(summary)
    if reply:
        assert summary["incidents"][0]["evidence_type"] == "HORIZONTAL_PORT_SCAN"


@pytest.mark.parametrize(
    "changes",
    [
        {"last_seen": float("nan")},
        {"last_seen": time.time() + 900},
        {"target": "224.0.0.251"},
        {"target": "255.255.255.255"},
        {"expires": time.time() + 86400},
        {"confidence": 2},
        {"revision": -1},
        {"state": "resolved"},
        {"description": "x" * 9000},
    ],
)
def test_reject_invalid_incidents(tmp_path: Path, changes: dict) -> None:
    """Reject malformed or stale authority; tmp_path isolates history and changes inject invalid fields."""
    _factory = ModuleFactory()
    store = CatchupStore(tmp_path / "catchup.sqlite", CatchupSettings())
    assert not store.save(incident(**changes))
    assert CatchupStore.view(store.path, "gateway:aa")["total"] == 0


def test_revisions_withdrawal_and_replay(tmp_path: Path) -> None:
    """Keep the latest signed revision across restarts; tmp_path isolates the journal."""
    _factory = ModuleFactory()
    store = CatchupStore(tmp_path / "catchup.sqlite", CatchupSettings())
    original = incident()
    assert store.save(original, "signed", "relay-a")
    assert not store.save(original, "signed", "relay-b")
    withdrawn = {**original, "state": "withdrawn", "revision": 2}
    assert store.save(withdrawn, "withdrawal", "relay-b")
    store = CatchupStore(store.path, store.settings)
    assert not store.save(original, "signed", "relay-a")
    view = CatchupStore.view(store.path, "gateway:aa")
    assert view["total"] == 1
    assert view["incidents"][0]["state"] == "withdrawn"
    assert view["incidents"][0]["author"] == "origin"
    assert view["incidents"][0]["via"] == "relay-b"


def test_priority_pages_and_immutable_snapshot(tmp_path: Path) -> None:
    """Send severe warnings first and keep pagination stable while new incidents arrive."""
    _factory = ModuleFactory()
    store = CatchupStore(
        tmp_path / "catchup.sqlite", replace(CatchupSettings(), page_records=1)
    )
    assert store.save(incident(incident="low", threat=1))
    assert store.save(incident(incident="critical", threat=4))
    request = {
        "network": "gateway:aa",
        "nonce": "a" * 32,
        "lane": "fresh",
        "since": time.time() - 3600,
    }
    page = store.page(request, "origin", "receiver")
    assert page["items"][0]["record"]["incident"] == "critical"
    assert page["more"]
    assert store.save(incident(incident="new", threat=4))
    second = store.page(
        {**request, "after": page["cursor"]}, "origin", "receiver"
    )
    assert second["items"][0]["record"]["incident"] == "low"
    assert not second["more"]


def test_old_records_only_enter_history_and_do_not_gain_freshness(
    tmp_path: Path,
) -> None:
    """Retain last-week observations without granting them current warning validity."""
    _factory = ModuleFactory()
    store = CatchupStore(tmp_path / "catchup.sqlite", CatchupSettings())
    old = incident(
        first_seen=time.time() - 3 * 86400,
        last_seen=time.time() - 2 * 86400,
        expires=time.time() - 2 * 86400 + 900,
    )
    assert store.save(old, "signature", "peer")
    request = {
        "network": "gateway:aa",
        "nonce": "b" * 32,
        "since": time.time() - 7 * 86400,
        "lane": "fresh",
    }
    assert store.page(request, "peer")["items"] == []
    history = store.page({**request, "lane": "history"}, "peer")
    assert history["items"][0]["record"]["last_seen"] == old["last_seen"]
    assert CatchupStore.view(store.path, "gateway:aa")["incidents"][0][
        "expired"
    ]


def test_store_capacity_preserves_replay_protection(tmp_path: Path) -> None:
    """Reject overflow without evicting accepted records or withdrawals."""
    _factory = ModuleFactory()
    store = CatchupStore(
        tmp_path / "catchup.sqlite", replace(CatchupSettings(), max_records=1)
    )
    first = incident()
    assert store.save(first)
    assert not store.save(incident(incident="another"))
    assert store.save({**first, "state": "withdrawn", "revision": 2})
    assert not store.save(first)


def test_foreign_network_and_unverified_reply_do_not_import(
    tmp_path: Path,
) -> None:
    """Only the requested authenticated reply can update catch-up storage."""
    _factory = ModuleFactory()
    store = CatchupStore(tmp_path / "catchup.sqlite", CatchupSettings())
    sender = Mock()
    controller = Catchup(store, lambda: "gateway:aa", lambda: "me", sender)
    controller.peer("other", True, True)
    controller.tick()
    request = sender.call_args.args[1]
    page = {
        **request,
        "message_type": "catchup_page",
        "items": [
            {
                "record": incident(),
                "seal": "signed",
                "verified_author": "origin",
            }
        ],
        "cursor": 1,
        "upto": 1,
        "more": False,
        "generation": "source",
    }
    controller.handle("other", page)
    controller.handle(
        "other", {**page, "verified": True, "network": "gateway:bb"}
    )
    controller.handle("attacker", {**page, "verified": True})
    assert CatchupStore.view(store.path, "gateway:aa")["total"] == 0
    controller.handle("other", {**page, "verified": True})
    assert CatchupStore.view(store.path, "gateway:aa")["total"] == 1
    assert store.transfer("gateway:aa", "other")["lane"] == "history"
    # No callback exists for scoring, trust credit, or enforcement.
    assert sender.call_count == 1


def test_local_summaries_ignore_peer_findings(tmp_path: Path) -> None:
    """Summaries contain first-hand local observations and coalesce repeated behavior."""
    _factory = ModuleFactory()
    store = CatchupStore(tmp_path / "catchup.sqlite", CatchupSettings())
    evidence = {
        "id": "e1",
        "timestamp": time.time() - 10,
        "attacker": {"value": "192.0.2.50"},
        "evidence_type": "UNKNOWN_PORT",
        "threat_level": "high",
        "confidence": 1,
    }
    store.observe(
        {**evidence, "peer_report": {"peer_id": "other"}}, "gateway:aa", "me"
    )
    assert CatchupStore.view(store.path, "gateway:aa")["total"] == 0
    store.observe(evidence, "gateway:aa", "me")
    store.observe(
        {**evidence, "id": "e2", "timestamp": time.time() - 5},
        "gateway:aa",
        "me",
    )
    view = CatchupStore.view(store.path, "gateway:aa")
    assert view["total"] == 1
    assert view["incidents"][0]["count"] == 2
    store.withdraw("other", {"e2"})
    assert (
        CatchupStore.view(store.path, "gateway:aa")["incidents"][0]["state"]
        == "observed"
    )
    store.withdraw("me", {"e2"})
    assert (
        CatchupStore.view(store.path, "gateway:aa")["incidents"][0]["state"]
        == "withdrawn"
    )


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"enabled": False},
        {"max_peers": 10000, "page_bytes": 999999},
        {"history_days": "bad"},
    ],
)
def test_config_is_bounded(config: dict) -> None:
    """Validate defaults and resource caps for the supplied configuration mapping."""
    _factory = ModuleFactory()
    settings = CatchupSettings.from_config(config)
    assert settings.max_peers <= 16
    assert settings.page_bytes <= 65536
    assert settings.history_days <= 30
    assert settings.enabled is (config.get("enabled", True) is True)


def test_network_scope_distinguishes_subnets_and_ignores_unknown_router() -> (
    None
):
    """Use both normalized gateway MAC and subnet; unknown connectivity grants no network scope."""
    _factory = ModuleFactory()
    from modules.p2p_trust.catchup import network_scope

    state = {
        "connected": True,
        "gateway_mac": "a2:b:c:d:e:f",
        "local_network": "192.168.1.1/24",
    }
    assert network_scope(state) == "gateway:a2:0b:0c:0d:0e:0f|192.168.1.0/24"
    assert network_scope(
        {**state, "local_network": "192.168.2.0/24"}
    ) != network_scope(state)
    assert network_scope({**state, "connected": False}) == ""
    assert network_scope({**state, "gateway_mac": ""}) == ""


@pytest.mark.parametrize(
    "local,authors,independent,age,expected",
    [
        (False, [], True, 5, False),
        (False, ["one"], True, 5, False),
        (False, ["one", "two"], True, 5, True),
        (False, ["one", "two"], False, 5, False),
        (False, ["one", "two"], True, 600, False),
        (True, [], True, 5, True),
    ],
)
def test_fresh_protection_requires_local_confirmation_or_enrolled_independent_authors(
    tmp_path: Path,
    local: bool,
    authors: list[str],
    independent: bool,
    age: int,
    expected: bool,
) -> None:
    """Only fresh qualified support requests temporary firewall protection, never peer discovery alone."""
    _factory = ModuleFactory()
    from tests.unit.modules.p2p_trust.test_p2p_trust import create_trust

    trust = create_trust()
    trust.args.interface = "en0"
    trust.args.access_point = None
    trust._catchup_network_identity = lambda: "gateway:aa"
    trust._network_identity = lambda: "gateway:aa"
    trust.catchup_protection = {"enabled": True, "peer_ids": authors}
    trust.db.get_pid_of.return_value = 1
    trust.db.get_network_state.return_value = {}
    trust.report_validation = Mock()
    trust.report_validation.local_report.return_value = (
        (0.9, 0.95, [{"method": "SIGNATURE"}]) if local else (None, None, [])
    )
    store = CatchupStore(tmp_path / "catchup.sqlite", CatchupSettings())
    trust.catchup = Catchup(store, lambda: "gateway:aa", lambda: "me", Mock())
    for author, module in [
        ("one", "http_analyzer"),
        ("two", "smb_analyzer" if independent else "http_analyzer"),
    ]:
        observed = time.time() - age
        record = incident(
            author,
            module=module,
            target="8.8.4.4",
            evidence_type="SUSPICIOUS_ACTIVITY",
            last_seen=observed,
            first_seen=observed - 1,
            expires=observed + 900,
        )
        assert store.save(record, "signed", author)
    with patch(
        "modules.p2p_trust.p2p_trust.utils.get_own_ips", return_value=[]
    ):
        trust._consider_catchup_protection(record)
    assert trust.db.publish.called is expected
    if expected:
        channel, encoded = trust.db.publish.call_args.args
        data = json.loads(encoded)
        assert channel == "new_blocking"
        assert data["lease_owner"].startswith("p2p-catchup:")
        assert 0 < data["lease_until"] - time.time() <= 300


def test_network_departure_revokes_only_the_departed_scope(
    tmp_path: Path,
) -> None:
    """A new network clears peer requests and notifies the owner of the old network."""
    _factory = ModuleFactory()
    current = ["gateway:aa"]
    leave = Mock()
    controller = Catchup(
        CatchupStore(tmp_path / "catchup.sqlite", CatchupSettings()),
        lambda: current[0],
        lambda: "me",
        Mock(),
        on_leave=leave,
    )
    controller.tick()
    controller.peer("old-peer", True, True)
    current[0] = "gateway:bb"
    controller.next_tick = 0
    controller.tick()
    leave.assert_called_once_with("gateway:aa")
    assert controller.peers == {}


def test_reconnect_cooldown_expires_instead_of_disabling_future_catchup(
    tmp_path: Path,
) -> None:
    """A brief reconnect waits, then requests new state after the cooldown."""
    _factory = ModuleFactory()
    store = CatchupStore(tmp_path / "catchup.sqlite", CatchupSettings())
    now = time.time()
    store.transfer(
        "gateway:aa",
        "peer",
        {
            "state": "complete",
            "started": now,
            "history_cursor": 17,
            "generation": "g",
        },
    )
    send = Mock()
    controller = Catchup(store, lambda: "gateway:aa", lambda: "me", send)
    controller.peer("peer", True, True)
    controller.tick()
    send.assert_not_called()
    with patch("modules.p2p_trust.catchup.time.time", return_value=now + 61):
        controller.next_tick = 0
        controller.tick()
    assert send.call_args.args[1]["message_type"] == "catchup_request"
    assert send.call_args.args[1]["lane"] == "fresh"
    assert send.call_args.args[1]["since_seq"] == 17
