"""Alert ingestion and labeling of the federated network module (DB mode).

The module reads SLIPS's own flows.sqlite at every wall-clock window close:
conn flows ("flows") and ARP records ("altflows", flow_type 'arp') by
insertion-order rowid, and alert -> evidence -> flow-uid matches by one
indexed query (alerts -> alert_evidence -> evidence_flows). Labels are
flow-exact: a flow is malicious only when an alert within the wall-clock
lookback cites its uid. ARP records are ingested and labeled like any other
flow. A flow sits in the ring for K windows before its cell finalizes and
its label is recorded.
"""

import json
import sqlite3
from collections import deque
from unittest.mock import MagicMock

import pytest

from modules.federated_network_module import (
    federated_network_module as fnm,
)

WIN = 300  # window_size_seconds
BASE = 1_000_000.0  # wall-clock origin for the test timeline


# --------------------------------------------------------------------------
# in-memory flows.sqlite matching the columns the module queries
# --------------------------------------------------------------------------
def _make_db():
    db = sqlite3.connect(":memory:")
    db.executescript(
        """
        CREATE TABLE flows(uid TEXT, flow TEXT);
        CREATE TABLE altflows(uid TEXT, flow TEXT, flow_type TEXT);
        CREATE TABLE alerts(alert_id TEXT, alert_time REAL);
        CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);
        CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);
        """
    )
    return db


def _flow_json(uid, ts):
    return json.dumps(
        {"uid": uid, "saddr": "10.0.0.1", "daddr": "10.0.0.2", "starttime": ts}
    )


def _insert_flow(db, uid, ts, arp=False):
    if arp:
        db.execute(
            "INSERT INTO altflows(uid, flow, flow_type) VALUES(?,?, 'arp')",
            (uid, _flow_json(uid, ts)),
        )
    else:
        db.execute(
            "INSERT INTO flows(uid, flow) VALUES(?,?)",
            (uid, _flow_json(uid, ts)),
        )
    db.commit()


def _insert_alert(db, alert_id, uids, at, evidence_map=None):
    """One alert at wall-clock `at`. uids -> one evidence each; or pass
    evidence_map {evidence_id: [uids]} to share evidence across alerts."""
    db.execute(
        "INSERT INTO alerts(alert_id, alert_time) VALUES(?,?)", (alert_id, at)
    )
    pairs = (
        evidence_map.items()
        if evidence_map is not None
        else {f"{alert_id}-e{i}": [u] for i, u in enumerate(uids)}.items()
    )
    for eid, euids in pairs:
        db.execute(
            "INSERT INTO alert_evidence(alert_id, evidence_id) VALUES(?,?)",
            (alert_id, eid),
        )
        for uid in euids:
            if uid:
                db.execute(
                    "INSERT INTO evidence_flows(evidence_id, uid) VALUES(?,?)",
                    (eid, uid),
                )
    db.commit()


def _module(db, k=0, retention=24):
    """A module instance with only the state the DB labeling path touches."""
    m = object.__new__(fnm.FederatedNetworkModule)
    m.print = MagicMock()
    m.logger = MagicMock()
    m._db_conn = db
    m.window_size_seconds = WIN
    m.label_finalize_delay_windows = k
    m.alert_uid_retention_windows = retention
    m.training_count_window = 0
    m.training_window_start = BASE
    # ring / DB cursors
    m._flow_ring = deque()
    m._window_bounds = {}
    m._next_window_flows = []
    m._seen_uids = set()
    m._flow_rowid = 0
    m._arp_rowid = 0
    m._last_alert_cut = 0.0
    # flip / label bookkeeping
    m._flip_events = []
    m._flipped_ids = set()
    m._trained_label_flows = {}
    m._trained_window_of = {}
    m._trained_per_window = {}
    m._pending_labeled = {}
    # buffers (never train in these tests)
    m.training_buffer_x = []
    m.training_buffer_y = []
    m.min_training_samples = 10**9
    # flags the close/test path reads
    m._is_fitted = False
    m._using_merged_model = False
    m.testing_flows_since_last_log = 0
    m._local_stream_used = False
    # isolate labeling from feature extraction / comparison logging
    m._add_flows_to_buffers = MagicMock()
    m._log_window_comparisons = MagicMock()
    m._get_simulated_gt = lambda flow: None
    return m


class Harness:
    """Drives wall-clock closes against the in-memory DB with a fake clock."""

    def __init__(self, monkeypatch, k=0, retention=24):
        self.db = _make_db()
        self.m = _module(self.db, k=k, retention=retention)
        self.n = 0
        self.now = BASE
        monkeypatch.setattr(fnm.time, "time", lambda: self.now)

    def close(self, flows=(), arp=(), alerts=()):
        """Insert this window's flows/arp/alerts, then close the window.

        flows/arp: uids (placed in the current window). alerts: tuples
        (alert_id, [uids]) at the current wall clock, or (alert_id, [uids],
        at) to backdate.
        """
        self.n += 1
        self.now = BASE + self.n * WIN
        ts = BASE + (self.n - 1) * WIN + 100  # inside this window's bounds
        for uid in flows:
            _insert_flow(self.db, uid, ts)
        for uid in arp:
            _insert_flow(self.db, uid, ts, arp=True)
        for spec in alerts:
            at = spec[2] if len(spec) == 3 else self.now
            _insert_alert(self.db, spec[0], spec[1], at)
        self.m._close_training_window()

    def label(self, uid):
        return self.m._pending_labeled[uid]["label"]


# --------------------------------------------------------------------------
# DB ingestion primitives
# --------------------------------------------------------------------------
def test_fetch_reads_conn_and_arp_dedup_by_uid():
    db = _make_db()
    m = _module(db)
    _insert_flow(db, "x", BASE)
    _insert_flow(db, "x", BASE)  # same uid again -> collapsed
    _insert_flow(db, "y", BASE)
    _insert_flow(db, "z", BASE, arp=True)
    flows, n_conn, n_arp = m._fetch_new_flows()
    assert {f["uid"] for f in flows} == {"x", "y", "z"}  # dedup, arp included
    assert n_conn == 3 and n_arp == 1
    # cursor advanced: nothing new on a second read
    assert m._fetch_new_flows() == ([], 0, 0)


def test_new_alerts_counts_distinct_evidence_and_nonempty_uids():
    db = _make_db()
    m = _module(db)
    _insert_alert(
        db, "A1", [], BASE, evidence_map={"E1": ["a", "b"], "E2": ["c", ""]}
    )
    _insert_alert(db, "A2", [], BASE, evidence_map={"E2": ["c"], "E3": ["d"]})
    alert_count, n_evidence, uids = m._new_alerts(BASE - WIN, BASE + WIN)
    assert alert_count == 2
    assert n_evidence == 3  # E1, E2, E3 distinct
    assert uids == {"a", "b", "c", "d"}  # empty uid dropped


def test_alerted_uids_only_returns_cited_uids_in_window():
    db = _make_db()
    m = _module(db)
    _insert_alert(db, "A1", ["a", "b"], BASE)
    assert m._alerted_uids(["a", "b", "z"], BASE - WIN, BASE + WIN) == {
        "a",
        "b",
    }
    # outside the time window -> nothing
    assert m._alerted_uids(["a", "b"], BASE + WIN, BASE + 2 * WIN) == set()


# --------------------------------------------------------------------------
# labeling at window close
# --------------------------------------------------------------------------
def test_flows_cited_by_evidence_are_malicious_the_rest_benign(monkeypatch):
    h = Harness(monkeypatch)
    h.close(flows=["mal", "ben"], alerts=[("A1", ["mal"])])
    assert h.label("mal") == 1 and h.label("ben") == 0


def test_arp_record_is_ingested_and_labeled_like_a_flow(monkeypatch):
    h = Harness(monkeypatch)
    h.close(flows=["conn1"], arp=["arp1"], alerts=[("A1", ["arp1"])])
    assert h.label("arp1") == 1  # ARP trained + labeled from the DB
    assert h.label("conn1") == 0


def test_alert_that_arrives_before_its_flow_still_labels_it(monkeypatch):
    h = Harness(monkeypatch)
    h.close(flows=["other"], alerts=[("A1", ["late"])])  # flow not there yet
    h.close(flows=["late"])  # flow reaches the module a window later
    assert h.label("late") == 1
    assert h.m._flip_events == []


def test_alert_older_than_the_lookback_does_not_label(monkeypatch):
    h = Harness(monkeypatch, retention=2)  # lookback = 2 * 300 = 600s
    h.close(alerts=[("A1", ["verylate"], BASE - 1)], flows=["x"])  # backdated
    h.close(flows=["verylate"])  # now = BASE+600, since = BASE -> A1 excluded
    assert h.label("verylate") == 0


@pytest.mark.parametrize("k, labeled", [(0, 0), (1, 1)])
def test_ring_k_lets_a_late_alert_label_the_previous_window(
    monkeypatch, k, labeled
):
    h = Harness(monkeypatch, k=k)
    h.close(flows=["f"])  # alert for f only comes one window later
    h.close(flows=["g"], alerts=[("A1", ["f"])])
    assert h.label("f") == labeled


# --------------------------------------------------------------------------
# flips: an alert that lands after a flow already trained benign
# --------------------------------------------------------------------------
def test_flip_is_counted_once_for_a_trained_benign_flow(monkeypatch):
    h = Harness(monkeypatch)
    h.m._trained_label_flows["t"] = {
        "label": 0,
        "uid": "t",
        "saddr": "",
        "daddr": "",
    }
    h.m._trained_window_of["t"] = 1
    h.m._trained_per_window = {1: 1}
    h.close(flows=["u"], alerts=[("A1", ["t"])])
    h.close(flows=["v"], alerts=[("A2", ["t"])])  # same flow cited again
    assert [e["flow_id"] for e in h.m._flip_events] == ["t"]


def test_malicious_trained_flow_is_not_a_flip(monkeypatch):
    h = Harness(monkeypatch)
    h.m._trained_label_flows["t"] = {
        "label": 1,
        "uid": "t",
        "saddr": "",
        "daddr": "",
    }
    h.m._trained_window_of["t"] = 1
    h.m._trained_per_window = {1: 1}
    h.close(flows=["u"], alerts=[("A1", ["t"])])
    assert h.m._flip_events == []
