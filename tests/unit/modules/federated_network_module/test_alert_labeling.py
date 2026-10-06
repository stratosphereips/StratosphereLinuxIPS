"""Alert ingestion and labeling of the federated network module.

Labels are flow-exact: alerts -> all their correlated evidences -> all flow
uids those evidences cite. Alert uid sets are retained for the large SLIPS
window, so a flow that reaches the module after its alert is still labeled;
queued messages are consumed before a window closes.
"""

import json
import time
from collections import deque
from unittest.mock import MagicMock

import pytest

from modules.federated_network_module import (
    federated_network_module as fnm,
)


def _module(k=0, retention=24, evidence=None):
    """A module instance with only the state the labeling path touches."""
    m = object.__new__(fnm.FederatedNetworkModule)
    m.print = MagicMock()
    m.logger = MagicMock()
    m.db = MagicMock()
    evidence = evidence or {}
    m.db.get_flows_causing_evidence.side_effect = lambda e: evidence.get(e, [])
    m.label_finalize_delay_windows = k
    m.alert_uid_retention_windows = retention
    m._alert_uid_memory = deque(maxlen=retention)
    m._flow_ring = deque()
    m.window_flows = {}
    m.pending_alerts = []
    m.test_time_predictions = {}
    m.training_count_window = 0
    m.training_count_alert = 0
    m.window_size_seconds = 300
    m.training_window_start = 0.0
    m._flip_events = []
    m._flipped_ids = set()
    m._trained_label_flows = {}
    m._trained_window_of = {}
    m._pending_labeled = {}
    m.training_buffer_x = []
    m.min_training_samples = 10**9  # never train in these tests
    m.testing_flows_since_last_log = 0
    m._using_merged_model = False
    m._is_fitted = False
    m._add_flows_to_buffers = MagicMock()
    m._log_window_comparisons = MagicMock()
    return m


def _flow(uid):
    return {"uid": uid, "saddr": "10.0.0.1", "daddr": "10.0.0.2"}


def _alert(*evidence_ids):
    return {
        "profile": {"ip": "10.0.0.1"},
        "timewindow": {"number": 1},
        "correl_id": list(evidence_ids),
        "last_evidence": {},
    }


def _close(m, flows=(), alerts=()):
    for uid in flows:
        m.handle_new_flow(_flow(uid))
    for alert in alerts:
        m.handle_new_alert(alert)
    m._close_training_window()


def _label(m, uid):
    return m._pending_labeled[uid]["label"]


def test_all_alerts_all_evidences_all_flows():
    m = _module(evidence={"e1": ["a", "b"], "e2": ["c", ""], "e3": ["d"]})
    m.pending_alerts = [
        {"evidence_ids": ["e1", "e2"]},
        {"evidence_ids": ["e2", "e3"]},
    ]
    uids, n_evidence = m._collect_alert_uids()
    assert uids == {"a", "b", "c", "d"}  # empty uids dropped
    assert n_evidence == 3
    # each evidence id is resolved once even when several alerts share it
    assert m.db.get_flows_causing_evidence.call_count == 3


def test_flows_cited_by_evidence_are_malicious_the_rest_benign():
    m = _module(evidence={"e1": ["mal"]})
    _close(m, flows=["mal", "ben"], alerts=[_alert("e1")])
    assert _label(m, "mal") == 1 and _label(m, "ben") == 0


def test_alert_that_arrives_before_its_flow_still_labels_it():
    m = _module(evidence={"e1": ["late-flow"]})
    _close(m, flows=["other"], alerts=[_alert("e1")])  # flow not there yet
    _close(m, flows=["late-flow"])  # flow reaches the module a window later
    assert _label(m, "late-flow") == 1
    assert m._flip_events == []


def test_retained_alert_uids_expire_after_the_large_window():
    m = _module(retention=2, evidence={"e1": ["very-late"]})
    _close(m, alerts=[_alert("e1")], flows=["x"])
    _close(m, flows=["y"])
    _close(m, flows=["very-late"])  # 3rd window: retention of 2 has expired
    assert _label(m, "very-late") == 0


@pytest.mark.parametrize("k, labeled", [(0, 0), (1, 1)])
def test_ring_k_lets_a_late_alert_label_the_previous_window(k, labeled):
    m = _module(k=k, evidence={"e1": ["f"]})
    _close(m, flows=["f"])  # alert for f only comes one window later
    _close(m, flows=["g"], alerts=[_alert("e1")])
    if k == 1:
        _close(m, flows=["h"])  # finalizes g's cell; f was finalized above
    assert _label(m, "f") == labeled


def test_flip_is_counted_once_for_a_trained_benign_flow():
    m = _module(evidence={"e1": ["t"]})
    m._trained_label_flows["t"] = {"label": 0, "uid": "t"}
    m._trained_window_of["t"] = 1
    _close(m, flows=["u"], alerts=[_alert("e1")])
    _close(m, flows=["v"], alerts=[_alert("e1")])
    assert [e["flow_id"] for e in m._flip_events] == ["t"]


def _queue(m, flows, alerts):
    queues = {
        "new_flow": deque(
            {"data": json.dumps({"flow": _flow(u), "stime": 0})} for u in flows
        ),
        "new_alert": deque({"data": json.dumps(a)} for a in alerts),
    }
    m.get_msg = lambda ch: queues[ch].popleft() if queues.get(ch) else None
    return queues


def test_drain_consumes_every_queued_flow_and_alert():
    m = _module()
    queues = _queue(m, [f"f{i}" for i in range(50)], [_alert("e1")] * 3)
    assert m._drain() == 53
    assert len(m.window_flows) == 50 and len(m.pending_alerts) == 3
    assert not queues["new_flow"] and not queues["new_alert"]


def test_drain_limit_bounds_one_pass():
    m = _module()
    queues = _queue(m, [f"f{i}" for i in range(10)], [])
    assert m._drain(limit=4) == 4
    assert len(queues["new_flow"]) == 6


def test_window_close_waits_for_already_queued_flows():
    m = _module()
    m.channels = {}
    m._p2p_connected = True
    m.training_window_start = time.time() - 301  # window is due
    calls = []
    m._drain = lambda limit=None: calls.append(("drain", limit)) or 0
    m._close_training_window = lambda: calls.append(("close", None))
    assert m._main_training() is False
    assert calls == [
        ("drain", m._DRAIN_BATCH),
        ("drain", None),
        ("close", None),
    ]
