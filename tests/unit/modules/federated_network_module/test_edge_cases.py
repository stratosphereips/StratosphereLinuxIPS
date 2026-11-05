"""Edge cases of the federated network module, driven through larger paths.

Live-like scenarios run the real window close (_close_training_window)
against an in-memory flows.sqlite with a fake clock and a real ModuleLogger,
so labels, flips and test streams are read back from the module's own
output files (trained_labels.jsonl, label_flips.log, *_test*.log) with the
regexes the experiment runner parses them with. Only the network update
(_train_batch) is stubbed there; separate tests run real local training and
merging, the P2P wire format, and the merge-rule contract.
"""

import base64
import json
import os
import pickle
import re
import sqlite3
from collections import deque
from types import SimpleNamespace
from unittest.mock import MagicMock

import numpy as np
import pytest
import torch
from sklearn.preprocessing import StandardScaler

from modules.federated_network_module import (
    federated_network_module as fnm,
)
from slips_files.common.abstracts import ml_module_base as ml_base

MAL, BEN = fnm.MALICIOUS, fnm.BENIGN
WIN = 300  # window_size_seconds
BASE = 1_000_000.0  # wall-clock origin of the test timeline
SEED = 1111
ATTACKER = "10.6.6.6"

# Mirrors of the runner's parsers (SCL-Federation-Experiment-Runner:
# visualizer.py _parse_test/_parse_train, sweep_labeling_strategies.py).
FLOW_RE = re.compile(
    r"flows=(\d+)\s+\|\s+GT\(Mal/Ben\):\s+(\d+)/(\d+)\s+\|\s+Pred\(Mal/Ben\):\s+(\d+)/(\d+)\s+\|"
    r"\s+TP/FP/TN/FN:\s+(\d+)/(\d+)/(\d+)/(\d+)\s+\|\s+Acc=([\d.]+)"
)
TRAIN_HDR_RE = re.compile(
    r"---\s+(\w+)_(\d+)\s+\|\s+(\d+)\s+mal\s*(?:\(\s*(\d+)\s+evidence\s*\))?,?\s*(\d+)\s+ben\s+---"
)
FLIP_TOTAL_RE = re.compile(
    r"@window_\d+ \| flips: (\d+) / (\d+) \(([\d.]+)%\)"
)
FLIP_WIN_RE = re.compile(
    r"window_(\d+) \| trained (\d+) \| flipped (\d+) \| pct ([\d.]+)"
)
COMP_HDR_RE = re.compile(
    r"--- (window_\d+) \| (\d+) alerts, (\d+) evidence\. "
    r"(\d+) malicious connected to evidence, (\d+) benign, (\d+) total"
)


# --------------------------------------------------------------------------
# live-like window-close pipeline
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


class Pipe:
    """Drives the real _close_training_window: flows/alerts go into an
    in-memory flows.sqlite, the fake clock jumps one window per close, and
    training fires for real down to _train_batch, which records the batch
    (window, labels) and clears the buffer like the real one does."""

    def __init__(
        self, monkeypatch, tmp_path, k=0, min_samples=1, fitted=False, batch=1
    ):
        self.db = _make_db()
        self.dir = tmp_path
        self.n = 0
        self.now = BASE
        self.batches = []
        monkeypatch.setattr(fnm.time, "time", lambda: self.now)
        m = object.__new__(fnm.FederatedNetworkModule)
        m.print = MagicMock()
        m.logger = fnm.ModuleLogger(str(tmp_path), True)
        m._db_conn = self.db
        m._db_rw = lambda: self.db
        m._simulated_attackers = lambda: (ATTACKER,)
        m.window_size_seconds = WIN
        m.label_finalize_delay_windows = k
        m.alert_uid_retention_windows = 24
        m.training_count_window = 0
        m.training_window_start = BASE
        m._flow_ring = deque()
        m._window_bounds = {}
        m._next_window_flows = []
        m._seen_uids = set()
        m._flow_rowid = 0
        m._arp_rowid = 0
        m._last_alert_cut = 0.0
        m._flip_events = []
        m._flipped_ids = set()
        m._trained_label_flows = {}
        m._trained_window_of = {}
        m._trained_per_window = {}
        m._pending_labeled = {}
        m.training_buffer_x = []
        m.training_buffer_y = []
        m.training_buffer_ids = []
        m._buffered_flow_ids = set()
        m.min_training_samples = min_samples
        m._undersample = False
        m._training_trigger = ""
        # testing streams
        m._is_fitted = fitted
        m._using_merged_model = False
        m._local_only_model = None
        m.testing_log_batch_size = batch
        m.testing_flows_since_last_log = 0
        m.malware_metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        m.seen_labels = {MAL: 0, BEN: 0}
        m.predicted_labels = {MAL: 0, BEN: 0}
        m._local_test = m._blank_test_statistics()
        m._local_stream_used = False
        m._span_label = ""
        m._local_span_marked = False
        m._conn_active = m._blank_test_statistics()
        m._conn_local = m._blank_test_statistics()
        m._sofar_chunks = []
        m.scaler = MagicMock(
            transform=lambda x: x,
            n_samples_seen_=0,
            mean_=np.zeros(18),
            var_=np.ones(18),
            scale_=np.ones(18),
        )
        m.predict_batch = lambda x: np.array([BEN] * len(x))
        m._train_batch = self._train
        self.m = m

    def _train(self, scaler_rows=None):
        m = self.m
        self.batches.append(
            (m.training_count_window, list(m.training_buffer_y))
        )
        m.training_buffer_x.clear()
        m.training_buffer_y.clear()
        m.training_buffer_ids.clear()
        m._buffered_flow_ids.clear()

    def add(self, uid, ts=..., saddr="10.0.0.1", arp=False):
        """One flow row; ts defaults to the middle of the window being
        filled, ts=None stores no starttime at all."""
        if ts is ...:
            ts = BASE + self.n * WIN + 100
        flow = json.dumps(
            {
                "uid": uid,
                "saddr": saddr,
                "daddr": "10.0.0.2",
                "starttime": ts,
                "type_": "arp" if arp else "conn",
            }
        )
        if arp:
            self.db.execute(
                "INSERT INTO altflows VALUES(?,?,'arp')", (uid, flow)
            )
        else:
            self.db.execute("INSERT INTO flows VALUES(?,?)", (uid, flow))

    def alert(self, alert_id, uids):
        """An alert created now (wall clock of the coming close)."""
        at = BASE + (self.n + 1) * WIN
        self.db.execute("INSERT INTO alerts VALUES(?,?)", (alert_id, at))
        for i, uid in enumerate(uids):
            eid = f"{alert_id}-e{i}"
            self.db.execute(
                "INSERT INTO alert_evidence VALUES(?,?)", (alert_id, eid)
            )
            self.db.execute(
                "INSERT INTO evidence_flows VALUES(?,?)", (eid, uid)
            )

    def close(self, *uids, alerts=()):
        for uid in uids:
            self.add(uid)
        for alert_id, cited in alerts:
            self.alert(alert_id, cited)
        self.db.commit()
        self.n += 1
        self.now = BASE + self.n * WIN
        self.m._close_training_window()

    def lines(self, name):
        path = self.dir / name
        return [ln.strip() for ln in path.read_text().splitlines() if ln]

    def trained(self):
        """uid -> {label, train_window} from trained_labels.jsonl; a flow
        must appear there at most once (trained exactly once)."""
        rows = [json.loads(ln) for ln in self.lines("trained_labels.jsonl")]
        out = {
            r["uid"]: {"label": r["label"], "train_window": r["train_window"]}
            for r in rows
        }
        assert len(out) == len(rows)
        return out

    def flips(self):
        return [
            (e["flow_id"], e["trained_window"], e["flip_window"])
            for e in self.m._flip_events
        ]


def _parse_flip_log(lines):
    totals, series = None, {}
    for line in lines:
        if m := FLIP_TOTAL_RE.search(line):
            totals = (int(m.group(1)), int(m.group(2)))
        if w := FLIP_WIN_RE.search(line):
            series[int(w.group(1))] = (int(w.group(2)), int(w.group(3)))
    return totals, series


# --------------------------------------------------------------------------
# labels vs flips at the finalize boundary
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "k, delay, flipped",
    [(0, 1, True), (2, 2, False), (2, 3, True)],
)
def test_alert_by_finalize_labels_after_finalize_flips(
    monkeypatch, tmp_path, k, delay, flipped
):
    """Flow f arrives in window 1; its cell finalizes and trains at close
    K+1. An alert citing f `delay` closes after f's own close (and again one
    close later) is normal labeling up to and including the finalize close,
    a single flip once f trained benign, and never a flip when f trained
    malicious."""
    p = Pipe(monkeypatch, tmp_path, k=k)
    for i in range(delay + 2):
        cite = [(f"A{i}", ["f"])] if i in (delay, delay + 1) else []
        p.close("f" if i == 0 else f"x{i}", alerts=cite)

    assert p.trained()["f"] == {
        "label": 0 if flipped else 1,
        "train_window": k + 1,
    }
    assert p.flips() == ([("f", k + 1, delay + 1)] if flipped else [])
    # what the flippiness sweep reads back from label_flips.log
    totals, series = _parse_flip_log(p.lines("label_flips.log"))
    assert totals[0] == int(flipped)
    assert series[k + 1] == (1, int(flipped))
    hdr = [
        COMP_HDR_RE.search(ln)
        for ln in p.lines("comp_inferred_gt.log")
        if f"window_{k + 1} |" in ln
    ]
    assert [(h.group(4), h.group(5)) for h in hdr] == [
        ("0", "1") if flipped else ("1", "0")
    ]


def test_flip_of_a_carried_over_flow_cited_before_its_batch_trains(
    monkeypatch, tmp_path
):
    """f finalizes benign at close 1, but its batch is below
    min_training_samples and waits. The alert citing f lands at close 2,
    where nothing trains. The carried batch trains at close 3. f trained
    benign and was cited after its finalize, so it is a flip."""
    p = Pipe(monkeypatch, tmp_path, k=0, min_samples=2)
    p.close("f")
    p.close(alerts=[("A1", ["f"])])
    p.close("g")
    assert p.trained()["f"] == {"label": 0, "train_window": 3}
    assert [fid for fid, *_ in p.flips()] == ["f"]


def test_reinserted_uid_trains_once_and_its_late_alert_is_a_flip(
    monkeypatch, tmp_path
):
    """SLIPS rewrites flow rows (INSERT OR REPLACE -> new rowid). A uid seen
    again in a later window must not be placed, labeled or trained again:
    the late alert flips the benign training instead of adding a
    malicious duplicate sample."""
    p = Pipe(monkeypatch, tmp_path, k=0)
    p.close("x")
    p.close("x", "y", alerts=[("A1", ["x"])])  # x row rewritten + cited
    assert p.batches == [(1, [BEN]), (2, [BEN])]  # x once, then only y
    assert p.trained() == {
        "x": {"label": 0, "train_window": 1},
        "y": {"label": 0, "train_window": 2},
    }
    assert p.flips() == [("x", 1, 2)]


def test_a_flow_belongs_to_the_window_it_reached_the_db_in(
    monkeypatch, tmp_path
):
    """Read-window placement: every flow read at a close joins that close's
    window whatever its own start ts - a flow stamped in the next window is
    not held back, a long-lived flow that started a window earlier is not
    back-dated (it is counted as late), and a flow without a start time
    joins the window it was read in."""
    p = Pipe(monkeypatch, tmp_path, k=1)
    p.add("a")
    p.add("fut", ts=BASE + WIN + 50)  # stamped in window 2, read at close 1
    p.close()
    p.add("long", ts=BASE + 10)  # started in window 1, stored in window 2
    p.add("stale", ts=None)
    p.add("b")
    p.close()
    p.close()
    windows = {uid: r["train_window"] for uid, r in p.trained().items()}
    assert windows == {"a": 2, "fut": 2, "long": 3, "stale": 3, "b": 3}
    db_hdr = [ln for ln in p.lines("local_train.log") if "db | window_2" in ln]
    assert len(db_hdr) == 1 and " late 1 " in db_hdr[0]


def test_each_flow_is_tested_once_before_the_window_that_trains_it(
    monkeypatch, tmp_path
):
    """Prequential order: every open cell is tested at every close BEFORE
    that close trains; a flow read late (its ts in an earlier window) joins
    the window it was read in - never back-dated; each flow is tested once,
    before the training that uses it."""
    p = Pipe(monkeypatch, tmp_path, k=1, fitted=True)
    events = []
    real_test_cell = p.m._test_cell

    def spy_test_cell(cell):
        before = set(cell["tested"])
        real_test_cell(cell)
        events.extend(("test", fid) for fid in cell["tested"] - before)

    def spy_train(scaler_rows=None):
        w = p.m.training_count_window
        uids = {f for f, tw in p.m._trained_window_of.items() if tw == w}
        events.append(("train", frozenset(uids)))
        p._train()

    p.m._test_cell = spy_test_cell
    p.m._train_batch = spy_train
    p.close("a", "b")
    p.add("late", ts=BASE + 150)  # stamped in window 1, read at close 2
    p.close("c")
    p.close()

    tests = [fid for kind, fid in events if kind == "test"]
    assert sorted(tests) == ["a", "b", "c", "late"]  # each exactly once
    pos = {fid: i for i, (kind, fid) in enumerate(events) if kind == "test"}
    trains = [
        (i, uids) for i, (kind, uids) in enumerate(events) if kind == "train"
    ]
    assert [set(u) for _, u in trains] == [{"a", "b"}, {"c", "late"}]
    for i, uids in trains:
        assert all(pos[uid] < i for uid in uids)
    assert (
        pos["c"] < trains[0][0]
    )  # B: tested BEFORE close 2 trains (model live during its window)


def test_a_window_is_one_complete_span_whatever_the_log_batch_size(
    monkeypatch, tmp_path
):
    """Option B writes each window once, at finalize, as ONE line per stream
    holding all of the window's scored flows: a large test_log_batch_size
    can never leave a residual behind, and the header precedes its line."""
    p = Pipe(monkeypatch, tmp_path, k=0, fitted=True, batch=1000)
    p.add("m1", saddr=ATTACKER)
    p.close("b1")
    for log in ("local_test.log", "local_test_conn.log"):
        lines = p.lines(log)
        assert lines[0] == "--- New local model (window_1) ---"
        assert len(lines) == 2  # header + the window's one line
        assert FLOW_RE.match(lines[1]).group(1, 2, 3) == ("2", "1", "1")


# --------------------------------------------------------------------------
# test-stream lines are what the runner parses
# --------------------------------------------------------------------------
def test_both_stream_writers_emit_the_line_the_runner_parses(tmp_path):
    """_write_stream_line (conn twins / local stream) and the active-stream
    path (store_testing_results -> _write_testing_snapshot) write the same
    counts for the same tested flows, in the line format the runner parses."""
    m = object.__new__(fnm.FederatedNetworkModule)
    m.logger = fnm.ModuleLogger(str(tmp_path), True)
    # (gt, pred): 2 TP, 1 FP, 3 TN, 1 FN
    pairs = [(MAL, MAL), (MAL, MAL), (BEN, MAL)] + [(BEN, BEN)] * 3
    pairs += [(MAL, BEN)]
    stats = m._blank_test_statistics()
    for gt, pred in pairs:
        m._tally(stats, gt, pred)
    m._write_stream_line("local_test", stats)
    assert stats["flows_since_snapshot"] == 0

    m._using_merged_model = True
    m.testing_log_batch_size = len(pairs)
    m.testing_flows_since_last_log = 0
    m.malware_metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    m.seen_labels = {MAL: 0, BEN: 0}
    m.predicted_labels = {MAL: 0, BEN: 0}
    for gt, pred in pairs:
        m.store_testing_results(gt, np.str_(pred))  # preds are numpy str
    expected = ("7", "3", "4", "3", "4", "2", "1", "3", "1", "0.7143")
    for name in ("local_test.log", "merged_test.log"):
        lines = (tmp_path / name).read_text().splitlines()
        assert len(lines) == 1
        assert FLOW_RE.match(lines[0].strip()).groups() == expected


# --------------------------------------------------------------------------
# P2P: wire format, incompatible and malformed peer payloads
# --------------------------------------------------------------------------
def _net(tmp_path, peer):
    stub = SimpleNamespace(
        rp_path=str(tmp_path / "rp.bin"), seed=SEED, input_dim=None
    )
    return fnm.build_with_init_seed(
        fnm.shared_init_seed(SEED),
        lambda: fnm._build_random_projection_mlp(stub),
    )


def _peer_module(tmp_path, peer, model=None):
    out = tmp_path / peer
    m = object.__new__(fnm.FederatedNetworkModule)
    m.print = MagicMock()
    m.logger = fnm.ModuleLogger(str(out), True)
    m.output_dir = str(out)
    m.merged_dir = str(out)
    m.my_peer_id = peer
    m.model_class_name = "random_projection_mlp"
    m.model = model
    m.peer_models = {}
    m.db = MagicMock()
    m.merge_rule = "average"
    m.merge_count = 0
    m._using_merged_model = False
    m._last_train_X = None
    m._last_train_Y = None
    return m


def test_model_sent_over_p2p_arrives_bit_exact_at_the_receiver(
    monkeypatch, tmp_path
):
    """send_model_to_peers -> (Go layer wraps as go_data) -> the receiver's
    main loop -> handle_p2p_model stores the sender's shared tensors."""
    a = _peer_module(tmp_path, "slips-a", _net(tmp_path, "slips-a"))
    a.send_model_to_peers()
    channel, raw = a.db.publish.call_args.args
    go = json.loads(raw)
    assert channel == "p2p_pygo" and go["recipient"] == "*"
    wire = {
        "message_type": "go_data",
        "message_contents": {
            "message": go["message"],
            "reporter": "QmPeerA",
            "report_time": 0,
        },
    }
    b = _peer_module(tmp_path, "slips-b", _net(tmp_path, "slips-b"))
    b.mode = "train"
    b.channels = {"p2p_gopy": object()}
    b._p2p_connected = True
    inbox = [{"data": json.dumps(wire)}]
    b.get_msg = lambda channel: inbox.pop() if inbox else None
    b.window_size_seconds = WIN
    b.training_window_start = fnm.time.time() + 10 * WIN  # no close now
    monkeypatch.setattr(fnm.time, "sleep", lambda s: None)
    assert b.main() is False

    sent = a.model.weights_for_sharing()
    got = b.peer_models["slips-a"]
    assert set(got) == set(sent) | {"timestamp"}
    for key, tensor in sent.items():
        assert got[key].dtype == tensor.dtype
        assert torch.equal(got[key], tensor)


@pytest.mark.parametrize(
    "bad",
    [
        "missing_key",
        "other_model_class",
    ],
)
def test_incompatible_peer_is_skipped_and_the_rest_still_merge(tmp_path, bad):
    """A stored peer payload that cannot be merged (a shared key missing, or
    the same keys with other shapes from another model_class) is skipped:
    own + the compatible peer still average, and merging_data.log names
    only the peer that was merged."""
    m = _peer_module(tmp_path, "slips-a", _net(tmp_path, "slips-a"))
    m._align_head_on_buffer = MagicMock()
    m._save_merged_model = MagicMock()
    m._save_final_merged_model = MagicMock()
    own = m.model.weights_for_sharing()
    good = _net(tmp_path, "slips-b").weights_for_sharing()
    if bad == "missing_key":
        cls = "random_projection_mlp"
        shared = _net(tmp_path, "slips-c").weights_for_sharing()
        del shared["fc1_bias"]
    else:
        cls = "simple_mlp"
        shared = fnm.build_with_init_seed(
            7, lambda: fnm.SimpleMLP(18)
        ).weights_for_sharing()
    for pid, pcls, ws in (
        ("slips-c", cls, shared),
        ("slips-b", "random_projection_mlp", good),
    ):
        m.handle_p2p_model(
            {
                "peer_id": pid,
                "model_class": pcls,
                "shared": {k: v.tolist() for k, v in ws.items()},
                "timestamp": 1.0,
            }
        )
    m.trigger_merge()
    assert m._using_merged_model and m.merge_count == 1
    merged = m.merged_model.weights_for_sharing()
    for key in own:
        assert torch.allclose(merged[key], (own[key] + good[key]) / 2)
    # the merge is built on a copy: the local lineage is untouched
    local = m.model.weights_for_sharing()
    assert all(torch.equal(local[key], own[key]) for key in own)
    merging = (tmp_path / "slips-a" / "merging_data.log").read_text()
    assert "peer=slips-b" in merging and "peer=slips-c" not in merging


def _sent_shared(module):
    """The shared tensors of the last model this module published."""
    _channel, raw = module.db.publish.call_args.args
    msg = json.loads(base64.b64decode(json.loads(raw)["message"]))
    return {k: torch.tensor(v) for k, v in msg["shared"].items()}


def _merge_ready(tmp_path, merge_head):
    m = _peer_module(tmp_path, "slips-a", _net(tmp_path, "slips-a"))
    m.merge_head = merge_head
    m._align_head_on_buffer = MagicMock()
    m._save_merged_model = MagicMock()
    m._save_final_merged_model = MagicMock()
    return m


def _receive(m, peer_id, shared):
    m.handle_p2p_model(
        {
            "peer_id": peer_id,
            "model_class": "random_projection_mlp",
            "shared": {k: v.tolist() for k, v in shared.items()},
            "timestamp": 1.0,
        }
    )


@pytest.mark.parametrize("merge_head", [False, True])
def test_the_head_is_sent_only_with_merge_head(tmp_path, merge_head):
    a = _peer_module(tmp_path, "slips-a", _net(tmp_path, "slips-a"))
    a.merge_head = merge_head
    w, b = a.model.get_head_weights()
    head = (w + 1.0, b - 1.0)
    a.send_model_to_peers(head=head)
    sent = _sent_shared(a)
    shared = a.model.weights_for_sharing()
    extra = set(fnm.HEAD_KEYS) if merge_head else set()
    assert set(sent) == set(shared) | extra
    if merge_head:
        assert torch.equal(sent["head_weight"], head[0])
        assert torch.equal(sent["head_bias"], head[1])


def test_with_merge_head_the_head_after_local_training_is_sent(tmp_path):
    """_train_batch shares the head as it is after local full training, the
    same head the merged fine-tune starts from - not the head after the
    local head fine-tune."""
    m = _trainable(tmp_path)
    m.merge_head = True
    after_local = {}
    real_fit = m.fit_incremental_model

    def spy_fit(x, y, classes=None, train_target="local"):
        out = real_fit(x, y, classes=classes, train_target=train_target)
        if train_target == "local":
            after_local["head"] = m.model.get_head_weights()
        return out

    m.fit_incremental_model = spy_fit
    m._train_batch()
    sent = _sent_shared(m)
    assert torch.equal(sent["head_weight"], after_local["head"][0])
    assert torch.equal(sent["head_bias"], after_local["head"][1])
    # the served local head is the fine-tuned one, not the one sent
    assert not torch.equal(m.model.get_head_weights()[0], sent["head_weight"])


@pytest.mark.parametrize("merge_head", [False, True])
def test_merge_head_merges_the_heads_with_the_unchanged_rule(
    tmp_path, merge_head
):
    """With merge_head the merge rule (here average, unchanged) also merges
    the heads - own = the head after local training - and the merged head
    fine-tune starts from that; without it the merged model starts from the
    own head. Either way the local model keeps its own head and layers."""
    m = _merge_ready(tmp_path, merge_head)
    own = m.model.weights_for_sharing()
    local_head = m.model.get_head_weights()
    head_before = (local_head[0] + 0.25, local_head[1] - 0.25)
    peer = _net(tmp_path, "slips-b")
    peer_head = tuple(t - 0.5 for t in peer.get_head_weights())
    payload = {k: v + 0.1 for k, v in peer.weights_for_sharing().items()}
    if merge_head:
        payload = fnm.with_shared_head(payload, peer_head)
    _receive(m, "slips-b", payload)
    m.trigger_merge(*head_before)
    assert m._using_merged_model and m.merge_count == 1
    merged = m.merged_model
    for key in own:
        assert torch.allclose(
            merged.weights_for_sharing()[key], (own[key] + payload[key]) / 2
        )
    want = (
        tuple((a + b) / 2 for a, b in zip(head_before, peer_head))
        if merge_head
        else head_before
    )
    got = merged.get_head_weights()
    assert torch.allclose(got[0], want[0]) and torch.allclose(got[1], want[1])
    assert torch.equal(m.model.get_head_weights()[0], local_head[0])
    assert torch.equal(m.model.get_head_weights()[1], local_head[1])
    local = m.model.weights_for_sharing()
    assert all(torch.equal(local[key], own[key]) for key in own)
    merging = (tmp_path / "slips-a" / "merging_data.log").read_text()
    assert ("merge_head=True" in merging) == merge_head


def test_with_merge_head_a_peer_without_a_head_is_skipped(tmp_path):
    m = _merge_ready(tmp_path, True)
    _receive(m, "slips-b", _net(tmp_path, "slips-b").weights_for_sharing())
    m.trigger_merge()
    assert m.merge_count == 0 and not m._using_merged_model


def test_merge_head_leaves_the_merge_rules_unchanged():
    """Head sharing only adds payload keys: every registered rule still has
    the (own_shared, peer_models, shared_keys, trust) signature."""
    import inspect

    for rule in fnm.MERGE_REGISTRY.values():
        assert list(inspect.signature(rule).parameters) == [
            "own_shared",
            "peer_models",
            "shared_keys",
            "trust",
        ]


def test_malformed_peer_payload_keeps_the_last_good_model(tmp_path):
    """Ragged or non-numeric tensors, or a payload without peer_id, are
    dropped without raising and leave the peer's last good model in place."""
    m = _peer_module(tmp_path, "slips-a")
    good = {"fc1_weight": [[1.0, 2.0], [3.0, 4.0]], "fc1_bias": [0.5, -0.5]}
    m.handle_p2p_model({"peer_id": "slips-b", "shared": good, "timestamp": 5})
    for shared in (
        {"fc1_weight": [[1.0, 2.0], [3.0]], "fc1_bias": [0.0]},  # ragged
        {"fc1_weight": "garbage", "fc1_bias": [0.0, 0.0]},  # not numeric
    ):
        m.handle_p2p_model(
            {"peer_id": "slips-b", "shared": shared, "timestamp": 9}
        )
    m.handle_p2p_model({"shared": good, "timestamp": 9})  # no peer_id
    assert set(m.peer_models) == {"slips-b"}
    stored = m.peer_models["slips-b"]
    assert stored["timestamp"] == 5
    assert torch.equal(stored["fc1_weight"], torch.tensor(good["fc1_weight"]))
    assert torch.equal(stored["fc1_bias"], torch.tensor(good["fc1_bias"]))


# --------------------------------------------------------------------------
# merge rules: shared contract + outlier handling
# --------------------------------------------------------------------------
@pytest.mark.parametrize("rule", sorted(fnm.MERGE_REGISTRY))
def test_every_merge_rule_is_a_pure_convex_blend(rule):
    """Any rule returns, per shared key, a new tensor of the same shape and
    dtype that lies inside the element-wise hull of own + peers, ignores
    non-shared entries of the peer stash (timestamp) and leaves its inputs
    untouched."""
    g = torch.Generator().manual_seed(0)

    def weights():
        return {
            "w": torch.randn(3, 4, generator=g),
            "b": torch.randn(3, generator=g),
        }

    own = weights()
    peers = {
        pid: {**weights(), "timestamp": 1.0} for pid in ("p1", "p2", "p3")
    }
    trust = {
        "p1": {"score": 0.9, "confidence": 0.8},
        "p2": {"score": 0.2, "confidence": 1.0},
    }
    before = [
        {k: v.clone() for k, v in d.items() if torch.is_tensor(v)}
        for d in (own, *peers.values())
    ]
    out = fnm.MERGE_REGISTRY[rule](own, peers, ["b", "w"], trust)
    assert sorted(out) == ["b", "w"]
    candidates = [own, *peers.values()]
    for key in ("b", "w"):
        assert out[key].shape == own[key].shape
        assert out[key].dtype == own[key].dtype
        stack = torch.stack([c[key] for c in candidates])
        assert (out[key] >= stack.min(0).values - 1e-6).all()
        assert (out[key] <= stack.max(0).values + 1e-6).all()
        assert all(
            out[key].data_ptr() != c[key].data_ptr() for c in candidates
        )
    for snap, live in zip(before, candidates):
        assert all(torch.equal(snap[k], live[k]) for k in snap)


def test_proximity_gives_a_far_outlier_peer_almost_no_weight():
    """With most candidates close to own, the median-heuristic bandwidth is
    small and a far peer's kernel weight vanishes (plain averaging would be
    dragged ~17 units towards it)."""
    own = {"w": torch.zeros(4)}
    peers = {f"p{i}": {"w": torch.full((4,), 0.1 * i)} for i in range(1, 5)}
    peers["outlier"] = {"w": torch.full((4,), 100.0)}
    out = fnm.merge_proximity(own, peers, ["w"])["w"]
    assert (out >= 0).all() and (out <= 0.4 + 1e-6).all()
    assert (fnm.merge_average(own, peers, ["w"])["w"] > 16).all()


# --------------------------------------------------------------------------
# class balancing presets through model creation and real training
# --------------------------------------------------------------------------
def _trainable(tmp_path, balancing=""):
    m = _peer_module(tmp_path, "slips-a")
    m.seed = SEED
    m.init_seed = fnm.shared_init_seed(SEED)
    m.rp_path = str(tmp_path / "rp.bin")
    m.input_dim = None
    m.balancing = balancing
    m._undersample = balancing == "undersample"
    m._read_module_config_bool = lambda key, default: default
    m.scaler = StandardScaler()
    m.is_preprocessor_fitted = False
    m.local_training_epochs = 2
    m.merge_finetune_epochs = 1
    m.device = torch.device("cpu")
    m._adam_state = {}
    m.training_count_window = 3
    m._training_trigger = "window"
    m.local_state_path = str(tmp_path / "local_state.bin")
    m.local_scaler_path = str(tmp_path / "local_scaler.bin")
    m._local_only_model = None
    m._is_fitted = False
    m._sofar_chunks = []
    rng = np.random.default_rng(0)
    m.training_buffer_x = list(rng.normal(size=(10, 18)).astype(np.float32))
    m.training_buffer_y = [MAL] * 8 + [BEN] * 2
    m.training_buffer_ids = [f"u{i}" for i in range(10)]
    m._buffered_flow_ids = {f"u{i}" for i in range(10)}
    return m


def test_learning_rate_scales_the_adam_step(tmp_path):
    """From a fresh Adam state the first step (incl. decoupled weight decay)
    is linear in the learning rate: doubling it doubles every weight change."""
    deltas = []
    for lr in (0.01, 0.02):
        m = _trainable(tmp_path / str(lr))
        m.local_training_epochs = 1
        m.learning_rate = lr
        m.model = _net(tmp_path, "slips-a")
        before = {k: v.clone() for k, v in m.model.state_dict().items()}
        m.fit_incremental_model(
            np.stack(m.training_buffer_x), m.training_buffer_y
        )
        after = m.model.state_dict()
        deltas.append({k: after[k] - before[k] for k in before})
    assert any(d.abs().sum() > 0 for d in deltas[0].values())
    for k in deltas[0]:
        assert torch.allclose(deltas[1][k], 2 * deltas[0][k], atol=1e-6)


def test_warm_start_keeps_its_scaler_through_the_base_read_model(
    tmp_path, monkeypatch
):
    """train_from_scratch: false reloads latest_local_* in init(); the base
    class read_model (pre_main) must not swap that scaler for an empty one.
    With nothing reloaded the base class still runs."""
    src = _trainable(tmp_path)
    src.model = src.create_empty_model()
    src.scaler.partial_fit(np.ones((5, 18)))
    torch.save(src.model.state_dict(), src.local_state_path)
    with open(src.local_scaler_path, "wb") as fh:
        pickle.dump(src.scaler, fh)
    base = MagicMock()
    monkeypatch.setattr(ml_base.MLBaseDetection, "read_model", base)

    m = _trainable(tmp_path)
    m._warm_started = False
    m._load_local_model()
    assert m._warm_started
    m.read_model()
    base.assert_not_called()
    assert m.scaler.n_samples_seen_ == 5 and m.preprocessor is m.scaler
    m._warm_started = False
    m.read_model()
    base.assert_called_once()


@pytest.mark.parametrize(
    "balancing, class_weighting_cfg, weighted",
    [
        ("undersample", True, False),
        ("none", True, False),
        ("weighting", False, True),
        ("", False, False),  # no preset: the yaml class_weighting decides
    ],
)
def test_balancing_preset_decides_the_class_weighting(
    tmp_path, balancing, class_weighting_cfg, weighted
):
    """A balancing preset overrides yaml class_weighting: only 'weighting'
    trains on the weighted loss. Without a preset, class_weighting applies.
    The override is per model instance; the class default is unchanged."""
    m = _trainable(tmp_path, balancing)
    m._read_module_config_bool = lambda key, default: (
        class_weighting_cfg if key == "class_weighting" else default
    )
    model = m.create_empty_model()
    assert model.USE_CLASS_WEIGHTING is weighted
    assert fnm.SimpleFederatedNet.USE_CLASS_WEIGHTING is True  # class intact


def test_undersample_preset_trains_and_logs_the_balanced_batch(tmp_path):
    """Real local training with balancing=undersample: 8 mal / 2 ben in the
    buffer -> both training stages see and log 2/2, on an unweighted loss;
    the buffer is consumed and the fresh model is published."""
    m = _trainable(tmp_path, "undersample")
    m._train_batch()
    out = tmp_path / "slips-a"
    for name in ("local_train.log", "local_head_train.log"):
        lines = [ln.strip() for ln in (out / name).read_text().splitlines()]
        hdr = [
            TRAIN_HDR_RE.match(ln) for ln in lines if TRAIN_HDR_RE.match(ln)
        ]
        assert [h.group(1, 2, 3, 5) for h in hdr] == [
            ("window", "3", "2", "2")
        ]
        assert any(ln.startswith("batch 4 (Mal:2 Ben:2)") for ln in lines)
    assert m.model.USE_CLASS_WEIGHTING is False
    assert m.training_buffer_x == [] and m._buffered_flow_ids == set()
    assert m._is_fitted and m._local_only_model is not m.model
    assert m.db.publish.call_args.args[0] == "p2p_pygo"


def test_merged_head_finetunes_on_the_same_batch_as_the_local_head(tmp_path):
    """Local and merged heads must differ only in fc1's origin (trigger_merge
    docstring): the merge fine-tune sees exactly the scaled batch the local
    head fine-tune saw, and merging adds no data to the scaler."""
    m = _trainable(tmp_path)
    m.peer_models["slips-b"] = _net(tmp_path, "slips-b").weights_for_sharing()
    seen = {}
    real_fit = m.fit_incremental_model

    def spy_fit(x, y, classes=None, train_target="local"):
        seen[train_target] = (
            np.array(x, copy=True),
            int(m.scaler.n_samples_seen_),
            m.scaler.mean_.copy(),
        )
        return real_fit(x, y, classes=classes, train_target=train_target)

    m.fit_incremental_model = spy_fit
    m._train_batch()
    assert set(seen) == {"local", "local_head", "merged"}
    assert m._using_merged_model and m.merge_count == 1
    x_head, n_head, mean_head = seen["local_head"]
    x_merged, n_merged, mean_merged = seen["merged"]
    assert n_head == 10
    assert np.allclose(x_merged, x_head)
    assert n_merged == n_head
    assert np.allclose(mean_merged, mean_head)


@pytest.mark.parametrize("n, size", [(10, 0), (10, 10), (10, 25)])
def test_without_a_smaller_minibatch_size_the_batch_stays_whole(n, size):
    y = np.array([MAL, BEN] * (n // 2))
    parts = fnm.minibatch_indices(y, size, np.random.default_rng(0))
    assert len(parts) == 1 and np.array_equal(parts[0], np.arange(n))


@pytest.mark.parametrize(
    "n_mal, n_ben, size", [(59, 59, 100), (615, 615, 100), (8, 2, 3)]
)
def test_minibatches_cover_the_batch_once_and_keep_its_class_ratio(
    n_mal, n_ben, size
):
    y = np.array([MAL] * n_mal + [BEN] * n_ben)
    parts = fnm.minibatch_indices(y, size, np.random.default_rng(0))
    n = len(y)
    assert len(parts) == -(-n // size)
    assert all(len(p) <= size for p in parts)
    assert np.array_equal(np.sort(np.concatenate(parts)), np.arange(n))
    for p in parts:
        want = n_mal * len(p) / n
        assert abs(int(np.sum(y[p] == MAL)) - want) <= 1


def test_both_finetunes_draw_the_same_minibatches():
    y = np.array([MAL] * 40 + [BEN] * 40)

    def split(finetune):
        rng = fnm.minibatch_rng(SEED, 2, 7, finetune)
        return [p.tolist() for p in fnm.minibatch_indices(y, 30, rng)]

    assert split(True) == split(True)
    assert split(True) != split(False)


@pytest.mark.parametrize("size, steps", [(0, 1), (3, 4), (100, 1)])
def test_minibatch_size_takes_one_adam_step_per_minibatch(
    tmp_path, size, steps
):
    """10 flows, one epoch: one step on the full batch, ceil(10 / 3) = 4
    steps with minibatch_size 3."""
    m = _trainable(tmp_path)
    m.local_training_epochs = 1
    m.minibatch_size = size
    m.fit_incremental_model(np.stack(m.training_buffer_x), m.training_buffer_y)
    assert m._adam_state["fc1.weight"]["step"] == steps
    assert m._adam_state["head.weight"]["step"] == steps


def _spy_train(m):
    """Record the fc1 after each training pass of _train_batch and the Adam
    state each pass starts from."""
    seen = {}
    real_fit = m.fit_incremental_model

    def spy_fit(x, y, classes=None, train_target="local"):
        start = {k: v["step"] for k, v in m._adam_state.items()}
        out = real_fit(x, y, classes=classes, train_target=train_target)
        seen[train_target] = (
            start,
            {k: v.clone() for k, v in m.model.weights_for_sharing().items()},
        )
        return out

    m.fit_incremental_model = spy_fit
    return seen


@pytest.mark.parametrize("finetune_fc_layers", [False, True])
def test_peers_get_the_model_after_local_training(
    tmp_path, finetune_fc_layers
):
    """What is sent and merged is fc1 after local training, before the
    fine-tune - also when finetune_fc_layers moves fc1 in the fine-tune."""
    m = _trainable(tmp_path)
    m.finetune_fc_layers = finetune_fc_layers
    m.peer_models["slips-b"] = _net(tmp_path, "slips-b").weights_for_sharing()
    seen = _spy_train(m)
    m._train_batch()
    after_local = seen["local"][1]
    sent = _sent_shared(m)
    assert all(torch.equal(sent[k], after_local[k]) for k in after_local)
    npz = np.load(tmp_path / "slips-a" / "weights" / "merge_0001.npz")
    own = torch.cat([after_local[k].reshape(-1) for k in sorted(after_local)])
    assert np.allclose(npz["own"], own.numpy())
    local_moved = any(
        not torch.equal(m.model.weights_for_sharing()[k], after_local[k])
        for k in after_local
    )
    assert local_moved == finetune_fc_layers


def test_finetune_fc_layers_trains_fc1_in_both_finetunes_from_fresh_adam(
    tmp_path,
):
    """merge_finetune_adam 'fresh': both fine-tunes start from an empty Adam
    state and move fc1; the local training state (2 epochs = 2 steps)
    carries on unchanged."""
    m = _trainable(tmp_path)
    m.finetune_fc_layers = True
    m.merge_finetune_adam = "fresh"
    peer = _net(tmp_path, "slips-b").weights_for_sharing()
    m.peer_models["slips-b"] = peer
    seen = _spy_train(m)
    m._train_batch()
    assert seen["local_head"][0] == {} and seen["merged"][0] == {}
    after_local = seen["local"][1]
    averaged = {k: (after_local[k] + peer[k]) / 2 for k in after_local}
    merged = m.merged_model.weights_for_sharing()
    assert any(not torch.allclose(merged[k], averaged[k]) for k in averaged)
    assert m._adam_state["fc1.weight"]["step"] == m.local_training_epochs


def _adam_copy(state):
    return {
        name: {k: v.clone() if torch.is_tensor(v) else v for k, v in s.items()}
        for name, s in state.items()
    }


def _adam_equal(a, b):
    return set(a) == set(b) and all(
        set(a[n]) == set(b[n])
        and all(
            (
                torch.equal(a[n][k], b[n][k])
                if torch.is_tensor(a[n][k])
                else a[n][k] == b[n][k]
            )
            for k in a[n]
        )
        for n in a
    )


@pytest.mark.parametrize("finetune_fc_layers", [False, True])
def test_finetunes_start_from_own_copies_of_the_local_training_adam_state(
    tmp_path, finetune_fc_layers
):
    """merge_finetune_adam 'copy': each fine-tune starts from its own copy
    of the state local training left (never the training state itself, nor
    the other's), trains on it, and the local training state carries on to
    the next window exactly as local training left it."""
    m = _trainable(tmp_path)
    m.finetune_fc_layers = finetune_fc_layers
    m.merge_finetune_adam = "copy"
    m.peer_models["slips-b"] = _net(tmp_path, "slips-b").weights_for_sharing()
    seen = {}
    real_fit = m.fit_incremental_model

    def spy(x, y, classes=None, train_target="local"):
        seen[train_target] = {
            "obj": m._adam_state,
            "start": _adam_copy(m._adam_state),
        }
        out = real_fit(x, y, classes=classes, train_target=train_target)
        seen[train_target]["end"] = _adam_copy(m._adam_state)
        return out

    m.fit_incremental_model = spy
    m._train_batch()
    trained = seen["local"]["end"]
    assert trained["head.weight"]["step"] == m.local_training_epochs
    objs = [seen[s]["obj"] for s in ("local", "local_head", "merged")]
    assert len({id(o) for o in objs}) == 3
    for stage in ("local_head", "merged"):
        assert _adam_equal(seen[stage]["start"], trained)
        assert (
            seen[stage]["end"]["head.weight"]["step"]
            == m.local_training_epochs + m.merge_finetune_epochs
        )
    assert m._adam_state is seen["local"]["obj"]
    assert _adam_equal(_adam_copy(m._adam_state), trained)


def test_head_only_finetune_leaves_the_averaged_fc1_as_merged(tmp_path):
    m = _trainable(tmp_path)
    m.finetune_fc_layers = False
    peer = _net(tmp_path, "slips-b").weights_for_sharing()
    m.peer_models["slips-b"] = peer
    seen = _spy_train(m)
    m._train_batch()
    after_local = seen["local"][1]
    merged = m.merged_model.weights_for_sharing()
    for k in after_local:
        assert torch.allclose(merged[k], (after_local[k] + peer[k]) / 2)


FINETUNE_RE = re.compile(
    r"finetune \| gap_before=([\d.]+) \| gap_after=([\d.]+) \| undone=(-?[\d.]+|nan)"
    r" \| local_moved=([\d.]+) \| merged_moved=([\d.]+) \| fc_trained=(\w+)"
)


@pytest.mark.parametrize("finetune_fc_layers", [False, True])
def test_each_merge_logs_how_much_the_finetunes_undo(
    tmp_path, finetune_fc_layers
):
    """gap_before is the merged-vs-own distance where the fine-tunes start
    (= merged_vs_own without merge_head: the heads start equal), gap_after
    the distance after them, undone = 1 - after / before."""
    m = _trainable(tmp_path)
    m.finetune_fc_layers = finetune_fc_layers
    m.peer_models["slips-b"] = _net(tmp_path, "slips-b").weights_for_sharing()
    m._train_batch()
    log = (tmp_path / "slips-a" / "merging_data.log").read_text()
    hit = FINETUNE_RE.search(log)
    assert hit
    before, after, undone, local_moved, merged_moved = map(
        float, hit.groups()[:5]
    )
    assert hit.group(6) == str(finetune_fc_layers)
    merged_vs_own = float(
        re.search(r"merged_vs_own \| L2_dist=([\d.]+)", log).group(1)
    )
    assert before == pytest.approx(merged_vs_own, rel=1e-4)
    assert undone == pytest.approx(1 - after / before, abs=1e-3)
    assert local_moved > 0 and merged_moved > 0


def test_the_scaler_learns_the_whole_window_not_the_undersampled_batch(
    tmp_path,
):
    """8 mal / 2 ben: the scaler sees all 10 flows, training only 2/2;
    scaler_stats.jsonl logs the fit."""
    m = _trainable(tmp_path, "undersample")
    m._train_batch()
    assert m.scaler.n_samples_seen_ == 10
    out = tmp_path / "slips-a"
    train = (out / "local_train.log").read_text()
    assert "batch 4 (Mal:2 Ben:2)" in train
    (row,) = [
        json.loads(ln)
        for ln in (out / "scaler_stats.jsonl").read_text().splitlines()
    ]
    assert (row["window"], row["rows"], row["n_seen"]) == (3, 10, 10)
    assert row["features"] == m._get_feature_order()
    assert np.allclose(row["mean"], m.scaler.mean_)
    assert np.allclose(row["scale"], m.scaler.scale_)


def test_one_scaler_fit_per_training_the_finetunes_reuse_it(tmp_path):
    """A training with a merge fits the scaler once (10 flows), and every
    training pass - local, local fine-tune, merged fine-tune - sees the
    batch scaled with that fit."""
    m = _trainable(tmp_path)
    m.peer_models["slips-b"] = _net(tmp_path, "slips-b").weights_for_sharing()
    seen = []
    real_fit = m.fit_incremental_model

    def spy_fit(x, y, classes=None, train_target="local"):
        seen.append((train_target, int(m.scaler.n_samples_seen_), x.copy()))
        return real_fit(x, y, classes=classes, train_target=train_target)

    m.fit_incremental_model = spy_fit
    raw = np.stack(m.training_buffer_x)
    m._train_batch()
    assert [t for t, _, _ in seen] == ["local", "local_head", "merged"]
    assert all(n == 10 for _, n, _ in seen)
    want = m.scaler.transform(raw)
    assert all(np.allclose(x, want) for _, _, x in seen)


def test_training_gets_the_whole_window_for_the_scaler_after_the_tests(
    monkeypatch, tmp_path
):
    """At each close every open window is scored first (with the previous
    scaler); the training then runs with the whole finalized window -
    before undersampling dropped flows - for its scaler fit."""
    p = Pipe(monkeypatch, tmp_path, k=1, fitted=True)
    p.m.seed = SEED
    p.m._undersample = True
    events = []
    real_test_cell = p.m._test_cell

    def spy_test_cell(cell):
        events.append(("test",))
        real_test_cell(cell)

    def spy_train(scaler_rows=None):
        events.append(("train", len(p.m.training_buffer_y), len(scaler_rows)))
        p._train()

    p.m._test_cell = spy_test_cell
    p.m._train_batch = spy_train
    p.close("a", "b", "c", alerts=[("A1", ["a"])])
    p.close("d")
    p.close()
    trains = [i for i, e in enumerate(events) if e[0] == "train"]
    # the 3-flow window (1 mal / 2 ben): scaler gets all 3, training 1/1
    assert [events[i] for i in trains] == [("train", 2, 3), ("train", 1, 1)]
    assert all(events[i - 1] == ("test",) for i in trains)


# --------------------------------------------------------------------------
# scaler sharing (merge_scaler)
# --------------------------------------------------------------------------
def _fitted_scaler(rng, n, loc, scale, constant=7.0):
    """A StandardScaler fit in two partial_fit calls (as the module fits
    window by window) on 18 features; feature 0 is constant."""
    x = rng.normal(loc, scale, size=(n, 18))
    x[:, 0] = constant
    sc = StandardScaler()
    sc.partial_fit(x[: n // 2])
    sc.partial_fit(x[n // 2 :])
    return sc, x


@pytest.mark.parametrize("rule", sorted(fnm.MERGE_REGISTRY))
@pytest.mark.parametrize("n_peers", [1, 3])
def test_merge_weights_are_the_weights_the_rule_blends_with(rule, n_peers):
    """For a one-tensor model, sum w_i * x_i with MERGE_WEIGHTS is exactly
    what the rule in MERGE_REGISTRY returns; the weights sum to 1."""
    g = torch.Generator().manual_seed(n_peers)
    own = {"w": torch.randn(12, generator=g)}
    peers = {
        f"p{i}": {"w": torch.randn(12, generator=g) * (i + 1)}
        for i in range(n_peers)
    }
    trust = {"p0": {"trust": 0.4}}
    weights = fnm.MERGE_WEIGHTS[rule](
        own["w"], {pid: m["w"] for pid, m in peers.items()}, trust
    )
    assert set(weights) == {"own", *peers}
    assert sum(weights.values()) == pytest.approx(1.0)
    blend = weights["own"] * own["w"] + sum(
        weights[pid] * m["w"] for pid, m in peers.items()
    )
    merged = fnm.MERGE_REGISTRY[rule](own, peers, ["w"], trust)["w"]
    assert torch.allclose(blend, merged, atol=1e-6)


def test_every_merge_rule_has_its_weights():
    assert set(fnm.MERGE_WEIGHTS) == set(fnm.MERGE_REGISTRY)


def test_scaler_payload_round_trips_through_json():
    sc, _ = _fitted_scaler(np.random.default_rng(0), 40, 2.0, 3.0)
    payload = fnm.scaler_payload(sc)
    assert set(payload) == {"mean", "var"}
    got = fnm.scaler_from_payload(json.loads(json.dumps(payload)), 18)
    assert np.array_equal(got["mean"], sc.mean_)
    assert np.array_equal(got["var"], sc.var_)


def test_an_unfitted_scaler_sends_no_payload():
    assert fnm.scaler_payload(StandardScaler()) is None


@pytest.mark.parametrize(
    "payload",
    [
        None,
        "garbage",
        {"mean": [0.0] * 18},
        {"mean": [0.0] * 17, "var": [1.0] * 17},
        {"mean": [0.0] * 18, "var": [1.0] * 17},
        {"mean": [0.0] * 17 + [float("nan")], "var": [1.0] * 18},
        {"mean": [0.0] * 18, "var": [1.0] * 17 + [float("inf")]},
        {"mean": [0.0] * 18, "var": [1.0] * 17 + [-1e-3]},
        {"mean": [[0.0], [1.0, 2.0]], "var": [1.0] * 18},
        {"mean": ["a"] * 18, "var": [1.0] * 18},
    ],
)
def test_a_malformed_peer_scaler_is_rejected(payload):
    assert fnm.scaler_from_payload(payload, 18) is None


@pytest.mark.parametrize("w_own", [0.5, 0.6225, 0.9])
def test_pooled_scaler_is_the_weighted_mixture_of_the_scalers(w_own):
    """mean = sum w_i mean_i, var = sum w_i (var_i + mean_i^2) - mean^2 (the
    formula, not an average of standard deviations); with w_i = n_i / N it
    equals the scaler fit on all the data together, a constant feature
    included (scale 1, as StandardScaler sets it)."""
    rng = np.random.default_rng(1)
    own, x_own = _fitted_scaler(rng, 60, 0.0, 1.0)
    peer, x_peer = _fitted_scaler(rng, 40, 5.0, 3.0)
    stats = {
        "own": fnm.scaler_from_payload(fnm.scaler_payload(own), 18),
        "peer": fnm.scaler_from_payload(fnm.scaler_payload(peer), 18),
    }
    weights = {"own": w_own, "peer": 1.0 - w_own}
    mean, var = fnm.pool_scaler_stats(stats, weights)
    want_mean = w_own * own.mean_ + (1 - w_own) * peer.mean_
    want_var = (
        w_own * (own.var_ + own.mean_**2)
        + (1 - w_own) * (peer.var_ + peer.mean_**2)
        - want_mean**2
    )
    assert np.allclose(mean, want_mean)
    assert np.allclose(var, want_var)
    # not the average of the standard deviations
    avg_sd = w_own * np.sqrt(own.var_) + (1 - w_own) * np.sqrt(peer.var_)
    assert not np.allclose(np.sqrt(var[1:]), avg_sd[1:])
    # sample-count weights reproduce the fit on the pooled data
    n_w = {"own": 60 / 100, "peer": 40 / 100}
    pooled = fnm.scaler_from_stats(own, *fnm.pool_scaler_stats(stats, n_w))
    direct = StandardScaler().fit(np.vstack([x_own, x_peer]))
    assert np.allclose(pooled.mean_, direct.mean_)
    assert np.allclose(pooled.var_, direct.var_)
    assert np.allclose(pooled.scale_, direct.scale_)
    assert pooled.scale_[0] == 1.0
    probe = rng.normal(2.0, 4.0, size=(5, 18))
    assert np.allclose(pooled.transform(probe), direct.transform(probe))
    # the own scaler is not touched
    assert np.allclose(own.mean_, x_own.mean(axis=0))


def test_scaler_travels_with_the_model_over_p2p(monkeypatch, tmp_path):
    """With merge_scaler the sender's scaler statistics ride in the same P2P
    model message (a few hundred bytes of ~100 KB); the receiver stores them
    validated next to the peer's model. Without the option the message is
    exactly the one before (no "scaler" key)."""
    a = _peer_module(tmp_path, "slips-a", _net(tmp_path, "slips-a"))
    a.scaler, _ = _fitted_scaler(np.random.default_rng(2), 40, 1.0, 2.0)
    a.send_model_to_peers()
    plain = json.loads(a.db.publish.call_args.args[1])["message"]
    assert "scaler" not in json.loads(base64.b64decode(plain))
    a.merge_scaler = True
    a.send_model_to_peers()
    channel, raw = a.db.publish.call_args.args
    go = json.loads(raw)
    assert channel == "p2p_pygo" and "\n" not in go["message"]
    assert len(go["message"]) - len(plain) < 0.02 * len(plain)
    wire = {
        "message_type": "go_data",
        "message_contents": {
            "message": go["message"],
            "reporter": "QmPeerA",
            "report_time": 0,
        },
    }
    b = _peer_module(tmp_path, "slips-b", _net(tmp_path, "slips-b"))
    b.mode = "train"
    b.channels = {"p2p_gopy": object()}
    b._p2p_connected = True
    inbox = [{"data": json.dumps(wire)}]
    b.get_msg = lambda channel: inbox.pop() if inbox else None
    b.window_size_seconds = WIN
    b.training_window_start = fnm.time.time() + 10 * WIN  # no close now
    monkeypatch.setattr(fnm.time, "sleep", lambda s: None)
    assert b.main() is False
    got = b.peer_scalers["slips-a"]
    assert np.array_equal(got["mean"], a.scaler.mean_)
    assert np.array_equal(got["var"], a.scaler.var_)
    assert set(b.peer_models["slips-a"]) == set(
        a.model.weights_for_sharing()
    ) | {"timestamp"}


def test_a_new_model_without_a_scaler_clears_the_stored_one(tmp_path):
    m = _peer_module(tmp_path, "slips-a")
    sc, _ = _fitted_scaler(np.random.default_rng(3), 20, 0.0, 1.0)
    shared = {"fc1_weight": [[1.0, 2.0]], "fc1_bias": [0.5]}
    m.handle_p2p_model(
        {
            "peer_id": "slips-b",
            "shared": shared,
            "scaler": fnm.scaler_payload(sc),
        }
    )
    assert m.peer_scalers["slips-b"] is not None
    m.handle_p2p_model({"peer_id": "slips-b", "shared": shared})
    assert m.peer_scalers["slips-b"] is None


def _scaler_merge(tmp_path, rule):
    """A real _train_batch with merge_scaler on and one peer whose model and
    scaler arrived over P2P; records each training pass's input."""
    m = _trainable(tmp_path)
    m.merge_scaler = True
    m.merge_rule = rule
    peer_scaler, _ = _fitted_scaler(np.random.default_rng(4), 40, 3.0, 2.0)
    peer = _net(tmp_path, "slips-b").weights_for_sharing()
    peer = {k: v + 0.05 for k, v in peer.items()}
    m.handle_p2p_model(
        {
            "peer_id": "slips-b",
            "model_class": "random_projection_mlp",
            "shared": {k: v.tolist() for k, v in peer.items()},
            "scaler": fnm.scaler_payload(peer_scaler),
            "timestamp": 1.0,
        }
    )
    seen = {}
    real_fit = m.fit_incremental_model

    def spy_fit(x, y, classes=None, train_target="local"):
        seen[train_target] = np.array(x, copy=True)
        return real_fit(x, y, classes=classes, train_target=train_target)

    m.fit_incremental_model = spy_fit
    raw = np.stack(m.training_buffer_x)
    seen["after_local"] = {}
    real_send = m.send_model_to_peers

    def spy_send(head=None, shared=None):
        seen["after_local"] = {k: v.clone() for k, v in shared.items()}
        return real_send(head=head, shared=shared)

    m.send_model_to_peers = spy_send
    m._train_batch()
    return m, peer, peer_scaler, raw, seen


@pytest.mark.parametrize("rule", ["average", "proximity"])
def test_merge_scaler_pools_the_scalers_with_the_rule_weights(tmp_path, rule):
    """The merged model gets own + peer scalers pooled with the merge rule's
    weights for the two models (average 1/2, proximity 62/38), and its
    fine-tune trains on the batch scaled with it; the local model keeps the
    own scaler, its fine-tune on the own scaling."""
    m, peer, peer_scaler, raw, seen = _scaler_merge(tmp_path, rule)
    assert m._using_merged_model and m.merged_scaler is not None
    own_flat = torch.cat(
        [seen["after_local"][k].reshape(-1) for k in sorted(peer)]
    )
    peer_flat = torch.cat([peer[k].reshape(-1) for k in sorted(peer)])
    weights = fnm.MERGE_WEIGHTS[rule](own_flat, {"slips-b": peer_flat}, {})
    want_own = {"average": 0.5, "proximity": 1 / (1 + np.exp(-0.5))}[rule]
    assert weights["own"] == pytest.approx(want_own)
    w = weights["own"]
    mean = w * m.scaler.mean_ + (1 - w) * peer_scaler.mean_
    var = (
        w * (m.scaler.var_ + m.scaler.mean_**2)
        + (1 - w) * (peer_scaler.var_ + peer_scaler.mean_**2)
        - mean**2
    )
    assert np.allclose(m.merged_scaler.mean_, mean)
    assert np.allclose(m.merged_scaler.var_, var)
    assert m.scaler.n_samples_seen_ == 10  # own scaler: own data only
    assert np.allclose(seen["local_head"], m.scaler.transform(raw))
    assert np.allclose(seen["merged"], m.merged_scaler.transform(raw))
    assert not np.allclose(seen["merged"], seen["local_head"])
    out = tmp_path / "slips-a"
    log = (out / "merging_data.log").read_text()
    line = re.search(r"  scaler \| weights own:([\d.]+) slips-b:([\d.]+)", log)
    assert float(line.group(1)) == pytest.approx(w, abs=1e-4)
    assert "peer=" not in line.group(0)
    (row,) = [
        json.loads(ln)
        for ln in (out / "merged_scaler.jsonl").read_text().splitlines()
    ]
    assert row["merge"] == 1 and row["window"] == 3
    assert np.allclose(row["mean"], m.merged_scaler.mean_)
    assert row["weights"]["own"] == pytest.approx(w)


def test_with_merge_scaler_a_peer_without_a_scaler_is_skipped(tmp_path):
    m = _merge_ready(tmp_path, False)
    m.merge_scaler = True
    m.scaler, _ = _fitted_scaler(np.random.default_rng(5), 20, 0.0, 1.0)
    _receive(m, "slips-b", _net(tmp_path, "slips-b").weights_for_sharing())
    m.trigger_merge()
    assert m.merge_count == 0 and not m._using_merged_model


def test_without_merge_scaler_the_merged_model_uses_the_own_scaler(tmp_path):
    m = _trainable(tmp_path)
    m.peer_models["slips-b"] = _net(tmp_path, "slips-b").weights_for_sharing()
    m._train_batch()
    assert m._using_merged_model and m.merged_scaler is None
    assert m._scaler_of(m.merged_model) is m.scaler
    assert (tmp_path / "slips-a" / "merged_scaler.jsonl").read_text() == ""


def test_each_model_is_scored_with_its_own_scaler(tmp_path):
    """While the merged model serves, the test cell scores it on features
    scaled with the pooled scaler and the local shadow with the own one;
    the so-far evaluation and the live path do the same; the next training
    discards the pooled scaler with the merged model."""
    m, *_ = _scaler_merge(tmp_path, "average")
    assert m._scaler_of(m.merged_model) is m.merged_scaler
    assert m._scaler_of(m.model) is m.scaler
    m.is_preprocessor_fitted = True
    used = []
    real_scale = m._scale

    def spy_scale(x_raw, scaler=None):
        used.append(scaler if scaler is not None else m.scaler)
        return real_scale(x_raw, scaler)

    m._scale = spy_scale
    m._extract_flow_features = lambda flow: [1.0] * 18
    m._get_simulated_gt = lambda flow: BEN
    blank = fnm.FederatedNetworkModule._blank_test_statistics
    cell = {
        "scorable": True,
        "flows": {"u1": {"type_": "conn"}, "u2": {"type_": "arp"}},
        "tested": set(),
        "test": {
            k: blank()
            for k in ("main", "conn_main", "shadow_local", "conn_shadow")
        },
        "preds": {},
    }
    m._test_cell(cell)
    assert used == [m.merged_scaler, m.scaler]
    assert cell["merged_served"]
    used.clear()
    m._scaled_features([("u1", {"type_": "conn"})])
    assert used == [m.merged_scaler]
    used.clear()
    x = np.ones((3, 18), dtype=np.float32)
    m._sofar_predict(m.merged_model, x)
    m._sofar_predict(m.model, x)
    assert used == [m.merged_scaler, m.scaler]
    m.training_buffer_x = list(np.ones((4, 18), dtype=np.float32))
    m.training_buffer_y = [MAL, BEN, MAL, BEN]
    m.training_buffer_ids = [f"v{i}" for i in range(4)]
    m.peer_models.clear()
    m._train_batch()
    assert m.merged_model is None and m.merged_scaler is None


def test_the_final_merged_scaler_artifact_is_the_pooled_one(tmp_path):
    m, *_ = _scaler_merge(tmp_path, "average")
    m.model_path = str(tmp_path / "store" / "model.bin")
    m.preprocess_path = str(tmp_path / "store" / "scaler.bin")
    m._save_final_merged_model()
    with open(m.preprocess_path, "rb") as fh:
        stored = pickle.load(fh)
    assert np.allclose(stored.mean_, m.merged_scaler.mean_)
    assert not np.allclose(stored.mean_, m.scaler.mean_)


# --------------------------------------------------------------------------
# global scaler (global_scaler)
# --------------------------------------------------------------------------
GLOBAL_SCALER = os.path.join(
    os.path.dirname(fnm.__file__), "artifacts", "global_scaler.json"
)


def test_the_shipped_global_scaler_loads_for_the_module_features(tmp_path):
    m = _trainable(tmp_path)
    sc = fnm.load_global_scaler(GLOBAL_SCALER, m._get_feature_order())
    assert sc.n_features_in_ == 18 and sc.n_samples_seen_ == 19635
    x = np.random.default_rng(0).normal(size=(4, 18)).astype(np.float32)
    assert np.allclose(sc.transform(x), (x - sc.mean_) / sc.scale_)
    # scale = sqrt(var), 1 where StandardScaler's rule saw a constant feature
    # (dir_num: variance 3e-33 at mean 1)
    eps = np.finfo(np.float64).eps
    n, var = sc.n_samples_seen_, sc.var_
    constant = var <= n * eps * var + (n * sc.mean_ * eps) ** 2
    assert np.allclose(sc.scale_, np.where(constant, 1.0, np.sqrt(var)))
    assert sc.scale_[m._get_feature_order().index("dir_num")] == 1.0


@pytest.mark.parametrize(
    "broken", ["features", "length", "zero_scale", "nan_mean", "no_scale"]
)
def test_a_broken_global_scaler_artifact_stops_the_module(tmp_path, broken):
    with open(GLOBAL_SCALER) as fh:
        saved = json.load(fh)
    features = list(saved["features"])
    if broken == "features":
        saved["features"] = features[::-1]
    elif broken == "length":
        saved["mean"] = saved["mean"][:17]
    elif broken == "zero_scale":
        saved["scale"][3] = 0.0
    elif broken == "nan_mean":
        saved["mean"][0] = float("nan")
    else:
        del saved["scale"]
    path = tmp_path / "global_scaler.json"
    path.write_text(json.dumps(saved))
    with pytest.raises(ValueError):
        fnm.load_global_scaler(str(path), features)


@pytest.mark.parametrize("merge_scaler", [False, True])
def test_with_global_scaler_no_model_ever_fits_a_scaler(
    tmp_path, merge_scaler
):
    """Every training pass - local, local fine-tune, merged fine-tune -
    sees the batch scaled with the global scaler, which training never fits
    (scaler_stats.jsonl logs it unchanged). With merge_scaler too, every
    peer sends the same statistics, so the pooled scaler is the global one."""
    m = _trainable(tmp_path)
    m.global_scaler = True
    m.merge_scaler = merge_scaler
    m.global_scaler_path = GLOBAL_SCALER
    m._apply_global_scaler()
    gs = fnm.load_global_scaler(GLOBAL_SCALER, m._get_feature_order())
    m.handle_p2p_model(
        {
            "peer_id": "slips-b",
            "model_class": "random_projection_mlp",
            "shared": {
                k: v.tolist()
                for k, v in _net(tmp_path, "slips-b")
                .weights_for_sharing()
                .items()
            },
            "scaler": fnm.scaler_payload(gs),
            "timestamp": 1.0,
        }
    )
    seen = {}
    real_fit = m.fit_incremental_model

    def spy_fit(x, y, classes=None, train_target="local"):
        seen[train_target] = np.array(x, copy=True)
        return real_fit(x, y, classes=classes, train_target=train_target)

    m.fit_incremental_model = spy_fit
    raw = np.stack(m.training_buffer_x)
    m._train_batch()
    assert m._using_merged_model
    assert m.scaler.n_samples_seen_ == 19635
    assert np.array_equal(m.scaler.mean_, gs.mean_)
    for stage in ("local", "local_head", "merged"):
        assert np.allclose(seen[stage], gs.transform(raw)), stage
    merged_scaler = m._scaler_of(m.merged_model)
    assert (merged_scaler is m.scaler) != merge_scaler
    assert np.allclose(merged_scaler.mean_, gs.mean_)
    assert np.allclose(merged_scaler.var_, gs.var_)
    (row,) = [
        json.loads(ln)
        for ln in (tmp_path / "slips-a" / "scaler_stats.jsonl")
        .read_text()
        .splitlines()
    ]
    assert row["n_seen"] == 19635 and np.allclose(row["mean"], gs.mean_)


def test_the_base_read_model_does_not_replace_the_global_scaler(
    tmp_path, monkeypatch
):
    """The base class's artifact loading (pre_main) sets an empty scaler;
    with global_scaler the global one is put back."""

    def base_read_model(self):
        self.scaler = StandardScaler()
        self.preprocessor = self.scaler

    monkeypatch.setattr(ml_base.MLBaseDetection, "read_model", base_read_model)
    m = _trainable(tmp_path)
    m.global_scaler = True
    m.global_scaler_path = GLOBAL_SCALER
    m._warm_started = False
    m.read_model()
    assert m.scaler.n_samples_seen_ == 19635
    assert m.preprocessor is m.scaler and m.is_preprocessor_fitted
