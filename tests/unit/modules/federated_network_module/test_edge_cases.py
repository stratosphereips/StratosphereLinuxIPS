"""Edge cases of the federated network module, driven through larger paths.

Live-like scenarios run the real window close (_close_training_window)
against an in-memory flows.sqlite with a fake clock and a real ModuleLogger,
so labels, flips and test streams are read back from the module's own
output files (trained_labels.jsonl, label_flips.log, *_test*.log) with the
regexes the experiment runner parses them with. Only the network update
(_train_batch) is stubbed there; separate tests run real local training and
merging, the P2P wire format, and the merge-rule contract.
"""

import json
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
        m.label_source = "alerts"
        m.scaler = MagicMock(transform=lambda x: x)
        m.predict_batch = lambda x: np.array([BEN] * len(x))
        m._train_batch = self._train
        self.m = m

    def _train(self):
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


def test_flows_are_placed_by_start_time_into_half_open_windows(
    monkeypatch, tmp_path
):
    """Windows are (start, end]: a flow starting exactly at a boundary
    belongs to the earlier window, a future flow waits for its own window,
    and a flow without a start time joins the oldest open cell (late)."""
    p = Pipe(monkeypatch, tmp_path, k=1)
    p.add("a")
    p.add("fut", ts=BASE + WIN + 50)  # starts in window 2, read at close 1
    p.close()
    p.add("edge", ts=BASE + WIN)  # == end of window 1
    p.add("stale", ts=None)
    p.add("b")
    p.close()
    p.close()
    windows = {uid: r["train_window"] for uid, r in p.trained().items()}
    assert windows == {"a": 2, "edge": 2, "stale": 2, "fut": 3, "b": 3}
    db_hdr = [ln for ln in p.lines("local_train.log") if "db | window_2" in ln]
    assert len(db_hdr) == 1 and " late 1 " in db_hdr[0]


def test_each_flow_is_tested_once_before_the_window_that_trains_it(
    monkeypatch, tmp_path
):
    """Prequential order: open cells are tested at every close, a late
    flow that lands in the cell being finalized is tested right before
    that cell trains, and open cells meet the freshly trained model."""
    p = Pipe(monkeypatch, tmp_path, k=1, fitted=True)
    events = []
    real_test_cell = p.m._test_cell

    def spy_test_cell(cell):
        before = set(cell["tested"])
        real_test_cell(cell)
        events.extend(("test", fid) for fid in cell["tested"] - before)

    def spy_train():
        w = p.m.training_count_window
        uids = {f for f, tw in p.m._trained_window_of.items() if tw == w}
        events.append(("train", frozenset(uids)))
        p._train()

    p.m._test_cell = spy_test_cell
    p.m._train_batch = spy_train
    p.close("a", "b")
    p.add("late", ts=BASE + 150)  # belongs to window 1, read at close 2
    p.close("c")
    p.close()

    tests = [fid for kind, fid in events if kind == "test"]
    assert sorted(tests) == ["a", "b", "c", "late"]  # each exactly once
    pos = {fid: i for i, (kind, fid) in enumerate(events) if kind == "test"}
    trains = [
        (i, uids) for i, (kind, uids) in enumerate(events) if kind == "train"
    ]
    assert [set(u) for _, u in trains] == [{"a", "b", "late"}, {"c"}]
    for i, uids in trains:
        assert all(pos[uid] < i for uid in uids)
    assert pos["c"] > trains[0][0]  # tested by the model trained at close 2


def test_training_close_keeps_the_residual_of_the_all_flows_stream(
    monkeypatch, tmp_path
):
    """With test_log_batch_size above the flows tested in a span, the
    training close must write the span's residual to local_test.log before
    the new span header, as it already does for local_test_conn.log."""
    p = Pipe(monkeypatch, tmp_path, k=0, fitted=True, batch=1000)
    p.add("m1", saddr=ATTACKER)
    p.close("b1")
    conn = p.lines("local_test_conn.log")
    assert FLOW_RE.match(conn[0]).group(1, 2, 3) == ("2", "1", "1")
    assert conn[1] == "--- New local model (window_1) ---"
    all_flows = p.lines("local_test.log")
    assert all_flows[-1] == "--- New local model (window_1) ---"
    counted = [FLOW_RE.match(ln) for ln in all_flows if FLOW_RE.match(ln)]
    assert counted and counted[-1].group(1, 2, 3) == ("2", "1", "1")


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
        fnm.peer_init_seed(SEED, peer),
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
            7, lambda: fnm.SimpleMLP3Layer(18)
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
    merged = m.model.weights_for_sharing()
    for key in own:
        assert torch.allclose(merged[key], (own[key] + good[key]) / 2)
    merging = (tmp_path / "slips-a" / "merging_data.log").read_text()
    assert "peer=slips-b" in merging and "peer=slips-c" not in merging


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
    m.init_seed = fnm.peer_init_seed(SEED, "slips-a")
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
    m.label_source = "alerts"
    rng = np.random.default_rng(0)
    m.training_buffer_x = list(rng.normal(size=(10, 18)).astype(np.float32))
    m.training_buffer_y = [MAL] * 8 + [BEN] * 2
    m.training_buffer_ids = [f"u{i}" for i in range(10)]
    m._buffered_flow_ids = {f"u{i}" for i in range(10)}
    return m


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
