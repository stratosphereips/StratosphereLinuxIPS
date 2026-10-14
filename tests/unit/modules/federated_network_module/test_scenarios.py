"""Live-run scenarios of the federated network module (integration).

Several wall-clock windows are driven through the module's own main loop
(_main_training -> _close_training_window) over a file-backed flows.sqlite
with SLIPS's schema: conn flows stored from real Conn records, ARP records in
altflows, alerts -> alert_evidence -> evidence_flows. Training is real (small
epochs), the ModuleLogger writes to tmp_path and merges are real, with peer
models arriving over the emulated p2p_gopy channel or handle_p2p_model.
Faked are only the true externals: the clock, the redis handle (p2p
publish/subscribe), yaml config reads, the sqlite location and the
simulated-attacker list. Assertions read the module's own artifacts
(trained_labels.jsonl, alert_uids.jsonl, label_flips.log, *_test*.log,
local_train.log, merging_data.log, weights/*.npz).

Nomenclature: a flow is labeled malicious only when an alert's evidence cites
its uid; a FLIP is a flow trained benign whose uid an alert cites only after
its cell finalized.
"""

import base64
import json
import os
import pickle
import re
import sqlite3
from collections import deque, namedtuple
from dataclasses import asdict
from types import SimpleNamespace

import numpy as np
import pytest
import torch
from sklearn.preprocessing import StandardScaler

from modules.federated_network_module import (
    federated_network_module as fnm,
)
from slips_files.common.output_paths import (
    get_this_db_path_inside_output_dir,
)
from slips_files.core.flows.zeek import ARP, Conn

WIN = 300  # module window (time_window_width), seconds
BASE = 1_000_000.0  # wall-clock origin of the run
SEED = 1111
ATTACKER = "172.20.0.66"
VICTIM = "172.20.0.10"
MAL, BEN = fnm.MALICIOUS, fnm.BENIGN

# the subset of SLIPS's flows.sqlite schema the module reads (same keys, so
# INSERT OR REPLACE behaves as in SLIPS: a re-added uid gets a new rowid)
SCHEMA = """
CREATE TABLE flows(uid TEXT PRIMARY KEY, flow TEXT, label TEXT,
                   profileid TEXT, twid TEXT, aid TEXT);
CREATE TABLE altflows(uid TEXT PRIMARY KEY, flow TEXT, label TEXT,
                      profileid TEXT, twid TEXT, flow_type TEXT);
CREATE TABLE alerts(alert_id TEXT PRIMARY KEY, alert_time REAL,
                    ip_alerted TEXT);
CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT,
                            PRIMARY KEY (alert_id, evidence_id));
CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT,
                            PRIMARY KEY (evidence_id, uid));
"""


# --------------------------------------------------------------------------
# flows as SLIPS stores them: asdict(Conn) / asdict(ARP) in the flow column
# uid prefix picks the kind: b = benign conn, a = attack conn, r = ARP scan
# --------------------------------------------------------------------------
def _ben(w, n):
    return [f"b{w}_{i}" for i in range(n)]


def _atk(w, n):
    return [f"a{w}_{i}" for i in range(n)]


def _scan(w, n):
    return [f"r{w}_{i}" for i in range(n)]


def _flow(uid, ts, i):
    if uid[0] == "r":
        return asdict(
            ARP(
                starttime=ts,
                uid=uid,
                saddr=ATTACKER,
                daddr=f"172.20.0.{100 + i % 150}",
                smac="02:42:ac:14:00:42",
                dmac="ff:ff:ff:ff:ff:ff",
                src_hw="02:42:ac:14:00:42",
                dst_hw="00:00:00:00:00:00",
                operation="request",
            )
        )
    if uid[0] == "a":
        return asdict(
            Conn(
                starttime=ts,
                uid=uid,
                saddr=ATTACKER,
                daddr=VICTIM,
                dur=0.0,
                proto="tcp",
                appproto="",
                sport=str(40000 + i),
                dport=str(20 + i),
                spkts=1,
                dpkts=1,
                sbytes=0,
                dbytes=0,
                state="REJ",
                history="Sr",
            )
        )
    return asdict(
        Conn(
            starttime=ts,
            uid=uid,
            saddr=VICTIM,
            daddr=f"10.0.1.{i % 200 + 1}",
            dur=1.5 + i % 7,
            proto="tcp",
            appproto="ssl",
            sport=str(50000 + i),
            dport="443",
            spkts=12 + i % 5,
            dpkts=10 + i % 3,
            sbytes=1500 + 37 * i,
            dbytes=9000 + 101 * i,
            state="SF",
            history="ShADadFf",
        )
    )


# --------------------------------------------------------------------------
# externals: clock, redis (p2p), config
# --------------------------------------------------------------------------
class Clock:
    now = BASE


class FakeRedis:
    """p2p_pygo publish sink (the Go p2p layer is the external)."""

    def __init__(self):
        self.published = []

    def publish(self, channel, data):
        self.published.append((channel, data))


def _module(root, name, *, k, balancing, merge_rule, model_class, min_samples):
    """A module instance carrying the state init() sets up, minus redis,
    yaml and the repo artifacts dir (all redirected into tmp)."""
    m = object.__new__(fnm.FederatedNetworkModule)
    m.printed = []
    m.print = lambda text, *a, **kw: m.printed.append(str(text))
    m.mode = "train"
    m.db = FakeRedis()
    m.channels = {"p2p_gopy": object()}
    m.channel_tracker = {}
    m._p2p_connected = True
    m.my_peer_id = name
    m.seed = SEED
    m.init_seed = fnm.peer_init_seed(SEED, name)
    m.model_class_name = model_class
    m.merge_rule = merge_rule
    m.balancing = balancing
    m._undersample = balancing == "undersample"
    m._read_module_config_bool = lambda key, default: default  # yaml
    art = root / "artifacts"
    (art / "merged").mkdir(parents=True)
    m.rp_path = str(art / "random_projection.bin")
    m.local_state_path = str(art / "latest_local_state.bin")
    m.local_scaler_path = str(art / "latest_local_scaler.bin")
    m.merged_dir = str(art / "merged")
    m.model_path = str(art / "model_custom.bin")
    m.preprocess_path = str(art / "scaler_custom.bin")
    m.parent_output_dir = str(root)
    m.output_dir = str(root / "logs")
    m.logger = fnm.ModuleLogger(m.output_dir, True)
    m.device = torch.device("cpu")
    m.input_dim = None
    m.model = None
    m.scaler = StandardScaler()
    m.is_preprocessor_fitted = False
    m._is_fitted = False
    m._adam_state = {}
    m.malware_metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    m.seen_labels = {MAL: 0, BEN: 0}
    m.predicted_labels = {MAL: 0, BEN: 0}
    m.testing_flows_since_last_log = 0
    m.testing_log_batch_size = 1  # as in config/slips.yaml
    m.training_buffer_x, m.training_buffer_y = [], []
    m.training_buffer_ids = []
    m._last_train_X = m._last_train_Y = None
    m._buffered_flow_ids = set()
    m.peer_models = {}
    m.merge_count = 0
    m._trained_label_flows = {}
    m._trained_window_of = {}
    m._trained_per_window = {}
    m._flip_events = []
    m._flipped_ids = set()
    m._pending_labeled = {}
    m.training_count_window = 0
    m._training_trigger = ""
    m._using_merged_model = False
    m._local_only_model = None
    m._local_test = m._blank_test_statistics()
    m._local_stream_used = False
    m._span_label = ""
    m._local_span_marked = False
    m._conn_active = m._blank_test_statistics()
    m._conn_local = m._blank_test_statistics()
    m.local_training_epochs = 3
    m.merge_finetune_epochs = 2
    m.finetune_head = True
    m.min_training_samples = min_samples
    m.window_size_seconds = WIN
    m.label_finalize_delay_windows = k
    m.alert_uid_retention_windows = 24
    m._flow_ring = deque()
    m._db_conn = None
    m._db_rw_conn = None
    m._flow_rowid = 0
    m._arp_rowid = 0
    m._seen_uids = set()
    m._next_window_flows = []
    m._window_bounds = {}
    m._last_alert_cut = 0.0
    m.training_window_start = BASE
    return m


Snapshot = namedtuple("Snapshot", "trigger window flips trained per_window")
SNAP_RE = re.compile(
    r"^--- (\w+) @window_(\d+) \| flips: (\d+) / (\d+) \(.*\) ---$"
)
PERW_RE = re.compile(r"^--- window_(\d+) \| trained (\d+) \| flipped (\d+) \|")
SPAN_RE = re.compile(r"^--- New local model \((\S+)\) ---$")
FLOWS_RE = re.compile(r"^  flows=(\d+) \|")
BATCH_RE = re.compile(r"^--- window_(\d+) \| (\d+) mal, (\d+) ben ---$")


class Peer:
    """One SLIPS peer: its own flows.sqlite + module, on the shared clock."""

    def __init__(
        self,
        tmp_path,
        clock,
        name,
        k=1,
        balancing="weighting",
        merge_rule="average",
        model_class="random_projection_mlp",
        min_samples=4,
    ):
        self.name, self.clock, self.n = name, clock, 0
        self.root = tmp_path / name
        db_path = get_this_db_path_inside_output_dir(
            str(self.root), "flows.sqlite"
        )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.w = sqlite3.connect(db_path)
        self.w.executescript(SCHEMA)
        self.m = _module(
            self.root,
            name,
            k=k,
            balancing=balancing,
            merge_rule=merge_rule,
            model_class=model_class,
            min_samples=min_samples,
        )
        self.inbox = deque()  # p2p_gopy messages waiting for the module
        self.m.get_msg = lambda channel: (
            self.inbox.popleft() if self.inbox else None
        )

    # ---- SLIPS side: what lands in flows.sqlite ------------------------ #
    def add_flow(self, uid, ts, i=0):
        raw = json.dumps(_flow(uid, ts, i))
        if uid[0] == "r":
            self.w.execute(
                "INSERT OR REPLACE INTO altflows(uid, flow, label, profileid,"
                " twid, flow_type) "
                "VALUES (?,?,'benign',?,'timewindow1','arp')",
                (uid, raw, f"profile_{ATTACKER}"),
            )
        else:
            self.w.execute(
                "INSERT OR REPLACE INTO flows(uid, flow, label, profileid, "
                "twid) VALUES (?,?,'benign','profile_x','timewindow1')",
                (uid, raw),
            )
        self.w.commit()

    def add_alert(self, alert_id, uids, at):
        self.w.execute(
            "INSERT INTO alerts(alert_id, alert_time, ip_alerted) "
            "VALUES (?,?,?)",
            (alert_id, at, ATTACKER),
        )
        for j, uid in enumerate(uids):
            eid = f"{alert_id}-e{j}"
            self.w.execute(
                "INSERT INTO alert_evidence VALUES (?,?)", (alert_id, eid)
            )
            self.w.execute(
                "INSERT INTO evidence_flows VALUES (?,?)", (eid, uid)
            )
        self.w.commit()

    def close(self, flows=(), alerts=()):
        """One window: SLIPS stores the flows (ts inside this window unless
        given as (uid, ts)) and alerts (at this close unless (id, uids, at)),
        then the module's main loop runs once at the window boundary."""
        self.n += 1
        self.clock.now = BASE + self.n * WIN
        ts = BASE + (self.n - 1) * WIN + 100
        for i, spec in enumerate(flows):
            uid, fts = spec if isinstance(spec, tuple) else (spec, ts)
            self.add_flow(uid, fts, i)
        for spec in alerts:
            at = spec[2] if len(spec) == 3 else self.clock.now
            self.add_alert(spec[0], spec[1], at)
        assert self.m._main_training() is False
        assert self.m.training_count_window == self.n  # the window closed
        crashes = [t for t in self.m.printed if "Traceback (most recent" in t]
        assert crashes == []

    # ---- artifacts ----------------------------------------------------- #
    def lines(self, name):
        with open(os.path.join(self.m.output_dir, name)) as f:
            return f.read().splitlines()

    def trained(self):
        return [json.loads(x) for x in self.lines("trained_labels.jsonl")]

    def trained_by_uid(self):
        rows = self.trained()
        by_uid = {r["uid"]: r for r in rows}
        assert len(by_uid) == len(rows)  # every flow trains at most once
        return by_uid

    def alert_uids(self):
        return [json.loads(x) for x in self.lines("alert_uids.jsonl")]

    def flip_snapshot(self):
        """The last snapshot in label_flips.log."""
        snap = None
        for line in self.lines("label_flips.log"):
            if match := SNAP_RE.match(line):
                trig, win, flips, trained = match.groups()
                snap = Snapshot(trig, int(win), int(flips), int(trained), {})
            elif (match := PERW_RE.match(line)) and snap is not None:
                win, trained, flipped = map(int, match.groups())
                snap.per_window[win] = (trained, flipped)
        return snap

    def span_tails(self, log):
        """span label -> its last (cumulative) flows= line; spans that never
        tested a flow are left out."""
        out, span = {}, None
        for line in self.lines(log):
            if match := SPAN_RE.match(line):
                span = match.group(1)
            elif FLOWS_RE.match(line):
                out[span] = line
        return out

    def spans(self, log):
        """span label -> number of flows it tested."""
        return {
            span: int(FLOWS_RE.match(line).group(1))
            for span, line in self.span_tails(log).items()
        }

    def batches(self):
        """train window -> (mal, ben) of each batch the local model fit."""
        return {
            int(w): (int(mal), int(ben))
            for w, mal, ben in (
                BATCH_RE.match(x).groups()
                for x in self.lines("local_train.log")
                if BATCH_RE.match(x)
            )
        }

    def gt_in_db(self, table, uid):
        return self.w.execute(
            f"SELECT json_extract(flow, '$.ground_truth_label') FROM {table} "
            "WHERE uid = ?",
            (uid,),
        ).fetchone()[0]

    def shutdown(self):
        self.m.logger.close()
        for conn in (self.m._db_conn, self.m._db_rw_conn, self.w):
            if conn is not None:
                conn.close()


class Net:
    """Peers on one fake clock + the Go p2p layer between them."""

    def __init__(self, tmp_path):
        self.tmp_path, self.clock, self.peers = tmp_path, Clock(), []

    def peer(self, name="slips-b", **cfg):
        p = Peer(self.tmp_path, self.clock, name, **cfg)
        self.peers.append(p)
        return p

    def payload(self, peer_id, model_class="random_projection_mlp"):
        """A model message as a peer of `model_class` would send it."""
        stub = SimpleNamespace(
            rp_path=str(self.tmp_path / f"{peer_id}-rp.bin"),
            seed=SEED,
            input_dim=None,
        )
        model = fnm.build_with_init_seed(
            fnm.peer_init_seed(SEED, peer_id),
            lambda: fnm.MODEL_REGISTRY[model_class](stub),
        )
        return {
            "message_type": "model",
            "model_class": model_class,
            "peer_id": peer_id,
            "shared": {
                key: t.tolist()
                for key, t in model.weights_for_sharing().items()
            },
            "timestamp": BASE,
        }

    @staticmethod
    def route(src, dst):
        """Go layer stand-in: src's last p2p_pygo publish arrives on dst's
        p2p_gopy as a go_data message. Returns the decoded model message."""
        channel, raw = src.m.db.published[-1]
        assert channel == "p2p_pygo"
        go = json.loads(raw)
        assert go["recipient"] == "*"
        dst.inbox.append(
            {
                "data": json.dumps(
                    {
                        "message_type": "go_data",
                        "message_contents": {
                            "message": go["message"],
                            "reporter": src.name,
                            "report_time": BASE,
                        },
                    }
                )
            }
        )
        return json.loads(base64.b64decode(go["message"]))


@pytest.fixture
def net(tmp_path, monkeypatch):
    n = Net(tmp_path)
    monkeypatch.setattr(fnm.time, "time", lambda: n.clock.now)
    attackers = tmp_path / "simulated_attackers.txt"
    attackers.write_text(ATTACKER + "\n")
    monkeypatch.setenv("FL_SIM_ATTACKERS", str(attackers))
    yield n
    for p in n.peers:
        p.shutdown()


def _flat(weights):
    return torch.cat(
        [weights[key].detach().reshape(-1) for key in sorted(weights)]
    )


def _wire_flat(msg):
    """A model message's shared tensors, flat in the module's key order."""
    return np.concatenate(
        [
            np.asarray(msg["shared"][key], dtype=np.float32).reshape(-1)
            for key in sorted(msg["shared"])
        ]
    )


# --------------------------------------------------------------------------
# late alerts: ring labeling vs flips
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "k, delay, flipped",
    [(1, 1, False), (0, 1, True), (2, 2, False), (1, 2, True)],
)
def test_late_alert_labels_in_the_ring_or_counts_flips(net, k, delay, flipped):
    """An attack whose alert lands `delay` windows after its flows: when the
    ring (K) still holds them they train malicious and nothing flips;
    otherwise they already trained benign and the alert counts 4 flips,
    attributed to the window they trained in."""
    p = net.peer(k=k)
    p.close(flows=_ben(1, 6))
    p.close(flows=_ben(2, 4) + _atk(2, 4))
    for w in range(3, 3 + delay):
        alerts = [("A1", _atk(2, 4))] if w == 2 + delay else []
        p.close(flows=_ben(w, 4), alerts=alerts)
    for w in range(3 + delay, 4 + delay + k):
        p.close(flows=_ben(w, 4))
    rows = p.trained_by_uid()
    attack = [rows[uid] for uid in _atk(2, 4)]
    assert {r["train_window"] for r in attack} == {2 + k}
    assert {r["label"] for r in attack} == {0 if flipped else 1}
    snap = p.flip_snapshot()
    assert snap.flips == (4 if flipped else 0)
    assert snap.per_window[2 + k] == (8, 4 if flipped else 0)


def test_alert_that_precedes_its_flow_labels_it_malicious_end_to_end(net):
    """Retention: an alert citing a uid SLIPS stores only two windows later
    (a quiet close in between) still labels the flow once it arrives; it
    trains malicious and never counts as a flip. alert_uids.jsonl shows the
    citation at the alert's close and the ring match at the flow's close."""
    p = net.peer(k=1)
    p.close(flows=_ben(1, 6), alerts=[("A1", ["a3_0"])])
    p.close(flows=_ben(2, 5))
    p.close(flows=_ben(3, 5) + ["a3_0"])
    p.close(flows=_ben(4, 5))
    row = p.trained_by_uid()["a3_0"]
    assert (row["label"], row["train_window"]) == (1, 4)
    assert p.flip_snapshot().flips == 0
    assert [
        (r["window"], r["uids"], r["open_cell_matches"])
        for r in p.alert_uids()
    ] == [(1, ["a3_0"], 0), (2, [], 0), (3, [], 1), (4, [], 0)]


def test_carried_flow_cited_before_its_batch_trains_is_a_flip(net):
    """min_training_samples carry-over: window 1 (5 flows < 8) finalizes
    benign but does not train; the alert citing its attack flows lands at
    close 2, after their finalize and before the carried batch trains there.
    They train benign as finalized, so they are flips, and label_flips.log
    attributes them to window 2, the window they trained in."""
    p = net.peer(k=0, min_samples=8)
    p.close(flows=_ben(1, 3) + _atk(1, 2))
    p.close(flows=_ben(2, 4), alerts=[("A1", _atk(1, 2))])
    p.close(flows=_ben(3, 8))
    rows = p.trained_by_uid()
    assert {
        (rows[u]["label"], rows[u]["train_window"]) for u in _atk(1, 2)
    } == {(0, 2)}
    snap = p.flip_snapshot()
    assert snap.flips == 2
    assert snap.per_window == {2: (9, 2), 3: (8, 0)}


def test_trained_labels_name_the_window_each_flow_arrived_in(net):
    """Every trained_labels.jsonl row carries arrival_window, the window of
    the cell the flow was placed in (by its ts, so a flow SLIPS stores a
    window late keeps its own window), next to the unchanged fields. The
    cell finalizes at close arrival_window + K; a sub-threshold cell is
    carried and trains later, so train_window - K is not its arrival."""
    p = net.peer(k=1, min_samples=8)
    p.close(flows=_ben(1, 5))
    p.close(flows=_ben(2, 5) + [("b1_late", BASE + 50)])  # 6 < 8: carried
    p.close(flows=_ben(3, 9))  # windows 1 + 2 train here
    p.close(flows=_ben(4, 1))  # window 3 trains here
    rows = p.trained_by_uid()
    assert {
        uid: (r["arrival_window"], r["train_window"])
        for uid, r in rows.items()
    } == {
        **{uid: (1, 3) for uid in _ben(1, 5) + ["b1_late"]},
        **{uid: (2, 3) for uid in _ben(2, 5)},
        **{uid: (3, 4) for uid in _ben(3, 9)},
    }
    fields = {"flow_id", "uid", "saddr", "daddr", "starttime", "label"}
    fields |= {"train_window", "arrival_window"}
    assert all(set(r) == fields for r in rows.values())


def test_trained_labels_alert_uids_and_label_flips_agree(net):
    """Cross-artifact audit of a mixed run (in-window alert, ARP, a late
    alert, an alert preceding its flow, a re-cited malicious flow, and a
    flow SLIPS re-stores with INSERT OR REPLACE):
    - each flow trains once and is tested once, before it trains;
    - label 1 <=> an alert cited the uid by its train window;
    - flips = label-0 flows cited only after their train window, per window;
    - label_flips.log totals match trained_labels.jsonl."""
    p = net.peer(k=0)
    p.close(flows=_ben(1, 5) + _atk(1, 2), alerts=[("A1", _atk(1, 2))])
    p.close(
        flows=_ben(2, 4) + _atk(2, 3) + _scan(2, 3),
        alerts=[("A2", _scan(2, 3))],
    )
    p.close(flows=_ben(3, 4), alerts=[("A3", _atk(2, 3) + ["a4_0"])])
    p.add_flow("b1_0", BASE + 3 * WIN + 10)  # SLIPS re-stores a trained flow
    p.close(flows=_ben(4, 4) + ["a4_0"])
    p.close(flows=_ben(5, 4), alerts=[("A5", ["a1_0"])])  # trained malicious

    rows = p.trained_by_uid()
    stored = (
        _ben(1, 5) + _atk(1, 2) + _ben(2, 4) + _atk(2, 3) + _scan(2, 3)
    ) + (_ben(3, 4) + _ben(4, 4) + ["a4_0"] + _ben(5, 4))
    assert set(rows) == set(stored)
    cited_at = {}
    for row in p.alert_uids():
        for uid in row["uids"]:
            cited_at.setdefault(uid, []).append(row["window"])
    flips = {}
    for uid, r in rows.items():
        cited = cited_at.get(uid, [])
        assert r["label"] == int(any(w <= r["train_window"] for w in cited))
        if r["label"] == 0 and any(w > r["train_window"] for w in cited):
            flips[r["train_window"]] = flips.get(r["train_window"], 0) + 1
    assert flips == {2: 3}  # the late-cited attack flows only
    snap = p.flip_snapshot()
    assert (snap.window, snap.flips, snap.trained) == (5, 3, len(rows))
    per_window = {}
    for r in rows.values():
        per_window[r["train_window"]] = (
            per_window.get(r["train_window"], 0) + 1
        )
    assert snap.per_window == {
        w: (t, flips.get(w, 0)) for w, t in per_window.items()
    }
    # prequential: everything after the first trained window tested once
    assert sum(p.spans("local_test.log").values()) == len(rows) - 7


def test_flips_found_on_a_quiet_last_window_reach_the_shutdown_snapshot(net):
    """A late alert landing in a window with no flows (nothing trains, so no
    finalize snapshot) still counts its flips; the shutdown snapshot
    reports them against the window the flows trained in."""
    p = net.peer(k=0)
    p.close(flows=_ben(1, 5) + _atk(1, 2))
    p.close(alerts=[("A1", _atk(1, 2))])
    assert p.flip_snapshot().flips == 0  # finalize @window_1 predates it
    p.m.store_model()
    snap = p.flip_snapshot()
    assert (snap.trigger, snap.window, snap.flips, snap.trained) == (
        "shutdown",
        2,
        2,
        7,
    )
    assert snap.per_window == {1: (7, 2)}


# --------------------------------------------------------------------------
# ARP records next to conn flows
# --------------------------------------------------------------------------
def test_arp_scan_and_conn_flows_train_together_conn_twin_counts_conn(net):
    """One window holds an ARP scan and conn flows: both are labeled from the
    alert and trained in one batch; the all-flows test stream counts every
    record, the conn-only twin only the conn flows; simulated ground truth
    is stamped back into both SLIPS tables."""
    p = net.peer(k=1)
    p.close(flows=_ben(1, 6))
    p.close(
        flows=_scan(2, 10) + _ben(2, 4) + _atk(2, 2),
        alerts=[("A1", _scan(2, 10) + _atk(2, 2))],
    )
    p.close(flows=_ben(3, 3))
    assert p.batches() == {2: (0, 6), 3: (12, 4)}
    rows = p.trained_by_uid()
    assert {rows[u]["label"] for u in _scan(2, 10) + _atk(2, 2)} == {1}
    assert {rows[u]["label"] for u in _ben(2, 4)} == {0}
    tested = p.span_tails("local_test.log")["window_2"]
    assert tested.startswith("  flows=16 | GT(Mal/Ben): 12/4 |")
    tested = p.span_tails("local_test_conn.log")["window_2"]
    assert tested.startswith("  flows=6 | GT(Mal/Ben): 2/4 |")
    assert p.gt_in_db("altflows", "r2_0") == "malicious"
    assert p.gt_in_db("flows", "a2_0") == "malicious"
    assert p.gt_in_db("flows", "b2_0") == "benign"


# --------------------------------------------------------------------------
# prequential dual testing streams once merged
# --------------------------------------------------------------------------
WINDOWS = [
    _ben(1, 4) + _atk(1, 2),
    _ben(2, 6) + _atk(2, 2),
    _ben(3, 4) + _atk(3, 1) + _scan(3, 2),
    [],  # a quiet window
    _ben(5, 6) + _atk(5, 1) + _scan(5, 2),
    _ben(6, 4) + _atk(6, 1),
]


@pytest.mark.parametrize(
    "k, spans_all, spans_conn, merges",
    [
        (
            0,
            {"window_1": 8, "window_2": 7, "window_3": 9, "window_5": 5},
            {"window_1": 8, "window_2": 5, "window_3": 7, "window_5": 5},
            5,
        ),
        (
            1,
            {"window_2": 8, "window_3": 7, "window_4": 9, "window_6": 5},
            {"window_2": 8, "window_3": 5, "window_4": 7, "window_6": 5},
            4,
        ),
    ],
)
def test_merged_and_local_streams_share_spans_and_flow_counts(
    net, k, spans_all, spans_conn, merges
):
    """With a peer model in hand every training merges. Both testing streams
    (and their conn twins) then carry the same span headers with the same
    per-span flow counts, and each flow is tested exactly once, by the model
    of the last training BEFORE the one that trains on it (a quiet window
    extends the span instead of opening one)."""
    p = net.peer(k=k)
    p.m.handle_p2p_model(net.payload("slips-a"))
    for w, flows in enumerate(WINDOWS, start=1):
        cited = [u for u in flows if u[0] in "ar"]
        p.close(flows=flows, alerts=[(f"A{w}", cited)] if cited else [])
    assert p.m.merge_count == merges
    for log in ("merged_test.log", "local_test.log"):
        assert list(p.spans(log).items()) == list(spans_all.items())
    for log in ("merged_test_conn.log", "local_test_conn.log"):
        assert list(p.spans(log).items()) == list(spans_conn.items())


# --------------------------------------------------------------------------
# class balancing
# --------------------------------------------------------------------------
def test_undersample_trains_all_malicious_window_and_balances_mixed_one(net):
    """balancing=undersample: an all-malicious first window (one class
    absent) trains unchanged on a plain loss and the model then tests the
    next window; a mixed window trains on a 50/50 batch."""
    p = net.peer(k=0, balancing="undersample")
    p.close(flows=_atk(1, 6), alerts=[("A1", _atk(1, 6))])
    p.close(flows=_ben(2, 5) + _atk(2, 1), alerts=[("A2", _atk(2, 1))])
    assert p.batches() == {1: (6, 0), 2: (1, 1)}
    assert p.m.model.USE_CLASS_WEIGHTING is False
    assert p.spans("local_test.log") == {"window_1": 6}


def test_undersampled_out_flows_are_not_recorded_as_trained(net):
    """balancing=undersample trains 2 mal / 2 ben out of 2 mal / 8 ben;
    only those 4 flows may be recorded as trained. A late alert citing all
    8 benign flows flips the 2 that trained benign, not the 6 undersampling
    dropped (they never trained)."""
    p = net.peer(k=0, balancing="undersample")
    p.close(flows=_ben(1, 8) + _atk(1, 2), alerts=[("A1", _atk(1, 2))])
    assert p.batches() == {1: (2, 2)}
    p.close(alerts=[("A2", _ben(1, 8))])
    p.m.store_model()  # shutdown snapshot (the quiet close writes none)
    rows = p.trained_by_uid()
    assert sorted(r["label"] for r in rows.values()) == [0, 0, 1, 1]
    snap = p.flip_snapshot()
    assert (snap.trigger, snap.trained, snap.flips) == ("shutdown", 4, 2)
    assert snap.per_window == {1: (4, 2)}


# --------------------------------------------------------------------------
# merging: real p2p path, rules, frozen layers
# --------------------------------------------------------------------------
E = float(np.exp(-0.5))


@pytest.mark.parametrize(
    "rule, far, expected",
    [
        ("average", True, lambda own, a, far: (own + a + far) / 3),
        ("mean_with_closest", True, lambda own, a, far: (own + a) / 2),
        # one peer: sigma = d(own, a), so its weight is exp(-1/2) per layer
        ("proximity", False, lambda own, a, far: (own + E * a) / (1 + E)),
    ],
)
def test_merge_rule_runs_through_the_live_merge_path(net, rule, far, expected):
    """Peer A trains and publishes; its message reaches B over p2p_gopy (and
    optionally a far-off third model); B trains and merges with the
    configured rule. merging_data.log names the rule, the snapshot holds
    exactly what A sent, and the merged weights follow the rule."""
    a = net.peer("slips-a", k=0)
    b = net.peer("slips-b", k=0, merge_rule=rule)
    a.close(flows=_ben(1, 6) + _atk(1, 2), alerts=[("A1", _atk(1, 2))])
    sent = net.route(a, b)
    if far:
        b.m.handle_p2p_model(
            {
                **sent,
                "peer_id": "slips-far",
                "shared": {
                    key: (np.asarray(v) + 5.0).tolist()
                    for key, v in sent["shared"].items()
                },
            }
        )
    b.close(flows=_ben(1, 5) + _atk(1, 3), alerts=[("B1", _atk(1, 3))])
    log = b.lines("merging_data.log")
    assert log[:2] == [
        f"--- merge_1 | {2 if far else 1} peers ---",
        f"  merge_rule={rule}",
    ]
    snap = np.load(os.path.join(b.m.output_dir, "weights", "merge_0001.npz"))
    assert np.array_equal(snap["peer_slips-a"], _wire_flat(sent))
    want = expected(
        snap["own"], snap["peer_slips-a"], snap["peer_slips-far"] if far else 0
    )
    np.testing.assert_allclose(snap["merged"], want, rtol=1e-5, atol=1e-6)
    # the merged model now owns the test stream (nothing tested yet)
    assert b.lines("merged_test.log") == ["--- New local model (window_1) ---"]
    assert b.lines("local_test.log") == []


def test_peers_exchange_local_models_and_merge_the_latest_one(net):
    """Two peers, three windows, models routed both ways after each close:
    every publish carries the sender's fresh local model (never its merged
    one), a newer model from a peer replaces the older one, and each merge
    averages the receiver's own fresh local model with that latest model."""
    a = net.peer("slips-a", k=0)
    b = net.peer("slips-b", k=0)
    sent = {}
    for w in (1, 2, 3):
        for p in (a, b):
            p.close(
                flows=_ben(w, 6) + _atk(w, 2),
                alerts=[(f"{p.name}-{w}", _atk(w, 2))],
            )
        for src, dst in ((a, b), (b, a)):
            msg = net.route(src, dst)
            local = _flat(src.m._local_only_model.weights_for_sharing())
            assert msg["peer_id"] == src.name
            assert np.array_equal(_wire_flat(msg), local.numpy())
            if w > 1:  # merged since window 2, and merged != local
                merged = _flat(src.m.model.weights_for_sharing())
                assert not torch.equal(merged, local)
            sent[src.name, w] = _wire_flat(msg)
    for me, peer in ((a, b), (b, a)):
        assert me.m.merge_count == 2
        heads = [x for x in me.lines("merging_data.log") if x[:3] == "---"]
        assert heads == [
            "--- merge_1 | 1 peers ---",
            "--- merge_2 | 1 peers ---",
        ]
        for n, w in ((1, 2), (2, 3)):  # merge n happens at window w
            snap = np.load(
                os.path.join(me.m.output_dir, "weights", f"merge_{n:04d}.npz")
            )
            assert set(snap.files) == {"own", "merged", f"peer_{peer.name}"}
            own, theirs = sent[me.name, w], sent[peer.name, w - 1]
            assert np.array_equal(snap["own"], own)
            assert np.array_equal(snap[f"peer_{peer.name}"], theirs)
            np.testing.assert_allclose(
                snap["merged"], (own + theirs) / 2, rtol=1e-6, atol=1e-7
            )


@pytest.mark.parametrize("stage", ["local_head", "merged"])
def test_head_only_finetune_leaves_federated_layers_untouched(net, stage):
    """Head-only fine-tuning must not change the federated layers: after
    local training the model sent to peers keeps the fc1 its full fit
    produced, and after a merge the merged model under test keeps exactly
    the merge rule's fc1."""
    p = net.peer(k=0)
    p.m.handle_p2p_model(net.payload("slips-a"))
    calls = []
    real_fit = p.m.fit_incremental_model

    def spy(x, y, classes=None, train_target="local"):
        before = (
            None
            if p.m.model is None
            else _flat(p.m.model.weights_for_sharing())
        )
        real_fit(x, y, classes=classes, train_target=train_target)
        calls.append(
            (train_target, before, _flat(p.m.model.weights_for_sharing()))
        )

    p.m.fit_incremental_model = spy
    p.close(flows=_ben(1, 6) + _atk(1, 2), alerts=[("A1", _atk(1, 2))])
    p.close(flows=_ben(2, 6) + _atk(2, 2), alerts=[("A2", _atk(2, 2))])
    staged = [(b, a) for t, b, a in calls if t == stage]
    assert len(staged) == 2
    for before, after in staged:
        assert torch.equal(before, after)


def test_merge_leaves_the_feature_scaler_of_the_run_untouched(net):
    """The merge only swaps federated weights and re-tunes the head; the
    merged model must be stored with the very scaler the local model was
    trained and stored with (the scaler is fit on raw flow features)."""
    p = net.peer(k=0)
    p.m.handle_p2p_model(net.payload("slips-a"))
    p.close(flows=_ben(1, 6) + _atk(1, 2), alerts=[("A1", _atk(1, 2))])
    with open(p.m.local_scaler_path, "rb") as f:
        local = pickle.load(f)  # saved before the merge
    with open(p.m.preprocess_path, "rb") as f:
        merged = pickle.load(f)  # saved after merge_1
    assert p.m.merge_count == 1 and local.n_samples_seen_ == 8
    assert merged.n_samples_seen_ == local.n_samples_seen_
    np.testing.assert_allclose(merged.mean_, local.mean_)
    np.testing.assert_allclose(merged.var_, local.var_)


def test_merge_without_a_usable_peer_keeps_testing_the_local_model(net):
    """A peer running another model_class sends no fc2_* tensors; the
    receiver (two-layer net) has nobody to merge with, so no merge may be
    recorded and its tests stay in the local stream rather than fill
    merged_test with a model that merged nothing."""
    p = net.peer(k=0, model_class="random_projection_two_layer")
    p.m.handle_p2p_model(net.payload("slips-a", "random_projection_mlp"))
    p.close(flows=_ben(1, 6) + _atk(1, 2), alerts=[("A1", _atk(1, 2))])
    p.close(flows=_ben(2, 6) + _atk(2, 2), alerts=[("A2", _atk(2, 2))])
    assert p.m.merge_count == 0
    assert p.lines("merged_test.log") == []
    assert p.spans("local_test.log") == {"window_1": 8}


# --------------------------------------------------------------------------
# placing flows into windows by their own ts
# --------------------------------------------------------------------------
def _db_counter(p, window, name):
    for line in p.lines("local_train.log"):
        if line.startswith(f"--- db | window_{window} |"):
            return int(re.search(rf" {name} (\d+)", line).group(1))
    raise AssertionError(f"no db line for window_{window}")


@pytest.mark.parametrize(
    "k, at_close, ts, counter",
    [
        # stored at close 1 with a ts inside window 2: waits for window 2
        (0, 1, BASE + WIN + 50, "next"),
        # stored at close 2 with a ts before every open window: joins the
        # oldest open cell (window 1, finalizing now) instead of vanishing
        (1, 2, BASE - 500, "late"),
    ],
)
def test_flow_is_placed_by_its_ts_and_still_meets_its_alert(
    net, k, at_close, ts, counter
):
    """A flow joins the open window that contains its ts, never an earlier
    one: a flow stamped in the next window is not trained benign before
    its alert can reach it, and a flow older than every open window joins
    the oldest (finalizing) cell, is labeled there and trains once."""
    p = net.peer(k=k)
    for close in (1, 2):
        extra = [("ax", ts)] if close == at_close else []
        alerts = [("A1", ["ax"])] if close == 2 else []
        p.close(flows=_ben(close, 6) + extra, alerts=alerts)
    p.close(flows=_ben(3, 6))
    row = p.trained_by_uid()["ax"]
    assert (row["label"], row["train_window"]) == (1, 2)
    assert p.flip_snapshot().flips == 0
    assert _db_counter(p, at_close, counter) == 1
