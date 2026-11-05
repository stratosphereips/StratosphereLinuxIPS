# Federated Network Module

A federated learning module for Slips that enables collaborative intrusion detection across multiple network monitoring nodes while preserving data privacy.

## Architecture

### Model Structure
```
input(18) -> RandomProjection(256, frozen, N(0, 2/256)) -> /√256 -> fc1(256->16)+ReLU -> head(16->2)
```

- **Random Projection**: Frozen, bias-free 18→256 layer, output scaled by 1/√256 = 1/16. Weights from `kaiming_normal_` (fan_in, ReLU gain) applied to an (18, 256) tensor, so PyTorch takes fan_in = 256: entries ~ N(0, 2/256), std ≈ 0.088 (He init for the 18 inputs would give std ≈ 0.33). Drawn from a generator seeded with `seed`; shared across peers via `artifacts/random_projection.bin` (regenerated from `seed` when missing).
- **fc1 Layer**: Learnable 256→16 with ReLU activation
- **Head Layer**: Classification 16→2 for benign/malicious prediction

### Training Regime

- **Optimizer**: Adam with $\eta=0.01$ (`learning_rate`), $\beta_1=0.9$, $\beta_2=0.999$, $\epsilon=10^{-8}$ (implemented by hand, fork-safe); the local model's Adam state persists across windows
- **Weight decay**: decoupled (AdamW-style), $\lambda=10^{-4}$: each step multiplies every trainable weight by $1-\eta\lambda$ before the Adam update; frozen parameters are not decayed
- **Class-weighted loss**: $w_c = \frac{N_{\text{total}}}{2 \cdot \max(N_c, 1)}$, computed once per training pass over the whole batch (mini-batches reuse it), applied as PyTorch's weighted mean $\mathcal{L} = -\sum_i w_{y_i} \log \hat{p}_{i,y_i} / \sum_i w_{y_i}$; only for models with `USE_CLASS_WEIGHTING` (see Class balance)
- **Minimum batch size**: 30 flows (`min_training_samples`), checked on the training buffer before undersampling — below it training is deferred and the buffer carries over to the next window close
- **Epochs**: 15 local (fc1 + head; `local_training_epochs` in config/slips.yaml, code default 10), 5 fine-tune (fc1 + head on both the local and the merged model; head-only with `finetune_fc_layers: false`)

### Seeds and shared initialization

Every peer with the same `seed` starts from the same weights: merging
combines the layers element by element, which only makes sense from one
common init.

- **Trainable layers** (fc1, head; PyTorch's default `nn.Linear` init): built under `torch.manual_seed((seed XOR 0x51ED5EED) mod 2^31)`, the same on every peer, without disturbing the global RNG
- **Random projection**: a generator seeded with `seed` (`random_projection_two_layer`'s second projection: `seed XOR 0x9E3779B1`)
- **Window offset**: md5 of the peer's hostname (with `run_seed`: hostname + `run_seed`)
- **Undersampling**: `numpy.random.default_rng(seed + window)`, with `run_seed` `default_rng((run_seed, window))`
- **Mini-batch split** (`minibatch_size`): `default_rng((seed, r, window, pass, 0x6D62))`, r = 0, or `run_seed + 1` with `run_seed`
- The base class also seeds `random` and `numpy.random` with `seed`

### Class balance (`balancing`, `class_weighting`)

`balancing` chooses how a training batch is balanced:

- `weighting`: the class-weighted loss above
- `undersample`: random flows of the majority class are dropped down to 50/50, then plain cross-entropy
- `none`: plain cross-entropy
- unset or `""` (default): `class_weighting` decides; its default is the model class's `USE_CLASS_WEIGHTING` (true for `random_projection_mlp`, false for the other models)

At a window close `min_training_samples` is checked on the buffer first and
the buffer is undersampled after, so a trained batch can be much smaller than
30 (twice the minority-class count). Undersampling happens before the labels
are committed: the dropped flows leave the buffer and are neither trained nor
recorded in `trained_labels.jsonl` (the own scaler is still fit on them, see
Feature scaler).

### Feature scaler

By default (`global_scaler: true`) every model, local and merged, scales with
one fixed pretrained scaler, `artifacts/global_scaler.json`, fit offline on the
published security-datasets-for-testing, and nothing is fit during a run (see
`global_scaler` below). With `global_scaler: false` each peer fits its own:

One `StandardScaler` per peer, empty at start (no warm start in the experiment
image), updated with `partial_fit` in exactly one place: at the start of the training
at a window close (`_train_batch`), which runs after that close has scored
every open window (prequential test). It is fit on the **whole** training
buffer — the finalized window plus any earlier windows carried over below
`min_training_samples`, before undersampling drops flows — and the training
batch is then scaled with it. Local training and both fine-tunes reuse that
scaled batch and never refit; every prediction is transform-only. So no
prequential score (test streams, `comp_*` logs, live scoring) uses a scaler
that has seen the flow; `sofar_test.jsonl` does, by design. Each fit appends a
line to `scaler_stats.jsonl` (window, rows, samples seen, feature names,
per-feature mean / var / scale) for comparing the peers' scalers. With
`merge_scaler` the merged model gets its own scaler, pooled from the own and
the peers' scalers at each merge (see the option below); the local model always
keeps the own one.

### Training Buffers

1. **Training Buffer**: Filled at each window close with the flows of the window finalized at that close (see Training Flow). Only cleared after a training (≥ `min_training_samples` flows); below that it carries over to the next close. Tracks buffered flow IDs to prevent duplicates.

2. **Last training batch** (`_last_train_X` / `_last_train_Y`): the scaled training batch (after undersampling) of the last training. Both fine-tunes, local and merged, train on it (the merged one rescaled with the pooled scaler under `merge_scaler`). Kept until the next training replaces it; there is no separate alignment buffer.

## Training Flow

> **Windowing:** training windows are wall-clock windows of
> `time_window_width` seconds (code default 1200 s; the federation experiment
> configs use 300 s), independent of the SLIPS time windows. Each peer's first
> window is shortened by a deterministic offset Δ ~ U(0, 300 s), seeded by the
> md5 of its hostname (plus `run_seed`), so peers close out of phase; the
> offset does not scale with the window width. Flows and alerts are not taken
> from channels: each close reads them from SLIPS's `flows.sqlite` (no
> per-alert trigger).

### 1. Local Training (at a Window Close)

At window close N the module:

1. reads every conn flow (`flows` table) and ARP record (`altflows`,
   `flow_type` arp) SLIPS stored since the previous close (rowid cursors,
   deduplicated by Zeek uid, rows without a uid skipped) and puts all of them
   into ring cell N, by the close that read them (not by flow start time)
2. labels every open cell: a flow is matched iff its uid is cited by the
   evidence of an alert (`alerts` → `alert_evidence` → `evidence_flows`)
   created within the last `alert_uid_retention_windows` windows (default:
   the SLIPS time window, 3600 s, in module windows, rounded up); matching
   is by uid only, never by IP
3. scores every open cell's not-yet-scored flows with the serving model,
   before anything trains at this close (prequential test, see Analysis
   Outputs)
4. finalizes cell N−K (K = `label_finalize_delay_windows`, default 1; the
   first K closes only fill the ring): matched flows → **MALICIOUS**, all
   others → **BENIGN**; writes the `comp_*` logs and adds the flows to the
   training buffer (duplicates skipped via `_buffered_flow_ids`)
5. if the buffer holds ≥ `min_training_samples` (30) flows: undersamples it
   (`balancing: undersample` only), trains once (below) and clears the
   buffer; otherwise training is deferred and the buffer carries over to the
   next close (the window still advances)

A training (`_train_batch`):

1. discards the merged model of the previous training close
2. fits the own scaler on the whole buffer (no-op with `global_scaler`) and
   scales the batch
3. trains fc1 + head for `local_training_epochs` epochs, continuing the local
   Adam state
4. keeps a copy of the weights after local training: this is what peers are
   sent and what the merge uses
5. fine-tunes the local model for `merge_finetune_epochs` epochs (fc1 + head;
   head only with `finetune_fc_layers: false`) from the Adam state
   `merge_finetune_adam` selects, and saves it as `latest_local_*`
6. sends the weights from step 4 to peers
7. merges, if a usable peer model is stored (section 2)
8. clears the buffer and scores this close's models on all traffic so far
   (`sofar_test.jsonl`)

The local model that serves the next window and trains on at the next
training is the one after its fine-tune (step 5); a merge never changes it.

**Labels are final once finalized**: a flow keeps the label it was finalized
with, also while it waits in a carried-over buffer. An alert citing it later
does not relabel it; it is counted as a label flip (`label_flips.log`).

### 2. Model Merging (after Own Training)

1. Peer models arriving via P2P are only stored: the latest payload per peer, kept and reused by every later merge until that peer sends a new one
2. At a training close, right after step 6 above, the usable stored payloads (same shared keys and shapes; with `merge_scaler` also valid scaler statistics) are combined with the own weights after local training by the configured **merge rule**; no usable payload → no merge, and the local model serves the next window
3. The merged model is a copy of the local model with the merged shared weights and the own head after local training (the merged head with `merge_head`); it is fine-tuned like the local model: `merge_finetune_epochs` epochs on the same batch, fc1 + head (head only with `finetune_fc_layers: false`), from its own Adam state (`merge_finetune_adam`)
4. Saved as `merged_N` model (`merged/merged_N_state.bin` and the configured store paths); it serves, and is scored, until the next training close discards it
5. Merged models NOT reused in future merges: never sent, never merged again, never fed back into the local model

### Merge rules (registry-selected)

`federated_network_module.merge_rule` in slips yaml picks HOW merged weights
are computed from own + peer models (independent of WHEN a merge fires).
Functions are pure: `merge_<name>(own_shared, peer_models, shared_keys,
trust=None) -> dict` (`trust` is filled only for `trust_weighted`); add your
own to `MERGE_REGISTRY` in the module file and its candidate weights to
`MERGE_WEIGHTS` (see Extending Aggregation Strategy). An unknown rule stops
the module at start.

| rule | computation |
|------|-------------|
| `average` (default) | plain mean of own + peers, per shared tensor |
| `trust_weighted` | weighted blend on RAW local trust: own anchored at weight 1, each peer weighs `1 − clamp01(score·confidence)` of OUR local SLIPS threat verdict on the peer's IP (`slips_reputation` in the trust sqlite, read-only): 1 = benign/fully trusted, 0 = confidently malicious; no local verdict → 1. `merged = (own + Σ w_p·peer_p)/(1 + Σ w_p)` per shared tensor — weights are absolute, never rescaled with other peers |
| `mean_with_closest` | per shared tensor (a layer's weight and bias separately): average own (50/50) with the single **peer** tensor closest to own in L2; no peers → own, one peer → plain average. Not Byzantine-robust (formerly mislabeled `byzantine`) |
| `proximity` | per shared tensor (weight and bias separately): weighted mean of own + peers with Gaussian-kernel weights `exp(-d²/2σ²)` on each candidate's L2 distance to own (own weight 1); σ = median pairwise candidate distance of that tensor; σ≈0 → plain average |
| `distance_weighted` | own pinned at 1/2, peers split the other 1/2 **proportional** to their flat-L2 distance to own (one distance per peer, latest models, fresh per merge) — farther peers pull MORE (inverse of `proximity`); identical candidates → plain average, one peer → 50/50 |

## Model Sharing Protocol

### Sending Models
After each training (at a training close), `send_model_to_peers()` broadcasts
the model **after local training, before its fine-tune**:
- Sends the model's **shared weights** (`weights_for_sharing()` — any tensors the class declares); the head only with `merge_head`, the scaler's per-feature mean / variance only with `merge_scaler`
- Published via the P2P module (p2p_pygo channel), as base64-encoded JSON addressed to all peers (`"recipient": "*"`)
- Includes `message_type: model`, `model_class`, `n_params`, timestamp and peer ID (the sender's hostname)

### Merge Trigger
Merge occurs only:
- at the module's own training close, right after local training, and
- when at least 1 usable peer model is stored (received at any earlier time); receiving a model never triggers a merge

## Model Loading on Startup

On init, if `train_from_scratch: false` in config and both local artifacts exist:
- Load `latest_local_state.bin` (full state_dict, any registry model) + `latest_local_scaler.bin`
- Restore model and scaler state (the warm start counts only when the loaded scaler is fitted; with `global_scaler` the global scaler then replaces it)
- Print confirmation log

If `train_from_scratch: true` or artifacts missing, training starts from scratch.
A warm start restores the weights and the scaler only: the Adam state, the
stored peer models, the ring and all counters start empty.

## Artifact Paths

The numbered artifacts below have fixed paths under the module's `artifacts/`
dir (set in `init()`); they are NOT configurable via `slips.yaml`. The
section's four `*_path` keys are a separate, required set (see Final merged
model).

### Base Artifacts (Shared Across All Peers)
- `artifacts/random_projection.bin` - Frozen random projection matrix (18×256; regenerated from `seed` if missing or invalid and re-saved at every model build; used by `random_projection_mlp` and as RP1 of `random_projection_two_layer`)
- `artifacts/global_scaler.json` - the pretrained global scaler's statistics, used by every model by default (`global_scaler`)

### Local Model (Own Training Only)
- `artifacts/latest_local_state.bin` - full model `state_dict` (class-driven: any registry model), written after every training (after the local fine-tune) and at shutdown
- `artifacts/latest_local_scaler.bin` - scaler state (pickle)

### Merged Models (Aggregated)
- `artifacts/merged/merged_N_state.bin` - full `state_dict` per merge N

### Final merged model (configured paths)
At **every merge end and at graceful shutdown** (if a merged model is still
serving) the module also persists the latest merged model to the configured
store paths, so those always hold the final state: `model_store_path` (dict
`{state_dict, model_class, merge_count}`) and `preprocess_store_path` (pickle
of the merged model's scaler: the pooled one with `merge_scaler`). All other
numbered artifacts stay at the fixed paths above. All four `*_path` keys are
required: the base class refuses to start without them. `model_load_path` /
`preprocess_load_path` are read by the base class only when no
`latest_local_*` warm start happened and `train_from_scratch` is false: the
model pickle goes to an attribute this module never uses; the preprocessor
pickle, when the file exists, becomes the own scaler's starting state with
`global_scaler: false` (`partial_fit` then continues from it). The files
config/slips.yaml names there are not shipped.

## Choosing / adding a network (federation protocol)

`federated_network_module.model_class` in slips yaml selects which neural
network instance runs (default `random_projection_mlp`). The module talks to a
model ONLY through this protocol; anything implementing it works untouched
(channels, wall-clock windows, merge policy, dual testing, artifacts,
telemetry, plots):

| method / attribute | meaning |
|---|---|
| `forward(X) -> logits` | training/testing |
| `weights_for_sharing()` / `set_shared_weights(dict)` | the FEDERATED tensors averaged with peers — **any count, any shapes** |
| `get_head_weights()` / `set_head_weights(w, b)` | non-shared trainable tail (identical fine-tune around merges) |
| `set_shared_frozen(b)` / `set_head_frozen(b)` | stage freezing |
| `USE_CLASS_WEIGHTING` | class-level default: `True` → per-batch class-weighted CE; `False` → plain CE (the deliberately-simple models); `class_weighting` / `balancing` override it per run |

Shipped classes (MODEL_REGISTRY):

| `model_class` | architecture | federated | class-weighted (default) |
|---|---|---|---|
| `random_projection_mlp` (default) | RP(18→256, frozen) → /16 → fc1 256→16 → head 16→2 | fc1 | yes |
| `simple_mlp` | Linear 18→256 → Linear 256→16 → head 16→2 (ReLU after each; trainable twin of the RP net, nothing frozen) | fc1 + fc2 | no |
| `random_projection_two_layer` | RP1(18→256, frozen, `seed`) → /16 → fc1 256→64 → RP2(64→256, frozen, `seed XOR 0x9E3779B1`) → /16 → lin2 256→32 → head 32→2 (ReLU after fc1 and lin2) | fc1 + lin2 (sent as `fc2_*`) | no |

Training follows the same schedule for all: `local_training_epochs` full
epochs + `merge_finetune_epochs` local and merged fine-tunes (shared layers +
head by default) on flows labeled from SLIPS alerts at each wall-clock window
close (`time_window_width`); only the loss weighting differs by class. To add
your own model: implement the protocol (copy `SimpleMLP`), add a
`_build_<name>` fn + a line in `MODEL_REGISTRY`, set `model_class: <name>` —
peers warn loudly (not crash) on class mismatch and skip payloads whose shared
tensors do not match their own.

## Analysis Outputs (telemetry in the slips output dir)

(The artifacts above live inside the container module install dir; the
following is what lands on the host via the mounted output dir.)

Everything below is written under `<slips_output>/federated_network_module/`,
which the experiment topology bind-mounts to the host in real time, and only
with `create_performance_metrics_log_files: true` (code default false;
`weights/*.npz` is written regardless). Beyond the counts, losses and
accuracies in the logs and a few distances (`merging_data.log`), metric
computation (norms, cosine, PCA, rates) happens downstream; the module only
serializes what it already holds in memory.

Training metrics (one batch per training run, epochs inside):

| File | Content |
|------|---------|
| `local_train.log` | per close a `--- db | window_N | read conn … ---` line, per finalizing close a `--- ring | … ---` line; per training `--- window_N | M mal, B ben ---` + `local_training_epochs` epoch lines + final batch `TP/FP/TN/FN` (full local training) |
| `local_head_train.log` | same shape, the local fine-tune after local training (`merge_finetune_epochs` epoch lines; fc1 + head by default) |
| `merged_train.log` | `--- merge_N | k peers: ... + own ---` + `merge_finetune_epochs` epoch lines + final batch |

Testing vs ground truth (prequential: one line per scored window and stream,
`flows=… | GT(Mal/Ben): … | Pred(Mal/Ben): … | TP/FP/TN/FN: … | Acc=…`, under
`--- New local model (window_N) ---` headers; see Span headers):

| File | Model under test |
|------|-----------------|
| `local_test.log` | the local model, as left by the last training close (after its fine-tune): the serving model in windows without a merged model; in merge-served windows the shadow score of the same flows (dual testing) |
| `merged_test.log` | the merged model, in the windows it served (from the first merge on) |
| `local_test_conn.log` / `merged_test_conn.log` | the same two streams counting **conn flows only** (same spans and line format). Every flow (conn + ARP) counts in the files above; ARP records dominate them under a scanning attacker, so score both scopes |
| `sofar_test.jsonl` | **all traffic so far** (not prequential): at every training close, the models of that close scored on every flow read since start, **including the flows they trained on** — optimistic, report it as such. Format below |

> All traffic so far (`sofar_test.jsonl`): every conn flow and ARP record the
> module reads from flows.sqlite is stored once, when first read (raw
> features as `float32`, GT, conn flag; flows read before the first fit
> included; no model snapshots). Right after the local training and the merge
> of a training close, each model of that close is scored on all of them with
> that model's scaler (the own one; the pooled one for the merged model with
> `merge_scaler`) and the same feature extraction as the test streams. One
> JSON object per (close, model, scope):
>
> ```
> {"window": 3, "model": "local", "scope": "all", "flows": 19, "gt_mal": 5, "gt_ben": 14, "tp": 5, "fp": 2, "tn": 12, "fn": 0}
> ```
>
> `window` = N of that training close (its `--- window_N | … ---` header in
> `local_train.log`; the models then serve, and are scored prequentially,
> from window N+1 on); `model`: `local` = the close's local model after its
> fine-tune (peers are sent it as it was before the fine-tune),
> `merged` = the merged model, written only when that close merged; `scope`:
> `all` = conn + ARP, `conn` = conn flows only; malicious is the positive
> class. Closes that train nothing write no rows. GT is fixed when a flow is
> first read (later edits of the simulated-attacker list do not relabel it).

> Span headers: window N's flows are scored once, at close N, before
> anything trains at that close, by the model(s) serving window N (built at
> the last training close before it, normally close N−1). The counts are
> written when window N is finalized (close N+K) or at shutdown: a
> `--- New local model (window_N) ---` header (N = the scored window; the
> name is historical) and one line per stream with that window's counts
> only. Spans are disjoint, so summing them gives the run totals. Pair the
> two streams **by that label**, not by position.

> Dual testing: while a merged model serves, every scored flow is also
> scored by the local model (one extra forward pass per flow): the merged
> model's counts go to merged_test.log, the local model's to local_test.log.
> Windows without a merged model (before the first merge, or after a training
> close without a usable peer model) are scored by the local model alone,
> into local_test.log. Windows that closed before the first training are
> never scored.

> Live scoring: between closes, flows arriving on the `new_flow` / `new_arp`
> channels are scored with the serving merged model (nothing before the first
> merge); at the close each live prediction is checked against the close-time
> one (`live_consistency.log`). Live predictions feed no metric.

Label evidence comparisons, written at every close that finalizes a non-empty
window (before undersampling, whether or not training fires): a
`--- window_N | A alerts, E evidence. M malicious connected to evidence, B benign, T total ---`
header (N = the finalizing close; the flows are window N−K's; A / E = alerts
and evidences created since the previous close) followed by bare
`... vs ...: n samples | Mal/Ben: ... vs ... | TP/FP/TN/FN: ... | Acc: ...` rows.
"pred" = the prediction stored at the window's prequential test, by the
serving model (the merged model's in merge-served windows):

| File | Comparison |
|------|-----------|
| `comp_inferred_gt.log` | inferred train labels vs GT |
| `comp_test_inferred.log` | serving-model predictions vs inferred (train) labels |
| `comp_test_gt.log` | serving-model predictions vs GT |
| `comp_merged_inferred_gt.log` | the `comp_inferred_gt.log` row again, for merge-served windows only (labels vs GT, no model involved; no header) |
| `comp_merged_test_gt.log` | the `comp_test_gt.log` row again, for merge-served windows only (no header) |

Federation internals:

| File | Content |
|------|---------|
| `merging_data.log` | per merge: `--- merge_N | k peers ---`, `merge_rule=<rule>` (+ `merge_head=True`), `peer=<name> | L2_dist | L2_norm | n_params` per merged peer (+ `trust=` with `trust_weighted`), `merged_vs_own | L2_dist | L2_norm | differs`, a `scaler | weights …` line with `merge_scaler`, and the `finetune | …` line (see `finetune_fc_layers`); L2_norm = L2_dist / √n_params |
| `merged_scaler.jsonl` | with `merge_scaler`, one row per merge: the merged model's pooled scaler (`merge`, `window`, `weights` per candidate, `features`, `mean`, `var`, `scale`); empty otherwise |
| `training_network.log` | timestamped events (`TRAIN_START`, `TRAIN_DONE`, `MODEL_SENT`, `MERGE_START`) |
| `weights/merge_XXXX.npz` | per merge: `float32` flat vectors of all shared tensors, keys in sorted order (default model: `fc1_bias` then `fc1_weight`; + `head_bias`, `head_weight` with `merge_head`) — `own` (after local training, before the fine-tune), `merged` (the merge rule's output, before the merged fine-tune), `peer_<name>` per merged peer; consumed by the UI for weight norms, cosine correlations and 3D-PCA trajectories |

Labels, scaler and run health:

| File | Content |
|------|---------|
| `trained_labels.jsonl` | one row per trained flow: `flow_id`, `uid`, `saddr`, `daddr`, `starttime`, `label` (1 = malicious, 0 = benign), `train_window`, `arrival_window` |
| `alert_uids.jsonl` | one row per close: `window`, `alert_count`, `evidence_count`, `uid_count`, `open_cell_matches`, `uids` (the flow uids cited by the alerts since the previous close) |
| `label_flips.log` | cumulative label-flip snapshot at every training and at shutdown: flows trained BENIGN that a later alert cited, overall and per train window |
| `scaler_stats.jsonl` | one row per training: the own scaler after its fit (see Feature scaler) |
| `live_consistency.log` | one line per close: live-scoring counts and live-vs-close agreement; a `MISMATCH` line per disagreeing flow (also recorded as an error) |
| `module_errors.log` | every caught exception, with traceback; empty = clean run |
| `training_federated_network_module.log` | opened by the base class (`training_<log_suffix>.log`; `testing_<log_suffix>.log` in test mode); stays empty |

## Configuration (slips.yaml)

The module, with its base class `MLBaseDetection`, reads these keys; values
are the code defaults, comments give config/slips.yaml where it differs:

```yaml
federated_network_module:
  mode: test                        # config/slips.yaml: train
  create_performance_metrics_log_files: false   # no log files; config/slips.yaml: true
  train_from_scratch: false
  seed: 1111
  # run_seed:                       # unset (see below)
  model_class: random_projection_mlp
  merge_rule: average
  time_window_width: 1200           # seconds
  label_finalize_delay_windows: 1
  # alert_uid_retention_windows:    # ceil(parameters.time_window_width / time_window_width)
  min_training_samples: 30
  local_training_epochs: 10         # config/slips.yaml: 15
  merge_finetune_epochs: 5
  finetune_head: true
  finetune_fc_layers: true
  merge_finetune_adam: copy
  learning_rate: 0.01
  minibatch_size: 0
  balancing: ""                     # "" = class_weighting decides
  # class_weighting:                # default: the model class's USE_CLASS_WEIGHTING
  merge_head: false
  merge_scaler: false
  global_scaler: true
  # test_log_batch_size:            # training_batch_size; test mode only (config/slips.yaml: 1)
  # required, no default (config/slips.yaml values):
  model_load_path: modules/federated_network_module/artifacts/model.bin
  preprocess_load_path: modules/federated_network_module/artifacts/scaler.bin
  model_store_path: modules/federated_network_module/artifacts/model_custom.bin
  preprocess_store_path: modules/federated_network_module/artifacts/scaler_custom.bin
```

| key | code default | config/slips.yaml | values / effect |
|---|---|---|---|
| `mode` | `test` | `train` | `train` / `test`; anything else → `test` |
| `create_performance_metrics_log_files` | `false` | `true` | false = no log files (only `weights/*.npz`) |
| `train_from_scratch` | `false` | `false` | true = no `latest_local_*` warm start |
| `seed` | `1111` | `1111` | see Seeds and shared initialization |
| `run_seed` | unset | – | int; re-seeds window offset, undersampling, mini-batches |
| `model_class` | `random_projection_mlp` | – | `simple_mlp`, `random_projection_two_layer`; unknown → error when the model is built |
| `merge_rule` | `average` | – | `trust_weighted`, `mean_with_closest`, `proximity`, `distance_weighted`; unknown → the module does not start |
| `time_window_width` | `1200` | `1200` | module window, seconds |
| `label_finalize_delay_windows` | `1` | – | K ≥ 0; 0 = finalize a window at its own close |
| `alert_uid_retention_windows` | ceil(`parameters.time_window_width` / `time_window_width`) | – | alert lookback in windows (3 with config/slips.yaml) |
| `min_training_samples` | `30` | – | int (an invalid value stops the module) |
| `local_training_epochs` | `10` | `15` | |
| `merge_finetune_epochs` | `5` | `5` | forced to 0 by `finetune_head: false` |
| `finetune_head` | `true` | `true` | |
| `finetune_fc_layers` | `true` | – | |
| `merge_finetune_adam` | `copy` | `copy` | `copy` / `fresh`; unknown → `copy` |
| `learning_rate` | `0.01` | – | float > 0; invalid → 0.01 |
| `minibatch_size` | `0` | – | ≤ 0 = full batch |
| `balancing` | `""` | – | `weighting` / `undersample` / `none`; unknown → ignored |
| `class_weighting` | per model class | – | used only when `balancing` is unset |
| `merge_head` | `false` | – | |
| `merge_scaler` | `false` | – | |
| `global_scaler` | `true` | `true` | |
| `test_log_batch_size` | `training_batch_size` | `1` | test mode only |
| `model_load_path`, `preprocess_load_path` | required | `artifacts/model.bin`, `artifacts/scaler.bin` | see Final merged model |
| `model_store_path`, `preprocess_store_path` | required | `artifacts/model_custom.bin`, `artifacts/scaler_custom.bin` | final merged model + scaler |
| `training_batch_size`, `validate_on_train`, `validation_percentage` | `50`, `true`, `0.1` | `500`, `false`, `0.1` | base-class keys; no effect on this module's training |
| `log_suffix` | `federated_network_module` | same | names the (empty) `training_` / `testing_<log_suffix>.log` |
| `parameters.time_window_width` | `3600` | `3600` | SLIPS's own window; sets the alert lookback default |

Booleans accept true/false, yes/no, on/off and 1/0. The federation experiment
configs (SCL-Federation-Experiment-Runner; a run's
`output/metadata/slips_p2p.yaml`) override several keys, e.g.
`time_window_width: 300` and `train_from_scratch: true`, and set `balancing`,
`learning_rate`, `merge_rule` and `model_class` per run; take a run's values
from that file.

`finetune_head` (default true) switches both fine-tunes (local and merged) on
or off. With false, `merge_finetune_epochs` collapses to 0: the local model
trains `local_training_epochs` only, and the merged model is the merge rule's
output as it is (with `merge_head`, also the merged head; without it, the own
head after local training), serving until the next training close and
discarded like any merged model. To give the local model the same training per
window as with the fine-tune on, raise `local_training_epochs` by
`merge_finetune_epochs` (e.g. 20 instead of 15 + 5); peers are then sent the
model after those 20 epochs.

`run_seed` (optional, unset by default) gives repeat experiments run-to-run
variation while keeping the model start fixed: it re-seeds each peer's window
offset, the undersampling draw and the mini-batch split, while the random
projection and the trainable-layer init still come from `seed`, so every
repeat starts from the same model. Unset = the previous behaviour.

`learning_rate` (optional, default 0.01) is the Adam step size of every
training stage: local training and both fine-tunes (local and merged), so
local and merged stay comparable. Invalid or non-positive values fall back to
0.01.

`merge_head` (optional, default false) also shares the head: each peer sends
its head as it is after local training (before the fine-tune) together
with the shared layers, the merge rule runs unchanged over shared layers +
head, and the merged fine-tune starts from the merged head instead of the
own one. A peer payload without a head is skipped. Nothing else changes: the
local model still trains only from the previous local model, and the merged
model serves until the next training close and is discarded.
`merging_data.log` gets a `merge_head=True` line, and its distances and
`weights/merge_*.npz` vectors then include the head parameters.

`merge_scaler` (optional, default false) also shares the scaler: each peer
sends, with its model, the scaler that model trained with as its per-feature
mean `μ_i` and variance `σ_i²` (`"scaler": {"mean", "var"}` in the P2P model
message, about 1 KB next to the model's ~120 KB). Each merge pools the own and
the merged peers' statistics with the merge rule's weight `w_i` for each model
(summing to 1), pooling the variances and never averaging standard deviations:

```
μ  = Σ w_i μ_i
σ² = Σ w_i (σ_i² + μ_i²) − μ²      (computed as Σ w_i (σ_i² + (μ_i − μ)²))
```

`w_i` is what the rule gives each candidate (`MERGE_WEIGHTS` in the module,
one function per rule): average 1/(1+peers), trust_weighted the normalized
trust, distance_weighted own 1/2 + the distance split, and the per-tensor rules
(proximity, mean_with_closest) computed over all shared tensors as one vector.
With one peer that equals their per-tensor weights (proximity: 62/38). The
merged model gets this pooled scaler: its fine-tune trains on the batch scaled
with it, and its predictions (test streams, live scoring, `sofar_test.jsonl`,
the final merged scaler at `preprocess_store_path`) use it. The local model
keeps the own scaler, and the pooled one is discarded with the merged model. A
received scaler is validated (18 finite means, 18 finite non-negative
variances); a peer whose model came without a valid scaler is skipped from
the merge, so the model and the scaler always pool the same peers. Every merge
adds a line to `merging_data.log`, `  scaler | weights own:<w> <peer>:<w> … |
mean_shift_sd=… | scale_ratio=<min>-<max>` (largest shift of the pooled mean in
own standard deviations; pooled / own scale per feature), and a
`merged_scaler.jsonl` row (merge, window, weights, pooled mean / var / scale).

`global_scaler` (default true; false = each peer fits its own scaler) gives
every model, local and merged, one fixed pretrained scaler:
`artifacts/global_scaler.json`, the
statistics (per-feature mean, variance, scale, samples seen, feature names,
source) of a StandardScaler fit on every conn flow of the published
[security-datasets-for-testing](https://github.com/stratosphereips/security-datasets-for-testing)
(707,212 flows of 34 Zeek conn logs at e1222857, repeated uids skipped), each
flow through SLIPS's Zeek parser and this module's feature extraction. The
datasets hold no ARP records, so ARP records are scaled with conn statistics.
It is loaded at start (and again after the base
class's artifact loading, which would replace it with an empty scaler) and
never fit: `update_preprocessor` does nothing, so `scaler_stats.jsonl` logs
the same statistics at every training. A file whose feature names differ from
the module's, or with an invalid value, stops the module at start. With
`merge_scaler` on as well every peer sends the same statistics, so the pooled
scaler is the global one. The file is reproducible: `fit_global_scaler.sh
OUT.json ROOT...` in
[SCL-Federation-Experiment-Runner](https://github.com/stratosphereips/SCL-Federation-Experiment-Runner)
(`thesis_experiments/`, branch `jsvobo/thesis-experiments`) runs the fit inside
the module's image, `partial_fit` one conn log at a time, and writes the
artifact with its `source` line, plus a per-file flow count in
`OUT.files.tsv` next to it.

Why it is the default: a peer's own scaler is fit only on what that peer has
seen so far (first its benign baseline), so the same flow is scaled
differently on different peers and over time; a fixed scaler from published
data keeps every model on one input scale and is fit on no lab traffic. In the
small-topology comparison (one run each, fc1 + head fine-tune, last 5 windows,
MCC over all flows of both peers, local → merged): own scaler 0.283 → 0.210,
the first pretrained scaler (19,635 flows of the dataset's captures
008/010/011, about 92% TCP; SLIPS 67ed1e0a6) 0.458 → 0.471, this one 0.703 →
0.706. Most of the gain is ARP on the weaker peer, which its local model
catches in 14 of 15 attack windows instead of 9 (own scaler) or about 12
(first scaler); with the first scaler the lab's protocol feature sat 10.7
standard deviations from its mean and the stronger peer flipped between
all-malicious and all-benign windows. The cost: the stronger peer misses a few
more conn flows than with its own scaler (conn MCC 0.90 instead of 0.98).

`finetune_fc_layers` (default true) makes the fine-tune after the merge point
train the fc (shared) layers + head instead of the head alone, on the local and on the merged
model alike, each from its own throwaway Adam state (`merge_finetune_adam`) with
the same learning rate (the local model's training state carries on to the next
window). Peers are
still sent the model after local training, before the fine-tune, and that is
what the merge averages, so both fine-tunes start from the merge point and only
their starting weights differ. Because the local fine-tune now changes fc1, the
local model trains `local_training_epochs + merge_finetune_epochs` epochs per
window. Each merge adds a line to `merging_data.log`:

```
  finetune | gap_before=… | gap_after=… | undone=0.42 | local_moved=… | merged_moved=… | fc_trained=True | n_params=…
```

over all trainable weights: `gap_before` = merged vs own model where the
fine-tunes start, `gap_after` = the two after them, `undone` = 1 − after/before
(1 = both end on the same model, 0 = as far apart as the merge put them). The
line is also written with the option off (`finetune_fc_layers: false`: head-only
fine-tunes with fc1 frozen, the behaviour before this option).

`merge_finetune_adam` (default `copy`) sets the Adam state both fine-tunes
start from. `copy`: right after local training, each fine-tune (local and
merged) gets its own copy of the training state; the two never share one, the
copies are discarded afterwards, and the local training state carries on to the
next window as local training left it. With warm moments a step is
proportional to the gradient, so a near-tie in the labels gets a small step.
`fresh`: an empty state, the behaviour before this option; Adam's first step
from an empty state moves every weight by about the learning rate whatever the
gradient size. With `fresh` and `finetune_fc_layers: false` the local
fine-tune does not get a separate state: it zeroes the head moments of the
training state itself, and the moments it leaves carry into the next local
training (the merged fine-tune always gets an empty state).

`minibatch_size` (optional, default 0 = full batch) splits every training pass
(local training and both fine-tunes) into ceil(n / minibatch_size) near-equal,
class-stratified mini-batches of at most that size, one Adam step each,
reshuffled every epoch from a generator seeded per window and pass (both
fine-tunes draw the same splits). An epoch is then
several steps instead of one, so the step count per window grows with the batch:
with 100 a 118-flow batch takes 2 steps per epoch, a 1,230-flow batch 13.

`label_finalize_delay_windows` (default 1) is K, how many closes a window's
flows wait in the ring before their labels are final and they enter the
training buffer, so that alerts raised after the window can still label
them; 0 finalizes a window at its own close. `alert_uid_retention_windows`
(default: the SLIPS `parameters.time_window_width` in module windows, rounded
up: 3 at 1200 s, 12 at 300 s) is how old an alert may be and still label a
flow.

`balancing` / `class_weighting`: see Class balance above.
`test_log_batch_size` only matters with `mode: test` (see Test Mode).

### Hyperparameter Summary

\begin{table}[h]
\centering
\caption{Federated Learning hyperparameters}
\label{tab:fl-hyperparams}
\begin{tabular}{@{}lll@{}}
\toprule
\textbf{Parameter} & \textbf{Value} & \textbf{Description} \\
\midrule
$E_{\text{local}}$  & 15  & Local training epochs (fc1 + head; config/slips.yaml, code default 10) \\
$E_{\text{merge}}$  & 5   & Fine-tuning epochs after the merge point (fc1 + head, both models) \\
$\eta$              & 0.01 & Learning rate (Adam, \texttt{learning\_rate}) \\
$\beta_1, \beta_2, \epsilon$ & 0.9, 0.999, $10^{-8}$ & Adam moment decays and epsilon \\
$\lambda$           & $10^{-4}$ & Decoupled (AdamW-style) weight decay \\
$B_{\text{min}}$    & 30  & Minimum training buffer (checked before undersampling) \\
$T_w$               & 1200 s & Module window width (federation experiment configs: 300 s) \\
$\Delta_T$          & $\sim\mathcal{U}(0, 300\,\text{s})$ & Per-peer first-window offset (hostname-seeded) \\
$K$                 & 1   & Label finalization delay (windows) \\
$T_{\text{alert}}$  & 3600 s & Alert lookback (\texttt{alert\_uid\_retention\_windows} $\times T_w$) \\
$\theta_{\text{RATL}}$ & 5 & SLIPS live alert gate (\texttt{detection.risk\_accumulated\_threat\_level}) \\
\multicolumn{3}{@{}l}{}\\
\textbf{Class-Weighted Loss} & & \\
\midrule
\multicolumn{3}{@{}l}{$w_c = \dfrac{N_{\text{mal}} + N_{\text{ben}}}{2 \cdot \max(N_c, 1)}$ \quad for $c \in \{\text{Benign}, \text{Malicious}\}$} \\
\multicolumn{3}{@{}l}{$\mathcal{L} = -\dfrac{\sum_{i} w_{y_i} \log \hat{p}_{i, y_i}}{\sum_{i} w_{y_i}}$ \quad (per-batch weights)} \\
\bottomrule
\end{tabular}
\end{table}

Values are the defaults (code / config/slips.yaml); the federation experiment
configs override some (see Configuration). The module reads no SLIPS alert
threshold: on live input (an interface, as the federation peers use) SLIPS
alerts when the risk-weighted accumulated threat level reaches
`detection.risk_accumulated_threat_level` (5 in config/slips.yaml and in the
experiment configs); `detection.evidence_detection_threshold` (0.25) applies
only to non-live input.

### Epochs
- **Local training**: 15 epochs (`local_training_epochs`; code default 10) per training close
- **Fine-tuning**: 5 epochs of fc1 + head after the merge point, on the local and the merged model (head-only with `finetune_fc_layers: false`)
- With `minibatch_size` an epoch takes one Adam step per mini-batch, else one full-batch step

### Learning Rate
- Adam optimizer with $\eta = 0.01$ (config `learning_rate`), decoupled weight decay $\lambda = 10^{-4}$
- The decay multiplies each trainable parameter by $1 - \eta\lambda$ per step; frozen parameters (the random projection, fc1 in head-only fine-tunes) are not decayed

## Feature Handling

- **Fixed Input Dimension**: 18 features, matching `SimpleFederatedNet.FIXED_INPUT_DIM`
- **All Protocols Kept**: Inclusive encoding (tcp=0, udp=1, icmp=2, icmp-ipv6=3, arp=4) via base class `_encode_proto()`; an unknown protocol encodes as 0 (like tcp)
- **State Inferred**: Uses base class `_infer_state()` (not raw conn_state)
- **IP to Numeric**: Converted via `ipaddress.ip_address()` modulo 1e6 (a missing address is 0; an unparseable one drops the flow from training and scoring)
- **Flow ID**: Uses Zeek `uid` when available, falls back to `saddr:sport-daddr:dport-starttime` (train mode only reads flows that have a uid)
- **Missing values**: missing numeric fields are 0; a missing `appproto` is other (10.0)

### Feature List (18 features)

In input order (`_get_feature_order()`; also the `features` list of
`artifacts/global_scaler.json`):

| # | Feature | Source | Description |
|---|---|---------|-------------|
| 1 | dur | flow.dur | Duration in seconds |
| 2 | sport | flow.sport | Source port |
| 3 | dport | flow.dport | Destination port |
| 4 | spkts | flow.spkts | Source packets |
| 5 | dpkts | flow.dpkts | Destination packets |
| 6 | sbytes | flow.sbytes | Source bytes |
| 7 | dbytes | flow.dbytes | Destination bytes |
| 8 | proto | `_encode_proto()` | Inclusive: tcp=0.0, udp=1.0, icmp=2.0, icmp-ipv6=3.0, arp=4.0 |
| 9 | appproto | `_encode_appproto()` | http=0.0, dns=1.0, ssl=2.0, ssh=3.0, smtp=4.0, ftp=5.0, pop3=6.0, imap=7.0, telnet=8.0, https=9.0, other=10.0 |
| 10 | state | `_infer_state()` | 1.0 or 0.0 based on state string and packet counts |
| 11 | saddr_num | Derived | ipaddress int % 1e6 |
| 12 | daddr_num | Derived | ipaddress int % 1e6 |
| 13 | dir_num | Derived | 1.0 if dir_=="->" (also when missing) else 0.0 |
| 14 | total_bytes | Derived | sbytes + dbytes |
| 15 | total_pkts | Derived | spkts + dpkts |
| 16 | avg_pkt_size | Derived | sbytes / max(spkts, 1) |
| 17 | throughput | Derived | total_bytes / max(dur, 0.001) |
| 18 | history_len | Derived | len(str(history)), 0 when empty |

## Evidence and Alerts

The module raises no SLIPS evidence and no alerts, in train or test mode:
`set_evidence_malicious_flow` is overridden to do nothing, because evidence of
its own would feed back into the alerts it labels its training data with (and
would change SLIPS's alerting). Its predictions only go to the logs above.
`malicious_flow_evidence_type` and `malicious_flow_description_template` are
defined only because the base class requires them. No code path of the
module calls the method either (its test path does not use the base class's
`_test_default`), so turning evidence on takes more than deleting the
override: the classification paths would also have to call it.

## Ground Truth (evaluation only)

Ground truth (GT) only scores models and labels; it is never used to train.
A flow's GT is:

1. its `ground_truth_label` (or `detailed_ground_truth_label`), when that
   starts with mal/attack (malicious) or ben/norm (benign);
2. otherwise malicious iff its `saddr` or `daddr` is listed in
   `/opt/network-setup/simulated_attackers.txt` (one IP per line, `#`
   comments; path overridable with the env var `FL_SIM_ATTACKERS`; re-read
   when the file changes), the list the experiment runtime writes;
3. otherwise benign (so every flow has a GT).

GT is therefore IP-based, while the training labels come from alert evidence
by uid. It is evaluated when used; `sofar_test.jsonl` fixes it when a flow is
first read.

When the attacker list exists, every window close also writes each fetched
flow's GT into SLIPS's `flows.sqlite` (`ground_truth_label` inside the stored
flow JSON, tables `flows` and `altflows`, by uid) for offline evaluation;
without the list (live capture) nothing is written. The other SLIPS modules
that read `ground_truth_label`, `ml_online_model` and `ml_linear_model`, run
with `mode: test` in the federation experiment configs, so no module trains on
these labels.

## Graceful Shutdown

On shutdown (train mode), the module:
1. Writes the scores of the windows still in the ring (scored during the run, never trained)
2. Writes a final `label_flips.log` snapshot
3. Saves the latest local model (if there is one)
4. Saves the merged model, if one is still serving (`merged/merged_N_state.bin` + the configured store paths)

Flows still in the training buffer or in unfinalized windows are not trained.
If `train_from_scratch: false`, the next run will load the local artifacts
(weights and scaler only, see Model Loading on Startup).

## Test Mode

With `mode: test` the module does not train, merge or read `flows.sqlite`: it
classifies every flow arriving on `new_flow` / `new_arp` with the warm-started
local model (it needs `latest_local_state.bin` + `latest_local_scaler.bin` and
`train_from_scratch: false`; without them nothing is classified) and appends a
cumulative line (the format of the test lines above, no headers) to
`local_test.log` every `test_log_batch_size` flows. `test_log_batch_size` has
no effect in train mode.

## Metrics and Logging

The main logs in `output/<timestamp>/federated_network_module/` (all files:
Analysis Outputs). The examples show the line formats; `<...>` are
placeholders, not results.

### local_train.log
Per close, per finalizing close and per training (full local training, fc1 + head):
```
--- db | window_<N> | read conn <c> arp <a> | placed <f> late <l> next 0 | newest ts lag <s>s ---
--- ring | pending <k> cells | finalized mal <m> ben <b> | ring matches <h> | alerts <A> | flips <F> ---
--- window_<N> | <m2> mal, <b2> ben ---
  epoch 1/15 | loss=<loss> | acc=<acc>
  ...
  epoch 15/15 | loss=<loss> | acc=<acc>
  batch <n> (Mal:<m2> Ben:<b2>) | loss=<loss> | acc=<acc> | TP/FP/TN/FN: <tp>/<fp>/<tn>/<fn>
```
`db`: the flows read at this close; `ring`: the window finalized at this close
(`ring matches` = flows newly matched at this close, `alerts` = alerts since
the previous close, `flips` = cumulative); the training block counts the
trained batch (the whole buffer, after undersampling).

### local_test.log / merged_test.log (+ *_test_conn.log)
Prequential testing: one line per scored window and stream, with that
window's counts only (see Span headers). The `_conn` twins count only conn
flows, under the same headers.
```
--- New local model (window_<N>) ---
  flows=<n> | GT(Mal/Ben): <gm>/<gb> | Pred(Mal/Ben): <pm>/<pb> | TP/FP/TN/FN: <tp>/<fp>/<tn>/<fn> | Acc=<acc>
```

### comp_inferred_gt.log
Inferred labels (from alert evidence) of the window finalized at close N vs
ground truth, written at finalization: what the buffer gets, before
undersampling, whether or not training fires.
```
--- window_<N> | <A> alerts, <E> evidence. <m> malicious connected to evidence, <b> benign, <t> total ---
  inferred vs GT: <t> samples | Mal/Ben: <m>/<b> vs <gm>/<gb> | TP/FP/TN/FN: <tp>/<fp>/<tn>/<fn> | Acc: <acc>
```

### comp_test_inferred.log
Serving-model predictions vs inferred (alert) labels. Tests: "was the model
live during the window agreeing with the alert evidence BEFORE we trained on
it?" Uses the predictions stored at the window's prequential test (the
merged model's in merge-served windows) against the labels the window got at
finalization.
```
--- window_<N> | ... ---
  pred vs inferred: <n> samples | Mal/Ben: <pm>/<pb> vs <m>/<b> | TP/FP/TN/FN: <tp>/<fp>/<tn>/<fn> | Acc: <acc>
```

### comp_test_gt.log
The same stored predictions vs ground truth. Every predicted flow is
included (GT defaults to benign, see Ground Truth).
```
--- window_<N> | ... ---
  pred vs GT: <n> samples | Mal/Ben: <pm>/<pb> vs <gm>/<gb> | TP/FP/TN/FN: <tp>/<fp>/<tn>/<fn> | Acc: <acc>
```

## Extending Aggregation Strategy

Merge rules live in two registries in the module file; `trigger_merge()`
needs no change. Add a rule, its candidate weights (used to pool the scalers
under `merge_scaler`; without them every merge fails with that option) and
two registry lines, then set `merge_rule: my_rule`:

```python
def merge_my_rule(own_shared, peer_models, shared_keys, trust=None) -> dict:
    # own_shared: {key: tensor}; peer_models: {peer_id: {key: tensor}};
    # trust: {peer_id: {"trust": float, "ip": str}}, filled only for
    # trust_weighted. Return {key: merged tensor} for every shared key.
    ...


def weights_my_rule(own_flat, peer_flats, trust=None) -> dict:
    # Weight per candidate ("own" + each peer id) over the flat vectors
    # (all shared tensors concatenated), summing to 1.
    ...


MERGE_REGISTRY = {..., "my_rule": merge_my_rule}
MERGE_WEIGHTS = {..., "my_rule": weights_my_rule}
```

## P2P Integration Requirements

Model sharing uses the P2P module's channels:
1. `p2p_pygo` (Python → Go) - the module publishes each model as `{"message": <base64 JSON>, "recipient": "*"}` (all peers)
2. `p2p_gopy` (Go → Python) - subscribed as soon as it exists; `go_data` messages whose inner `message_type` is `model` are stored, other messages are ignored
3. Peer ID - each peer names itself by its hostname (`peer_id` in the payload); `trust_weighted` resolves that name via DNS to the IP whose SLIPS reputation it reads

If P2P channels are unavailable, local training continues normally but model sharing is disabled.

## Troubleshooting

**"Preprocessor not fitted" error**: raised by `transform_features()` before any scaler is fitted, i.e. only with `global_scaler: false` before the first training (the default global scaler is fitted from the start). The module scores nothing before its first training.

**"Input dimension … does not match expected fixed size 18"**: the networks take exactly the 18 features of `_get_feature_order()`; `artifacts/global_scaler.json` must list the same features, or the module stops at start.

**No peer models received**: P2P module may not be available. Check P2P module configuration. Merges run only at the module's own training closes, using the stored peer models; none stored → no merge (no periodic timer, no merge on receipt).

**Label comparison shows high FP**: Alerts from other modules may have false positives. The FL module learns from alert evidence, not Zeek ground truth. This is by design — the comparison logs quantify alert noise.

**Model not loading on startup**: Check `train_from_scratch: false` in config and verify that both `latest_local_state.bin` and `latest_local_scaler.bin` exist in `modules/federated_network_module/artifacts/`.

**Stale `__pycache__` causing silent training failure**: When the module source is updated, old `.pyc` bytecode cache can cause Python to load stale code where `fit_incremental_model` is a `pass`-only abstractmethod. Fix: the module's `init()` calls `shutil.rmtree()` on `__pycache__` at startup. Also documented in `bugs.md`.
