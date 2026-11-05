# Federated Network Module

A federated learning module for Slips that enables collaborative intrusion detection across multiple network monitoring nodes while preserving data privacy.

## Architecture

### Model Structure
```
input(18) -> RandomProjection(256, frozen, He init) -> /√256 -> fc1(256->16)+ReLU -> head(16->2)
```

- **Random Projection**: Frozen 18→256 layer with He (`kaiming_normal_`) initialization, output scaled by 1/√256 ≈ 1/16. Shared across peers via `artifacts/random_projection.bin`.
- **fc1 Layer**: Learnable 256→16 with ReLU activation
- **Head Layer**: Classification 16→2 for benign/malicious prediction

### Training Regime

- **Optimizer**: Adam with $\eta=0.005$, L2 weight decay $\lambda=10^{-4}$
- **Class-weighted loss**: $w_c = \frac{N_{\text{total}}}{2 \cdot \max(N_c, 1)}$ per batch, computed fresh each call
- **Minimum batch size**: 30 flows — training deferred, buffer accumulates across consecutive alerts/windows until threshold met
- **Epochs**: 15 local (fc1 + head), 5 fine-tune (fc1 + head on both the local and the merged model; head-only with `finetune_fc_layers: false`)

### Feature scaler

By default (`global_scaler: true`) every model, local and merged, scales with
one fixed pretrained scaler, `artifacts/global_scaler.json`, fit offline on the
published security-datasets-for-testing, and nothing is fit during a run (see
`global_scaler` below). With `global_scaler: false` each peer fits its own:

One `StandardScaler` per peer, empty at start (no warm start in the experiment
image), updated with `partial_fit` in exactly one place: at the start of the training
at a window close (`_train_batch`), which runs after that close has scored
every open window (prequential test). It is fit on the **whole** finalized
window — before undersampling drops flows — and the training batch is then
scaled with it. Local training and both fine-tunes reuse that scaled batch and
never refit; every prediction is transform-only. So no flow is ever
scored with a scaler that has seen it. Each fit appends a line to
`scaler_stats.jsonl` (window, rows, samples seen, per-feature mean / var /
scale) for comparing the peers' scalers. With `merge_scaler` the merged model
gets its own scaler, pooled from the own and the peers' scalers at each merge
(see the option below); the local model always keeps the own one.

### Training Buffers

1. **Training Buffer**: Populated incrementally across deferred alerts/twcloses. Only cleared after successful training (≥30 flows). Tracks buffered flow IDs to prevent duplicates.

2. **Alignment Buffer**: Mirrors the training buffer. Used for head-only fine-tuning during weight-averaging merging. Cleared alongside training buffer.

## Training Flow

> **Windowing note (2026-09-10):** the trigger described below as "alert or
> sub-window close" is implemented as **wall-clock training windows**
> (default 5 minutes) with a deterministic per-peer offset. On each window
> close the module labels everything buffered during the window and trains
> once. Buffered alerts are consumed together at window close (no
> per-alert training trigger).

### 1. Local Training (on Alert or Sub-Window Close)

**On New Alert:**
1. Extract evidence IDs from alert (`correl_id` + `last_evidence.ID`)
2. Match evidence UIDs against current window flows
3. Fallback: match by attacker/victim IP from `last_evidence` against window
4. Label connected flows **MALICIOUS**, all other window flows **BENIGN**
5. Add newly labeled flows to accumulating training buffer (skip duplicates via `_buffered_flow_ids`)
6. Compare labels vs ground truth → write to `comp_inferred_gt.log` / `comp_test_inferred.log` / `comp_test_gt.log`
7. If buffer ≥ 30 flows: train fc1 + head, clear buffer + window, send model to peers
8. If buffer < 30 flows: defer training, keep buffer and window for next alert/twclose

**On Sub-Window Close:**
1. Flow timestamps trigger sub-window expiry (independent of Slips global TW)
2. Per-instance random offset (≤ $T_w/2$) desynchronizes peer window boundaries
3. All flows in window → **BENIGN**, added to accumulating buffer
4. If buffer ≥ 30: train, clear, restart window
5. If buffer < 30: defer, keep buffer and window

**Accumulation across deferred alerts**: Labeled flows persist in the buffer even if subsequent alerts' evidence doesn't match them. Their original labels (malicious/benign) are preserved.

### 2. Model Merging (Event-Based)

1. Receive peer models via P2P → aggregated with the configured **merge rule**
2. Freeze the shared layers, fine-tune the head on the alignment buffer (same data as last training batch)
3. Save as `merged_N` model
4. Merged models NOT reused in future merges

### Merge rules (registry-selected)

`federated_network_module.merge_rule` in slips yaml picks HOW merged weights
are computed from own + peer models (independent of WHEN a merge fires).
Functions are pure: `merge_<name>(own_shared, peer_models, shared_keys) ->
dict`; add your own in the registry in the module file.

| rule | computation |
|------|-------------|
| `average` (default) | plain mean of own + peers, per shared tensor |
| `trust_weighted` | weighted blend on RAW local trust: own anchored at weight 1, each peer weighs `1 − clamp01(score·confidence)` of OUR local SLIPS threat verdict on the peer's IP (`slips_reputation` in the trust sqlite, read-only): 1 = benign/fully trusted, 0 = confidently malicious; no local verdict → 1. `merged = (own + Σ w_p·peer_p)/(1 + Σ w_p)` per shared tensor — weights are absolute, never rescaled with other peers |
| `mean_with_closest` | per shared layer: average own (50/50) with the single **peer** layer closest to own in L2; no peers → own, one peer → plain average. Not Byzantine-robust (formerly mislabeled `byzantine`) |
| `proximity` | per shared layer: weighted mean of own + peers with Gaussian-kernel weights `exp(-d²/2σ²)` on each candidate's L2 distance to own (own weight 1); σ = median pairwise candidate distance of that layer; σ≈0 → plain average |
| `distance_weighted` | own pinned at 1/2, peers split the other 1/2 **proportional** to their flat-L2 distance to own (one distance per peer, latest models, fresh per merge) — farther peers pull MORE (inverse of `proximity`); identical candidates → plain average, one peer → 50/50 |

## Model Sharing Protocol

### Sending Models
After each local training event (alert or window close), call `send_model_to_peers()`:
- Sends the model's **shared weights** (`weights_for_sharing()` — any tensors the class declares; head never shared)
- Published via the P2P module (p2p_pygo channel)
- Includes `model_class`, `n_params`, timestamp and peer ID

### Merge Trigger
Merge occurs only when:
- At least 1 peer model received (event-based only)

## Model Loading on Startup

On init, if `train_from_scratch: false` in config and local artifacts exist:
- Load `latest_local_state.bin` (full state_dict, any registry model) + `latest_local_scaler.bin`
- Restore model and scaler state
- Print confirmation log

If `train_from_scratch: true` or artifacts missing, training starts from scratch.

## Artifact Paths

All paths are hardcoded in `init()`. They are NOT configurable via `slips.yaml`.

### Base Artifacts (Shared Across All Peers)
- `artifacts/random_projection.bin` - Frozen random projection matrix (created once, distributed to the default model only)
- `artifacts/global_scaler.json` - the pretrained global scaler's statistics, used by every model by default (`global_scaler`)

### Local Model (Own Training Only)
- `artifacts/latest_local_state.bin` - full model `state_dict` (class-driven: any registry model)
- `artifacts/latest_local_scaler.bin` - scaler state (pickle)

### Merged Models (Aggregated)
- `artifacts/merged/merged_N_state.bin` - full `state_dict` per merge N

### Final merged model (configured paths)
At **every merge end and at graceful shutdown** the module also persists the
latest merged model to the configured store paths, so those always hold the
final state: `model_store_path` (dict `{state_dict, model_class, merge_count}`)
and `preprocess_store_path` (scaler pickle). All other numbered artifacts stay
at the hardcoded paths above. The `model_load_path` / `preprocess_load_path`
keys are read but intentionally unused (warm-load keeps the hardcoded
`latest_local_state.bin`, gated by `train_from_scratch`).

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
| `USE_CLASS_WEIGHTING` | class-level flag: `True` → per-batch class-weighted CE; `False` → plain CE (the deliberately-simple models) |

Shipped classes (MODEL_REGISTRY):

| `model_class` | architecture | federated | class-weighted |
|---|---|---|---|
| `random_projection_mlp` (default) | RP(18→256, frozen) → fc1 256→16 → head 16→2 | fc1 | yes |
| `simple_mlp` | Linear 18→256 → Linear 256→16 → head 16→2 (trainable twin of the RP net, nothing frozen) | fc1 + fc2 | no |
| `random_projection_two_layer` | RP(18→256, frozen, same seed) → fc1 256→64 → fc2 64→32 → head 32→2 | fc1 + fc2 | no |

Training is identical for all: 15 full epochs + 5-local-head + 5-merged-head
fine-tunes on flows labeled from SLIPS alerts at each wall-clock window close
(`time_window_width`). To add your own model: implement the protocol (copy
`SimpleMLP`), add a `_build_<name>` fn + a line in `MODEL_REGISTRY`,
set `model_class: <name>` — peers warn loudly (not crash) on class mismatch.

## Analysis Outputs (telemetry in the slips output dir)

(The artifacts above live inside the container module install dir; the
following is what lands on the host via the mounted output dir.)

Everything below is written under `<slips_output>/federated_network_module/`,
which the experiment topology bind-mounts to the host in real time. All
metric computation (norms, cosine, PCA, rates) happens downstream; the
module only serializes what it already holds in memory.

Training metrics (one batch per training run, epochs inside):

| File | Content |
|------|---------|
| `local_train.log` | `--- window_N | M mal, B ben ---` + 15 epoch lines + final batch `TP/FP/TN/FN` (full local training) |
| `local_head_train.log` | same shape, head fine-tune after local full training |
| `merged_train.log` | `--- merge_N | k peers: ... + own ---` + 5 epoch lines + final batch |

Testing vs ground truth (cumulative per-flow `GT(Mal/Ben)` / pred / Acc lines
under `--- New local model (window_N) ---` headers):

| File | Model under test |
|------|-----------------|
| `local_test.log` | local-only model (the frozen snapshot from the last full local training; from the first merge on, this stream is driven by the dual-testing second forward pass) |
| `merged_test.log` | merged model (active once a merge is done) |
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
> `window` = N of that close's `New local model (window_N)` header; `model`:
> `local` = the local-only model of the close (the one sent to peers),
> `merged` = the merged model, written only when that close merged; `scope`:
> `all` = conn + ARP, `conn` = conn flows only; malicious is the positive
> class. Closes that train nothing write no rows. GT is fixed when a flow is
> first read (later edits of the simulated-attacker list do not relabel it).

> Span headers: each stream's lines follow a `--- New local model (window_N) ---`
> header naming the training that produced the model under test; pair the two
> streams **by that label**, not by position. The local stream writes its
> header when it is first used in a span, so the first merged span has one in
> both files.

> Dual testing (2026-09-10): after every full local training the local-only
> weights are deep-copied; while a merged model is active, EVERY flow is
> classified by **both** models (the legacy path writes merged_test.log, the
> second stream writes local_test.log). Cost: one extra forward pass per flow
> when merged. Before the first merge, local_test.log is produced by the
> legacy active-model path as before.

Label evidence comparisons (windowed `--- window_N | A alerts ... ---` headers
and/or bare `... vs GT: N samples | ... | TP/FP/TN/FN: ... | Acc: ...` rows):

| File | Comparison |
|------|-----------|
| `comp_inferred_gt.log` | inferred train labels vs GT |
| `comp_test_inferred.log` | local model predictions vs inferred (train) labels |
| `comp_test_gt.log` | local model predictions vs GT |
| `comp_merged_inferred_gt.log` | merged model predictions vs inferred (train) labels |
| `comp_merged_test_gt.log` | merged model predictions vs GT |

Federation internals:

| File | Content |
|------|---------|
| `merging_data.log` | per merge: `peer=<name> | L2_dist | L2_norm | n_params`, plus `merged_vs_own | L2_dist | L2_norm | differs` (and a `scaler | weights …` line with `merge_scaler`) |
| `merged_scaler.jsonl` | with `merge_scaler`, one row per merge: the merged model's pooled scaler (`merge`, `window`, `weights` per candidate, `features`, `mean`, `var`, `scale`); empty otherwise |
| `training_network.log` | timeline events (`TRAIN_START/DONE`, `MODEL_SENT`, `MERGE_START`, `ALERT`) |
| `weights/merge_XXXX.npz` | per merge: flat fc1 vectors (`float32`) — `own` (pre-merge), `merged`, `peer_<name>` per received model (+ biases); consumed by the UI for weight norms, cosine correlations and 3D-PCA trajectories |

## Configuration (slips.yaml)

Only these keys are actually read by the module:

```yaml
federated_network_module:
  mode: train
  train_from_scratch: false
  create_performance_metrics_log_files: true
  local_training_epochs: 15
  merge_finetune_epochs: 5
  min_training_samples: 30
  time_window_width: 1200
  test_log_batch_size: 1
  seed: 1111
  evidence_detection_threshold: 0.20
  # run_seed: 2   # optional, for repeat runs (see below)
  # learning_rate: 0.01   # optional, Adam step size (see below)
  # merge_head: false      # optional, also share + merge the head (see below)
  # merge_scaler: false    # optional, also share the scaler; the merged model gets the pooled one (see below)
  global_scaler: true      # every model uses the pretrained artifacts/global_scaler.json, never fit; false = own scaler per peer (see below)
  # finetune_head: true    # false = no fine-tune at all (see below)
  # finetune_fc_layers: true  # fine-tune fc1 + head on both models (false = head only, see below)
  # merge_finetune_adam: copy  # Adam state the fine-tunes start from (fresh = empty, see below)
  # minibatch_size: 0       # optional, mini-batch size of every training pass (see below)
```

`finetune_head` (default true) switches both fine-tunes (local and merged) on
or off. With false, `merge_finetune_epochs` collapses to 0: the local model
trains `local_training_epochs` only, and the merged model is the merge rule's
output as it is (with `merge_head`, also the merged head; without it, the own
head after local training), scored for one window and discarded like any merged
model. To give the local model the same training per window as with the
fine-tune on, raise `local_training_epochs` by `merge_finetune_epochs` (e.g.
20 instead of 15 + 5); peers are then sent the model after those 20 epochs.

`run_seed` (optional, unset by default) gives repeat experiments run-to-run
variation while keeping the model start fixed: it re-seeds each peer's window
offset and the undersampling draw, while the random projection and the
trainable-layer init still come from `seed`, so every repeat starts from the
same model. Unset = the previous behaviour.

`learning_rate` (optional, default 0.01) is the Adam step size of every
training stage: local training and both head fine-tunes (local and merged), so
local and merged stay comparable. Invalid or non-positive values fall back to
0.01.

`merge_head` (optional, default false) also shares the head: each peer sends
its head as it is after local training (before the head fine-tune) together
with the shared layers, the merge rule runs unchanged over shared layers +
head, and the merged head fine-tune starts from the merged head instead of the
own one. A peer payload without a head is skipped. Nothing else changes: the
local model still trains only from the previous local model, and the merged
model serves one window and is discarded. `merging_data.log` gets a
`merge_head=True` line, and its distances and `weights/merge_*.npz` vectors
then include the head parameters.

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
trust, distance_weighted own 1/2 + the distance split, and the per-layer rules
(proximity, mean_with_closest) computed over all shared tensors as one vector.
With one peer that equals their per-layer weights (proximity: 62/38). The
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
artifact with its `source` line plus a per-file flow count.

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
`fresh`: an empty state (head-only: the head moments reset), the behaviour
before this option; Adam's first step from an empty state moves every weight by
about the learning rate whatever the gradient size.

`minibatch_size` (optional, default 0 = full batch) splits every training pass
(local training and both fine-tunes) into ceil(n / minibatch_size) near-equal,
class-stratified mini-batches of at most that size, one Adam step each, shuffled
per window and pass (both fine-tunes draw the same split). An epoch is then
several steps instead of one, so the step count per window grows with the batch:
with 100 a 118-flow batch takes 2 steps per epoch, a 1,230-flow batch 13.

### Hyperparameter Summary

\begin{table}[h]
\centering
\caption{Federated Learning hyperparameters}
\label{tab:fl-hyperparams}
\begin{tabular}{@{}lll@{}}
\toprule
\textbf{Parameter} & \textbf{Value} & \textbf{Description} \\
\midrule
$E_{\text{local}}$  & 15  & Local training epochs (fc1 + head) \\
$E_{\text{merge}}$  & 5   & Fine-tuning epochs after the merge point (fc1 + head, both models) \\
$\eta$              & 0.01 & Learning rate (Adam, \texttt{learning\_rate}) \\
$\lambda$           & $10^{-4}$ & L2 weight decay \\
$B_{\text{min}}$    & 30  & Minimum training batch size \\
$T_w$               & 1200 s & Sub-window width \\
$\Delta_T$          & $\sim\mathcal{U}(0, T_w/2)$ & Per-instance random window offset \\
$s_{\text{thresh}}$ & 0.20 & Slips evidence detection threshold \\
\multicolumn{3}{@{}l}{}\\
\textbf{Class-Weighted Loss} & & \\
\midrule
\multicolumn{3}{@{}l}{$w_c = \dfrac{N_{\text{mal}} + N_{\text{ben}}}{2 \cdot \max(N_c, 1)}$ \quad for $c \in \{\text{Benign}, \text{Malicious}\}$} \\
\multicolumn{3}{@{}l}{$\mathcal{L} = -\sum_{i} w_{y_i} \log \hat{p}_{i, y_i}$ \quad (per-batch weights)} \\
\bottomrule
\end{tabular}
\end{table}

### Epochs
- **Local training**: 15 epochs per batch (alert or twclose trigger)
- **Fine-tuning**: 5 epochs of fc1 + head after the merge point, on the local and the merged model (head-only with `finetune_fc_layers: false`)

### Learning Rate
- Adam optimizer with $\eta = 0.01$ (config `learning_rate`), weight decay $\lambda = 10^{-4}$
- L2 penalty applied to all learnable parameters (fc1 + head)

## Feature Handling

- **Fixed Input Dimension**: 18 features, matching `SimpleFederatedNet.FIXED_INPUT_DIM`
- **All Protocols Kept**: Inclusive encoding (tcp=0, udp=1, icmp=2, icmp-ipv6=3, arp=4) via base class `_encode_proto()`
- **State Inferred**: Uses base class `_infer_state()` (not raw conn_state)
- **IP to Numeric**: Converted via `ipaddress.ip_address()` modulo 1e6
- **Flow ID**: Uses Zeek `uid` when available, falls back to `saddr:sport-daddr:dport-starttime`

### Feature List (18 features)

| # | Feature | Source | Description |
|---|---|---------|-------------|
| 1 | dur | flow.dur | Duration in seconds |
| 2 | proto | `_encode_proto()` | Inclusive: tcp=0.0, udp=1.0, icmp=2.0, icmp-ipv6=3.0, arp=4.0 |
| 3 | appproto | `_encode_appproto()` | http=0.0, dns=1.0, ssl=2.0, ssh=3.0, smtp=4.0, ftp=5.0, pop3=6.0, imap=7.0, telnet=8.0, https=9.0, other=10.0 |
| 4 | sport | flow.sport | Source port |
| 5 | dport | flow.dport | Destination port |
| 6 | spkts | flow.spkts | Source packets |
| 7 | dpkts | flow.dpkts | Destination packets |
| 8 | sbytes | flow.sbytes | Source bytes |
| 9 | dbytes | flow.dbytes | Destination bytes |
| 10 | state | `_infer_state()` | 1.0 or 0.0 based on state string and packet counts |
| 11 | total_bytes | Derived | sbytes + dbytes |
| 12 | total_pkts | Derived | spkts + dpkts |
| 13 | avg_pkt_size | Derived | sbytes / max(spkts, 1) |
| 14 | throughput | Derived | total_bytes / max(dur, 0.001) |
| 15 | history_len | Derived | len(str(history)) |
| 16 | saddr_num | Derived | ipaddress int % 1e6 |
| 17 | daddr_num | Derived | ipaddress int % 1e6 |
| 18 | dir_num | Derived | 1.0 if dir_=="->" else 0.0 |

## Graceful Shutdown

On shutdown, the module saves:
1. Latest local model (always)
2. Latest merged model (if any merges occurred)

This ensures no progress is lost between runs. If `train_from_scratch: false`, the next run will load these artifacts.

## Metrics and Logging

Seven log files in `output/<timestamp>/federated_network_module/`:

### local_train.log
Per-epoch training metrics for local model (alert or twclose):
```
--- alert_1 | 26 mal (295 evidence), 18 ben ---
  epoch 1/15 | loss=0.9281 | acc=0.4091
  ...
  epoch 15/15 | loss=0.7974 | acc=0.4091
  batch 44 (Mal:26 Ben:18) | loss=0.7852 | acc=0.4091 | TP/FP/TN/FN: 0/0/18/26
```

### local_test.log / merged_test.log (+ *_test_conn.log)
Continuous per-flow testing: the latest model classifies each incoming flow against GT.
The `_conn` twins count only conn flows, under the same headers.
Metrics accumulate between training events, reset after each `--- New local model ---` marker.
```
--- New local model (alert_1) ---
  flows=44 | GT(Mal/Ben): 26/18 | Pred(Mal/Ben): 0/44 | TP/FP/TN/FN: 0/0/18/26 | Acc=0.4091
```

### comp_inferred_gt.log
Inferred labels (from alert evidence / twclose default) vs ground truth.
Calculated at training time — compares what we're ABOUT to train on against the actual GT.
```
--- alert_1 | 295 evidence data. 26 mal connected, 18 benign, 44 total ---
  inferred vs GT: 10 samples | Mal/Ben: 5/5 vs 8/2 | TP/FP/TN/FN: 3/2/0/5 | Acc: 0.3000
```

### comp_test_inferred.log
Model predictions vs inferred (alert) labels. Tests: "was the model agreeing with the
alert evidence BEFORE we trained on it?" Uses predictions stored during the main loop
(test-time inference) compared against the labels assigned by the current alert.
```
--- alert_1 | ... ---
  pred vs inferred: 5 samples | Mal/Ben: 0/5 vs 3/2 | TP/FP/TN/FN: 0/0/2/3 | Acc: 0.4000
```

### comp_test_gt.log
Model predictions vs ground truth. Same stored test-time predictions, but compared against
actual GT labels (from Slips metadata). Only includes flows with genuine GT labels.
```
--- alert_1 | ... ---
  pred vs GT: 3 samples | Mal/Ben: 0/3 vs 3/0 | TP/FP/TN/FN: 0/0/0/3 | Acc: 0.0000
```

## Extending Aggregation Strategy

The default AVERAGE aggregation can be replaced by modifying `trigger_merge()`:

```python
def trigger_merge(self):
    # Current: Simple average
    merged[key] = torch.stack([own[key]] + [m[key] for peers]).mean(dim=0)  # per shared key

    # Alternative: Weighted average (by peer reliability)
    # weights = torch.tensor([peer_reliability[p] for p in peer_ids])
    # merged_fc1_weight = torch.stack(all_fc1_weights).sum(dim=0) / weights.sum()

    # Alternative: Median (robust to outliers)
    # merged_fc1_weight = torch.stack(all_fc1_weights).median(dim=0).values
```

## P2P Integration Requirements

For full functionality, the P2P module must provide:
1. `p2p_model_outgoing` channel - for publishing model weights
2. `p2p_model_received` channel - for receiving peer models
3. Peer ID management - unique identifier for each node

If P2P channels are unavailable, local training continues normally but model sharing is disabled.

## Troubleshooting

**"Preprocessor not fitted" error**: Ensure training has occurred before testing. In train mode, wait for first alert or window close.

**"Input dimension not determined"**: Model always uses fixed 18 features. Check that `process_features()` produces exactly 18 columns.

**No peer models received**: P2P module may not be available. Check P2P module configuration. Merge only triggers on peer model receipt (no periodic timer).

**Label comparison shows high FP**: Alerts from other modules may have false positives. The FL module learns from alert evidence, not Zeek ground truth. This is by design — the comparison logs quantify alert noise.

**Model not loading on startup**: Check `train_from_scratch: false` in config and verify artifact files exist in `modules/federated_network_module/artifacts/`.

**Stale `__pycache__` causing silent training failure**: When the module source is updated, old `.pyc` bytecode cache can cause Python to load stale code where `fit_incremental_model` is a `pass`-only abstractmethod. Fix: the module's `init()` calls `shutil.rmtree()` on `__pycache__` at startup. Also documented in `bugs.md`.
