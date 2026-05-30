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
- **Epochs**: 15 local (fc1 + head), 5 merge fine-tune (head-only)

### Training Buffers

1. **Training Buffer**: Populated incrementally across deferred alerts/twcloses. Only cleared after successful training (≥30 flows). Tracks buffered flow IDs to prevent duplicates.

2. **Alignment Buffer**: Mirrors the training buffer. Used for head-only fine-tuning during FedAvg model merging. Cleared alongside training buffer.

## Training Flow

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

1. Receive peer models via P2P → aggregate fc1 using **AVERAGE**
2. Freeze fc1, retrain head on alignment buffer (same data as last training batch)
3. Save as `merged_N` model
4. Merged models NOT reused in future merges

## Model Sharing Protocol

### Sending Models
After each local training event (alert or window close), call `send_model_to_peers()`:
- Sends fc1 and head weights (not random projection - shared base)
- Published via P2P module's `p2p_model_outgoing` channel
- Includes timestamp and peer ID

### Receiving Models
When `p2p_model_received` channel message arrives:
- Parse peer_id and model weights
- Store in `peer_models[peer_id]` dictionary
- Overwrite previous model from same peer (keep only latest)

### Merge Trigger
Merge occurs only when:
- At least 1 peer model received (event-based only)

## Model Loading on Startup

On init, if `train_from_scratch: false` in config and local artifacts exist:
- Load `latest_local_fc1.bin` + bias, `latest_local_head.bin` + bias, `latest_local_scaler.bin`
- Restore model and scaler state
- Print confirmation log

If `train_from_scratch: true` or artifacts missing, training starts from scratch.

## Artifact Paths

All paths are hardcoded in `init()`. They are NOT configurable via `slips.yaml`.

### Base Artifacts (Shared Across All Peers)
- `artifacts/random_projection.bin` - Frozen random projection matrix (created once, distributed to all)

### Local Model (Own Training Only)
- `artifacts/latest_local_fc1.bin` - fc1 weights
- `artifacts/latest_local_fc1_bias.bin` - fc1 bias
- `artifacts/latest_local_head.bin` - head weights
- `artifacts/latest_local_head_bias.bin` - head bias
- `artifacts/latest_local_scaler.bin` - scaler state (pickle)

### Merged Models (Aggregated)
- `artifacts/merged/merged_1_fc1.bin`, `merged_1_fc1_bias.bin` - First merge
- `artifacts/merged/merged_1_head.bin`, `merged_1_head_bias.bin`
- `artifacts/merged/merged_2_*` - Second merge
- etc.

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
```

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
$E_{\text{merge}}$  & 5   & Merge fine-tuning epochs (head-only) \\
$\eta$              & 0.005 & Initial learning rate (Adam) \\
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
- **Merge fine-tuning**: 5 epochs head-only after model aggregation

### Learning Rate
- Adam optimizer with $\eta = 0.005$, weight decay $\lambda = 10^{-4}$
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

### local_test.log / merged_test.log
Continuous per-flow testing: the latest model classifies each incoming flow against GT.
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
    merged_fc1_weight = torch.stack(all_fc1_weights).mean(dim=0)

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
