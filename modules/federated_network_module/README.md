# Federated Network Module

A federated learning module for Slips that enables collaborative intrusion detection across multiple network monitoring nodes while preserving data privacy.

## Architecture

### Model Structure
```
input(18 features, fixed) -> RandomProjection(64, frozen, shared) -> Linear(64->16)+ReLU [fc1] -> Linear(16->2) [head]
```

- **Random Projection**: Frozen layer with 0-1 weights, loaded from shared base `artifacts/random_projection.bin`. Same across all peers for compatibility.
- **fc1 Layer**: Learnable linear layer (64->16) with ReLU activation
- **Head Layer**: Classification layer (16->2) for benign/malicious prediction

All artifact paths are hardcoded in `init()` under `modules/federated_network_module/artifacts/`.

### Training Buffers

Two separate buffers manage different training phases:

1. **Training Buffer** (small): Used for local training on alert/window data. Cleared after each training event. Trains both fc1 and head.

2. **Alignment Buffer** (large): Accumulates ALL flows processed locally. Used only for head alignment after model merging. Never cleared.

## Training Flow

### 1. Local Training (on Alert or Sub-Window Close)

**On New Alert:**
1. Extract evidence IDs from alert (`correl_id` + `last_evidence.ID`)
2. Find flows connected to evidence via `db.get_flows_causing_evidence()`
3. Also collect window flows matching attacker/victim IPs as fallback
4. Label connected flows as **MALICIOUS**, all other window flows as **BENIGN**
5. Compare inferred labels vs Zeek ground truth -> write to `label_comparison_*.log`
6. Train fc1 + head for configured epochs
7. Send latest local model to peers via P2P

**On Sub-Window Close (20 min by default):**
1. Flow timestamps trigger sub-window expiry (independent of Slips global TW)
2. All remaining unlabeled flows -> **BENIGN**
3. Compare inferred labels vs Zeek ground truth -> write to `label_comparison_*.log`
4. Train fc1 + head for configured epochs
5. Clear window, start fresh sub-window

### 2. Head Alignment (After Merge)

1. Freeze fc1 weights
2. Train head ONLY on alignment buffer (all accumulated flows)
3. Unfreeze fc1
4. This aligns the head with the merged fc1 without overwriting learned features

### 3. Model Merging (Event-Based Only)

1. Collect latest local models from all connected peers + own latest
2. Aggregate fc1 weights using **AVERAGE** strategy:
   ```python
   merged_fc1 = sum(peer.fc1 for peer in all_peers) / len(all_peers)
   ```
3. Replace fc1 weights with merged values
4. Freeze fc1, retrain head ONCE on alignment buffer
5. Save as `merged_N` model (N = merge count)
6. Log merge metrics to `training_merged_*.log`

**Important**: Merged models are NOT used in future merges. Only latest local models participate in aggregation.

**Note**: There is no periodic merge timer. Merge only triggers when a peer model is received via P2P.

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
  mode: train  # or test
  train_from_scratch: false  # If false, load latest_local artifacts on startup
  create_performance_metrics_log_files: true
  validate_on_train: false
  validation_percentage: 0.1
  training_batch_size: 500  # Currently unused (trains on alert/TW close)
  local_training_epochs: 4   # Epochs for local training (fc1 + head)
  merge_finetune_epochs: 3   # Epochs for head fine-tuning after merge
  time_window_width: 1200    # 20 minutes (sub-window, independent of Slips global TW)
  seed: 1111
  log_suffix: federated_network_module
  test_log_batch_size: 1000
  model_load_path: modules/federated_network_module/artifacts/model.bin  # Unused
  preprocess_load_path: modules/federated_network_module/artifacts/scaler.bin  # Unused
  model_store_path: modules/federated_network_module/artifacts/model_custom.bin  # Unused
  preprocess_store_path: modules/federated_network_module/artifacts/scaler_custom.bin  # Unused
```

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

Five separate log files in `output/<timestamp>/federated_network_module/`:

### training_local_federated_network_module.log
Per-batch training metrics:
```
[alert] Trained (4 epochs) | Loss: 0.2932 | Acc: 0.8500 | Samples: 55 (Mal: 5, Ben: 50) | TP/FP/TN/FN: 5/0/50/0
[twclose] Trained (4 epochs) | Loss: 0.1200 | Acc: 1.0000 | Samples: 23 (Mal: 0, Ben: 23) | TP/FP/TN/FN: 0/0/23/0
```

### training_merged_federated_network_module.log
Per-merge training metrics (only when merge occurs):
```
--- MODEL 1 ---
[merge] Trained (3 epochs) | Loss: 0.1500 | Acc: 0.9200 | Samples: 200 (Mal: 50, Ben: 150) | TP/FP/TN/FN: 48/5/145/2
```

### testing_local_federated_network_module.log
Per-batch testing metrics when using local model:
```
Batch flows: 1000; Total flows: 1000; Seen labels: {Malicious: 52, Benign: 948}; Predicted labels: {Malicious: 45, Benign: 955}; Malware metrics (TP/FP/TN/FN): {'TP': 40, 'FP': 5, 'TN': 943, 'FN': 12};
--- Local model retrained ---
```

### testing_merged_federated_network_module.log
Per-batch testing metrics when using merged model (switches after merge):
```
Batch flows: 1000; Total flows: 5000; ... Malware metrics (TP/FP/TN/FN): {'TP': ..., 'FP': ..., 'TN': ..., 'FN': ...};
```

### label_comparison_federated_network_module.log
Compares inferred labels (from alert evidence / benign-default) vs Zeek ground truth:
```
[alert_1] Batch: 172 | Inferred (Mal/Ben): 128/44 | GT (Mal/Ben): 44/128 | TP/FP/TN/FN: 0/128/0/44
[twclose_1] Batch: 23 | Inferred (Mal/Ben): 0/23 | GT (Mal/Ben): 19/4 | TP/FP/TN/FN: 0/4/0/19
```

Note: Discrepancies between inferred and GT labels are expected when alerts from other modules have false positives. The label comparison log quantifies this noise.

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

**Label comparison shows high FP**: Alerts from other modules may have false positives. The FL module learns from alert evidence, not Zeek ground truth. This is by design - the label comparison log helps quantify alert noise.

**Model not loading on startup**: Check `train_from_scratch: false` in config and verify artifact files exist in `modules/federated_network_module/artifacts/`.
