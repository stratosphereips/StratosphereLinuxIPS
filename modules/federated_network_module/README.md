# Federated Network Module

A federated learning module for Slips that enables collaborative intrusion detection across multiple network monitoring nodes while preserving data privacy.

## Architecture

### Model Structure
```
input(N features, dynamic) → RandomProjection(64, frozen, shared) → Linear(64→16)+ReLU [fc1] → Linear(16→2) [head]
```

- **Random Projection**: Frozen layer with 0-1 weights, loaded from shared base `artifacts/random_projection.bin`. Same across all peers for compatibility.
- **fc1 Layer**: Learnable linear layer (64→16) with ReLU activation
- **Head Layer**: Classification layer (16→2) for benign/malicious prediction

### Training Buffers

Two separate buffers manage different training phases:

1. **Training Buffer** (small): Used for local training on alert/window data. Cleared after each training event. Trains both fc1 and head.

2. **Alignment Buffer** (large): Accumulates ALL flows processed locally. Used only for head alignment after model merging. Never cleared.

## Training Flow

### 1. Local Training (on Alert or Sub-Window Close)

**On New Alert:**
1. Extract evidence IDs from alert (correl_id + last_evidence)
2. Find flows connected to evidence via `db.get_flows_causing_evidence()`
3. Label connected flows as **MALICIOUS**, all other window flows as **BENIGN**
4. Compare inferred labels vs Zeek ground truth → write to `label_comparison_*.log`
5. Train fc1 + head for configured epochs
6. Send latest local model to peers via P2P

**On Sub-Window Close (20 min by default):**
1. Flow timestamps trigger sub-window expiry (independent of Slips global TW)
2. All remaining unlabeled flows → **BENIGN**
3. Compare inferred labels vs Zeek ground truth → write to `label_comparison_*.log`
4. Train fc1 + head for configured epochs
5. Clear window, start fresh sub-window

### 2. Head Alignment (After Merge)

1. Freeze fc1 weights
2. Train head ONLY on alignment buffer (all accumulated flows)
3. Unfreeze fc1
4. This aligns the head with the merged fc1 without overwriting learned features

### 3. Model Merging (Periodic or Event-Based)

1. Collect latest local models from all connected peers + own latest
2. Aggregate fc1 weights using **AVERAGE** strategy:
   ```python
   merged_fc1 = sum(peer.fc1 for peer in all_peers) / len(all_peers)
   ```
3. Replace fc1 weights with merged values
4. Freeze fc1, retrain head ONCE on alignment buffer
5. Save as `merged_N` model (N = merge count)

**Important**: Merged models are NOT used in future merges. Only latest local models participate in aggregation.

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
Merge occurs when:
- At least 1 peer model received
- Or periodically based on `merge_interval_seconds` config

## Artifact Paths

### Base Artifacts (Shared Across All Peers)
- `artifacts/random_projection.bin` - Frozen random projection matrix (created once, distributed to all)
- `artifacts/scaler.bin` - StandardScaler state (local only)

### Local Model (Own Training Only)
- `artifacts/latest_local_fc1.bin` - fc1 weights
- `artifacts/latest_local_fc1_bias.bin` - fc1 bias
- `artifacts/latest_local_head.bin` - head weights
- `artifacts/latest_local_head_bias.bin` - head bias
- `artifacts/latest_local_scaler.bin` - scaler state

### Merged Models (Aggregated)
- `artifacts/merged_1_fc1.bin`, `merged_1_fc1_bias.bin` - First merge
- `artifacts/merged_1_head.bin`, `merged_1_head_bias.bin`
- `artifacts/merged_2_*` - Second merge
- etc.

## Configuration (slips.yaml)

```yaml
federated_network_module:
  mode: train  # or test

  # Base random projection (shared across all peers)
  random_projection_path: modules/federated_network_module/artifacts/random_projection.bin

  # Local model paths
  local_fc1_path: modules/federated_network_module/artifacts/latest_local_fc1.bin
  local_head_path: modules/federated_network_module/artifacts/latest_local_head.bin
  local_scaler_path: modules/federated_network_module/artifacts/latest_local_scaler.bin

  # Merged models directory
  merged_models_dir: modules/federated_network_module/artifacts/merged

  # Training settings
  training_batch_size: 500
  local_training_epochs: 4   # Epochs for local training (fc1 + head)
  merge_finetune_epochs: 3   # Epochs for head fine-tuning after merge
  time_window_width: 1200    # 20 minutes (sub-window, independent of Slips global TW)

  # Merge settings
  merge_interval_seconds: 3600  # Merge every hour (or event-based)
  min_peers_for_merge: 1  # Minimum peers needed before merging

  # Logging
  create_performance_metrics_log_files: true
  log_suffix: federated_network_module
  seed: 1111
```

## Feature Handling

- **Fixed Input Dimension**: 18 features, matching `SimpleFederatedNet.FIXED_INPUT_DIM`
- **All Protocols Kept**: Inclusive encoding (tcp=0, udp=1, icmp=2, icmp-ipv6=3, arp=4) via base class `_encode_proto()`
- **State Inferred**: Uses base class `_infer_state()` (not raw conn_state)
- **IP to Numeric**: Converted via `ipaddress.ip_address()` modulo 1e6

### Feature List (18 features)

| # | Feature | Source | Description |
|---|---------|--------|-------------|
| 1 | dur | flow.dur | Duration in seconds |
| 2 | proto | `_encode_proto()` | Inclusive: tcp=0.0, udp=1.0, icmp=2.0, icmp-ipv6=3.0, arp=4.0 |
| 3 | appproto | `_encode_appproto()` | http=0.0, dns=1.0, ssl=2.0, ssh=3.0, etc., other=10.0 |
| 4 | sport | flow.sport | Source port |
| 5 | dport | flow.dport | Destination port |
| 6 | spkts | flow.spkts | Source packets |
| 7 | dpkts | flow.dpkts | Destination packets |
| 8 | sbytes | flow.sbytes | Source bytes |
| 9 | dbytes | flow.dbytes | Destination bytes |
| 10 | state | `_infer_state()` | Established/new=1.0, failed/closed=0.0 |
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

This ensures no progress is lost between runs.

## Metrics and Logging

Three separate log files in `output/<timestamp>/federated_network_module/`:

### training_federated_network_module.log
Per-batch training metrics (base class format):
```
Batch trained (4 epochs). Loss: 0.2932, Accuracy: 0.8500, Samples: 55 (Malicious: 5, Benign: 50)
```

### testing_federated_network_module.log
Per-1000-flows testing metrics (base class format):
```
Batch flows: 1000; Total flows: 1000; Seen labels: {Malicious: 52, Benign: 948}; Predicted labels: {Malicious: 45, Benign: 955}; Malware metrics (TP/FP/TN/FN): {TP: 40, FP: 5, TN: 943, FN: 12};
```
Metrics written every `test_log_batch_size` flows via `store_testing_results()`.
Local model retrains are marked with `--- Local model retrained ---`.

### label_comparison_federated_network_module.log
Compares inferred labels (from alert evidence / benign-default) vs Zeek ground truth:
```
[alert] Batch size: 12 | Inferred labels: {Malicious: 5, Benign: 7} | GT labels: {Malicious: 3, Benign: 9} | Metrics (TP/FP/TN/FN): {TP: 3, FP: 2, TN: 7, FN: 0}
[twclose] Batch size: 55 | Inferred labels: {Malicious: 0, Benign: 55} | GT labels: {Malicious: 2, Benign: 53} | Metrics (TP/FP/TN/FN): {TP: 0, FP: 0, TN: 53, FN: 2}
```
Written once per training batch, before training, using the labels we assigned vs the Zeek file's labels.

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

**"Input dimension not determined"**: Module needs to see at least one flow before initializing. Check that flows are being received.

**Merge fails with dimension mismatch**: All peers must use the same `random_projection.bin` base file. Verify artifact distribution.

**No peer models received**: Check P2P module configuration and network connectivity between peers.
