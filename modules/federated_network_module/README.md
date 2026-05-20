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

### 1. Local Training (on Alert or Window Close)

**On New Alert:**
1. Get evidence from alert via database
2. Find flows connected to evidence IPs in current 15-minute window
3. Label connected flows as **MALICIOUS**, all other window flows as **BENIGN**
4. Train fc1 + head ONCE on this batch
5. Send latest local model to peers via P2P

**On Time Window Closed:**
1. All remaining unlabeled flows in window → **BENIGN**
2. Train fc1 + head ONCE on this batch
3. Clear window flow storage

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
  local_training_epochs: 10  # Epochs for local training (fc1 + head)
  merge_finetune_epochs: 5   # Epochs for head fine-tuning after merge
  time_window_width: 900     # 15 minutes

  # Merge settings
  merge_interval_seconds: 3600  # Merge every hour (or event-based)
  min_peers_for_merge: 1  # Minimum peers needed before merging

  # Off-sync window offset (random 0-900, generated at first run if not set)
  window_offset_seconds: 423

  # Logging
  create_performance_metrics_log_files: true
  log_suffix: federated_network_module
  seed: 1111
```

## Feature Handling

- **Dynamic Input Dimension**: Determined from first flow received (count numerical columns)
- **All Numerical Features Kept**: No feature engineering, no dropping (except non-numeric like saddr, daddr, uid)
- **Consistent Ordering**: Features must be in same order across all peers (Zeek output order)

Supported features include: dur, src_bytes, dst_bytes, count, srv_count, serror_rate, rerror_rate, same_srv_rate, diff_srv_rate, dst_host_count, dst_host_serror_rate, etc. (all Zeek flow numerical fields)

## Graceful Shutdown

On shutdown, the module saves:
1. Latest local model (always)
2. Latest merged model (if any merges occurred)

This ensures no progress is lost between runs.

## Metrics and Logging

Uses base class methods for consistent logging:
- `self.write_to_log(message)` - Writes to `training_<suffix>.log` or `testing_<suffix>.log`
- `self.store_testing_results(original_label, predicted_label)` - Accumulates TP/FP/TN/FN metrics
- `self.print(message, level, verbosity)` - Console output

Metrics logged per training batch:
- Loss value
- Accuracy
- Sample counts (malicious vs benign)

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
