# Federated Network Module - Design Notes

## Overview
Federated learning module for Slips with model sharing across peers. The
default model (`random_projection_mlp`) is a frozen random projection + a
trainable fc1 + a head; `simple_mlp` and `random_projection_two_layer` are the
other registry models. All trainable layers start from the same weights on
every peer (`shared_init_seed`). README.md is the full reference.

## Core Workflow

### 1. Window close (every `time_window_width` s, fixed wall-clock grid)
```
Read every conn flow + ARP record SLIPS stored in flows.sqlite since the last
close into this window's ring cell (by read time)
    ↓
Label all open cells: malicious iff an alert's evidence cites the flow's uid
(alerts within the lookback); the rest benign. No IPs, no ground truth
    ↓
Score every open cell's unscored flows with the model serving this window
(prequential: before this close trains anything)
    ↓
Finalize the cell label_finalize_delay_windows (K, default 1) closes old into
the training buffer; train when it holds >= min_training_samples flows
```

### 2. Training (at a close that trains)
```
Scale the batch: global scaler (default, never fit) or the own scaler
(fit on the whole buffer first, global_scaler: false)
    ↓
Local training: fc1 + head for local_training_epochs
    ↓
Send the model after local training to the peers (fc1; + head with
merge_head; + scaler statistics with merge_scaler)
    ↓
Local fine-tune: merge_finetune_epochs, fc1 + head (head only with
finetune_fc_layers: false), from its own copy of the training Adam state
(merge_finetune_adam) - the local model carries on from here
    ↓
Merge (if any peer model is stored): merge_rule over own + the latest model of
every peer; merged head with merge_head, else the own head after local
training; then the same fine-tune as the local model (merged_train.log)
```
`finetune_head: false` skips both fine-tunes (0 epochs).

### 3. Key Design Decisions
- **Comparable local and merged models**: both start from the model after
  local training (own vs merged weights) and get the same fine-tune on the same
  batch; only the starting weights differ.
- **Merged models are never adopted**: the merged model serves until the next
  training close and is then discarded; it never feeds the local model or a
  later merge. Each merge uses the peers' latest local models.
- **Labels only from SLIPS alerts**: flow-exact (uid) matching of alert
  evidence; ground truth is for evaluation only.
- **No evidence emission**: `set_evidence_malicious_flow` is a no-op, so the
  module never feeds the alerts it learns from.
- **Wall-clock windows** independent of the Slips time windows; each peer's
  first window is shortened by a random offset (`uniform(0, 300)` s, seeded by
  hostname and run_seed) so peers train out of phase.

## Artifact Structure
```
artifacts/
├── random_projection.bin      # shared frozen projection (seeded, all peers)
├── global_scaler.json         # pretrained global scaler (global_scaler)
├── latest_local_state.bin     # local model state_dict (any registry model)
├── latest_local_scaler.bin    # local scaler
└── merged/
    ├── merged_1_state.bin     # merge results (state_dict)
    └── ...
```
The final merged model and scaler go to `model_store_path` /
`preprocess_store_path`.

## P2P Integration
- **Sending**: after each local training, a base64 JSON message
  (`message_type: model`, recipient `*`) on the `p2p_pygo` channel
- **Receiving**: `p2p_gopy`; the latest model per peer is stored (keyed by the
  sender's hostname) and kept until replaced
- **Merge trigger**: right after own local training, if any peer model is
  stored - never on receipt

## Base Class Integration
- Override `store_model()` for graceful shutdown (flush the last windows'
  scores, save local + merged)
- `update_preprocessor()` = `partial_fit` of the own scaler; a no-op with
  global_scaler
- `transform_features()` raises if the preprocessor is not fitted
- Test mode (`run_test_on_flow`) uses `store_testing_results()`

## Implementation Notes
- No unnecessary abstractions - keep logic inline where possible
- Fixed 18-feature input (`_get_feature_order`), no feature engineering
  beyond the derived features
- Try/catch around training and merging; errors go to module_errors.log
