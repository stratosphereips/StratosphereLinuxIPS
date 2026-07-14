# Federated Network Module - Implementation Plan

## Overview
Federated learning module for Slips with model sharing across peers. Uses frozen random projection + learnable fc1 + head layers.

## Core Workflow

### 1. Local Training (Wall-Clock Window Close)
```
Buffer flows and alerts for 5 minutes (with per-peer offset)
    ↓
Close window: label flows from all buffered alerts' evidence
    ↓
Train fc1 + head for local_training_epochs
    ↓
Save head produced by local training as "head_before"
    ↓
Freeze fc1, fine-tune head for merge_finetune_epochs (local_head_train.log)
    ↓
Save as latest_local model
    ↓
Send to peers via P2P
```

### 2. Model Merging (Event-Based)
```
Receive peer models
    ↓
Aggregate fc1 weights (AVERAGE)
    ↓
Restore "head_before" (head from local full training)
    ↓
Freeze fc1, fine-tune head for merge_finetune_epochs (merged_train.log)
    ↓
Save as merged_N model
```

### 3. Key Design Decisions
- **Comparable local and merged models**: both heads are fine-tuned for the same number of epochs from the same starting head; only fc1 differs (local-only vs averaged).
- **Wall-clock training windows**: windows close every 5 minutes, independent of Slips global time windows, with a per-peer random offset.
- **Buffered alerts**: alerts are not processed immediately; all evidence from a window is used together to label flows at window close.
- **Merged models NOT reused**: Each merge uses only latest local models from peers, not previous merges.
- **Off-sync windows**: Random time offset per peer to avoid synchronized training pulses.

## Artifact Structure
```
artifacts/
├── random_projection.bin      # Shared base (frozen, distributed to all peers)
├── scaler.bin                  # Local scaler state
├── latest_local_fc1.bin        # Current local fc1 weights
├── latest_local_head.bin       # Current local head weights
└── merged/
    ├── merged_1_fc1.bin        # First merge result
    ├── merged_1_head.bin
    ├── merged_2_fc1.bin        # Second merge result
    └── ...
```

## P2P Integration
- **Sending**: After each local training, publish model weights to `p2p_pygo` channel
- **Receiving**: Subscribe to `p2p_gopy`, store latest per peer in memory
- **Merge trigger**: After own local training if any peer models are pending

## Base Class Integration
- Use `store_testing_results()` for TP/FP/TN/FN metrics
- Use `write_to_log()` for training/testing logs
- Override `store_model()` for graceful shutdown (save local + merged)
- Use `partial_fit()` for incremental scaler training
- Throw exception in `transform_features()` if preprocessor not fitted

## Minimal Implementation Notes
- No unnecessary abstractions - keep logic inline where possible
- Reuse base class methods for logging, metrics, model loading/saving
- Dynamic input dimension detected from first flow
- All numerical features kept (no feature engineering)
- Try/catch around training batch to handle errors gracefully
