# Federated Network Module - Implementation Plan

## Overview
Federated learning module for Slips with model sharing across peers. Uses frozen random projection + learnable fc1 + head layers.

## Core Workflow

### 1. Local Training (Triggered by Alert or Window Close)
```
Alert/Window Close
    ↓
Label flows (malicious from evidence, rest benign)
    ↓
Train fc1 + head ONCE on training buffer
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
Freeze fc1, retrain head on alignment buffer
    ↓
Save as merged_N model
```

### 3. Key Design Decisions
- **Two buffers**: training (cleared after each train) + alignment (accumulates all flows)
- **Model separation**: latest_local (own data only, sent to peers unchanged) vs merged (aggregated, used for inference)
- **Merged models NOT reused**: Each merge uses only latest local models from peers, not previous merges
- **Off-sync windows**: Random time offset per peer to avoid network pulses

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
- **Sending**: After each local training, publish model weights to `p2p_model_outgoing` channel
- **Receiving**: Subscribe to `p2p_model_received`, store latest per peer in memory
- **Merge trigger**: When new peer model received or periodic interval

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
