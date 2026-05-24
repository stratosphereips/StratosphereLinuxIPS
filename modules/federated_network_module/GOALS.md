# Federated Network Module - Implementation Goals & Status

## Current State (Post-Rebase)
- **Base**: Clean rebase onto `origin/ml_modules_refactor` (latest)
- **Status**: All improvements reverted, need to re-apply from scratch
- **Branch**: `fl_module_jan`

---

## Critical Goals (Must Implement)

### 1. Fixed Feature Set (18 Features)
**Goal**: Enforce exactly 18 features with fixed order matching Slips flow fields
- Define `SimpleFederatedNet.FIXED_INPUT_DIM = 18`
- Update `process_features()` to produce exactly these 18 features:
  ```python
  # Zeek-native numerics (9)
  dur, sport, dport, spkts, dpkts, sbytes, dbytes

  # Encoded categoricals (3)
  proto, appproto, state

  # Derived (6)
  total_bytes, total_pkts, avg_pkt_size, throughput,
  history_len, dir_num, saddr_num, daddr_num
  ```
- Remove dynamic input dimension detection
- Validate at model creation time

### 2. Enhanced process_features()
**Goal**: Proper feature engineering matching ml_online_model patterns
- Normalize categoricals to lowercase (`proto`, `appproto`, `state`)
- Use base class `_encode_proto()` with INCLUSIVE order (tcp=0, udp=1, icmp=2, icmp-ipv6=3, arp=4)
- Encode appproto with hardcoded mapping (http=0, dns=1, ssl=2, ssh=3, etc.)
- Encode history as LENGTH only (not complexity)
- Use `_infer_state()` from base class (NOT conn_state directly)
- Convert IPs to numeric via `ipaddress` library (`saddr_num`, `daddr_num`)
- Keep ALL protocols (no filtering of icmp/arp)
- Direction encoded as numeric (-> = 1.0, else 0.0)

### 3. Alert-Based Training with UID Matching
**Goal**: Train on malicious+benign flows when alert occurs
- Extract `profileid`, `twid`, `alert_id` from alert message
- Call `db.get_evidence_causing_alert(profileid, twid, alert_id)` → evidence_ids
- For each evidence_id, call `db.get_flows_causing_evidence(evidence_id)` → flow UIDs
- Match UIDs against `window_flows` by `flow['uid']`
- Label matched flows MALICIOUS, remaining unlabeled flows BENIGN
- Train on this batch with proper metrics logging

### 4. Random Projection Validation
**Goal**: Handle dimension mismatches gracefully
- Validate loaded `random_projection.bin` has correct input dimension
- Reconstruct from seed if dimension mismatch or load fails
- Log errors via `write_to_log()` to training log
- Print warning to stderr during `__init__`

### 5. IP-to-Numeric Conversion
**Goal**: Convert IP addresses to numeric values for ML
- Use `ipaddress.ip_address(str).int()` for conversion
- Store as `saddr_num`, `daddr_num` in feature set
- Handle invalid IPs by returning 0.0

---

## High Priority Goals

### 6. Config Updates
**Goal**: Separate epochs for training vs head realignment
- Add `training_epochs` to slips.yaml (default: 1)
- Add `head_realign_epochs` to slips.yaml (default: 1)
- Read via `ConfigParser.ml_module_training_epochs()` and `ml_module_head_realign_epochs()`
- Pass to `fit_incremental_model()` as parameter

### 7. Detailed Logging
**Goal**: Comprehensive metrics for debugging and analysis
- Log per-epoch losses during training
- Log TP/FP/TN/FN, accuracy, precision, recall, F1 per batch
- Log qualitative reasoning (sample predictions with ground truth)
- Log P2P events (model received/broadcast with timestamps)
- Log random projection status (loaded/recreated)
- Prefix logs: `[TRAIN]`, `[MERGE]`, `[ALERT]`, `[TWCLOSE]`, `[P2P]`, `[DEBUG]`

---

## Medium Priority Goals

### 8. Time Window Handling
**Goal**: Skip training on empty windows
- Check if `remaining_flows` is empty in `handle_tw_closed()`
- Skip training and clear window immediately if no flows
- Log "No unlabeled flows, skipping training"

### 9. P2P Integration (Optional for now)
**Goal**: Model sharing across peers
- Subscribe to P2P channels only if p2p_trust available
- Broadcast model after training
- Store peer models for deferred merging
- Merge on next training trigger (alert/TW close)

---

## Testing Goals

### 10. End-to-End Test
**Goal**: Verify full pipeline works
- Run on dataset 008 (CTU scenario)
- Verify random projection loads/creates correctly
- Verify alerts trigger training with proper labeling
- Verify training logs show loss, TP/FP/TN/FN metrics
- Verify artifacts saved (random_projection.bin, fc1, head, scaler)
- Verify model learns (loss decreases over batches)

### 11. Unit Tests
**Goal**: Ensure individual components work
- Test feature extraction produces 22 features
- Test proto/service/state encoding
- Test IP-to-numeric conversion
- Test alert parsing and UID matching
- Test random projection validation

---

## Documentation Goals

### 12. Update README.md
**Goal**: Document architecture and usage
- Neural network architecture table
- Feature list with descriptions
- Training procedure (epochs, triggers)
- Log format examples
- Configuration parameters

### 13. Update AGENTS.md
**Goal**: Implementation plan for future developers
- Core workflow diagrams
- Key design decisions
- P2P communication protocol
- Artifact structure
- Troubleshooting guide

---

## Known Issues / TODOs

- [ ] Alert message structure unclear - need to debug what fields are actually present
- [ ] DB method signatures need verification (`get_evidence_causing_alert`, `get_flows_causing_evidence`)
- [ ] Need to test with actual alerts (dataset 008 may not generate them)
- [ ] P2P integration requires p2p_trust module to be enabled
- [ ] Need to verify random projection seed reproducibility across peers

---

## Next Steps (Immediate)

1. **Re-implement FIXED_INPUT_DIM = 22** in SimpleFederatedNet
2. **Rewrite process_features()** with all encodings and derived features
3. **Fix handle_new_alert()** to extract correct fields from alert message
4. **Add random projection validation** in __init__ and init()
5. **Test with dataset 008** to verify basic functionality

---

## Notes

- **Do NOT filter protocols** - keep icmp, arp, icmp-ipv6
- **Use state, not conn_state** - rely on base class _infer_state()
- **Keep all fields** until final drop step (except identifiers)
- **History encoded as length only**, not complexity
- **IPs converted to numeric**, not dropped entirely
- **UID kept until AFTER label matching**, then dropped before training

---

*Last updated: 2026-05-21*
*Status: Post-rebase, ready to re-implement improvements*
