# Federated Network Module - Implementation Goals & Status

## Current State
- **Base**: `origin/ml_modules_refactor` with `fl_module_jan` branch
- **Status**: Feature-complete for training, testing, and model saving. P2P merge tested only in code path (no live peers in test).
- **Branch**: `fl_module_jan`

---

## Implemented (Done)

### 1. Fixed Feature Set (18 Features)
- `SimpleFederatedNet.FIXED_INPUT_DIM = 18`
- `process_features()` produces exactly 18 features in fixed order
- Feature extraction validated in `_extract_flow_features()`
- No dynamic input dimension detection

### 2. Enhanced process_features()
- Categoricals normalized to lowercase
- `_encode_proto()` via base class with INCLUSIVE order (tcp=0, udp=1, icmp=2, icmp-ipv6=3, arp=4)
- `_encode_appproto()` with hardcoded mapping (http=0, dns=1, ssl=2, ssh=3, smtp=4, ftp=5, pop3=6, imap=7, telnet=8, https=9, other=10)
- `_infer_state()` from base class (NOT conn_state directly)
- IPs converted to numeric via `ipaddress` library
- ALL protocols kept (no filtering)
- Direction encoded as numeric (-> = 1.0, else 0.0)

### 3. Alert-Based Training
- Extract `correl_id` and `last_evidence.ID` from alert message
- Find malicious flows via `db.get_flows_causing_evidence(evid_id)` and `db.get_flow(uid)`
- Also match attacker/victim IPs against current window flows as fallback
- Label matched flows MALICIOUS, remaining window flows BENIGN
- Train with proper metrics logging

### 4. Timestamp-Based Sub-Windowing
- `time_window_width: 1200` (20 min) in module config
- Independent of Slips global time windows
- No `tw_closed` subscription
- `_get_flow_id()` uses Zeek `uid` when available, falls back to 5-tuple

### 5. Random Projection Validation
- Validate loaded `random_projection.bin` has correct input dimension
- Reconstruct from seed if dimension mismatch or load fails
- Print warning during `__init__`

### 6. Model Loading on Startup
- Read `train_from_scratch` config (default false)
- If false and artifacts exist, load `latest_local_fc1/head/scaler` from disk
- Warm-start model and scaler state

### 7. Two-Buffer Design
- Training buffer (cleared after each train)
- Alignment buffer (accumulates all flows, never cleared)

### 8. Centralized Logging (ModuleLogger)
Five log targets:
- `training_local` - per-batch local training metrics
- `training_merged` - per-merge training metrics
- `testing_local` - testing metrics when using local model
- `testing_merged` - testing metrics when using merged model
- `label_comparison` - inferred vs Zeek GT comparison per batch

### 9. Testing Snapshot Routing
- `_using_merged_model` flag tracks which model is active
- `_write_testing_snapshot()` routes to `testing_local` or `testing_merged` accordingly

---

## Remaining / Known Limitations

### P2P Integration (Not Tested End-to-End)
- Model sending works (publishes to `p2p_model_outgoing`)
- Model receiving works (stores in `peer_models` dict)
- Merge triggers when peer model received
- No periodic merge timer (only event-based)

### Alert Noise
- Alerts come from other Slips modules (ml_linear_model, ml_online_model, network_discovery, etc.)
- These modules may have false positives
- FL module learns from alert evidence, not Zeek ground truth
- Label comparison log quantifies this discrepancy
- No active noise filtering or reliability weighting implemented

### Config Path Inconsistency
- Config `model_load_path` / `preprocess_load_path` point to non-existent `model.bin` / `scaler.bin`
- Module actually uses hardcoded paths: `latest_local_fc1/head/scaler.bin`
- Config keys are effectively unused for the federated module

---

## Testing Status

### End-to-End Tests
- [x] Dataset 024 (zeek-malicious, 6544 flows) - **PASSED**
  - Alerts fire from other modules
  - FL module trains on alert evidence with malicious + benign flows
  - Model artifacts saved to disk
  - Logs generated for training_local, label_comparison, testing_local
  - Loss converges from ~0.8 to ~0.0003 over batches
- [x] Dataset 008 (zeek-mixed, 5671 flows) - **PASSED**
  - No alerts fire (benign traffic)
  - Sub-window closes produce benign-only training
  - Model artifacts saved

### Unit Tests
- [ ] Test feature extraction produces 18 features
- [ ] Test proto/service/state encoding
- [ ] Test IP-to-numeric conversion
- [ ] Test alert parsing and flow matching
- [ ] Test random projection validation
- [ ] Test model save/load roundtrip

---

## Documentation

- [x] README.md updated to match actual code behavior
- [x] AGENTS.md contains implementation plan (local)

---

## Notes

- **Do NOT filter protocols** - keep icmp, arp, icmp-ipv6
- **Use state, not conn_state** - rely on base class `_infer_state()`
- **Model paths are hardcoded** - not configurable via slips.yaml
- **Merge is event-based only** - no `merge_interval_seconds` timer
- **Label comparison shows alert noise** - this is expected and logged
- **Single-node testing** - P2P merge path only exercised in code, no live peers
