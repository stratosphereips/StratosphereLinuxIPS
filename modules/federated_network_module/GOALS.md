# Federated Network Module - Implementation Goals & Status

## Current State (2026-09-10)
- **Branch**: `fl_module_jan_rebased` (thesis `slips/slips.Dockerfile` pins `d1637bf81`)
- **Status**: Live-tested end-to-end with 3 peers in the stratocyberlab
  federation topology (local train → P2P send → receive → weight-averaging merge →
  merged head fine-tune → merged-vs-GT evaluations) across multiple runs.
- **Imaging**: the federation image is baked by `thesis_project/slips/slips.Dockerfile`;
  runtime deviations from the pinned commit ship via `thesis_project/slips/patches/`
  (`config_parser.py` risk-weight accessors + `detection.low_risk_weight` defaults,
  `supported_module_names.py` FEDERATED enum, `p2p_trust.py` hostname fallback,
  `federated_network_module.py` weight snapshots).

### Landed since the last status update
- Wall-clock 5-minute training windows (deterministic per-peer offset) replacing
  the alert/sub-window-trigger descriptions below (historic sections kept).
- Comparable local/merged models: both fine-tune head-only from the same
  head-before state; only fc1 origin differs. Merged models are NOT reused.
- Runtime attacker ground truth: the experiment runner injects per-peer
  `attacker_ips` GT rules into the netflow labeler (no hardcoded monkeypatch).
- Telemetry for the experiments UI (all computed downstream, module only
  serializes): `merging_data.log` (`L2_dist`/`L2_norm`/`n_params`/merged-vs-own),
  `comp_merged_{inferred_gt,test_gt}.log`, and per-merge flat fc1 weight
  vectors `weights/merge_XXXX.npz` (own, merged, per-received-peer).
- Dual model testing: the last fully-local-trained model is deep-copied after
  each local train; when merged, every flow is evaluated by BOTH models —
  `merged_test.log` (legacy path) + `local_test.log` (local-only stream).
- Configured store path: the final merged model + scaler are saved to
  yaml `model_store_path` / `preprocess_store_path` at **every merge end** and
  at shutdown (`_save_final_merged_model()`); load paths are read but unused.
  All other numbered artifacts stay at their hardcoded module paths.
- Protocol-driven model registry (2026-09-14): a model class implements
  `forward` + `weights_for_sharing`/`set_shared_weights` +
  `get/set_head_weights` + `set_shared/head_frozen`; a `MODEL_REGISTRY`
  maps yaml `model_class` to builders; send/merge/artifacts/vector-dumps are
  fully key/shape-agnostic (works for ANY layer count/shapes). All artifacts
  are full `state_dict`s (`latest_local_state.bin`, `merged_N_state.bin`,
  final-store `{state_dict, model_class, merge_count}`). Working scaffold:
  `random_projection_two_layer` (RP + fc1 + fc2 federated, unweighted CE).
  Model set (2026-09-15): `random_projection_mlp` (base, RP→fc1→head,
  class-weighted CE), `simple_mlp` (plain 3-layer MLP, no RP, fc1+fc2
  federated, plain CE), `random_projection_two_layer` (RP→fc1→fc2→head,
  fc1+fc2 federated, plain CE). Class weighting is a per-model declared flag
  (`USE_CLASS_WEIGHTING`).
- Merge-rule registry (2026-09-14): yaml `merge_rule` selects HOW peer models
  are combined (never WHEN): `average` (plain mean of shared weights, default), `trust_weighted`
  (weighted by SLIPS classic p2p trust score×confidence — trust is passed to
  the merge functions per merge; own=1, unknown peer=0, empty map → average),
  `blending` (adopt the single model closest to the mean) — pure functions in
  the module, add-and-register to extend. Merges also log
  `merge_rule=<name>` + per-peer `trust=` into merging_data.log.
- Aracne-side config contract: `summarizer_source`/`summarizer_model` must
  exist in the baked config even with `summarizing: false` (loader reads them
  unconditionally; missing keys = instant boot crash — fixed in the runner's
  `aracne/aracne-config.yaml`).

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
- If false and artifacts exist, load `latest_local_state.bin` (state_dict) + `latest_local_scaler.bin` from disk
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
- Module uses hardcoded paths: `latest_local_state.bin` (class-driven state_dict) + `latest_local_scaler.bin`
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
- **Multi-peer live testing** - 3-peer federation runs end-to-end in the
  stratocyberlab topology; telemetry is consumed live by the experiment-runner
  UI (see `Analysis Outputs` in README.md)
