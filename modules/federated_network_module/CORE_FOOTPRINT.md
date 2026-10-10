# SLIPS core footprint — changes outside the FL module

**Audience:** thesis reviewers / teammates auditing what this fork changes in SLIPS
*outside* `modules/federated_network_module/`. Purpose: show that the federated
experiment does **not** modify SLIPS detection logic, the input module, or any
other module — the core footprint is registration + config + a dependency only.

- **Fork branch:** `fl_module_jan_rebased`
- **Rebase base (upstream SLIPS develop):** `ccd0b1581` (Oct 5 2026)
- **Reproduce this audit:**
  ```
  git diff ccd0b1581..HEAD --stat -- . \
    ':(exclude)modules/federated_network_module' \
    ':(exclude)tests/unit/modules/federated_network_module'
  ```

## Complete list of non-module changes (vs base)

`+60 / −2` across **5 files**. Nothing else in the tree is touched.

| File | Δ | What | Why |
|---|---|---|---|
| `modules/supported_module_names.py` | +1 | `FEDERATED_NETWORK_MODULE = "federated_network_module"` | register the module name (SLIPS requires every module in this enum) |
| `slips_files/core/structures/evidence.py` | +1 | `FEDERATED_NETWORK_MALICIOUS_FLOW = auto()` | one new `EvidenceType` enum member, so the module *could* emit its own evidence. **Purely additive** — adds a member, changes no existing value or logic. (The module does not currently emit evidence.) |
| `install/requirements.txt` | +1 | `torch>=2.0.0` | the module's ML dependency |
| `config/slips.yaml` | +55 | a new `federated_network_module:` section with the module's **own** defaults (mode, epochs, batch size, window width, seed, log/artifact paths) | module defaults only — see note below |
| `.secrets.baseline` | ±4 | detect-secrets baseline (line-number + regenerated-at timestamp) | pre-commit tooling, not code |

### Exact code diffs
```python
# modules/supported_module_names.py
+    FEDERATED_NETWORK_MODULE = "federated_network_module"

# slips_files/core/structures/evidence.py   (EvidenceType enum)
+    FEDERATED_NETWORK_MALICIOUS_FLOW = auto()

# install/requirements.txt
+torch>=2.0.0
```

The `config/slips.yaml` addition is a single self-contained `federated_network_module:`
block (mode/train_from_scratch/epochs/training_batch_size/time_window_width/seed/
log_suffix/model+preprocess paths). It **does not touch any other module's config,
nor any SLIPS detection threshold** (`network_discovery`, `flowalerts`,
`flowmldetection`, `risk_accumulated_threat_level`, time_window_width global, etc.
are all left at upstream defaults in this file).

## What is explicitly NOT changed
Verified by the diff above — the fork does **not** modify:
- **SLIPS core logic:** `slips.py`, `managers/`, `slips_files/core/` (except the one
  additive enum member above), `slips_files/common/` incl. `abstracts/ml_module_base.py`
  and `abstracts/imodule.py`, the config parser.
- **The input module** (`modules/input_process` / zeek command building / `__load__`).
- **Any other detection module** (`network_discovery`, `flowalerts`, `flowmldetection`,
  `p2p_trust`, `threat_intelligence`, …) — zero lines.
- **Submodules** (`SlipsWeb`, `iris`, `p2p4slips`, `fides`, `feel_project`) — no pointer
  changes on the committed branch.
- **Ground-truth injection:** the fork does **not** patch SLIPS to inject
  `ground_truth_label`. GT is eval-only, read by the module from
  `/opt/network-setup/simulated_attackers.txt` (`_get_simulated_gt`); SLIPS core is
  untouched for GT.

## Dropped pre-rebase patches (history, per MANIFEST §00)
Before the Oct-5 squash-rebase, the old branch carried several **invasive** core
patches. The rebase **intentionally dropped all of them**; they are NOT in this branch:
`config_parser` overwrite, an `imodule` patch, an `ml_module_base` patch (incl. a
`172.20.1.4` GT monkeypatch — never used by the module), a `p2p_trust` patch, a
`zeek_cmd_builder` patch, and a zeek `__load__` change. The old head is preserved as
`fl_module_jan_rebased_backup` for comparison. Net effect of the rebase: core footprint
shrank to the registration-only set above.

## Where the per-peer config actually comes from (not this repo)
The values a peer runs with are **not** this `config/slips.yaml`; they are the
`config/slips_p2p*.yaml` files rendered at image-build time by the **topology plugin**
(`scl-network-topology-plugin/federation/slips/configs/{overrides,variants}.yaml`),
and then patched per experiment by the **experiment runner** (`_apply_fl_overrides`,
e.g. `model_class`/`merge_rule`/`balancing`). Those live in their own repos — this
file documents only the SLIPS-fork (`StratosphereLinuxIPS`) footprint.
