# SLIPS core footprint — changes outside the FL module

**Audience:** thesis reviewers / teammates auditing what this fork changes in SLIPS
*outside* `modules/federated_network_module/`. Purpose: show that the federated
experiment does **not** modify SLIPS detection logic, the input module, or any
other module's behaviour — the core footprint is registration + config + a
dependency (**§A**), plus one behaviour-neutral upstream perf backport that is
being contributed to SLIPS `develop` on its own branch and is not part of the FL
experiment path (**§B**).

- **Fork branch:** `fl_module_jan_rebased`
- **Rebase base (upstream SLIPS develop):** `ccd0b1581` (Oct 5 2026)
- **Reproduce this audit:**
  ```
  git diff ccd0b1581..HEAD --stat -- . \
    ':(exclude)modules/federated_network_module' \
    ':(exclude)tests/unit/modules/federated_network_module'
  ```

## A. FL-module integration (vs base)

`+60 / −2` across **5 files** — registration + config + dependency only.

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

## B. Backported upstream perf fix — public-IP caching (not FL logic)

A **behaviour-neutral** performance fix, backported **verbatim** from upstream
`sebas_testing` commit `e44723f92` (S. Garcia, *"Avoid repeat public IP lookups
and exclude Slips-owned P2P traffic"* — **part A only**, the public-IP caching;
the P2P-traffic-exclusion part B of that commit is **not** taken). Problem: SLIPS
asked `ipinfo.io` for **its own** public IP on every caller of `get_own_ips()`,
flooding the network. Fix: `get_public_ip()` caches the result per detected
network; call sites that only need local IPs pass `include_public=False`. No
detection threshold or logic changes.

`+279 / −27` across **6 files** (5 source + 1 test). Every touched region is
byte-identical to `sebas_testing`:

| File | Δ | What |
|---|---|---|
| `slips_files/common/slips_utils.py` | +144/−23 | `get_public_ip()` caches by network signature (iface IPs + gateway + gateway MAC, thread-safe `Lock`); `get_own_ips()` gains `include_public=True` param; two private helpers |
| `modules/arp/filter.py` | +3/−1 | build `our_ips` with `include_public=False` |
| `modules/conn_analyzer/conn_analyzer.py` | +3/−1 | same |
| `modules/flow_alerts/dns.py` | +3/−1 | same |
| `slips_files/core/evidence_handler_worker.py` | +3/−1 | same |
| `tests/unit/slips_files/common/test_slips_utils.py` | +123 | 4 tests (cache-per-network, signature tracks route / gateway MAC, skip-public) |

**Upstreaming:** this slice is also pushed as a standalone branch off SLIPS
`develop` with a PR, so it can merge upstream independently of the thesis fork.

## What is explicitly NOT changed
Verified by the diff above — the fork does **not** modify:
- **SLIPS core logic:** `slips.py`, `managers/`, `slips_files/core/` (except the one
  additive enum member in §A and the behaviour-neutral §B caller edit in
  `evidence_handler_worker.py`), `slips_files/common/` incl. `abstracts/ml_module_base.py`
  and `abstracts/imodule.py`, the config parser (`slips_utils.py` is touched only by §B).
- **The input module** (`modules/input_process` / zeek command building / `__load__`).
- **Any other detection module's logic** (`network_discovery`, `flowalerts`,
  `flowmldetection`, `p2p_trust`, `threat_intelligence`, …) — zero detection-logic
  lines; the only edits are the §B `include_public=False` one-liners in `arp`,
  `conn_analyzer`, and `flow_alerts`, which change how own-IPs are fetched, not detection.
- **Submodules** (`SlipsWeb`, `iris`, `p2p4slips`, `fides`, `feel_project`) — no pointer
  changes on the committed branch.
- **Ground-truth injection:** no SLIPS **core-layer** file is patched for GT.
  The module derives GT from `/opt/network-setup/simulated_attackers.txt`
  (`_get_simulated_gt`) and, **eval-only**, stamps it into each flow's
  `ground_truth_label` field in `flows.sqlite` (`_write_ground_truth`, via the
  module's **own** short-lived read-write SQLite connection + `json_set`). This is
  a no-op in live capture (no attacker list → nothing written), writes only the
  GT label (never the detection output), and adds **no** method to SLIPS's DB
  layer — the write lives entirely inside the module. (Before 2026-10-13 the
  module only read `flows.sqlite`; it now also writes this one eval field.)

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
