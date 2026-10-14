# Known Bugs & Footguns

## __pycache__ staleness (Silent fit_incremental_model dead-return)

**Severity**: Critical (silently prevents all training)

**Root cause**: Python's bytecode cache (`__pycache__/*.pyc`) persists across Git
checkouts. When `federated_network_module.py` overrides the base class
`@abstractmethod fit_incremental_model` with a real implementation, stale `.pyc`
files still reference the base class's `pass`-only body. Python loads the cached
bytecode, and every call to `fit_incremental_model` returns silently — no
training, no metrics, no artifacts, no error.

**Symptoms**:
- `"Training for N epochs on M samples"` prints in the log
- No epoch progress messages appear
- `training_local_*.log` stays empty
- No `latest_local_*.bin` artifacts are saved
- Training runs successfully in isolation outside Slips

**Fix applied**: `init()` calls `shutil.rmtree()` on `__pycache__` at startup so
every module process compiles from source. This is a one-time fix that prevents
the cache from ever going stale.

**Date fixed**: 2026-05-29

## OOM-kill false positive in Slips shutdown

**Severity**: Low (cosmetic, no functional impact)

**Root cause**: Slips' `main.py` SIGTERM handler prints `"SIGTERM received,
likely due to OOM kill"` on every graceful shutdown, even when the analysis
completed normally. This is misleading in logs.

**Symptoms**: Every run log ends with the OOM-kill message regardless of
whether memory pressure actually existed.

**Date identified**: 2026-05-29

## resolve_artifact_path uses CWD instead of SLIPS dir for relative paths

**Severity**: Critical (breaks all ML module artifact loading in Docker)

**Root cause**: `MLBaseDetection.resolve_artifact_path` returns `os.path.join(".", path.lstrip("./"))` for relative paths. The leading `"./"` resolves against the Python process's *current working directory*, not the SLIPS installation directory. In the Docker image `WORKDIR` is `/opt`, but SLIPS lives under `/opt/StratosphereLinuxIPS`. Every child module process inherits `/opt` as CWD, so paths like `modules/ml_linear_model/artifacts/pca.bin` resolve to `/opt/modules/...` (missing) instead of `/opt/StratosphereLinuxIPS/modules/...` (present).

**Symptoms**:
- All ML modules (ml_linear_model, ml_online_model, federated_network_module) report `"No PCA found in test mode"` even though `pca.bin` exists in the repo
- `_read_pickle_or_none()` silently returns `None` because the resolved path does not exist
- `read_model()` falls through to test-mode fallback, leaving PCA/scaler/model uninitialized
- `detect()` prints `"Classifier/preprocessor is not initialized. Please train the model before detecting."` on every flow
- Training and test logs stay empty

**Fix applied**: Changed `resolve_artifact_path` to derive `slips_dir` from `__file__` (four `os.path.dirname` levels up from `ml_module_base.py`) and join relative paths against it instead of `"."`.

**Files changed**:
- `slips_files/common/abstracts/ml_module_base.py` — `resolve_artifact_path` method

**Date fixed**: 2026-05-30

**Superseded (2026-10-05)**: the core patch was dropped in the rebase
onto develop. The module's own artifacts are resolved from `__file__`;
SLIPS is started from `/opt/StratosphereLinuxIPS`, so the base class's
relative store/load paths resolve correctly without a core change.

## Merge scaling, frozen layers, label bookkeeping, test-stream tail (Oct 14 tests)

**Severity**: High (local-vs-merged comparison, trained/flip counts)

**Root cause / fix** (each pinned by a test in
`tests/unit/modules/federated_network_module/`):
1. `trigger_merge` passed the already-scaled `_last_train_X` to
   `_align_head_on_buffer`, which `partial_fit` the shared scaler on it and
   scaled it again. Now the merged head fine-tunes on exactly the batch the
   local head used; the scaler is fit on raw training features only.
2. The manual Adam skipped only `grad is None`; frozen federated layers keep
   a zeroed grad, so weight decay + stale momentum moved them in head-only
   stages. Frozen params are now skipped (no step, no decay, no Adam state).
3. Undersampling ran inside `_train_batch`, after the labels were committed:
   dropped flows were recorded as trained (jsonl, flip registry and
   denominators). The pooled buffer is now undersampled (same per-window
   selection) before the commit, and only buffered flows commit
   (`training_buffer_ids` is row-aligned with the buffer).
4. A flow finalized benign but carried in a sub-threshold batch and cited
   after its finalize was never a flip. It is marked while pending and
   counts as a flip when its batch trains.
5. A training close reset the all-flows test counters without flushing the
   tail below `test_log_batch_size`; it is now flushed before training.
6. A peer payload with matching keys but other shapes aborted the whole
   merge; it is now skipped and the rest merges.
7. With no usable peer payload `trigger_merge` still recorded a merge
   (merge_count, merged stream/artifacts); it now returns first.

Also: `trained_labels.jsonl` rows carry `arrival_window` (window of the cell
the flow arrived in; it finalizes at close `arrival_window + K`).

**Date fixed**: 2026-10-14
