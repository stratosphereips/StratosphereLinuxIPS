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
