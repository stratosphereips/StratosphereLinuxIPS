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
