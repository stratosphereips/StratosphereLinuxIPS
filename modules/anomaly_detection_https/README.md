# Anomaly Detection HTTPS Module

## Overview

`AnomalyDetectionHTTPS` is a stateful, host-centric anomaly detector for TLS/HTTPS behavior in Slips.

It combines:

1. **Flow-level detection** (new server, new JA3/JA3S, unusual bytes to known server)
2. **Hourly behavioral detection** (changes in host TLS activity profile)
3. **Adaptive retraining** (different update speed for normal drift vs suspicious behavior)

The implementation lives in:

- `modules/anomaly_detection_https/anomaly_detection_https.py`


## Why this design

Malware infections often show up as **behavior change over time**, not only as one malicious flow. A robust detector should:

- learn a local baseline per host,
- catch sudden deviations (spikes, drops, novelty),
- keep adapting to benign drift,
- avoid quickly learning malicious behavior as normal.

This module uses per-host EWMA baselines and z-score style anomaly scoring because that gives:

- fast processing with low CPU and memory usage,
- interpretable scores,
- online adaptation without offline batch retraining jobs.

### What "fast processing with low CPU and memory usage" means

In this module, this means:

- it uses little CPU and little RAM while Slips is running,
- for each event it does small math updates only (no heavy model fitting),
- it updates models incrementally instead of retraining from scratch,
- it avoids storing all historical flows in memory.

In practical terms: it is cheap enough to run continuously on live traffic.


## Data sources and channels

The module subscribes to:

- `new_ssl` for TLS features (`server_name`, `ja3`, `ja3s`, timestamps, uid)
- `new_flow` for conn-level byte totals linked by `uid`

Rationale:

- `new_ssl` carries protocol-level metadata required for malware-like HTTPS behavior.
- `new_flow` adds traffic volume (`sbytes + dbytes`) to detect "more/less data to known servers".
- `uid` correlation provides combined SSL+flow context per event.


## Processing pipeline

### 1) Input correlation

For each SSL event:

- parse SSL flow from `new_ssl`,
- correlate with conn bytes by `uid` from `new_flow`,
- if conn is not available yet, keep pending SSL entry for short-term reconciliation.

For each conn event:

- cache conn bytes by `uid`,
- if pending SSL exists for the same `uid`, process both together.

Short TTL cleanup is used to bound memory for unmatched events.

Note:

- wall-clock time is only used for temporary cache expiration of unmatched `uid`s.
- all detection windows and training-hour progression use traffic time.


### 2) Host-hour state tracking

The model state is per `profileid`:

- current hour bucket,
- known servers set,
- known JA3 / JA3S sets,
- EWMA models for hourly features,
- EWMA models for per-server byte baselines.

Each hour bucket aggregates:

- `ssl_flows`: count of SSL flows in the hour,
- `servers`: unique servers seen this hour,
- `new_servers`: servers never seen before by this host,
- `known_servers_total_bytes` and `known_servers_flow_count`,
- `flow_anomaly_count`: number of anomalous flow events in the hour.


### 3) Training phase ("assume benign")

For the first `training_hours` per host, hourly data is treated as benign baseline input:

- no anomaly alerts are emitted,
- hourly and server models are updated with `baseline_alpha`.

This matches your requirement: "train model for X time as if all traffic is benign".

Important:

- "hours" here are based on **traffic timestamps** (`flow.starttime`), not computer wall-clock time.
- this keeps behavior consistent across interfaces, live Zeek folders, pcaps, and historical Zeek logs.
- if `training_hours` is set to `0`, detection starts immediately and anomalies are marked with **low confidence**.


### 4) Flow-level anomaly checks

When in detection mode (post-training), each SSL flow can trigger:

1. **New server anomaly**
   - server (SNI or fallback IP) not in host known server set.

2. **New JA3 / JA3S anomaly**
   - JA3 or JA3S not seen before for this host.

3. **Bytes-to-known-server anomaly**
   - only for known servers with enough baseline points,
   - compute z-score from per-server EWMA mean/variance,
   - alert if z-score >= `flow_zscore_threshold`.

Flow anomalies are logged as JSON lines in:

- `anomaly_detection_https.log` with event type `flow_detection`.


### 5) Hourly anomaly checks

On hour rollover, the module computes hourly features:

- `ssl_flows`
- `unique_servers` = `len(servers)`
- `new_servers` = `len(new_servers)`
- `known_server_avg_bytes` = `known_servers_total_bytes / known_servers_flow_count`

Each feature is scored against its EWMA baseline:

- z-score = `abs(value - mean) / std`
- with a standard deviation floor to avoid division-by-zero instability.

If z-score >= `hourly_zscore_threshold`, that feature is anomalous.

Hourly anomalies are logged as JSON lines with:

- total `anomaly_score` (sum of anomalous feature z-scores),
- list of anomalous features,
- `flow_anomaly_count`,
- `"type": "hourly"`.


## Adaptive retraining strategy

After each hour, model update speed is selected by anomaly severity:

1. **Training period**:
   - use `baseline_alpha`.

2. **Post-training, small anomaly / drift**:
   - if `hourly_score <= adaptation_score_threshold` and
   - `flow_anomaly_count <= max_small_flow_anomalies`
   - use `drift_alpha`.

3. **Post-training, suspicious behavior**:
   - otherwise use `suspicious_alpha` (very low).

Why:

- benign behavior shifts should be learned,
- strongly suspicious periods should not poison the baseline quickly.


## Mathematical model details

Each baseline uses online EWMA moments:

- mean update:
  - `mean_t = mean_{t-1} + alpha * (x_t - mean_{t-1})`
- variance update:
  - `var_t = (1 - alpha) * (var_{t-1} + alpha * (x_t - mean_{t-1})^2)`

Scoring:

- `z = |x - mean| / sqrt(max(var, min_std^2))`

Operationally:

- lower `alpha` -> slower adaptation, more memory of older behavior,
- higher `alpha` -> faster adaptation, less stable anomaly boundary.


## Learn more (algorithms and ideas used here)

- Exponential smoothing / EWMA:
  - https://en.wikipedia.org/wiki/Exponential_smoothing
  - https://www.itl.nist.gov/div898/handbook/pmc/section4/pmc431.htm
- Z-score:
  - https://en.wikipedia.org/wiki/Standard_score
- Concept drift:
  - https://en.wikipedia.org/wiki/Concept_drift
- ADWIN drift detector (for a future upgrade path):
  - https://riverml.xyz/0.7.0/api/drift/ADWIN/


## Configuration reference

Configuration section:

```yaml
anomaly_detection_https:
  training_hours: 24
  hourly_zscore_threshold: 3.0
  flow_zscore_threshold: 3.5
  adaptation_score_threshold: 2.0
  baseline_alpha: 0.1
  drift_alpha: 0.05
  suspicious_alpha: 0.005
  min_baseline_points: 6
  max_small_flow_anomalies: 1
```

Parameter meaning:

- `training_hours`:
  number of per-host hours used for benign-only baseline.
  If set to `0`, anomaly confidence is marked as `low`.
- `hourly_zscore_threshold`:
  trigger threshold for aggregated hourly features.
- `flow_zscore_threshold`:
  trigger threshold for bytes-to-known-server deviations.
- `adaptation_score_threshold`:
  max hourly anomaly score still considered drift.
- `baseline_alpha`:
  update speed during initial training.
- `drift_alpha`:
  update speed for small anomalies considered benign drift.
- `suspicious_alpha`:
  update speed for suspicious hours; keeps model conservative.
- `min_baseline_points`:
  minimum history count before z-score checks are trusted.
- `max_small_flow_anomalies`:
  max flow anomalies per hour still treated as drift.


## Operational log

The module writes one operational log file in the current Slips output directory:

1. `anomaly_detection_https.log`
   - line-based operational events,
   - includes wall-clock timestamp and traffic timestamp,
   - includes event type, clear message, and JSON metrics payload.

The log is now production-oriented (the SNI test log was removed).

### Verbosity and style controls

Use these config keys:

```yaml
anomaly_detection_https:
  log_verbosity: 3
  log_emojis: true
  log_colors: true
```

Use `log_verbosity: 3` for full operational visibility.

`log_verbosity` levels:

- `0`: no operational logging.
- `1`: important events only (detections, training fit, drift/suspicious adaptation, start/stop).
- `2`: level 1 + hourly summaries.
- `3`: level 2 + per-flow arrivals and detailed model updates.

`log_emojis`:

- if `true`, adds event icons like `🚨`, `🧠`, `🌊`.

`log_colors`:

- if `true`, adds ANSI terminal colors to log lines.

### What is logged

The module explicitly logs:

- **flow arrivals** (`flow_arrival`):
  SSL and conn flow ingestion/correlation events.
- **hour close** (`hour_close`):
  computed hourly features and counters before scoring.
- **model fitting during training** (`training_fit`):
  when a host-hour is absorbed into baseline while still in benign training period.
- **drift adaptation** (`drift_update`):
  when small anomalies are treated as drift and model update is allowed.
- **suspicious adaptation** (`suspicious_update`):
  when strong anomalies lead to conservative (very slow) updates.
- **model updates** (`model_update`):
  EWMA update details (feature/server, value, mean, variance, alpha, count).
- **detections**:
  `flow_detection` and `hourly_detection` with exact reasons, triggering metrics, and confidence level.

### Metrics included in log events

Depending on event type, metrics include:

- host/profile context (`profileid`),
- flow context (`uid`, `server`, `sni`),
- timestamp context (wall clock + traffic time),
- hourly features (`ssl_flows`, `unique_servers`, `new_servers`, `known_server_avg_bytes`),
- anomaly details (feature names, values, means, z-scores),
- adaptation details (`hourly_score`, `flow_anomaly_count`, selected `alpha`),
- model state (`mean`, `var`, `count`).


## What requirements are covered

From your requested behavior:

- "train for X time as benign": implemented with `training_hours`.
- "then detect anomalies": automatic after training hours.
- "retrain automatically / drift": adaptive alpha logic implemented.
- "more or less ssl servers than before":
  captured by `unique_servers` and `ssl_flows` hourly features.
- "new servers":
  captured by flow-level `new_server` and hourly `new_servers`.
- "more or less data to known servers":
  captured by flow-level per-server bytes anomaly and hourly known-server average bytes.


## Current scope and limitations

1. **No explicit `new_x509` channel integration yet**
   - current Slips channel set does not expose `new_x509` for modules in the same way as `new_ssl`.
   - certificate-related information currently comes from SSL flow fields.

2. **No direct evidence creation yet**
   - anomalies are logged to files; they are not turned into Slips Evidence objects in this version.

3. **No persistence of model state across restarts**
   - baselines are in-memory for now.

4. **Host identity is `profileid`**
   - expected behavior if profiles map to monitored hosts.


## Tuning guidance

If too many false positives:

- increase `hourly_zscore_threshold` and `flow_zscore_threshold`,
- reduce `baseline_alpha`,
- increase `training_hours`,
- increase `max_small_flow_anomalies`.

If detector misses changes:

- lower z-score thresholds,
- increase `baseline_alpha`,
- lower `adaptation_score_threshold`,
- lower `max_small_flow_anomalies`.


## Suggested next improvements

1. Add `new_x509` end-to-end and include certificate-specific features.
2. Persist model state to disk to survive restarts.
3. Emit Slips Evidence records for high-confidence anomalies.
4. Add explainability fields (top contributors and expected ranges) per anomaly.
