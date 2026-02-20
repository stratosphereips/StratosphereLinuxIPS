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

This module uses a two-stage baseline (Welford during known-benign training,
then EWMA adaptation) with z-score style anomaly scoring because that gives:

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


## Data source and lookup model

The module subscribes to exactly one channel:

- `new_ssl` for TLS features (`server_name`, `ja3`, `ja3s`, timestamps, uid)
- conn-level bytes are **not** consumed from a channel; they are fetched on demand from DB using SSL `uid`

Rationale:

- `new_ssl` carries protocol-level metadata required for malware-like HTTPS behavior.
- DB lookup by `uid` adds traffic volume (`sbytes + dbytes`) to detect "more/less data to known servers".
- this is the only correlation path used by this module (no `new_flow` subscription).


## Processing pipeline

### 1) Input correlation

For each SSL event:

- parse SSL flow from `new_ssl`,
- query DB for the matching conn flow using the SSL `uid`,
- if conn exists, extract `daddr` and `sbytes + dbytes` for per-server byte modeling,
- if conn is not available yet, process SSL-only features and keep detection running.

Important:

- the module does **not** subscribe to all conn flows.
- correlation is always SSL `uid` -> DB conn lookup.

Note:

- all detection windows and training-hour progression use traffic time.


### 2) Host-hour state tracking

The model state is per `profileid`:

- current hour bucket,
- known servers set,
- known JA3 / JA3S sets,
- per-feature moment models (Welford fit in training, EWMA adaptation post-training),
- per-server byte models (same two-stage update policy).

Each hour bucket aggregates:

- `ssl_flows`: count of SSL flows in the hour,
- `servers`: unique servers seen this hour,
- `new_servers`: servers never seen before by this host,
- `known_servers_total_bytes` and `known_servers_flow_count`,
- `flow_anomaly_count`: number of anomalous flow events in the hour.


### 3) Training phase ("assume benign")

For the first `training_hours` per host, hourly data is treated as benign baseline input:

- no anomaly alerts are emitted,
- hourly and per-server models are fitted with **Welford online moments**
  (uniform fit over all benign samples, not EWMA-weighted).

This implements configurable "assume-benign" training for the first `training_hours`.

Important:

- "hours" here are based on **traffic timestamps** (`flow.starttime`), not computer wall-clock time.
- this keeps behavior consistent across interfaces, live Zeek folders, pcaps, and historical Zeek logs.
- if `training_hours` is set to `0`, detection starts immediately and baseline is learned online.


### 4) Flow-level anomaly checks

When in detection mode (post-training), each SSL flow can trigger:

1. **New server anomaly**
   - server (SNI or fallback IP) not in host known server set.

2. **JA3S novelty anomaly**
   - `new_ja3s` is host-level novelty.

JA3 client fingerprints are handled as an hourly statistical feature
(`ja3_changes`), not as direct per-flow novelty alerts.

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
- `ja3_changes` = number of first-seen JA3 values (per server) in the hour
- `known_server_avg_bytes` = `known_servers_total_bytes / known_servers_flow_count`

Each feature is scored against its EWMA baseline:

- z-score = `abs(value - mean) / std`
- with an adaptive robust standard-deviation floor learned from recent residuals.

If z-score >= `hourly_zscore_threshold`, that feature is anomalous.

Hourly anomalies are logged as JSON lines with:

- total `anomaly_score` (sum of anomalous feature z-scores),
- list of anomalous features,
- `flow_anomaly_count`,
- `"type": "hourly"`.


## Adaptive retraining strategy

Model updates are always online, but the training stage uses a different fit method.

After each hour, one update state is selected:

1. **Training period**:
   - condition: `trained_hours < training_hours`
   - hourly models use Welford benign fit (equal weight to all training samples)
   - host `trained_hours` increments by one on each closed traffic hour.

2. **Post-training, small anomaly / drift**:
   - condition: `hourly_score <= adaptation_score_threshold` and
     `flow_anomaly_count <= max_small_flow_anomalies`
   - hourly models update with `drift_alpha`.

3. **Post-training, suspicious behavior**:
   - condition: all other post-training hours
   - hourly models still update, but with `suspicious_alpha` (very low).
   - this is intentionally conservative adaptation, not a full freeze.

Current default values:

- `baseline_alpha = 0.1`
- `drift_alpha = 0.05`
- `suspicious_alpha = 0.005`

Flow-level per-server byte models:

- training period -> Welford benign fit
- no flow anomaly (post-training) -> `baseline_alpha`
- small flow anomaly -> `drift_alpha`
- suspicious flow anomaly -> `suspicious_alpha`

### Exact definitions: "small" vs "suspicious"

At **hour level** (used for `drift_update` vs `suspicious_update`):

- `hourly_score` is the sum of z-scores of hourly features that crossed `hourly_zscore_threshold`.
- `flow_anomaly_count` is the number of anomalous flows seen in that hour.
- a closed hour is **small/drift-like** iff:
  - `hourly_score <= adaptation_score_threshold` and
  - `flow_anomaly_count <= max_small_flow_anomalies`.
- otherwise the closed hour is **suspicious**.

At **flow level** (used for per-server-bytes model update speed):

- `flow_anomalies` is the list of reasons triggered for that flow (`new_server`, `new_ja3s`, `bytes_to_known_server`).
- a flow is **small** iff `0 < len(flow_anomalies) <= max_small_flow_anomalies`.
- a flow is **suspicious** iff `len(flow_anomalies) > max_small_flow_anomalies`.

Why:

- benign behavior shifts should be learned,
- strongly suspicious periods should not poison the baseline quickly.


## Mathematical model details

Training stage (known benign):

- Welford online mean/variance:
  - `n_t = n_{t-1} + 1`
  - `delta = x_t - mean_{t-1}`
  - `mean_t = mean_{t-1} + delta / n_t`
  - `M2_t = M2_{t-1} + delta * (x_t - mean_t)`
  - `var_t = M2_t / (n_t - 1)` for `n_t > 1`

Post-training adaptation stage:

- EWMA mean/variance:
  - `mean_t = mean_{t-1} + alpha * (x_t - mean_{t-1})`
  - `var_t = (1 - alpha) * (var_{t-1} + alpha * (x_t - mean_{t-1})^2)`

Reason for this two-stage design:

- training should strongly absorb all known-benign data (Welford, uniform weighting),
- post-training should adapt to drift with controlled speed (EWMA via `alpha` policy).

Scoring:

- residual stream per model:
  - `r_t = |x_t - mean_{t-1}|`
- robust floor candidates from the recent residual window:
  - `Q10(r)` (10th percentile of residuals)
  - `sigma_MAD = 1.4826 * MAD(r)` where `MAD(r) = median(|r - median(r)|)`
- floor update (smoothed):
  - `min_std_floor_t = (1 - beta) * min_std_floor_{t-1} + beta * clip(max(Q10, sigma_MAD))`
- z-score:
  - `z = |x - mean| / sqrt(max(var, min_std_floor^2))`

Current floor defaults in code:

- initial `min_std_floor = 0.1`
- residual window size `64`
- floor smoothing `beta = 0.05`
- floor clamp `[0.01, 1e6]`

Operationally:

- lower `alpha` -> slower adaptation, more memory of older behavior,
- higher `alpha` -> faster adaptation, less stable anomaly boundary.


## Learn more (algorithms and ideas used here)

- Exponential smoothing / EWMA:
  - https://en.wikipedia.org/wiki/Exponential_smoothing
  - https://www.itl.nist.gov/div898/handbook/pmc/section4/pmc431.htm
- Welford online variance:
  - https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
- Z-score:
  - https://en.wikipedia.org/wiki/Standard_score
- Quantile:
  - https://en.wikipedia.org/wiki/Quantile
- Median absolute deviation:
  - https://en.wikipedia.org/wiki/Median_absolute_deviation
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
  ja3_min_variants_per_server: 3
```

Parameter meaning:

- `training_hours`:
  number of per-host hours used for benign-only baseline.
  If set to `0`, baseline learning starts online from the first seen traffic.
- `hourly_zscore_threshold`:
  trigger threshold for aggregated hourly features.
- `flow_zscore_threshold`:
  trigger threshold for bytes-to-known-server deviations.
- `adaptation_score_threshold`:
  upper bound on `hourly_score` for classifying a closed hour as small/drift-like.
- `baseline_alpha`:
  default EWMA update speed in post-training normal (non-anomalous) updates.
- `drift_alpha`:
  update speed when an anomaly is classified as small/drift-like.
- `suspicious_alpha`:
  update speed when an anomaly is classified as suspicious; keeps adaptation conservative.
- `min_baseline_points`:
  minimum history count before z-score checks are trusted.
- `max_small_flow_anomalies`:
  threshold used in both paths:
  max anomalous flows per hour still considered drift-like, and
  max anomaly reasons per flow still considered small.
- `ja3_min_variants_per_server`:
  fallback gate used only when `training_hours = 0`:
  `ja3_changes` is not scored as anomalous unless hourly value is at least
  this threshold.


## Operational log

The module writes one operational log file in the current Slips output directory:

1. `anomaly_detection_https.log`
   - line-based operational events,
   - includes wall-clock timestamp and traffic timestamp,
   - includes event type, clear message, and JSON metrics payload.

The log is now production-oriented (the SNI test log was removed).

### Verbosity control

Use these config keys:

```yaml
anomaly_detection_https:
  log_verbosity: 3
```

Use `log_verbosity: 3` for full operational visibility.

`log_verbosity` levels:

- `0`: no operational logging.
- `1`: important events only (detections, training fit, drift/suspicious adaptation, start/stop).
- `2`: level 1 + hourly summaries.
- `3`: level 2 + per-flow arrivals and detailed model updates.

Log style is fixed:

- emojis are always enabled (for example `🚨`, `🧠`, `🌊`),
- ANSI colors are always enabled.

### What is logged

The module explicitly logs:

- **flow arrivals** (`flow_arrival`):
  SSL ingestion and SSL->conn DB match events.
- **hour close** (`hour_close`):
  computed hourly features and counters before scoring.
- **model fitting during training** (`training_fit`):
  when a host-hour is absorbed into baseline while still in benign training period.
- **drift adaptation** (`drift_update`):
  when small anomalies are treated as drift and model update is allowed.
- **suspicious adaptation** (`suspicious_update`):
  when strong anomalies lead to conservative (very slow) updates.
- **model updates** (`model_update`):
  model update details (feature/server, value, mean, variance, alpha, count, fit method).
- **detections**:
  `flow_detection` and `hourly_detection` with exact reasons, triggering metrics, and confidence level.
- **evidence emission** (`evidence_emit`):
  confirmation that each detection was stored as Slips Evidence (including confidence/threat mapping context).

### Confidence scaling logic

Confidence is numeric and score-based (not a binary warmup flag).

For each detection, the module computes:

```text
confidence_score =
  0.45 * severity +
  0.25 * persistence +
  0.20 * baseline_quality +
  0.10 * multi_signal
```

Where:

- `severity`: from strongest anomaly z-score (`1 - exp(-max_z/3)`).
- `persistence`: anomaly recurrence in recent 3 traffic-hours.
- `baseline_quality`: amount of baseline history available (`count` normalized).
- `multi_signal`: how many independent signals fired in the same detection.

Final confidence level:

- `high` if score >= 0.80
- `medium` if score >= 0.55 and < 0.80
- `low` otherwise

### Metrics included in log events

Depending on event type, metrics include:

- host/profile context (`profileid`),
- flow context (`uid`, `server`, `sni`),
- timestamp context (wall clock + traffic time),
- hourly features (`ssl_flows`, `unique_servers`, `new_servers`, `known_server_avg_bytes`),
- anomaly details (feature names, values, means, z-scores),
- adaptation details (`hourly_score`, `flow_anomaly_count`, selected `alpha`),
- model state (`mean`, `var`, `count`, `min_std_floor`).


## What requirements are covered

Implemented behavior:

- "train for X time as benign": implemented with `training_hours`.
- "then detect anomalies": automatic after training hours.
- "retrain automatically / drift": adaptive alpha logic implemented.
- "more or less ssl servers than before":
  captured by `unique_servers` and `ssl_flows` hourly features.
- "new servers":
  captured by flow-level `new_server` and hourly `new_servers`.
- "more or less data to known servers":
  captured by flow-level per-server bytes anomaly and hourly known-server average bytes.
- "report every anomaly as evidence":
  implemented for both flow-level and hourly detections with confidence, reasons, and rich context.


## Slips Evidence emitted

Every detection (`flow_detection` and `hourly_detection`) is emitted as Slips Evidence.

Evidence design:

- `evidence_type`: `MALICIOUS_FLOW`
- `method`: `STATISTICAL`
- `attacker`: source host (`profileid` IP, direction `SRC`)
- `victim`: best available destination context (`SNI` domain first, otherwise destination IP/domain)
- `proto`: `TCP`
- `timewindow`: from incoming `twid` (parsed to numeric form)
- `timestamp`: traffic/packet time converted to Slips alerts timestamp format
- `confidence`: confidence score in `[0,1]` (same score used by detector)
- `threat_level`: derived from confidence level using module policy
  - confidence `low` -> threat level `low`
  - confidence `medium` -> threat level `low`
  - confidence `high` -> threat level `medium`
- `uid`: triggering flow UID for flow anomalies; aggregated hour UIDs for hourly anomalies

Description includes:

- anomaly kind (`flow` or `hourly`),
- confidence level and score,
- confidence factors (severity, persistence, baseline quality, multi-signal, max_z),
- server/SNI/destination context,
- detection reasons (feature/value/mean/zscore when available),
- extra metrics (for example `bytes_total`, `anomaly_score`, `flow_anomaly_count`).


## Current scope and limitations

1. **No explicit `new_x509` channel integration yet**
   - current Slips channel set does not expose `new_x509` for modules in the same way as `new_ssl`.
   - certificate-related information currently comes from SSL flow fields.

2. **No persistence of model state across restarts**
   - baselines are in-memory for now.

3. **Host identity is `profileid`**
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
3. Add explainability fields (top contributors and expected ranges) per anomaly.


## Visual report tool (local webpage)

Use the included script to generate a local HTML analysis dashboard from the module log:

```bash
python3 modules/anomaly_detection_https/analyze_ad_log.py \
  --log output/<run>/anomaly_detection_https.log \
  --out output/<run>/anomaly_detection_https_report.html
```

What it generates:

- timeline plots (traffic time) for event volume and detections,
- move mouse over the plot area to see exact time-bin values for all plotted series,
- confidence plot with per-bin `confidence_avg` and `confidence_max` for anomalies,
- hourly feature plot with individual values (`ssl_flows`, `unique_servers`, `new_servers`, `ja3_changes`, `known_server_avg_bytes`),
- highlighted benign training window in all time plots (traffic time),
- vertical markers for model-adaptation decisions:
  green dashed = `drift_update`, red dashed = `suspicious_update` (very conservative / near-denied update),
- all timestamps shown in charts/tables are traffic (packet) time; only the "Generated" line at top is wall time,
- confidence breakdown (`high` / `medium` / `low`) over time,
- top anomaly reasons and affected profiles,
- score summaries,
- auto-generated "What Happened" explanation,
- recent events table with parsed metrics.

Open the generated `anomaly_detection_https_report.html` in a web browser.
