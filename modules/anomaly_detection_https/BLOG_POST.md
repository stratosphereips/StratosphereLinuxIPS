# HTTPS Anomaly Detection in Slips: Adaptive Baselines for Real Traffic

Network defenders often face a practical contradiction: HTTPS is where critical business traffic lives, but it is also where modern malware hides. Static signatures and one-shot thresholds rarely survive contact with real enterprise behavior. User activity changes by hour, hosts age, software updates shift fingerprints, and traffic can be processed live or replayed from old PCAPs.

The `anomaly_detection_https` module in Slips is built to handle that reality.

![HTTPS Anomaly Detection Example](../../docs/images/Slips-AD-example.png)

This post explains the module end-to-end: goals, feature engineering, statistical modeling, confidence scoring, adaptation strategy, evidence generation, and why each design decision was made.

---

## Why this module exists

The goal is not to classify “malware family X” directly. The goal is to detect **behavioral deviations in HTTPS usage per host** with low operational friction:

- Work with live interfaces, live Zeek folders, PCAPs, and Zeek files.
- Keep decisions in **traffic time** (packet timestamps), not wall clock.
- Use a model that can start with known benign training, but also run with `training_hours = 0`.
- Adapt automatically while reducing poisoning risk.
- Produce evidence readable by humans and usable by downstream systems.

The module treats each host independently. Baselines are never global across all hosts.

---

## Data pipeline and correlation

The detector is triggered by SSL/TLS flows. For each SSL event it also retrieves related conn metadata (same UID) from the DB to get transport context and bytes.

Core signals consumed:

- SSL/TLS: `uid`, `server_name` (SNI), `ja3`, `ja3s`, ports.
- Conn correlation: destination IP, bytes, timing, 5-tuple context.

This produces two levels of detection:

1. **Flow-level checks** (per SSL event).
2. **Hourly host-level checks** (aggregated behavior in one-hour buckets).

---

## Time semantics: traffic time first

A major design decision is strict use of **traffic timestamps** for model logic:

- Hour buckets are based on packet/log timestamps.
- Training completion is measured in traffic hours.
- Drift and suspicious updates happen on traffic-hour boundaries.

This avoids distortions when replaying old captures fast, pausing, or processing out of real-time.

---

## Feature set

The model combines novelty and magnitude features.

### Hourly features (host-level)

For each host and each traffic hour:

1. `ssl_flows`: number of SSL flows.
2. `unique_servers`: number of distinct servers contacted.
3. `new_servers`: number of first-seen servers for this host.
4. `ja3_changes`: number of new JA3 variants per server observed in the hour.
5. `known_server_avg_bytes`: average bytes for flows to already-known servers.

### Flow-level feature (server-level)

- `bytes_to_known_server`: bytes anomaly for a flow to a known server.

This captures three practical infection indicators:

- New remote infrastructure patterns.
- Sudden changes in endpoint/client TLS behavior.
- Volume shifts against known destinations.

---

## Statistical model

Each modeled signal uses online moments plus robust scoring designed for non-Gaussian HTTPS traffic.

### Online moments

For a feature value stream \(x_t\), the module maintains per-host (and for bytes, per-server) summary statistics:

- Mean \(\mu_t\)
- Variance \(\sigma_t^2\)
- Count \(n_t\)

During benign training it uses Welford-style updates (stable online mean/variance estimation).

### Detection score

For heavy-tail non-negative features, the module first applies:

\[
y_t = \log(1 + x_t)
\]

Then it computes robust center/scale from a recent window:

\[
m = \mathrm{median}(y), \quad
\mathrm{MAD} = \mathrm{median}(|y - m|), \quad
\sigma_{\mathrm{robust}} = \max(1.4826 \cdot \mathrm{MAD}, \sigma_{\min})
\]

And scores the point with:

\[
z_{\mathrm{robust},t} = \frac{|y_t - m|}{\sigma_{\mathrm{robust}}}
\]

Why this choice:

- `log1p` compresses extreme right tails common in bytes and flow counts,
- median/MAD is less sensitive to outliers than mean/std,
- \(\sigma_{\min}\) prevents unstable divisions when variability is very low.

Detection rules:

- If benign training exists, thresholds are calibrated per signal from benign robust-z quantiles:
  \[
  \theta_s = Q_q(z_{\mathrm{robust,benign},s}), \; q=\texttt{empirical\_threshold\_quantile}
  \]
- Without benign training, defaults are used:
  - hourly: `hourly_zscore_threshold`
  - flow bytes: `flow_zscore_threshold`

---

## Training modes

## 1) Explicit benign training (`training_hours > 0`)

For the first configured traffic hours, data is treated as benign baseline fit:

- Models are fitted strongly.
- Hourly z-score detections are not used for baseline decisions.
- Baseline quality rises quickly as points accumulate.

This mode is for environments where the first N hours are trusted.

## 2) Zero-hour start (`training_hours = 0`)

The module starts detecting immediately while learning online.

A specific guard is used for early JA3 volatility:

- `ja3_changes` hourly signal can be gated until reaching `ja3_min_variants_per_server` (fallback behavior for no-training mode).

This reduces startup noise when no curated benign period is available.

---

## Adaptation strategy: learn, but do not get poisoned

After each hourly window closes, the module decides how aggressively to update the baseline.

Let:

- `hourly_score` = sum of hourly z-scores that crossed threshold.
- `flow_anomaly_count` = number of flow-level anomalies in that hour.

### State A: `training_fit`

If still in benign training period:

- Update with training fit (Welford), not EWMA alpha.

### State B: `drift_update`

If anomalies are small:

- `hourly_score <= adaptation_score_threshold`
- `flow_anomaly_count <= max_small_flow_anomalies`

Then treat as benign drift and update with `drift_alpha`.

### State C: `suspicious_update`

Otherwise:

- Update with much smaller `suspicious_alpha`.

This still allows slow adaptation (important for long runs), but limits rapid model poisoning during suspicious periods.

For clean non-anomalous operation outside training, normal adaptation uses `baseline_alpha`.

### Optional ADWIN trigger

The module can optionally use ADWIN (from `river`) as drift trigger in both levels:

- Hourly: ADWIN receives each raw hourly feature stream.
- Per-flow: ADWIN receives each raw per-flow signal stream.
- ADWIN detects drift -> classify as normal drift (`drift_update`) or suspicious drift (`suspicious_update`) using existing thresholds.
- ADWIN does not detect drift -> apply `baseline_update` with `baseline_alpha`.
- During benign training, ADWIN is warmed with benign scores so post-training behavior is more stable.

Why raw streams and not z-score streams for drift:

- drift is defined on the observed data distribution itself,
- feeding ADWIN raw streams preserves that signal,
- robust z-scores remain useful for anomaly severity and explainability, but they are secondary for drift triggering.

Operational cost:

- hourly: one ADWIN update per hourly feature and host,
- per-flow: one ADWIN update per raw per-flow signal and host,
- still small in absolute terms, but higher than a single aggregated detector.

---

## Confidence model

Every detection gets a confidence score in \([0,1]\), then a confidence level (`low`/`medium`/`high`).

The score blends multiple factors:

- **Severity** (how strong are anomaly signals, including z-scores)
- **Persistence** (recent anomaly continuity)
- **Baseline quality** (how reliable the learned model is)
- **Multi-signal agreement** (single weak reason vs multiple supporting reasons)

This avoids naive confidence definitions and produces more stable triage behavior.

Threat level mapping in emitted evidence:

- `low` confidence -> threat `low`
- `medium` confidence -> threat `low`
- `high` confidence -> threat `medium`

---

## Evidence generation: human-first descriptions

Evidence descriptions are now plain text, concise, and operational:

`HTTPS anomaly: type=<type>; confidence=<level> (<score>); reason=<reason>; value=<value>; why=<explanation>.`

Examples of reasons:

- New Server
- New JA3S
- Bytes to Known Server
- Hourly deviations like New Servers Count or JA3 Changes

The source IP is already part of the evidence object, so it is not repeated in the description body.

---

## Operational observability

The module logs key lifecycle events with structured metrics:

- flow arrival and correlation context,
- hourly bucket close and computed features,
- model update mode (`training_fit`, `drift_update`, `suspicious_update`),
- alpha used for each update,
- detection reasons and confidence factors,
- evidence emission.

This makes the detector explainable during troubleshooting and tuning.

---

## Why these design choices

1. **Per-host modeling**: avoids blending unrelated behavior across machines.
2. **Traffic-time windows**: works consistently in live and offline modes.
3. **Hybrid flow+hour detection**: catches both spikes and pattern shifts.
4. **Online stats + z-score**: simple, interpretable, cheap at runtime.
5. **Adaptive update states**: keeps learning while resisting poisoning.
6. **Human-readable evidence**: easier analyst triage and auditability.

---

## Configuration knobs that matter most

In `config/slips.yaml` (`anomaly_detection_https` section):

- `training_hours`
- `hourly_zscore_threshold`
- `flow_zscore_threshold`
- `adaptation_score_threshold`
- `baseline_alpha`
- `drift_alpha`
- `suspicious_alpha`
- `min_baseline_points`
- `max_small_flow_anomalies`
- `use_adwin_drift`
- `adwin_delta`
- `adwin_clock`
- `adwin_grace_period`
- `adwin_min_window_length`
- `empirical_threshold_quantile`
- `ja3_min_variants_per_server`
- `log_verbosity`

Practical tuning rule:

- If false positives are high after trusted training, first increase z-score thresholds slightly and/or reduce adaptation aggressiveness.
- If adaptation is too slow in stable environments, increase `baseline_alpha` carefully.

---

## Closing note

This module is designed as a production-oriented anomaly detector: statistically grounded, explainable, adaptive, and compatible with the real operational constraints of network telemetry.

It does not rely on a fragile single indicator. It combines novelty, distribution shifts, per-host baselines, and controlled adaptation to surface HTTPS anomalies that are both detectable and actionable.

Reference:

- River ADWIN documentation: https://riverml.xyz/latest/api/drift/ADWIN/
- Time-series/data transformations (`log1p` context): https://otexts.com/fpp3/transformations.html
- Median Absolute Deviation (robust scale): https://en.wikipedia.org/wiki/Median_absolute_deviation
