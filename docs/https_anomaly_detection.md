# HTTPS Anomaly Detection Module

This document describes how the `anomaly_detection_https` module detects anomalies from TLS/HTTPS traffic in Slips.

![HTTPS anomaly detection example](images/Slips-AD-example.png)

## Goal

Detect unusual HTTPS behavior per host, using:

- Hourly behavior changes (volume and novelty patterns).
- Flow-level deviations (for known servers).
- Adaptive baselines that update over time, with poisoning resistance.

## Input data used

The module subscribes to SSL/TLS events and reads related connection metadata from DB for the same UID.

Main fields used:

- SSL: `uid`, `server_name` (SNI), `ja3`, `ja3s`, `dport`, `sport`
- Conn (correlated): destination IP, total bytes, timing info

## Traffic-time logic

All detection windows are based on **traffic timestamps** (packet/log time), not wall clock time.

This keeps behavior consistent for:

- live interface capture,
- live Zeek folder input,
- offline PCAP,
- offline Zeek logs.

## Features

The module computes per-host hourly features:

- `ssl_flows`: number of SSL flows in the hour.
- `unique_servers`: number of distinct destination servers.
- `new_servers`: number of servers not seen before for that host.
- `ja3_changes`: number of new JA3 variants seen per server in the hour.
- `known_server_avg_bytes`: mean bytes for flows to already-known servers.

Flow-level feature:

- `bytes_to_known_server`: per-server bytes deviation on each flow.

## Baseline and training

Each host has independent models.

### Training phase (`training_hours > 0`)

For the first configured benign hours, the module does **fit-only** (Welford online moments):

- no detection decisions are emitted from hourly z-score rules before training ends,
- baseline mean/variance are learned strongly from this period.

### No explicit training (`training_hours = 0`)

Detection starts immediately using online adaptation.

Special fallback only for `ja3_changes`:

- if hourly `ja3_changes < ja3_min_variants_per_server`, that hourly signal is ignored until enough activity exists.

## Scoring

Each modeled feature uses z-score:

- `z = |x - mean| / std_effective`
- `std_effective` uses variance with a robust minimum floor to avoid unstable near-zero std.

Thresholds:

- `hourly_zscore_threshold` for hourly features
- `flow_zscore_threshold` for flow bytes to known servers

## Adaptation states

After each hour closes, the module chooses model update mode:

1. `training_fit`  
   During benign training: Welford fit (no EWMA alpha).

2. `drift_update`  
   If anomaly score is small (`hourly_score <= adaptation_score_threshold`) and flow anomaly count is small (`<= max_small_flow_anomalies`), update with `drift_alpha`.

3. `suspicious_update`  
   Otherwise update with `suspicious_alpha` (much smaller), to limit poisoning.

For normal non-anomalous periods outside training, per-feature EWMA uses `baseline_alpha`.

## New server vs JA3 behavior

- `new_servers` is modeled as an hourly statistical feature and adapted over time.
- `new_server` can also appear as a direct flow-level novelty reason.
- `ja3_changes` is handled statistically at hourly level (with fallback gate only when training is zero).
- `new_ja3s` can appear as direct flow-level novelty reason.

## Confidence and threat level

Each detection computes confidence score `[0,1]` from multiple factors:

- anomaly severity,
- persistence in recent history,
- baseline quality,
- multi-signal agreement.

Mapped levels:

- low / medium / high confidence

Threat level used in evidence:

- `low` for low or medium confidence
- `medium` for high confidence

## Evidence format

Evidence description is human-readable and concise:

`HTTPS anomaly: type=<type>; confidence=<level> (<score>); reason=<reason>; value=<value>; why=<explanation>.`

Examples of reasons:

- New Server
- New JA3S
- Bytes to Known Server
- Hourly feature deviations (e.g., New Servers Count, JA3 Changes)

## Configuration keys

Section: `anomaly_detection_https` in `config/slips.yaml`.

Main keys:

- `training_hours`
- `hourly_zscore_threshold`
- `flow_zscore_threshold`
- `adaptation_score_threshold`
- `baseline_alpha`
- `drift_alpha`
- `suspicious_alpha`
- `min_baseline_points`
- `max_small_flow_anomalies`
- `ja3_min_variants_per_server`
- `log_verbosity`

## Operational logs

The module logs key events such as:

- flow arrivals,
- hour close and computed features,
- training fit updates,
- drift updates,
- suspicious updates,
- detections and emitted evidence.

