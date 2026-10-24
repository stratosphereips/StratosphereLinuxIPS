# Service anomaly detection

`anomaly_detection_services` learns who normally accesses a responding service,
when they access it, and how long completed connections usually last. It works
when Zeek connection records arrive; it does not require early packet events.

The module is separate from `anomaly_detection_https`. Its normalized
observations and baseline engine are independent of TLS, so protocol-specific
adapters and additional behavior signals can be added later. The first adapter
accepts Zeek `conn` records for unicast TCP and UDP. Application-specific DNS,
HTTP, SSH and TLS semantics are not modeled by this module yet.

Both detectors use `slips_files/common/anomaly_detection.py` for empirical
quantiles and median/MAD center and scale estimates. HTTPS keeps its EWMA,
drift and threshold calibration; this module keeps its client, clock and
duration models. Future protocol detectors can reuse the statistical methods
without inheriting TLS-specific features or a shared training state.

## Enable and train

Add this section to the custom YAML configuration used for your capture:

```yaml
anomaly_detection_services:
  enabled: true
  mode: auto
  timezone: Europe/Prague
  training_hours: 168
  min_training_connections: 30
  min_training_days: 3
```

The shipped default is `enabled: false`. Restart Slips after enabling it or
changing its settings. Enabling this module does not enable the HTTPS detector.

All warmup requirements are in `config/slips.yaml` and can be overridden in
your custom configuration:

| Setting | Default | Requirement |
| --- | --- | --- |
| `training_hours` | `168` (7 days) | Elapsed flow time per service; fractional hours are allowed. |
| `min_training_connections` | `30` | Accepted connections per service. |
| `min_training_days` | `3` | Distinct UTC observation days per service. |
| `time_min_days` | `14` | Distinct local observation days for a timing model. |
| `time_min_matching_days` | `3` | Observed local weekdays or weekends matching the scored flow. |
| `duration_min_samples` | `50` | Completed TCP connections for a duration model. |

The first three requirements must all pass before any findings are emitted.
Timing and duration have their own additional requirements. Days count observed
dates, not idle time since startup. Restarting preserves the baseline and its
original training start; changing a threshold does not start training again.

- `auto` learns each service, then detects anomalies. A service needs the
  configured elapsed traffic time, accepted-connection count and number of
  distinct observation days. The default is seven days, 30 connections and
  three distinct days. New services start their own training period.
- `train` fits accepted connections without generating anomaly evidence. Use
  this mode only during traffic you intend to accept as normal, including when
  adding legitimate clients to an existing model. Then return to `auto` or
  `detect`.
- `detect` evaluates existing trained services without fitting their client,
  timing or duration distributions. It still checkpoints activity timestamps
  and rate limits. Unknown or insufficiently trained services remain unscored.

Only accepted connections teach normal client relationships. Repeated failed
attempts cannot enroll a client. Explicit malicious/malware/attack input labels
also prevent fitting, while existing models can still detect those records.
Unlabeled training traffic is assumed representative and benign. Once trained,
a new client remains outside
the baseline until an explicit training period accepts it. Normal connections
from known clients adapt gradually by updating the bounded observation history;
connections with anomaly reasons do not update those fitted distributions.
Set `adapt_known_clients: false` to freeze automatic post-training adaptation.

## Short functional tests

Use these overrides in a separate test run:

```yaml
anomaly_detection_services:
  enabled: true
  mode: auto
  timezone: UTC
  training_hours: 0.0167  # About one minute of flow timestamps.
  min_training_connections: 10
  min_training_days: 1
  time_min_days: 1
  time_min_matching_days: 1
  time_probability_threshold: 0.03
  time_min_concentration: 0
  duration_min_samples: 10
  alert_cooldown_seconds: 0
```

Ten accepted connections from client A can establish a service in one minute
of flow time. A subsequent new client B, including an unanswered attempt, can
then produce evidence. Ten completed TCP connections also enable duration
checks; their normal ratio, deviation and absolute-distance thresholds still
apply. These are per-service requirements; ten unrelated services do not count
as ten samples for one service.

For a timing test, replay connections at a regular hour and then one at a
distant hour on the same date. PCAP replay uses recorded timestamps, so an
hour or several weeks of traffic can be processed without waiting that long
on the wall clock. The test settings above disable the schedule-concentration
gate and relax the rarity/support requirements to make a one-day clock test
possible. They cannot establish a reliable human schedule. Keep the shipped
defaults for ordinary operation and evaluate timing with representative
multi-day traffic before deployment.

Finite PCAP runs already isolate their models from live capture. For a separate
live test, use a separate `parameters.permanent_dir` as well as the normal
isolated Redis/output settings; a second process cannot share the live baseline
writer. Returning to normal settings does not erase a weak test-trained model.

## What constitutes a service

Models are keyed by network, server identity, transport and destination port.
A successful TCP establishment or an observed originator SYN and responder
SYN-ACK can establish a responding service. A TCP refusal/reset alone cannot.
UDP requires packets in both directions. Later unfamiliar attempts to an
already trained service are eligible even when unanswered or rejected.

Multicast, broadcast, ICMP, self-connections, invalid ports and ambiguous
midstream TCP records are excluded. Directed IPv4 broadcasts are excluded when
the monitored subnet is known. Missing replies cannot establish a new service.

A verified gateway MAC and subnet distinguish networks, including two networks
using the same private range. A trustworthy local endpoint MAC can identify a
device across IP changes. Routed hosts never inherit the gateway's MAC.
Packet-time network history is used for flows that complete after roaming.
Without network identity, the scope is isolated to the current run; without
local MAC proof, the endpoint is identified by its IP in that scope. When an
address is still associated with a retained known client, uncertain MAC
disappearance or discovery does not alone justify a new-client finding.
Changed server identity can require fresh service training.

## Unusual connection times

The model learns half-hour activity slots across distinct local calendar days,
with separate weekday and weekend distributions. Each client contributes at
most once per slot per day, so a busy burst does not establish a daily routine.
A circular triangular smoother spans neighboring slots, including midnight.
Multiple normal activity periods can coexist. Broad, irregular distributions
produce no timing finding unless their concentration passes the configured gate.

Timing uses observation days up to the connection's start date within
`history_days`. Old schedules after a long capture gap and later calendar days
cannot supply timing confidence for an earlier flow. It needs `time_min_days`
distinct observed days (14 by default) and
`time_min_matching_days` observations in the applicable weekday/weekend category
(three by default). Missing coverage is not treated as observed inactivity;
insufficient day categories are unscored. This conservative activity model does
not infer a person's working schedule, holidays or service uptime from silence.
Confidence in a schedule depends on observations, not the number of flows in
one burst. Initial training time alone does not satisfy the timing requirements.

`time_probability_threshold: 0.01` gates the smoothed slot frequency, and
`time_min_concentration: 0.35` requires a sufficiently regular schedule. These
values are scores of learned activity, not probabilities of maliciousness.
A known client uses its own model; an unfamiliar/uncertain client can use the
service-wide model, with that fallback identified in the evidence description.

Timestamps are stored as UTC epoch values and converted using the configured
IANA timezone. Daylight-saving transitions use that timezone's rules. Changing
the timezone preserves client and duration baselines but clears clock bins so
timing can be learned again. Assess false-positive rates on later benign data,
including weekends, occasional late work and periods with capture gaps.

## Unusual session lengths

The first version compares duration only for normally completed TCP flows
(`SF`), with an observed response. Failed attempts, incomplete connections and
UDP timeout-grouped flows do not train or trigger this dimension. The measured
quantity is Zeek connection duration, not an application's login/session time.

Models retain up to `duration_samples: 128` log-transformed durations per client
and service. Scoring requires `duration_min_samples: 50`. A short or long
finding must pass all three conservative checks:

- robust deviation above `duration_zscore: 4.5`, using median/MAD and a scale floor;
- a factor of `duration_ratio: 3` beyond the learned 1st/99th percentile bounds;
- at least `duration_min_difference_seconds: 30` beyond the applicable bound.

The tail check retains legitimate short and long modes instead of comparing
every session with one average. During ordinary adaptation the bounded sample
updates only from accepted, known-client connections without anomaly reasons.
Long-lived/incomplete flows need a future protocol-specific treatment before
their durations can be interpreted reliably.

## Evidence and response

The module emits one `ANOMALOUS_FLOW` evidence per anomalous connection, combining
client, time and duration reasons. Evidence keeps the source client as attacker
and profile, the server as victim, transport/ports, the original UID and flow
timestamp. The description distinguishes attempts from answered connections,
client models from service fallbacks, and shows the learned duration range or
timing support. Evidence is low severity, with confidence capped at 0.65.

Slips' normal scoring, whitelist, alert and prevention policies still apply.
An anomaly is not a maliciousness verdict, and one evidence need not cross the
global alert threshold. Existing `ANOMALOUS_FLOW` suppression affects both this
module and the HTTPS detector; disabling this module is independent. A whitelist
`blocking` rule preserves evidence while exempting the target from enforcement.

Repeated client/service/reason combinations have a 3,600-second cooldown by
default. Each service emits at most `max_alerts_per_service_hour: 10` findings
per traffic hour. Suppression counters survive normal restarts. Additional
attempts are still recorded as ordinary flows subject to normal flow retention.

## Persistence and resource limits

Live interfaces and growing captures use
`<parameters.permanent_dir>/anomaly_detection_services/baseline.sqlite`.
Finite analyses use their own
`output/<run>/anomaly_detection_services/baseline.sqlite`, so a PCAP does not
modify a live model. An unidentified network deliberately gets a run-specific
scope. Only one process can own a baseline database at a time. A new run creates
an empty database. An unreadable, corrupt or unsupported existing model causes
an error instead of being reset automatically.

Models are checkpointed every `flush_interval_seconds: 30` and on graceful
shutdown. Abrupt termination can lose observations since the last checkpoint.
This is a separate SQLite database, outside the flow/detection writer. Busy
checkpoints defer and retry with bounded warnings; they do not wait on capture.

Defaults cap state at `max_services: 1024`, `max_clients: 4096` total, and
`max_clients_per_service: 64`. Each schedule retains `history_days: 56` days,
each duration sample has its configured cap, and duplicate/rate/identity caches
are bounded. Inactive services and clients expire after `retention_days: 90`.
Client novelty means absence from this retained baseline, not proof of never
having connected before.

At a service/client capacity limit, the module warns and does not evict an
active known model to admit arbitrary new identities. A partial client set is
marked incomplete and cannot produce new-client findings. Time and duration
checks can still operate. Review limits and use a fresh, deliberately trained
baseline after backing up the old model if complete membership must be rebuilt.

Flow handling uses an existing subscription, bounded cached lookups and small
models; it adds no Redis keys, history scans or scientific-computing dependencies.
It runs in its own Slips process. Enabling it still has a per-flow processing
cost; tune limits and measure on the intended capture workload.
