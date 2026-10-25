# Numeric recurring-connection and suspected C2 detection

The `beaconing` module examines connection timing, bytes, packets and duration
as numbers. It reports two different observations:

- `PERIODIC_CONNECTION` (**info**): connections have a strong recurring interval.
  Normal applications can produce this finding. No malicious example is needed.
- `SUSPECTED_C2_CHANNEL` (**low**): an answered recurring channel also resembles
  the selected malware C2 examples. The score measures pattern similarity;
  it is **not the probability that a computer is infected**.

Both are statistical findings. The default configuration marks them as DAMP.
They go through the usual evidence, whitelist and alert pipeline. The numeric
module does not call the firewall or ARP poisoner directly. A configured response
policy can still act on accumulated evidence; neither finding establishes malware
by itself. Threat intelligence and other independent findings remain useful.

## Enable it

In `config/slips.yaml`:

```yaml
beaconing:
  enabled: true
  model_file: modules/beaconing/model.json
  c2_score_threshold: 0.5

modules:
  disable:
    - template
    - rnn_cc_detection
```

The repository default enables this module and disables the old RNN. Existing
custom configuration files retain their explicit module selections. To use only
the timing detector, set `model_file: ''`. Restart the relevant Slips instance
after changing module settings. The website shows each finding under its source
host and identifies `beaconing` as its source module.

If you run with `-c permanent/pcap-analysis/slips.yaml`, add this section to that
file too. Copies made before this module was added do not gain new sections
automatically. Without an explicit section, this module uses its built-in
defaults, but the web Configuration tab only lists the startup YAML snapshot.
A missing section there therefore does not mean the detector was disabled.

There is no period during which all observed traffic is declared benign. A
channel needs at least 12 connections spanning 30 seconds before its first check.
For a slow beacon, collecting those connections takes longer. A one-minute test
cannot reveal a channel that connects once per hour.

## What is measured

A channel is one source IP, destination IP, destination port and transport
protocol. Changes to the client's temporary source port do not split it. The
current adapter accepts unicast TCP and UDP conn records. It excludes ICMP,
multicast, broadcast addresses when the subnet is known, and malformed records.
A destination profile's copy of the same flow is ignored.

For the latest connections, Slips compares three possible patterns:

1. Time from one connection start to the next start.
2. Time from one connection's end to the next start. This handles clients that
   sleep for a fixed interval after receiving an answer.
3. Time between the starts of groups of closely spaced connections. This handles
   recurring bursts that contain several requests.

It examines several candidate intervals from the observed gaps. Normally at
least 80% must fit within 25% of an interval. Gaps of two or three intervals can
represent missed callbacks, but at least half must be direct single intervals.
Zero gaps do not establish a period. Slips checks the configured range of
frequencies, rather than assuming that only a particular frequency is malicious.
This is a dominant-interval test, not an exhaustive Fourier search through every
possible weak frequency in mixed traffic.

The finding explains the measured period in seconds and frequency in Hz, the
number of connections, elapsed time, fraction following the pattern, variation
in those intervals, missing cycles, median bytes in each direction and median
connection duration. Up to 32 supporting flow UIDs link to the original records.
Overlapping connections are recorded rather than treated as negative sleep times.

The classifier uses variation in intervals, sizes, packet counts and duration,
plus their typical values, the fraction answered, missing cycles and overlap.
It does not use IP addresses, ports, domains, capture names or stratoletters as
predictive features. It is a small forest of 32 trees, each at most three decisions
deep. Runtime reads a reviewed JSON file; it imports neither TensorFlow nor
scikit-learn and does not execute a pickle. The shipped classifier covers **TCP**
only. UDP recurrence is still reported, but this TCP model cannot label it C2.

The adapter receives completed Zeek flow summaries, so detection happens when
those summaries arrive. It cannot see individual callbacks inside one long-lived
TLS connection from a single conn record. Such detection needs additional packet
or application events. Completely irregular C2 and weak patterns mixed with other
traffic can be missed. Different destination IPs remain separate: the module does
not assume that unrelated users of the same CDN are one service.

## Keeping it running

State is bounded by `max_channels` and `window_connections`. Recently used
channels replace older ones at capacity, with a warning in the logs. This is a
coverage limit: an evicted channel must collect observations again. UID duplicate
checks are bounded too; the recent window provides a second check after global
UID entries expire. Zeek records that arrive out of start-time order are inserted
into the bounded window without losing the original timestamp precision.

A private checkpoint lives in `<output>/beaconing/channels.sqlite`. It uses WAL,
nonblocking writes, an exclusive writer lock and an age index. Only changed
windows are saved periodically, outside the per-flow path. Busy writes retain
pending changes for a later retry, including on Python 3.10 systems such as
older Raspberry Pi installations. Checkpoints expire old records and cap the
number of saved channels. There are no new Redis keys or periodic database-wide
flow scans. Offline analyses begin with fresh detector state; live runs restore
recent state in that output directory, including evidence cooldowns.

For TCP records with Zeek history, handshake evidence must support the recorded
client/server roles. Traffic first seen during an ongoing session is skipped
instead of building a channel toward a temporary client port. Zeek-flipped
flows remain eligible when their packet history supports the final direction;
the raw records are preserved. See
[TCP direction handling](flow_alerts.md#tcp-direction-when-capture-starts-during-an-existing-connection).

Live channels include the interface, gateway MAC, subnet and observed client MAC
when available. Delayed flows use recorded network history. A phone hotspot and
a Wi-Fi network do not share a private-IP baseline. Without a known gateway,
Slips uses a run-specific scope rather than guessing that a reused private IP is
the same computer. This fallback deliberately does not combine restart histories.

## Settings: what each one changes

Every option also has an explanation beside it in `config/slips.yaml`.

| Option (default) | What it does and why |
|---|---|
| `enabled` (`true`) | Starts this module on the next Slips launch. Disable it to remove its work and findings. |
| `min_connections` (`12`) | Requires this many connections before checking a channel. More reduces accidental matches and delays slow-beacon detection. |
| `window_connections` (`128`) | Keeps only this many recent connections per channel. More remembers longer behavior and uses more memory. Must cover `min_connections`. |
| `min_span_seconds` (`30`) | Requires observations to span this many seconds, reducing findings from brief request bursts. Lower it for short tests. |
| `min_period_seconds` (`0.1`) | Smallest recurring interval to examine. Smaller values include faster application loops. |
| `max_period_seconds` (`86400`) | Largest recurring interval to examine. Longer intervals need enough retention to collect the required connections. |
| `jitter_tolerance` (`0.25`) | Allows timing error up to 25% of one interval. Raising it tolerates less regular callbacks and more ordinary traffic. |
| `min_support` (`0.8`) | Requires 80% of the observed gaps to match. Lower values tolerate interruptions but increase chance matches. |
| `max_missed` (`2`) | Allows up to two missing callbacks between observed connections. Longer gaps count against support. |
| `evaluate_every` (`4`) | Requires four new connections between checks. Raising it reduces work and delays detection of changed behavior. |
| `evaluate_interval_seconds` (`5`) | Minimum time between checks of one channel. Uses the processing clock live and packet time offline, so accelerated PCAP playback still gets repeated checks. |
| `max_channels` (`2048`) | Caps retained endpoint combinations. Raising it reduces evictions and increases memory and checkpoint size. |
| `retention_hours` (`72`) | Removes older observations and inactive channels. Must cover the period being sought: 12 daily callbacks require at least 264 hours. |
| `alert_cooldown_seconds` (`3600`) | Limits repeated evidence of one category per channel. A later suspected-C2 finding can follow a periodicity finding immediately. |
| `flush_interval_seconds` (`30`) | Time between saving changed windows. Larger values reduce disk work but lose more recent observations after a crash. |
| `model_file` (`modules/beaconing/model.json`) | Loads a reviewed C2-pattern classifier. An empty value keeps only the numeric periodicity detector. |
| `c2_score_threshold` (`0.5`) | Minimum similarity score for suspected C2. Raising it reduces findings and recall. The model's validation threshold is also enforced; neither is a malware probability. |

## Initial data check, 25 October 2026

Capture-level splits were assigned before choosing the numeric classifier.
Training used selected repeated C2 endpoints from the 2020-01-21 Hancitor,
2021-02-09 Hancitor and 2021-02-12 Qakbot recordings, plus CTU-Normal-38.
SystemBC 2021-02-01 and CTU-Normal-39 were validation captures. A small tree-depth
comparison on validation favored the simplest tested forest. Whole captures,
not random prefixes of the same channel, were kept in separate splits.

The selected endpoint annotations identify malware callback traffic; other flows
in those malware captures were left unlabeled. The model is mainly tuned to
these Hancitor/Cobalt Strike examples. This is not independent malware-family
validation or a claim of general malware recall.

| Recording | Flows replayed | Recurring channels | Suspected-C2 channels | Role/result |
|---|---:|---:|---:|---|
| Hancitor 2020-01-21 | 60 | 2 | 2 | Training endpoints |
| Hancitor 2021-02-09 | 711 | 2 | 2 | Training endpoints |
| Qakbot 2021-02-12 | 1,105 | 3 | 1 | Training; the TLS C2 endpoint was missed |
| SystemBC 2021-02-01 | 517 | 2 | 2 | Validation endpoints |
| CTU-Normal-38 | 72,307 | 40 | 0 | Benign training recording |
| CTU-Normal-39 | 114,520 | 50 | 0 | Benign validation recording |
| Qakbot 2021-05-18 | 605 | 1 | 0 | Held out; its labeled Cobalt Strike endpoint was missed |
| Syprix spyware capture 1 | 125 | 0 | 0 | Exploratory; inspected connections did not meet the recurrence test |
| NuclearEk02 | 395 | 1 | 0 | Exploratory; recurring attempts were not promoted to C2 |
| `test-cc` simulation 1 | 299 | 1 | 0 | Held out; recurring behavior detected |
| `test-cc` simulation 2 | 263 | 1 | 0 | Held out; recurring behavior detected |
| Cherry's saved live flows | 235,931 | 64 | 1 | Independent assumed-benign check; one false C2 candidate |

**The live false candidate matters.** It was an HTTP channel whose numerical
pattern resembled the training examples. The result stays a low-severity
suspicion. The held-out misses and this false candidate are retained in the
results; the model was not adjusted to hide them. Broader labeled examples,
including legitimate TCP polling, are needed before increasing severity or
claiming dependable malware classification. Do not use the score alone as an
infection verdict. The simulations were not labeled real malware.

Replay of the 114,520-flow normal recording used about 7.5 CPU seconds; replay
of 235,931 saved live flows used about 17.6 CPU seconds including JSON/SQLite
reading, before adding the small forest evaluation. These are total replay costs,
not continuously consumed CPU percentages. A deliberately full 2,048-channel,
128-connection state used about 84 MiB of Python allocations (86 MiB peak), in
addition to the module's interpreter/import overhead. Saving that deliberately
full state took 0.44 CPU seconds (0.53 seconds elapsed) and produced a 12.2 MiB
checkpoint. This work runs at the configured save interval, not per flow.
Pi hardware and sustained full-capacity performance still need separate measurement.

The primary capture descriptions and endpoint evidence are available from
[Hancitor 2020-01-21](https://malware-traffic-analysis.net/2020/01/21/index2.html),
[Hancitor 2021-02-09](https://www.malware-traffic-analysis.net/2021/02/09/index2.html),
[Qakbot 2021-02-12](https://www.malware-traffic-analysis.net/2021/02/12/index.html),
[SystemBC 2021-02-01](https://www.malware-traffic-analysis.net/2021/02/01/index.html),
and [Qakbot 2021-05-18](https://www.malware-traffic-analysis.net/2021/05/18/index.html).
Training input fingerprints, selected endpoints, validation counts and the model
schema are recorded in `modules/beaconing/model.json`. The recordings themselves
are not copied into the repository.

## Reproduce or retrain

Run commands from the repository root. Export PCAPs to conn logs with your
installed Zeek, using separate output directories:

```bash
mkdir -p output/beaconing/sample
nice -n 15 zeek -C -r path/to/sample.pcap LogAscii::use_json=T \
  'Log::default_logdir=output/beaconing/sample'
```

Create a JSON manifest; `path` can refer to JSON/TSV conn logs or a saved Slips
`flows.sqlite`. Set the split on whole independent captures. Give malicious
captures `label: "malicious-capture"` and explicitly review each `c2_endpoints`
entry (`IP:port/protocol`). Merely being in a malware capture does not label a
flow C2. Benign training/validation captures use `label: "benign"`. Keep live
traffic labeled `benign-assumed` and simulations labeled `simulation`, for
independent checks rather than automatic training.

```json
[
  {"name":"normal-training","path":"path/to/normal/conn.log","split":"train","label":"benign"},
  {"name":"c2-training","path":"path/to/malicious/conn.log","split":"train","label":"malicious-capture","c2_endpoints":["203.0.113.10:443/tcp"]}
]
```

Include separate benign **and** labeled-C2 validation captures; these two example
entries alone cannot train a model. Keep final test captures out of selection.
The trainer rejects identical capture fingerprints or related `group` names
assigned to different splits. Set `group` when captures or generated variants
come from the same recording/session.
It weights each channel so a single long recording does not dominate training.
Retraining needs scikit-learn and NumPy; the Slips module does not.

```bash
python -m tools.beaconing.evaluate manifest.json --output output/beaconing/features.json
python -m tools.beaconing.train output/beaconing/features.json --output output/beaconing/candidate.json
python -m tools.beaconing.evaluate test-manifest.json --model output/beaconing/candidate.json \
  --output output/beaconing/test-results.json
```

Review false candidates, missed labeled endpoints and CPU/memory use before
changing `model_file`. Keep model versioning and provenance with the coefficients.

## Legacy RNN repairs

The old module remains available for comparison. Its runtime now recognizes Zeek
`SF` and matches state names exactly, rather than accepting `NotEstablished`.
Training and runtime share preprocessing: numeric zero padding and the latest
500 symbols, with bounded published prediction inputs. Confidence counts flow
symbols rather than punctuation or long-gap markers. Prediction cadence,
cooldowns and a bounded local cache limit repeated work.

The shipped RNN's token map is preserved for compatibility. In that old map,
letter `a` and padding both have token zero. Changing its tokens without retraining
would invalidate its weights. The replacement trainer reserves a separate padding
token, writes encoding metadata, requires explicit benign/C2 labels and capture
splits, rejects overlapping encoded inputs, uses validation for Optuna and only
evaluates the test split after selection. Broad old Botnet/Malware labels are
rejected. The old `.h5` weights have not been retrained or silently relabeled.

To train a replacement RNN, provide a tab-separated file with `group`, `split`,
`label`, `state` headers, splits `train`, `validation`, `test`, and labels `benign`
or `c2`. Group related sessions and generated variants together. Each split must
contain both classes. Run:

```bash
python -m modules.rnn_cc_detection.training_code.train_optimization_optuna \
  -D reviewed-labels.tsv -S output/beaconing/rnn_model.h5 --epochs 30 --trials 10
```

Deploy its `.h5` and matching `.h5.json` together after independent evaluation.
See the [original audit](cc_detection_strategy.md) for the evidence behind these
repairs and the longer-term protocol and service-association ideas.
