# Horizontal port scans

A horizontal scan is one source trying the same destination port on many IP
addresses. The `network_discovery` module checks TCP and UDP flows as they arrive.
It needs no training and starts checking immediately, including port 443.

## Why startup and network changes caused false positives

The previous detector counted flows classified as "not established" over one
Slips time window, normally one hour. That category also contained incomplete
observations of old connections. After starting capture or changing Wi-Fi,
closing packets and resets from many HTTPS sessions could therefore look like
new connection attempts. Packet count increased confidence, even when the packets
were only retransmissions or connection closure.

The replacement examines the packets recorded in Zeek's `history`, together
with the connection state, packet counts, payload sizes and duration. It keeps
separate counts for different probe patterns. Retries to one IP count as one
target, and more packets do not increase confidence.

## What contributes to a finding

The checks use distinct destinations for one network, source, transport protocol
and destination port. The default fast check covers 60 seconds and requires 10
new targets. A separate slow check covers 30 minutes and requires 25. These are
rolling periods based on connection start timestamps, independent of Slips time
windows. A long retransmission timeout does not by itself make a burst fall
outside the fast period. Summaries arriving very late after newer traffic can
still fall outside the retained periods.
The current event's time window identifies where the evidence is stored.

| Observed traffic | Treatment |
| --- | --- |
| Outgoing TCP SYN without a completed handshake | Counts as a new attempt. At the target threshold, scattered unanswered attempts produce Low evidence because connectivity failure is also possible. |
| New SYN attempts with rejections to at least half the target threshold, or concentrated address coverage as defined below | High evidence if the required failed-target share is met. Address coverage supports suspicion; it does not prove malicious intent. |
| Failures on at least three destination ports, with no recent successful use by the source | Reduces a SYN-only finding to Low because an outage is possible. Rejected probes keep their own assessment. This context reflects flows received so far. |
| Completed TCP handshake, no application payload in either direction, source closes or resets within three seconds | Separate check for scans of open services. Requires the target threshold and concentrated address coverage; produces Medium evidence. Ordinary connections carrying application data do not count. |
| ACK/FIN-only history, no response or application data, at most two source packets, duration at most one second | Separate, cautious check for ACK/FIN probes. Requires the failed-target share and concentrated coverage; produces Medium evidence and explicitly mentions incomplete capture as another explanation. |
| Unanswered UDP flows | Separate check requiring the failed-target share and concentrated coverage; produces Medium evidence. UDP does not use a TCP handshake. Scattered unanswered QUIC traffic does not by itself pass this check. |
| Failed-flow summary without actual packet history | Can produce Low evidence at the target threshold and failed-target share. It cannot establish that a new SYN was observed. |
| Closing packets, resets or one-way application data without a new SYN, outside the small ACK/FIN rule above | Do not contribute to the new SYN-attempt counter. |
| Flow whose direction Zeek reversed (`^` in history) | Keep Zeek's final endpoints and interpret flags across each flip. A confirmed final-source SYN can count; traffic without one does not enter SYN probe counts. |

For failed-probe checks, the default required share is 80%: failed-probe targets
divided by all distinct recent targets in the same source/port group.
Successful traffic reduces this share. Familiar destinations are excluded
from new-target thresholds, even when reconnections to them fail. Each probe family is assessed separately; TCP and UDP counts never mix.

Concentrated coverage means at least 80% of the candidate destinations share one
IPv4 /24 or IPv6 /64, and at least half the addresses between the lowest and
highest observed address there were contacted. For example, contacting addresses
1 through 10 is stronger evidence of a sweep than contacting ten scattered
addresses across a /24. Sharing a CDN subnet alone is insufficient.

A destination used successfully on that port within the previous hour is familiar.
Failed reconnections to it do not count as new targets until that memory expires.
Successful use means TCP handshake evidence with ordinary use, or a reply to
UDP traffic. Payload alone cannot establish which TCP endpoint was the client.
A short empty connection is kept
as a possible connect scan instead. A successful retry removes an outstanding
failed target. Delayed older failures cannot undo a later recorded success.
For Argus, NetFlow and other inputs without Zeek packet history, the profiler's
coarse state provides a Low-confidence fallback. Some legacy files have only a
total packet count: that total keeps the record eligible, without claiming an
observed packet direction. Such records cannot produce a High-confidence SYN
finding. UDP records without directional counts use the coarse state too.

This context is temporary and bounded; it is not a whitelist.

## Confidence and a continuing scan

High TCP scan findings start at 85% confidence. Confidence increases when more
**distinct destinations**, not more packets or retries, support the same pattern
inside a fast or slow period:

| Confidence | Required observations |
| --- | --- |
| 85% | At least the configured target threshold, the required failed-target fraction, and repeated rejections or concentrated address coverage. |
| 95% | At least twice that period's target threshold, with a minimum of 20 targets, and at least 90% failed targets. The strong-pattern requirement above still applies. |
| 100% | At least ten times that period's target threshold, with a minimum of 100 targets, and at least 95% failed targets. Also requires concentrated coverage or rejections from at least as many destinations as that period's target threshold. |

Thus the default fast period can reach 100% at 100 targets; the default slow
period needs 250. A higher confidence or threat level can be reported during the
normal cooldown. A 100% score means the detector's scan-pattern requirements are
fully met. It does not establish malicious intent or successful exploitation.
Missing packet history, scattered unanswered attempts and the possible-outage
case retain their lower assessments; packet volume cannot promote them to 100%.

At 100%, Slips releases the full destination records for that source/port and
stops repeating expensive scan classification. It keeps a fixed **1 KiB
distinct-IP counter**, at most 20 recent sample flows and up to 31 pending probes.
Continued SYN/rejection probes are checked in batches of 32 against authenticated
Slips P2P connections before being added to the counter. Successful connections
and other probe families do not add to this confirmed SYN scan's count.

Continuing scans generate evidence at logarithmic growth milestones: approximately
1,000, 10,000, 100,000 distinct targets, and so on. These bypass the time cooldown
and retain 100% confidence from the original confirmation. They are explicitly
described as continuations of a confirmed scan, with **approximate** totals and
sampled flow links. The period shown covers the continuing scan, rather than a
new rolling-window test. Retries to the same IP do not increase the counter.
The batched update can delay a milestone by up to 31 additional probes.

The counter uses [HyperLogLog](https://dmtcs.episciences.org/en/articles/3545),
with 1,024 registers and typical relative standard error of about 3.25%; this is
not a guaranteed error bound. Approximation can move the point at which a
logarithmic milestone is reported. It is used only **after exact confirmation**,
not to decide the initial threat or confidence.
After a gap of `horizontal_alert_cooldown_seconds` without SYN/rejection probes,
the next event starts fresh detection. A later scan must qualify again. The
network, interface, source, transport and destination port still separate groups.

Only the original source profile contributes. Evidence links at most 20 actual
probe UIDs, and its timestamp is the latest contributing probe's start time.
Slips checks known P2P connection tuples in one batch when a candidate exists,
removes its own P2P traffic, and recalculates the finding before reporting.
Only Medium and High findings mark the source as a scanner for related detectors.
DNS resolution alone does not exempt an IP.

## Configuration

Put these options under `network_discovery:` in the YAML file supplied with `-c`.
Restart Slips to apply changes. Custom files without this section use the same
defaults. Independent PCAP runs have their own configuration; the Configuration
page shows the copy saved when that run started.

| Parameter | Default | What it does and why |
| --- | --- | --- |
| `horizontal_fast_window_seconds` | `60` | Seconds of flow history used to find a burst. A shorter period avoids accumulating unrelated failures. Range: 1–3600. |
| `horizontal_fast_min_targets` | `10` | Minimum distinct new destinations for a fast finding. Retransmissions do not increase it. Higher values miss smaller scans but reduce incidental fanout findings. Integer, 5–4096. |
| `horizontal_slow_window_seconds` | `1800` | Seconds used by the separate slow check. It must cover the fast period. Range: 1–86400. |
| `horizontal_slow_min_targets` | `25` | Minimum distinct new destinations during the slow period. Using a larger count avoids treating occasional failures as a slow scan. Integer, 5–4096. |
| `horizontal_min_failure_ratio` | `0.8` | Required fraction of distinct recent targets with failed probes. Successful traffic lowers this fraction. Does not gate the separate open-service check. Range: 0.5–1. |
| `horizontal_success_history_seconds` | `3600` | How long successful use makes a destination familiar on this port. Prevents ordinary reconnects counting as exploration. Larger values can hide scans revisiting recently used targets. Range: 1–86400. |
| `horizontal_alert_cooldown_seconds` | `300` | Minimum seconds between ordinary findings for the same network/source/transport/port/probe family. Higher threat, higher confidence and continuing-scan logarithmic milestones bypass it. After confirmation, this also sets the probe-free gap that ends the continuing scan. Range: 1–86400. |
| `horizontal_evaluation_interval_seconds` | `1` | Minimum seconds between full checks of a group. Each minimum target count of new probes also triggers a check, so a subsecond burst can alert. Zero checks every flow and costs more CPU. Range: 0–60. |
| `horizontal_max_groups` | `256` | Maximum network/source/transport/port groups in memory. Discards the least recently used group at capacity. Increasing it covers more simultaneous sources and services but costs memory. Integer, 1–4096. |
| `horizontal_max_targets` | `256` | Maximum destinations per unconfirmed group, including successful-use context. Discards the least recently used target at capacity. Must cover both target thresholds. A limit below the full-confidence target count can prevent reaching 100%. Confirmed scans use the fixed-size counter instead. Increasing this improves pre-confirmation coverage and costs memory and evaluation time. Integer, 5–4096. |

## Performance, restart and limits

The detector reads the connection already present in the `new_flow` event. It
adds no per-flow SQLite searches or Redis keys. Horizontal detection no longer
writes or reads the old per-time-window Redis scan totals; vertical detection
now also uses original-direction events and bounded local state. Most updates are dictionary lookups. Full checks
visit only the bounded group and run at the configured cadence or target-count
boundary. Correlation with other failed services is performed only for a strong
SYN-only candidate.

At defaults, at most 65,536 full target records can be held across 256 groups;
confirmed groups replace their full records with the smaller counter and samples.
Counter updates maintain their sum incrementally, so neither updates nor estimates
scan the 1,024 registers. Detection work runs in the module workers. The core
stops writing obsolete vertical-scan Redis indexes and avoids service lookups
for failed/non-TCP flows; established unknown-service aggregation is preserved.
No detection logic is added to capture, profiling or routing.
The vertical-scan check also uses only the arriving connection. It no longer
queries Redis scan totals, reads every accumulated destination or retrieves an
expanding list of scan UIDs. Evidence uses the arriving connection timestamp.
Old
records expire when later packet timestamps advance beyond the larger of the
slow period and successful-use history. With no traffic, the bounded allocation
remains in memory. Capacity eviction forgets context and can reduce detection or
make an old destination appear new. Saturating a large confirmed scan is normal
and does not count as capacity loss. The module reports actual capacity eviction counts
at most once per minute. Increasing the limits is a coverage/resource tradeoff.

Live capture separates interfaces and observed gateway/subnet identities. Gateway
state is cached for five seconds to limit Redis work; network changes may take
that long to appear. Delayed flows use saved network history when available.
Observed subnet broadcasts, multicast, unspecified addresses and loopback traffic
are excluded. PCAP analyses use their own process-local state. No scan context
is persisted: restarting starts with empty counters and successful-use history,
while previously stored evidence remains available.

There is no blanket startup delay or port exemption. Incomplete capture, NAT,
packet loss, CDN traffic and a real outage can still resemble probing. A small
FIN scan and the closure of an unseen connection can be indistinguishable from
flow summaries alone; the separate ACK/FIN check therefore requires concentrated
coverage and uses Medium threat. Scans making full application exchanges or
ACK/FIN/UDP scans scattered across unrelated networks, or ACK/FIN probes with
replies, may escape these checks.
These limits are preferable to treating every incomplete flow as a certain scan.

## Validation

Regression tests cover saved startup packet patterns, retries, successful
reconnections, network/interface separation, delayed summaries, long timeouts,
subsecond bursts with mixed probe types, fast and slow scans across time windows,
open-service scans, IPv6, UDP, P2P exclusions, confidence growth, logarithmic
continuation reports, quiet-period reset and memory caps.
Run the focused checks from the repository root:

```sh
python3 -m pytest tests/unit/modules/network_discovery/ \
  tests/unit/slips_files/core/database/redis_db/test_scan_detections_db.py \
  tests/unit/slips_files/common/test_config_parser.py
```

The implementation was also checked through Slips' profiler and evidence pipeline
using independent Redis instances, without generating traffic on the network.
A controlled Zeek-log input produced the expected SYN, empty-connect, ACK and UDP
findings, and no finding for leftover session traffic. A legacy Argus scan is
checked with the missing-history fallback.

On an Apple M1, replays of CTU-Normal-38 and CTU-Normal-39 covered 186,827 flows
with no horizontal findings, using about four CPU seconds including log parsing.
These two captures do not establish a general false-positive rate. A separate
saved local-traffic replay is treated as assumed benign, not a verified clean
capture. Startup closing-packet findings no longer reproduce; ambiguous
unanswered SYN bursts can still produce Low evidence rather than certain scans.
A full-state memory check retained 65,536 probe targets using approximately
35.5 MiB of Python allocations, in addition to the interpreter and other Slips
components. Normal traffic usually retains much less state.

A replay of the 15,274 saved connection records from `output/pcap-case-16`
reached 100% confidence on the TCP/445 scan at 100 distinct probes in timestamp
order (250 in original log order) and reported
continuations near 1,000 and 10,000 targets. It produced zero capacity evictions;
the previous implementation produced 13,968 in the same replay. This validates
the saved metadata path, not a fresh capture or a general false-positive rate.
An already running module keeps its loaded code and settings; rerun an analysis
to obtain evidence from the updated detector. Opening its old results with
`--view` does not recalculate evidence or change old confidence values.

## Vertical port scans and other scan types

Vertical detection keeps distinct failed ports for one source/destination,
transport, probe family and network. Only the source profile contributes.
Successful use of a port removes its earlier failed observation. The default
rolling period is one hour, preserving coverage of slow probing. Confirmed SYN
attempts start at 85%, and unanswered UDP at 65%; each can reach 95% at 20 ports
and 100% at 100 ports. Missing history and ACK/FIN-only patterns retain their
lower confidence. Established empty connections do not enter this failed-port
check. Context is transient and separated by interface/network; Slips P2P tuples
are cached for five seconds, with at most 4,096 connections retained.

Exact records are replaced by a 1 KiB counter at full confidence. Continuing
findings report approximate powers-of-ten growth with at most 20 flow IDs. A
probe-free cooldown ends the continuation. A first-contact cache holds at most
`4 × vertical_max_groups` single-port source/destination/family observations; a
multi-port group is allocated only after a second distinct port. Cache rotation
can forget an isolated old probe, while protecting active multi-port contexts
from a large horizontal scan. Actual multi-port/group capacity loss is warned.

| Parameter | Default | What it does and why |
| --- | --- | --- |
| `vertical_window_seconds` | `3600` | Seconds of distinct failed-port history. An hour covers slow scans; shortening it requires a tighter burst. Range 1–86400. |
| `vertical_min_ports` | `10` | Distinct failed ports needed to examine a scan. Retries count once; increasing this reduces sensitivity to small scans. Integer 5–4096. |
| `vertical_alert_cooldown_seconds` | `300` | Gap between ordinary reports and the probe-free interval ending a confirmed scan. Higher confidence and logarithmic continuations bypass reporting cooldown. Range 1–86400. |
| `vertical_max_groups` | `256` | Maximum active multi-port/family/network groups, plus a separate first-contact cache of at most four times this size. Protects memory from large fanout. Integer 1–4096. |
| `vertical_max_ports` | `256` | Maximum exact failed ports in an unconfirmed group. Must cover the initial threshold. Too small a cap can prevent full confirmation. Integer 5–4096. |
| `other_scan_max_groups` | `256` | Separate hard limits on DHCP client groups and ICMP notice groups. Bounds memory as sources change. Integer 1–4096. |
| `other_scan_quiet_seconds` | `300` | Gap that starts fresh DHCP/ICMP tracking. DHCP also separates client MACs, interfaces and Slips windows. Range 1–86400. |
| `dhcp_min_addresses` | `4` | Distinct requested addresses before a DHCP broad-request finding. Requests and representative IDs stay local to the module, with no per-request Redis set searches/writes. Confidence grows to 95% at twice this count (minimum 20), then 100% at ten times it (minimum 100). Integer 2–100 bounds pre-confirmation storage. |

Strong horizontal empty-connect and concentrated UDP sweeps also use confidence
growth and compact continuation, retaining medium threat. Uncertain packet
patterns keep their existing lower confidence. See [scan progress](scan_progress.md)
for common equations, approximate counting, ICMP notices and cross-module behavior.
