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
| `horizontal_alert_cooldown_seconds` | `300` | Minimum seconds between findings for the same network/source/transport/port/probe family. A higher threat level bypasses the cooldown. Range: 1–86400. |
| `horizontal_evaluation_interval_seconds` | `1` | Minimum seconds between full checks of a group. Each minimum target count of new probes also triggers a check, so a subsecond burst can alert. Zero checks every flow and costs more CPU. Range: 0–60. |
| `horizontal_max_groups` | `256` | Maximum network/source/transport/port groups in memory. Discards the least recently used group at capacity. Increasing it covers more simultaneous sources and services but costs memory. Integer, 1–4096. |
| `horizontal_max_targets` | `256` | Maximum destinations per group, including successful-use context. Discards the least recently used target at capacity. Must cover both target thresholds. Increasing it improves coverage and costs memory and evaluation time. Integer, 5–4096. |

## Performance, restart and limits

The detector reads the connection already present in the `new_flow` event. It
adds no per-flow SQLite searches or Redis keys. Horizontal detection no longer
writes or reads the old per-time-window Redis scan totals; vertical detection
keeps its existing counters. Most updates are dictionary lookups. Full checks
visit only the bounded group and run at the configured cadence or target-count
boundary. Correlation with other failed services is performed only for a strong
SYN-only candidate.

At defaults, at most 65,536 target records can be held across 256 groups. Old
records expire when later packet timestamps advance beyond the larger of the
slow period and successful-use history. With no traffic, the bounded allocation
remains in memory. Capacity eviction forgets context and can reduce detection or
make an old destination appear new. The module reports capacity eviction counts
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
open-service scans, IPv6, UDP, P2P exclusions, cooldown escalation and memory caps.
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
