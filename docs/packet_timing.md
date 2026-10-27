# Packet periodicity inside one TCP connection

The optional packet timing collector detects recurring packets inside a single
long-lived TCP connection. Connection-level beacon detection measures separate
connections and cannot recover these timings from `conn.log` alone.

## What training-capture-022 contains

The confirmed DarkVNC endpoint is `10.0.2.15 → 37.48.125.108:443`. Its client
sends repeated **8-byte application messages about every 300.5–300.8 seconds**.
One TCP session contains 85 such messages over roughly seven hours. These bytes
advance TCP sequence numbers; they are application callbacks, not retransmitted
segments or transport keepalive probes. The server sends application data at
the start, but Zeek recognizes no TLS or other application protocol on port 443.

The first long session provides 12 callbacks by about capture time T+01:01:30.
Their period is approximately 300.503 seconds. The default rules produce
`SUSPICIOUS_PACKET_HEARTBEAT` for that session, without matching the endpoint IP
or the `DARKVNC` string. Short sessions containing only a few callbacks do not
provide enough observations for the default timing check.

The supplied PCAP ends in a truncated packet. Testing used an independent copy
containing the readable complete packets; the original capture and analysis
output were preserved. This file problem is separate from periodicity detection.

## Enable and run

Add this to the configuration selected by `-c`:

```yaml
beaconing:
  enabled: true
  packet_timing:
    enabled: true
```

Other packet timing options use the defaults listed below. Reprocess the PCAP
with Zeek to collect the new `packet_timing.log`; reopening the old output with
`--view` cannot reconstruct packet arrival times. A Zeek directory can be
analyzed directly when it already includes this log.

Keep `parameters.tcp_inactivity_timeout` longer than the expected callback gap.
Slips defaults to 60 minutes. Zeek's own five-minute default would split callbacks
spaced 300.7 seconds apart into separate connections. Lowering `min_events` can
speed experiments, but a conservative configuration retains the default 12
events and requires strong timing and size agreement.

The collector is loaded only when both beaconing and its packet timing option
are enabled. It is **off by default** because packet-level Zeek events cost CPU.
Enabling a different evidence type or opening a web page does not enable packet
collection. Benchmark packet collection on the intended capture rate before
using it for continuous high-volume traffic.

## A conservative profile for this capture

The original `output/pcap-case-22` run also contains many broad model findings
away from the confirmed DarkVNC endpoint: 447 from `ml_linear_model`, 12 from
`ml_online_model`, and 108 from `anomaly_detection_https`. Given the capture's
stated labels, these require review before using those models to score this
traffic. Lowering the global alert threshold would amplify this background.

For a conservative evaluation, append those three module names to the existing
`modules.disable` list and enable packet timing. Keep the normal `beaconing`
connection model and the protocol-specific detectors. This setting is for this
evaluation; it does not change the repository's model defaults. A separate
configuration was prepared at
`output/packet-rhythm-development/conservative-pcap-022.yaml`, based on the
user's PCAP-analysis configuration, with the originals preserved.

```bash
nice -n 15 .venv-macos/bin/python slips.py -m -w \
  -c output/packet-rhythm-development/conservative-pcap-022.yaml \
  -f output/packet-rhythm-development/readable-capture.pcap \
  -o output/pcap-case-22-packet-timing --web-port 55022
```

Choose an unused web port and a fresh output directory. The readable capture is
an independent copy without the incomplete final packet. PCAP isolation copies
the selected source whitelist into the new output as usual.

## Evidence and scoring

- `PERIODIC_PACKETS`: **info**, confidence 0.60 by default. Reports recurring
  application data or optional ACK/keepalive packets. Its score contribution is
  zero. Recognized TLS, HTTP and other protocols stay informational.
- `SUSPICIOUS_PACKET_HEARTBEAT`: **medium**, confidence 0.85 by default. Requires
  originator application data, supported TCP client direction, application bytes
  from both endpoints, an unrecognized protocol on an expected TLS port, small
  uniform messages and stricter timing agreement. Its default score contribution
  is `0.5 × 0.85 = 0.425` for the initiating host.

Pure ACKs and TCP keepalives cannot produce the stronger finding. Retransmissions
do not count as advancing data. Fast bursts and large data packets reset the
relevant data window rather than being sampled into a fake regular rhythm.
Native transport keepalives can be indistinguishable from some retransmitted
one-byte probes; both stay out of the scored application-data rule.

The stronger finding describes a suspicious behavior, not a malware-family
classification. A custom legitimate protocol can use regular messages on port
443 too. Use evidence-type-specific source/destination whitelist rules for
reviewed legitimate traffic. Do not globally whitelist port 443 or label all
periodic packets malicious. The existing connection-level ML model is not used
on these packet windows: packet features require their own reviewed training
data before such a classifier would be appropriate.

Evidence identifies the packet sender and receiver, connection UID, measured
period, timing support, variation and typical payload size. Supporting summary
records retain timestamps and lengths, not packet bodies, and link to the
connection in the web interface. Evidence can arrive while the connection is
still active; its final `conn.log` record arrives when Zeek closes that connection.
A stronger finding can upgrade an informational
one immediately. Continuing reports use the parent beaconing
`report_growth_factor` (default 10): first report, then near 100, 1,000, etc.
An already reported stronger finding suppresses subsequent informational
downgrades for that same connection and packet category.

## Bounded work and storage

`zeek-scripts/packet-timing.zeek` does constant-size bookkeeping per TCP packet
after admission checks. Each admitted connection has at most six directional
windows, each a capped ring buffer. The collector sends a summary after the
minimum count, after each `emit_every` further events, and on connection removal
if there is an unreported complete window. It retains no payload bytes.
Connection removal releases state; idle entries expire after an hour. At the
connection cap it stops admitting additional connections and logs a warning.

Python receives summaries through `new_packet_timing`, not one Redis message per
packet. The profiler only parses, stores and routes this metadata. Rhythm fitting
and scoring stay in the beaconing worker, using the same numeric timing methods
as connection-level detection. Report progress is bounded per connection.
Collector state starts fresh with each Zeek process; saved packet metadata can
be viewed later but ordinary flow history cannot replace missing packet timings.

## Parameters

All options below are under `beaconing.packet_timing` and require restarting
Slips to change collection. The existing beaconing period range and maximum
missed cycles also apply to fitting packet intervals.

| Option | Default | What it does and why |
|---|---|---|
| `enabled` | `false` | Loads the Zeek collector and consumes its summaries. Opt in to the packet-event processing cost. |
| `include_acks` | `false` | Also collect pure ACK and non-advancing one-byte probe timing. Keep off to reduce transport-maintenance noise; these findings always remain info. |
| `min_events` | `12` | Require this many events in one direction of one connection. More reduces chance patterns and delays slow-beacon detection. Range 8–256. |
| `window_events` | `64` | Maximum recent timestamps and lengths retained per direction/category. Must cover `min_events`; range 12–256. |
| `emit_every` | `8` | Additional events between collector summaries. Larger values reduce log/Redis/database work and delay recognizing changes. Range 1–256. |
| `max_connections` | `2048` | Maximum concurrent collector states; additional connections are skipped until space becomes available. Range 16–16384. |
| `min_connection_age_seconds` | `30` | Ignore early connection traffic before collecting events, keeping handshakes and startup exchanges out of timing windows. Range 0–86400. |
| `min_interval_seconds` | `1` | Minimum spacing between retained events. A faster burst resets the window; it is not downsampled into artificial regularity. Range 0.01–86400. |
| `min_span_seconds` | `60` | Minimum elapsed time across the window, avoiding findings from a brief burst. Range 0–604800. |
| `max_payload_bytes` | `512` | Larger data packets reset their directional window, excluding bulk transfers from sparse heartbeat analysis. Range 1–65535. |
| `min_support` | `0.9` | Fraction of gaps required to follow the fitted interval for ordinary periodicity. Range 0.8–1. |
| `jitter_tolerance` | `0.1` | Allowed timing error relative to the period; 0.1 allows ±10%. Range 0.01–0.25. |
| `suspicious_min_support` | `0.95` | Stricter fraction of fitting gaps required for scored heartbeat evidence. Range 0.9–1. |
| `suspicious_max_jitter` | `0.05` | Largest robust timing variation allowed for scored heartbeats, relative to the period. Range 0.001–0.1. |
| `small_payload_bytes` | `128` | Largest median application message size for the stronger rule; must not exceed `max_payload_bytes`. Range 1–4096. |
| `uniform_size_fraction` | `0.9` | Fraction of events with the same payload length required for the stronger rule. Range 0.8–1. |
| `expected_tls_ports` | `[443]` | Ports where a regular small-data channel with no recognized application protocol deserves closer attention. Recognized TLS/HTTP/etc. are excluded from the stronger rule. Up to 64 ports; an empty list disables this escalation. |
| `suspicious_threat_level` | `medium` | Severity assigned to the stronger finding. Supports info, low, medium, high or critical. Lower it to reduce its contribution to host scoring. |
| `suspicious_confidence` | `0.85` | Confidence used for the stronger finding; multiplied by threat weight for scoring. Range 0–1. |
| `periodic_confidence` | `0.6` | Confidence for informational rhythms. Their zero threat weight still gives a zero score contribution. Range 0–1. |

Zeek documents the processing cost and sequence-number semantics of its
[`tcp_packet` event](https://docs.zeek.org/en/v8.0.5/scripts/base/bif/plugins/Zeek_TCP.events.bif.zeek.html#id-tcp_packet).

## Initial validation on training-capture-022

The readable 613,753-packet capture produced 17 timing summaries. The new rules
reported three medium-threat heartbeats, all at the confirmed DarkVNC endpoint,
and one informational observation. No other endpoint received a scored packet
timing finding. This is a result for this capture, not a general false-positive
rate estimate.

With the same Slips Zeek policies, TCP timeout and capture, the initial replay
used 2.586 seconds of Zeek CPU without packet collection and 3.218 seconds with
it: approximately 0.632 seconds extra, or 24%. Wall times were cache-sensitive.
The default disabled path registers no additional packet event handler. Python
does not process every packet; it fits only the emitted bounded summaries.
