# ARP scan detection

ARP is how a computer asks which MAC address owns a local IP. A computer that
reconnects and resumes communication with many neighbours can send many normal
ARP requests. The number of requests alone does not prove a scan.

Slips separates normal neighbour resolution from possible scanning using
source-specific history and the shape of the search. This improves the existing
`arp` module; it does not add a separately trained machine-learning module.

## What causes evidence

With the default `arp` settings:

1. Consider distinct target IPs in the last **30 seconds**. Retries count once;
   each target expires according to its own most recent request. Five targets
   make a candidate for examination.
2. Wait briefly, normally **3 seconds** from the candidate, for additional
   context. The detector can finish a quiet burst without another ARP packet.
3. Produce low-threat `ARP_SCAN` evidence when **at least 10 targets are
   unfamiliar to this source**, **at least 80% of all targets are unfamiliar**,
   and either at least **70% of successive distinct requests visit adjacent
   addresses**, or at least **32 unfamiliar targets** are requested. Thus a
   larger search can be detected even when the target order is randomized.
   If this source has no prior successful-contact history, at least 10 targets
   must also be addresses not previously observed sending traffic on this
   network. Otherwise questions about already-observed devices remain ambiguous;
   missing unicast visibility does not establish a new scan.
4. If a burst has at least **32 targets** but does not meet the scan conditions,
   keep it as **info-threat `ARP_DISCOVERY`**, describing broad neighbour
   discovery. Info evidence adds nothing to the alert score and cannot trigger
   an alert by itself. Smaller ambiguous bursts produce no scan evidence.

Requests with an unspecified source, a multicast/broadcast target, or equal
source and target IPs are not scan requests. Address-conflict probes and address
announcements therefore do not count. The existing live gateway exemption is
retained when the interface's gateway IP is available.

The window spans Slips time-window boundaries. One source device/address/network
normally produces at most one finding every 300 seconds, including repeated
sweeps. A scan finding can supersede an earlier informational discovery during
that interval. Evidence links one representative request per retained target;
retries do not inflate the count or add unbounded flow IDs.

| Example | Result |
| --- | --- |
| 15 previously used neighbours queried after reconnecting | No scan evidence |
| 12 unfamiliar consecutive addresses, with few familiar targets | Possible ARP scan |
| 40 unfamiliar addresses in random order | Possible ARP scan |
| 40 familiar neighbours | Informational broad discovery, not a scan alert |
| One familiar device repeatedly queried 200 times | One target, not a scan |
| A device is known globally, but has never been contacted by this source | Still unfamiliar to this source |

## What “familiar” means

A neighbour must have **two completed TCP/UDP contacts carrying application
bytes in both directions**, separated by at least `scan_familiar_min_interval_seconds`
(300 seconds by default). An empty TCP connect probe, unanswered flow, ARP
question, or ARP reply cannot establish familiarity. Repeated copies of the same
connection UID are ignored. This is evidence of prior use, not a declaration
that the computer or its traffic is safe.

The successful contacts must predate the burst's first request, or the beginning
of the current rolling window when a source sends continuously. Familiarity
within that window cannot be established by its own traffic. As old requests
expire, confirmed use from before a later window can help that later decision;
a busy source does not keep its first-capture unfamiliar flags forever.
Only local IPv4 contacts are learned: both endpoints must belong to the recorded
local subnet, or, when that subnet is unavailable, both must already have been
observed sending ARP on the link. Both endpoints need individual MAC identities;
missing MACs can be filled from previously observed senders. An IP asked about
in an ARP request is not thereby recorded as alive.

History is specific to the source MAC and destination IP/MAC, within the gateway
MAC and subnet. A different source, different network, or observed change in the
neighbour's MAC does not inherit an exception. A known neighbour can still be
part of a scan; a source cannot bypass detection of its unfamiliar targets simply
by including a few familiar neighbours.

Observed ARP replies and subsequent two-way application traffic appear in the
finding. Sufficient observed application traffic reduces scan confidence, but a
reply alone does not prove the requester is benign. Missing replies or traffic
are treated as **unknown**, never as failures: a passive capture may see broadcast
ARP but miss another device's unicast exchanges, and Zeek may log a connection
only after it ends. Initial discovery on a new network and authorized inventory
tools can still resemble scanning. The evidence explains the observed pattern;
ARP alone cannot establish the requester's intent.

## Checking which rule created an evidence record

New ARP records save the target counts, the configured minimum unfamiliar
count, and the other conditions used for that decision. The web displays these
saved values. By default the minimum is **10 target IPs**, not ten minutes.
Seven linked requests alone cannot satisfy that minimum.

Older records without this assessment are labeled **Legacy ARP scan evidence**.
Their linked flow count does not show how many neighbours were unfamiliar.
They are preserved as historical records, not presented as a decision made by
the current detector.

A worker must belong to the currently running Slips coordinator, even when
the same output directory is reused with `--keep-history`. Evidence writes
check that coordinator's PID. Module and profiler-worker processes also watch
their actual spawning parent's death sentinel. If that parent dies abruptly,
the worker exits within about one second instead of consuming a later run's
traffic. Normal shutdown still performs its regular checkpoint and cleanup.
The watcher waits locally; it does not poll Redis or scan the process table.

## Restarting, changing networks and storage

Live capture keeps its bounded contact checkpoint in
`<permanent_dir>/arp/contacts.sqlite`. Restarting Slips restores contacts for the
same verified network and devices. No blanket startup grace period is used.
Without a verified gateway/subnet, context belongs to this run/interface and is
not reused by another run. Imported PCAP/Zeek logs always start with independent
history, checkpointed under `<output_dir>/arp/contacts.sqlite`; they never load or
alter live contacts, even when they reuse private IP addresses.

No existing host names or host-history data are deleted. Relationships expire
after the configured number of days without successful use. All request,
relationship, sender and duplicate-flow caches have explicit size limits. At
capacity old context is discarded and a rate-limited warning reports this;
forgotten neighbours may be considered unfamiliar again. Target-limit findings
explicitly mark their counts as partial.

The ARP worker consumes the existing connection channel to learn context. It
uses bounded in-memory operations, caches network state for five seconds and
does no database queries or disk writes for each contact. Its separate,
single-writer SQLite checkpoint cannot lock the main detection database. A dirty
snapshot is saved periodically and on clean shutdown. A busy checkpoint is
retried later without blocking the profiler. A crash can lose learning since the
last checkpoint. The former ARP evidence-combining timer thread is no longer
needed.

## Configuration

Put these options in the **`arp:` section** of your Slips YAML. They are also
shown by the web Configuration tab; the main configuration template includes
short explanations for every option. Restart Slips after changing them.

| Option | Default | What it does and why |
| --- | --- | --- |
| `scan_window_seconds` | 30 | Seconds of requests considered together. Old target requests expire independently. |
| `scan_min_targets` | 5 | Minimum distinct targets before examining a candidate. This count alone does not produce evidence. |
| `scan_min_unfamiliar_targets` | 10 | Minimum targets without prior source-specific use for a scan. Allows smaller ordinary discovery bursts. |
| `scan_min_unfamiliar_ratio` | 0.8 | Required unfamiliar share. Avoids treating a few new neighbours among familiar ones as a scan. |
| `scan_broad_targets` | 32 | This many unfamiliar targets can establish a large search without ordered addresses. Bursts of this size lacking enough scan indicators become informational discovery. |
| `scan_ordered_ratio` | 0.7 | Share of consecutive distinct targets whose IPs differ by one, in either direction. Supports smaller ordered sweeps. |
| `scan_context_wait_seconds` | 3 | Short wait after candidate creation for context. Zero decides immediately; it does not create a startup blind period. |
| `scan_alert_cooldown_seconds` | 300 | Minimum interval between repeated findings for a source/device/network; a scan can supersede info sooner. Prevents one burst repeatedly increasing scores. |
| `scan_familiar_min_interval_seconds` | 300 | Minimum separation between two successful contacts before a neighbour is familiar. Stops a single short discovery burst from creating its own benign history. |
| `scan_familiar_retention_days` | 30 | Days since last successful use before contact history expires. Handles changes while keeping history bounded. |
| `scan_checkpoint_seconds` | 120 | Minimum interval between dirty history saves. Larger values reduce writes but risk more lost learning on a crash. |
| `scan_max_sources` | 256 | Maximum device/address/network request groups. Oldest-used context is evicted at capacity. |
| `scan_max_targets` | 512 | Maximum distinct targets and representative UIDs per group. Counts become partial at capacity. |
| `scan_max_relationships` | 8192 | Maximum source-to-neighbour history records; separately caps observed senders and recently seen connection UIDs. Higher limits retain more context at a memory/disk cost. |

Counts must satisfy `scan_min_targets ≤ scan_min_unfamiliar_targets ≤
scan_broad_targets ≤ scan_max_targets`. Invalid settings stop this module's
initialization with an explanatory error instead of silently changing the rule.

## Evidence in the web interface

Evidence and Hosts show either **ARP_SCAN** or **ARP_DISCOVERY** with its actual
threat, confidence, explanation and triggering requests. The investigation pane
shows target counts, prior familiar/unfamiliar counts, observed replies and
observed application traffic. Structured decision details are retained in
`detection_details.arp_scan`, including the thresholds used by that run. These
details are separate from P2P report provenance and survive P2P annotation.
Old evidence without these details retains its legacy five-target rule
explanation; upgrading never rewrites historical findings or scores.
