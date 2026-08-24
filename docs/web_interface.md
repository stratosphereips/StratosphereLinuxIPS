# Local web interface

The web_interface module is a read-only technical view of one Slips run. It is designed for the person running Slips, not for receiving data from remote installations or combining concurrent runs. It binds to localhost by default.

## Start it

Enable the interface with -w:

```bash
./slips.py -e 1 -f dataset/test7-malicious.pcap -w
```

The default URL is http://localhost:55000/. It can also be enabled in config/slips.yaml:

```yaml
web_interface:
  enabled: true
  bind: localhost
  port: 55000
```

The `-w` flag enables the module even when `enabled` is false. `bind` accepts:

- `localhost` — default; listens only on `127.0.0.1`.
- `interface` — listens only on the IPv4 address of the interface Slips is monitoring. Slips reports the resulting URL in the console. This mode fails closed if no monitored IPv4 interface is available.

The interface mode exposes run data to hosts that can reach that network interface. The server has no login layer; use host firewall rules or a trusted network.

Only one web-enabled Slips run is supported on a host. A new -w run replaces an older listener only after verifying that it is a Slips web server owned by the same user. It never terminates an unrelated program using the port. If another program owns the port, the module reports an error and stops.

When a file or folder analysis finishes naturally, or after the first Ctrl-C stops a web-enabled live analysis, Slips asks `Slips analysis has stopped. Stop the web interface? [y/N]`. Answer `y` or `yes` to stop the page and finish shutdown. Answer `n`, `no`, or press Enter to keep the page and its Redis/SQLite data available; Slips then waits until the page is stopped or you press Ctrl-C. A later web-enabled run can replace a verified older listener.

If the `slipsBlocking` chain contains Slips-managed rules at shutdown, Slips
first asks `Keep the installed firewall rules? [Y/n]`. Press Enter or answer
`y` to retain enforcement; answer `n` or `delete` to remove the complete Slips
chain and its local recovery records. Non-interactive and forced shutdowns
keep the rules because silently dropping enforcement would be unsafe.

A second Ctrl-C, SIGTERM, SIGHUP, SIGQUIT, daemon stop, core-module failure, and update shutdowns stop the web server with Slips without prompting. SIGKILL and SIGSTOP cannot be caught by any process, so no application can perform cleanup for those signals. In a non-interactive session where Slips cannot read a console answer, the web interface is stopped instead of leaving the command blocked indefinitely.

Every data request checks that Redis still advertises the output directory configured for that server. If Redis belongs to a different run, the API returns HTTP 409 and the page displays a persistent run-mismatch banner instead of mixing runs. Detection producers perform the same ownership check before publishing evidence, so a delayed process from a replaced run cannot write into the new run.

Do not enable this interface with -m or for several concurrent Slips instances.

## Storage and retention

The interface separates current state from durable history.

Redis database 0 on this run's assigned port contains current profiles, time windows, process IDs, and counters. Redis expiry is not treated as historical storage.

The run database keeps raw traffic and durable detection relationships:

```text
output/<run>/databases/flows.sqlite
```

It contains the existing unlimited flows and altflows rows, normalized evidence with its complete serialized record, evidence UUID to triggering flow UID relationships, and alert UUID to evidence UUID relationships. Evidence and alert relationships are written transactionally when Slips creates them, whether or not a browser is open.

When an older run is opened after this upgrade, the module first backfills evidence and correlations still in Redis. Backfill runs only when Redis belongs to the same output directory. The web interface does not read `DisabledAlerts` or make its own suppression decisions. It presents the records and whitelist decisions Slips stored; deciding whether a detection should be generated belongs to the Slips detection and evidence pipeline. The module then consumes this file incrementally in bounded batches as a best-effort fallback for records that already expired:

```text
output/<run>/alerts/alerts.json
```

Web-only indexes and operational history are stored inside the module output directory:

```text
output/<run>/web_interface/history.sqlite
```

This database contains a compact bidirectional flow index, last-known host identity, parsed log events, runtime samples, rollups, and restart checkpoints. It references raw flows by UID and does not duplicate raw flow JSON.

The live flow index and one-second performance sample are incremental. A full
last-known host identity snapshot runs once per minute rather than on every UI
refresh. Redis detection recovery is a one-time compatibility import only when
the durable evidence table is empty; afterward, the append-only alerts file is
processed incrementally from its saved byte offset once per minute. The web
workers never rescan all retained profile/time-window keys on a timer.

The canonical error source is output/<run>/errors.log. For older runs, output/<run>/error.log is used only when errors.log does not exist. It is tailed from a saved byte offset and is never reread completely.

The web server's own log is:

```text
output/<run>/web_interface/server.log
```

For example:

```text
output/test7-malicious.pcap_2026-08-22_18:10:46/web_interface/server.log
```

All paths belong to this specific run. Nothing is written to a repository-level performance_metrics directory.

## Long-running behavior

Slips never deletes raw flows automatically. Overview shows the size of flows.sqlite, free space on the output disk, recent growth, and disk usage. Raw-flow history is limited only by available disk.

The browser never loads a complete run:

- General tables contain at most 100 rows per page.
- Host traffic supports 25, 50, 100, 250, 500, or 1000 rows per page.
- Previous and Next use stable server cursors ordered by the selected column and record ID.
- Search, threat, association, scope, time filters, and column sorting execute on the server.
- Refresh replaces visible rows and chart points; it never appends indefinitely.
- Charts receive server-side aggregates with no more than 1200 points.

Alerts, Evidence, Hosts, and host traffic support Live, 1 hour, 24 hours, 7 days, Full run, and Custom ranges. Custom and past ranges are frozen during investigation. Changing a filter resets pagination. Badges show full-run durable totals; each table separately reports its filtered total and current page size.

For offline files, named ranges use the newest timestamp in that data source as their endpoint. For example, Live evidence means the final hour of evidence currently processed from the capture, not the final hour on the computer's wall clock. This keeps offline evidence and host traffic visible while retaining normal wall-clock behavior for interface analyses.

Offline file and folder analyses initially open Alerts, Evidence, Hosts, and host traffic at **Full run**, so a short final capture interval cannot make a populated run look empty. Interface, standard-input, and CYST analyses initially open at **Live**. The user can change the range at any time. Capture-relative timestamps are displayed as elapsed values such as `T+07:53:06`, never as misleading dates in 1970.

Only the active tab refreshes every five seconds and only when its range includes the present. Polling pauses while the browser tab is hidden. Returning triggers an immediate refresh. Superseded requests are cancelled, and repeated failures back off exponentially to 60 seconds.

## Tabs

### Overview

Overview prioritizes Alerts, Hosts, Slips uptime, Evidence, processed flows, and firewall rules currently active, added, and discarded. Uptime is elapsed wall-clock time since this Slips run started and freezes at the recorded analysis end time for completed runs. Run version, branch, and commit stay visible in the header. Full run facts from `metadata/info.txt` are in **Metadata**, and parsed runtime messages are in **Logs**. Each module row includes state, PID, CPU, resident memory, flows per minute, evidence, and parsed log events. Modules start sorted by CPU usage and remain sortable by every displayed column. CPU and memory cells are heat mapped from the normal table background at 0% to red at 100%; memory is scaled to total host RAM while the displayed value remains MiB.

Overview also shows the run-wide estimated firewall impact: packets and flows
observed from blocked source IPs during recorded enforcement intervals, plus
evidence created for those IPs while blocked. Zeek captures ingress packets
from the interface before the iptables INPUT hook drops them, so an attempted
connection can be counted without reaching a local service.

The **Current host load** card describes the whole machine, not only the Slips process. **CPU** and **Memory** are the current host-wide utilization percentages. **Load 1 / 5 / 15m** is the operating system load average over the previous 1, 5, and 15 minutes: the average number of tasks that were runnable or waiting in uninterruptible I/O. It is not a percentage. Compare it with the host's logical CPU count; for example, a sustained load of 8 means roughly one task per logical CPU on an 8-CPU machine when the workload is CPU-bound, while it indicates queued work on a 4-CPU machine. The runtime charts below are different: their CPU and resident-memory series measure only the Slips process tree.

**Recent growth** is the short-term increase in this run's `flows.sqlite` file size, displayed as bytes per second. The collector compares the current file size with its preceding storage sample, normally about five seconds earlier, divides the positive size difference by elapsed wall-clock time, and reports zero when the file became smaller. It measures disk-file growth, not flows processed per second, packet throughput, or network bandwidth. SQLite WAL writes and checkpoints can make the value briefly show zero or jump, so use it as a recent disk-consumption estimate rather than an exact sustained rate. **flows.sqlite** is its current file size; **Output disk** reports utilization and remaining free space for the filesystem containing this run's output directory.

The **Current host load** card describes the whole machine, not only the Slips process. **CPU** and **Memory** are the current host-wide utilization percentages. **Load 1 / 5 / 15m** is the operating system load average over the previous 1, 5, and 15 minutes: the average number of tasks that were runnable or waiting in uninterruptible I/O. It is not a percentage. Compare it with the host's logical CPU count; for example, a sustained load of 8 means roughly one task per logical CPU on an 8-CPU machine when the workload is CPU-bound, while it indicates queued work on a 4-CPU machine. The runtime charts below are different: their CPU and resident-memory series measure only the Slips process tree.

**Recent growth** is the short-term increase in this run's `flows.sqlite` file size, displayed as bytes per second. The collector compares the current file size with its preceding storage sample, normally about five seconds earlier, divides the positive size difference by elapsed wall-clock time, and reports zero when the file became smaller. It measures disk-file growth, not flows processed per second, packet throughput, or network bandwidth. SQLite WAL writes and checkpoints can make the value briefly show zero or jump, so use it as a recent disk-consumption estimate rather than an exact sustained rate. **flows.sqlite** is its current file size; **Output disk** reports utilization and remaining free space for the filesystem containing this run's output directory.

The **Current host load** card describes the whole machine, not only the Slips process. **CPU** and **Memory** are the current host-wide utilization percentages. **Load 1 / 5 / 15m** is the operating system load average over the previous 1, 5, and 15 minutes: the average number of tasks that were runnable or waiting in uninterruptible I/O. It is not a percentage. Compare it with the host's logical CPU count; for example, a sustained load of 8 means roughly one task per logical CPU on an 8-CPU machine when the workload is CPU-bound, while it indicates queued work on a 4-CPU machine. The runtime charts below are different: their CPU and resident-memory series measure only the Slips process tree.

**Recent growth** is the short-term increase in this run's `flows.sqlite` file size, displayed as bytes per second. The collector compares the current file size with its preceding storage sample, normally about five seconds earlier, divides the positive size difference by elapsed wall-clock time, and reports zero when the file became smaller. It measures disk-file growth, not flows processed per second, packet throughput, or network bandwidth. SQLite WAL writes and checkpoints can make the value briefly show zero or jump, so use it as a recent disk-consumption estimate rather than an exact sustained rate. **flows.sqlite** is its current file size; **Output disk** reports utilization and remaining free space for the filesystem containing this run's output directory.

The **Current host load** card describes the whole machine, not only the Slips process. **CPU** and **Memory** are the current host-wide utilization percentages. **Load 1 / 5 / 15m** is the operating system load average over the previous 1, 5, and 15 minutes: the average number of tasks that were runnable or waiting in uninterruptible I/O. It is not a percentage. Compare it with the host's logical CPU count; for example, a sustained load of 8 means roughly one task per logical CPU on an 8-CPU machine when the workload is CPU-bound, while it indicates queued work on a 4-CPU machine. The runtime charts below are different: their CPU and resident-memory series measure only the Slips process tree.

**Recent growth** is the short-term increase in this run's `flows.sqlite` file size, displayed as bytes per second. The collector compares the current file size with its preceding storage sample, normally about five seconds earlier, divides the positive size difference by elapsed wall-clock time, and reports zero when the file became smaller. It measures disk-file growth, not flows processed per second, packet throughput, or network bandwidth. SQLite WAL writes and checkpoints can make the value briefly show zero or jump, so use it as a recent disk-consumption estimate rather than an exact sustained rate. **flows.sqlite** is its current file size; **Output disk** reports utilization and remaining free space for the filesystem containing this run's output directory.

Internal worker threads share Redis PID bookkeeping with processes but are not
shown as standalone modules. Their work and resource use belong to the parent
module row.

CPU, resident memory, and processed flows per second are sampled from the complete Slips process tree every second. CPU is a percentage of total host capacity. Exact samples are retained for 24 hours. Complete old minutes are transactionally compacted into permanent average, maximum, and flow-total rollups. Charts support 5 minutes, 15 minutes, 1 hour, 24 hours, and Full run.
Flow totals use exact profiler counter deltas rather than assuming every sample is exactly one second apart. Existing web history databases are upgraded in place when the module starts.

### Logs

The Logs tab shows the newest bounded runtime events parsed from the run's
`errors.log`. Select any row to open a console-style investigation panel with
the complete timestamp, module, presentation severity, full message, and the
untouched raw source line. Colors highlight severity, paths, and IP addresses
without rewriting the stored log. Keyboard users can open a selected row with
Enter.

### Firewall

The Firewall tab lists IPs currently confirmed in Slips' `slipsBlocking` firewall state. It distinguishes the current blocking window from the final **probation** window, shows the scheduled unblock time and remaining duration when available, and includes each IP's evidence and alert totals. A block whose deadline has passed but whose rules have not been removed is marked **overdue** instead of silently showing `0s` probation.

Each new iptables rule has a readable ownership comment containing the run,
the original block time, and the scheduled deletion time, for example
`Slips run=eno1_... blocked=2026-08-28T10:00:00Z delete=2026-08-28T11:00:00Z`.
When firewall blocking starts, Slips inspects existing managed rules before it
accepts new requests. It warns in the console, rebuilds the local active-block
and probation schedule from valid comments, resumes future deadlines, and
queues already-expired rules for removal. The Firewall tab's **Rule origin**
column identifies these recovered records. Older `Slips rule` comments and
malformed comments do not provide a trustworthy deletion deadline; Slips
keeps them, warns about them, and marks them **stale** in the web interface for
manual review rather than guessing when to remove them.

The tab includes the same run-wide estimated impact and cumulative per-IP
columns. A **stopped flow** is an indexed flow whose source IP was inside a
block interval when that flow began. **Stopped packets** sums originator packet
counts for those flows. **Evidence while blocked** counts durable evidence for
that profile IP whose creation time falls inside the interval. Block intervals
are reconstructed from the durable transition log and supplemented with the
current Redis block timestamps, so completed block/unblock/reblock periods
remain part of the run total. These are estimates of attempted traffic stopped
by enforcement, not firewall rule counters and not proof that every observed
packet was malicious.

The tab also shows a newest-first block/unblock history for the run. Its authoritative append-only source is `output/<run>/blocking/blocking.log`; Slips records the human timestamp, IP, direction when blocked, successful removal, and failed removal attempts. The unblocker retains zero-window requests until their rules are actually absent, retries partial failures, and restores persisted schedules after a blocker restart.

### ARP poisoning

The ARP poisoning tab separates local ARP isolation from iptables firewall
blocking. It shows whether `arp_poisoner` is running, every host poisoned or
released during the run, its target MAC, the current and release time windows,
the scheduled release time, remaining duration, and every schedule extension.
If a release deadline passes without a recorded release, the host is marked
**release due** instead of being shown as released.

Poison, extension, and release transitions come from the run's durable
`arp_poisoner/arp_poisoning.log`. The detection table comes from durable Slips
evidence produced by the `arp` module. Every displayed column is sortable;
search applies to isolation state, transition history, and ARP evidence.

### P2P

The P2P tab combines current Redis connectivity with the persistent local P2P trust database. It shows the local Pigeon identity and listen address, connected and previously known peers, peer trust and reliability, reliability evolution, peer reports received during the current run, and bounded recent send/receive activity. An enabled module with zero connected peers is shown as healthy and listening.

Message counters begin when telemetry-capable P2P code starts. Reliability history can span earlier runs because `permanent/p2p_trust_runtime/trustdb.db` is persistent; the reports table is filtered using this run's analysis start time.

Pigeon adds the running Slips version to every Go-to-Python message. The P2P module also accepts unversioned messages only on its dedicated local Pigeon channel so an older bundled binary cannot silently disconnect the data pipeline. Peer activation and deactivation updates maintain `connected_peers` and `peer_info` in Redis; the persistent trust database continues to hold reliability, peer-IP mappings, and reports. The local identity and listen address come from Pigeon's Redis `multiAddress`, with `p2p.log` used only as a fallback for older runs.

### Configuration

The Configuration tab reads the YAML snapshot copied to
`output/<run>/metadata/` when this run started. It does not display the file as
raw text. Every captured leaf setting is grouped by component and shown with a
readable name, its parsed value, its complete YAML path, and a short explanation
of what it controls. Sections can be expanded and searched by section, setting,
value, or explanation.

This is the configuration supplied to the run, not the current repository
file. A setting omitted from the snapshot can still use a built-in default in
Slips. Values whose names indicate API keys, passwords, private keys, secrets,
or tokens are shown as configured but are never returned to the browser.

### Whitelists

The Whitelists tab shows what the run actually parsed. Local IP, domain,
organization, and MAC rules come from the run's Redis whitelist hashes, with
the captured `metadata/*.conf` file as an offline fallback. Each row explains
whether the rule applies to a source, destination, or either side and whether
it suppresses flows, evidence/alerts, or both. The table is searchable and can
be filtered by rule type.

The source cards also show whether local and online whitelisting were enabled,
the captured local filename, the configured online benign-domain source and
limit, its refresh period, and the number of domains currently present in the
shared cache. The latter is explicitly current cache state because that cache
can be refreshed independently of an already completed run.

### Host score history

The host workspace plots the real detector score recorded after each evidence
is processed for the selected profile IP. Scores are never combined across
MAC-derived host aliases because Slips accumulators are IP-specific. Interface,
standard-input, and CYST runs plot RATL; finite input runs plot ATL. The chart
includes the configured alert threshold, the last score and peak score in each
bounded server-side interval, and detected drops.
A time-window change is labeled separately from a same-window drop after an
alert resets the accumulator. The host range selector also controls this
plot.

Evidence creation and evidence scoring are separate pipeline stages. The plot
therefore reports how many durable evidence records have a persisted score
sample. A host can have many evidence records and a current score of zero when
those records are still waiting for Evidence Handler processing, when an
alert reset the accumulator, when a new time window started, or when records
predate score persistence. Missing samples are reported explicitly and are
never replaced with scores calculated by the web interface.

### Alerts and evidence

Alerts come from durable SQLite. The default table shows individual alerts, bounded to 100 rows per page. Each row shows the exact Slips score at threshold crossing and the configured threshold. **Group by host** is an optional display mode that shows alert count, evidence-link count, latest alert time, highest threat, peak threshold-crossing score, and labels. Selecting a host aggregate shows its newest individual alerts; selecting an individual alert shows related evidence.

Evidence also includes records that did not cross the alert threshold. Individual rows show the exact accumulated score Slips recorded when the evidence was processed; grouped rows show the highest recorded score in the group. The default table is **Group by host and type**, bounded to 100 rows per page, and shows evidence, triggering-flow, alert-link, and whitelist-exclusion counts. **Individual evidence** remains available from the display selector. Selecting an aggregate shows its newest individual evidence. Selecting an individual record groups each triggering UID into one primary **flow** (the conn.log-style connection) and a separate **Related protocol flows** section containing alternative-flow records such as DNS, HTTP, TLS, SSH, DHCP, files, and notices.

The module column is provenance recorded by the Slips module that submitted the evidence, not a web-interface guess based on evidence type. New evidence stores this `source_module` in Redis, `flows.sqlite`, and the evidence `Note` in `alerts.json`. Runs created before this field existed retain the legacy type-based module label.

When Evidence Handler finds a whitelisted attacker or victim, the evidence is
retained for investigation but deliberately excluded from the host score and
from alert formation. These rows show **Whitelisted** under **Score handling**,
and their score cell shows **Excluded** instead of **Pending**. The evidence
drawer identifies the matching attacker or victim, value, direction, and local
rule whenever those details can be reconstructed. Grouped Evidence and the
host workspace show how many records were excluded. New runs persist this
decision with the evidence in `flows.sqlite`; older active runs use Slips'
existing `whitelisted_evidence` decision set while it remains available.

The displayed score is not calculated by the web interface. For interface,
standard-input, and CYST runs it is Slips' risk-adjusted accumulated threat
level (RATL), compared with `detection.risk_accumulated_threat_level`. For
finite file analyses it is Slips' accumulated threat level (ATL), compared
with `detection.evidence_detection_threshold × time-window minutes`. Values
are rendered as `score / threshold`, and the score columns are sortable.

Protocol activity is rendered as labeled fields instead of connection metrics. For example, DNS shows the queried name and type, response code such as `NXDOMAIN`, answers, and TTLs; HTTP shows method, host, URI, response status, user agent, body sizes, MIME types, and response file IDs; TLS shows server name, version, validation, cipher, and certificate fields. Other supported protocols have equivalent structured fields, with a readable generic field view for unknown types. Complete flow and protocol-flow records remain available in separately labeled JSON expanders. Alert to evidence to flow drill-down remains available after Redis time windows expire.

Alert and evidence drill-down uses structured cards instead of unformatted
record text. Drag the left edge of the investigation panel to resize it
horizontally; the browser remembers the selected width. Source and destination
IP addresses in triggering flows open the corresponding host workspace. The
expandable JSON sections are explicitly labeled as the complete alert,
evidence, or flow record.

Nested investigation panels keep an in-browser navigation history. **Back**
restores the previous panel with its loaded content and scroll position.
**Close** discards the complete panel history and returns to the underlying
table, so the next selection starts a new investigation.

### Hosts

The host list combines current Redis metadata with persisted last-known identity, so hosts that expired from Redis remain visible. Inventory can be filtered by local/public scope and by the host's maximum threat level. Its current Slips score column reads the active time-window accumulator directly from Redis and retains the last snapshot for completed runs. The separate **Past peak Slips score** column shows the maximum real score persisted after evidence processing for that exact profile IP over the full run. Both values show the configured threshold and are sortable server-side.

Selecting a host opens a full-width workspace with:

- MAC and vendor metadata, the exact profile IP, hostname, DNS, scope, and cached threat intelligence; the host and alert tables also show cached rDNS (or the most related DNS domain) and the TI feeds that contain the IP;
- total and inbound/outbound flow and byte counts, plus packet, evidence, and alert totals;
- inbound/outbound flow and byte plots;
- protocol/application distribution and top peers;
- compact related alerts and a full-width, sortable evidence table showing time, threat, type, module, confidence, triggering-flow count, alert links, and description; its search box matches every stored evidence field, including raw evidence attributes, triggering flow UIDs, and linked alert IDs;
- newest historical flows with cursor navigation into older traffic.

DNS resolution context is shown as structured fields: domains pointing to the selected IP, the hosts that requested those resolutions, the latest DNS observation and flow UID, and the relevant Slips time windows. Resolver addresses are clickable and open their host workspace.

Traffic, scores, alerts, and evidence match only the selected Slips profile IP. MAC metadata never expands a workspace into other addresses because an observed Ethernet address can belong to a router or next hop shared by unrelated remote IPv4 and IPv6 traffic. Rows show normalized direction, peer, addresses, ports, protocol/application, state, duration, packets, bytes, label, UID, and expandable raw details.

Native horizontal and vertical port-scan evidence links at most 20 contributing
non-established connection UIDs. The interface identifies this limit when a
scan is opened; other evidence types retain all of their triggering-flow links.
Selecting scan evidence therefore shows a bounded sample of attempted connections.

Native horizontal and vertical port-scan evidence records every contributing
non-established connection UID. Selecting scan evidence therefore shows the
actual attempted connections and any related protocol activity.

## Historical API

The page uses bounded local endpoints:

```text
GET /api/identity
GET /api/overview
GET /api/metrics?range=...&max_points=...
GET /api/alerts?...filters...&sort=...&order=...&cursor=...
GET /api/evidence?...filters...&sort=...&order=...&cursor=...
GET /api/hosts?...filters...&sort=...&order=...&cursor=...
GET /api/hosts/<ip>
GET /api/hosts/<ip>/evidence?sort=...&order=...&cursor=...
GET /api/hosts/<ip>/flows?limit=...&from=...&to=...&cursor=...
GET /api/hosts/<ip>/traffic-summary?from=...&to=...&max_points=...
GET /api/hosts/<ip>/score-history?range=...&from=...&to=...&max_points=...
GET /api/evidence/<uuid>/flows
```

Responses include bounded page metadata and selected ranges. Overview and identity include source freshness and indexing state. Request handlers use short-lived read-only SQLite connections so browser requests do not hold back WAL checkpoints.
