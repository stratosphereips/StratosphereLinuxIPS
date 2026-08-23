# Local web interface

The web_interface module is a read-only technical view of one local Slips run. It is designed for the person running Slips, not for receiving data from remote installations or combining concurrent runs. The HTTP server binds only to 127.0.0.1.

## Start it

Enable the interface with -w:

```bash
./slips.py -e 1 -f dataset/test7-malicious.pcap -w
```

The default URL is http://localhost:55000/. It can also be enabled in config/slips.yaml:

```yaml
web_interface:
  enabled: true
  port: 55000
```

The -w flag enables the module even when enabled is false. The bind address is deliberately not configurable.

Only one web-enabled Slips run is supported on a host. A new -w run replaces an older listener only after verifying that it is a Slips web server owned by the same user. It never terminates an unrelated program using the port. If another program owns the port, the module reports an error and stops.

A completed file analysis remains available at the same URL. A later web-enabled run replaces it. Every data request checks that Redis still advertises the output directory configured for that server. If Redis belongs to a different run, the API returns HTTP 409 and the page displays a persistent run-mismatch banner instead of mixing runs.

Do not enable this interface with -m or for several concurrent Slips instances.

## Storage and retention

The interface separates current state from durable history.

Redis database 0 on this run's assigned port contains current profiles, time windows, process IDs, and counters. Redis expiry is not treated as historical storage.

The run database keeps raw traffic and durable detection relationships:

```text
output/<run>/databases/flows.sqlite
```

It contains the existing unlimited flows and altflows rows, normalized evidence with its complete serialized record, evidence UUID to triggering flow UID relationships, and alert UUID to evidence UUID relationships. Evidence and alert relationships are written transactionally when Slips creates them, whether or not a browser is open.

When an older run is opened after this upgrade, the module first backfills evidence and correlations still in Redis. It then consumes this file incrementally in bounded batches as a best-effort fallback for records that already expired:

```text
output/<run>/alerts/alerts.json
```

Web-only indexes and operational history are stored inside the module output directory:

```text
output/<run>/web_interface/history.sqlite
```

This database contains a compact bidirectional flow index, last-known host identity, parsed log events, runtime samples, rollups, and restart checkpoints. It references raw flows by UID and does not duplicate raw flow JSON.

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

Overview shows run state, source freshness, disk use, Slips counters, and module health. It also displays the version, input path, branch, commit, command, start time, and Zeek version written to this run's `metadata/info.txt`. Each module row includes state, PID, CPU, resident memory, flows per minute, evidence, and parsed log events.

Internal worker threads share Redis PID bookkeeping with processes but are not
shown as standalone modules. Their work and resource use belong to the parent
module row.

CPU, resident memory, and processed flows per second are sampled from the complete Slips process tree every second. CPU is a percentage of total host capacity. Exact samples are retained for 24 hours. Complete old minutes are transactionally compacted into permanent average, maximum, and flow-total rollups. Charts support 5 minutes, 15 minutes, 1 hour, 24 hours, and Full run.
Flow totals use exact profiler counter deltas rather than assuming every sample is exactly one second apart. Existing web history databases are upgraded in place when the module starts.

### Alerts and evidence

Alerts come from durable SQLite. The default table shows individual alerts, bounded to 100 rows per page. **Group by host** is an optional display mode that shows alert count, evidence-link count, latest alert time, highest threat, and labels. Selecting a host aggregate shows its newest individual alerts; selecting an individual alert shows related evidence.

Evidence also includes records that did not cross the alert threshold. The default table shows individual evidence, bounded to 100 rows per page. **Group by host and type** is optional and shows evidence, triggering-flow, and alert-link counts. Selecting an aggregate shows its newest individual evidence. Selecting an individual record groups each triggering UID into one primary **flow** (the conn.log-style connection) and a separate **Related protocol flows** section containing alternative-flow records such as DNS, HTTP, TLS, SSH, DHCP, files, and notices.

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

The host list combines current Redis metadata with persisted last-known identity, so hosts that expired from Redis remain visible. Inventory can be filtered by local/public scope and by the host's maximum threat level.

Selecting a host opens a full-width workspace with:

- MAC, vendor, all associated IPv4 and IPv6 addresses, hostname, DNS, scope, and cached threat intelligence;
- total and inbound/outbound flow and byte counts, plus packet, evidence, and alert totals;
- inbound/outbound flow and byte plots;
- protocol/application distribution and top peers;
- durable related alerts and evidence;
- newest historical flows with cursor navigation into older traffic.

DNS resolution context is shown as structured fields: domains pointing to the selected IP, the hosts that requested those resolutions, the latest DNS observation and flow UID, and the relevant Slips time windows. Resolver addresses are clickable and open their host workspace.

Traffic matches any associated host address as source or destination. Rows show normalized direction, peer, addresses, ports, protocol/application, state, duration, packets, bytes, label, UID, and expandable raw details.

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
GET /api/hosts/<ip>/flows?limit=...&from=...&to=...&cursor=...
GET /api/hosts/<ip>/traffic-summary?from=...&to=...&max_points=...
GET /api/evidence/<uuid>/flows
```

Responses include bounded page metadata and selected ranges. Overview and identity include source freshness and indexing state. Request handlers use short-lived read-only SQLite connections so browser requests do not hold back WAL checkpoints.
