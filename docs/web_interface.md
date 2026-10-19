# Local web interface

The web_interface module is a technical view of one Slips run. It is designed for the person running Slips, not for receiving data from remote installations or combining concurrent runs. It binds to localhost by default.

Host addresses in the Overview, Alerts, Evidence, Firewall, ARP, and Hosts views,
including IPs mentioned in evidence descriptions, appear with their stored
hostname or cached DNS name. Addresses on the monitored
computer are labeled **This device** with the system hostname. The header also
shows **This device** and the hostname separately from the run name. When no name
has been learned, the interface says **Name unknown** beside the IP. Name lookup
uses bounded batches of addresses already visible in the current view.

The shared header refreshes its network name and current IP from the
five-second backend heartbeat, including while another tab is open. It does
not wait for Overview to load.

The browser tab title shows alert and host counts from the rolling one-hour
**Live** range. It checks for new counts every five seconds, including while
the tab is in the background, and refreshes immediately when the tab becomes
visible again. Browsers may delay background timers. It does not depend on the
selected tab, search, or date filter. The Alerts and Evidence navigation
badges show the records matching those tabs' selected range and filters after
each tab loads; the Hosts badge likewise shows the matching host count.
Overview keeps its run totals.

Use the **Light** or **Dark** button in the page header to switch between the
daylight and dark themes. The choice is saved in this browser and restored when
the page is reopened, including after a Slips restart. Dark remains the default
until a theme is selected.

For live interface capture, the header offers **Current network only** on every
tab. It limits alert and evidence lists, their grouped views, the Overview
counts, and the Hosts inventory to activity recorded since the current
continuous network connection began. Host traffic totals, flow pages, peers,
protocols, and score plots use the same boundary. Selected time ranges intersect
this connection period. The choice is saved in this browser. Turning it off
restores the selected time range across the full run.
When the monitored interface disconnects, the scoped lists are empty until a
network is connected. If the router MAC is unavailable, Slips uses the most
recent network-settings change as the conservative boundary. The switch is
hidden for file analyses and until the running web server advertises support.

**Device view** combines local IPv4 and IPv6 profiles that have the same
recorded unicast MAC address. It affects the Hosts inventory, grouped Alerts,
grouped Evidence, and the selected device's alert, evidence, and traffic
pages. Each device row lists its addresses. Public profiles and ambiguous MACs
shared by more than 16 profiles remain separate. Slips still scores each IP
profile independently; the device list shows the highest member score.

The browser also remembers pane filters, search terms, review filters, time
ranges, grouping, table sort and direction, optional host columns, and resized
pane widths after Slips restarts. These view choices stay in browser storage.
Restart a running Slips server after updating its Python code.

The input watcher observes only Zeek log files. It does not watch or remove
files in `config/`. A whitelist saved by the web interface is written to the
configured local whitelist file; its private recovery copy is kept beside it.
If the configured file is missing, Slips restores the copy before parsing and
fails startup when neither file exists. The recovery copy is local and ignored
by Git, just like a personal whitelist.

## Reviewing and cleaning up detections

Alerts open as **Active**. Mark one **In review** while investigating, or
**Resolved** with a required analyst note once checked. The Alerts tab shows
Active and In review alerts by default; its Review filter can show either
state, Resolved, or all alerts. Resolved alerts and their evidence remain in
the current run database after a Slips restart. Reopen a resolved alert by
setting it Active. The Overview and live alert counts exclude resolved alerts.
The Alerts view has visible **Group by host** and **All alerts** choices. The
second choice shows a pageable list of individual alerts. Search, severity, time, visibility, review, and
sorting filters apply in both views. Selecting an individual alert opens its
existing evidence and review details beside the list.

An alert also has a separate optional human verdict: True positive, False
positive, Expected behavior, or Inconclusive. Its workflow state and verdict
are saved independently, so an alert may stay In review while its linked flows
receive an analyst label in an export.

Evidence can be marked **Unreviewed**, **In review**, **True positive**,
**False positive**, **Expected behavior** (correct detection of authorized
activity), or **Inconclusive** (insufficient data), with an optional note.
The Evidence Review filter works
with grouped and individual views. These labels record analyst judgment; they
do not change Slips scoring, the detector, or the whitelist. Use the
Whitelist control separately to suppress future matches.
The Evidence view has a resizable table, a full-height record list, and a
third pane for the selected record. The third pane retains triggering flows,
the complete record, review, whitelist, JSON, and previous/next navigation.
Closing a record returns to the selected group and scroll position.

The review panel also offers permanent deletion. For an alert, choose alert
only, alert plus evidence, or alert plus evidence and linked flows. For one
evidence record, choose evidence only or evidence and linked flows. A deletion
reason and browser confirmation are required. Evidence still linked to another
alert is kept when deleting an alert. A flow still linked to other evidence is
kept. Deletion removes stored rows from the run's `flows.sqlite`; the small
`review_deletions` table retains the record ID, reason, time, and removal
counts. Deleted rows cannot be restored from the web interface. Free SQLite
pages are reused by later writes; runs using incremental vacuum can also
return those pages to disk. The analyst decisions are run scoped, so deleting
the entire output directory also removes them.
If Slips is already running when the web code is updated, its existing web
server process must be restarted by the operator before these controls are
enabled. The browser disables the new actions until the server advertises
support; refreshing the page alone does not reload Python code.

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
  require_password: true
```

The `-w` flag enables the module even when `enabled` is false. `bind` accepts:

- `localhost` — default; listens only on `127.0.0.1`.
- `interface` — listens only on the IPv4 address of the interface Slips is monitoring. Slips reports the resulting URL in the console. This mode fails closed if no monitored IPv4 interface is available.

### Login

The web interface requires a password before it shows any run data. By
default this is the same password slips generates for Redis (see
[installation.md](installation.md), section "Redis authentication") -
retrieve it with `cat permanent/redis_auth.conf`. Submitting it on the
login page issues a signed session cookie valid for one year. The browser
retains it when Slips or the browser closes. Sessions remain valid across
Slips runs using the same persistent web password record, and changing that
password invalidates existing sessions. After this upgrade, log in once to
replace the previous run-scoped cookie.

`require_password: false` disables this password. Only use it for local
testing/CI - never on a machine reachable beyond localhost, and especially
never combined with `bind: interface`.

`bind: interface` exposes run data, and the login password, to any host that
can reach that network interface over plain HTTP (no TLS).
Prefer `bind: localhost` plus an SSH port-forward (`ssh -L 55000:localhost:55000
<host>`) for remote access instead.

When interface binding is used and the interface changes IPv4 address,
the web listener restarts on the new address. The new URL appears in
slips.log. The browser must reconnect there.


Hover anywhere inside an Overview, P2P, or Host plot to see the nearest sample's
full local date and time and plotted values. Host score, flow, and byte charts
show each series available at that sample.

## Live network changes

When Slips monitors an interface, it checks that interface's current network
settings every five seconds on Linux and macOS. The Overview page shows the
current computer IP address, local subnet, router IP and MAC, DNS servers, connection
state, and time of the last change for each monitored interface. A change is
also written to `slips.log` with the old and new values.

Slips reads addresses and prefixes from the interface, its router from the
system route table, and DNS from `resolvectl` or NetworkManager on Linux and
`scutil --dns` on macOS. If neither link-specific source is available, Slips
uses the system resolver only when it monitors one interface. An unavailable
value is shown as Unknown; Slips does not reuse the previous network's value.
Alerts that require a known local subnet remain inactive until it is known.
The ten most recent settings for each interface are retained in the current
run so delayed flow records can be checked against the network active when
they were captured. Older records with no matching settings are not judged
against the wrong network.
Saved captures and log files do not use the analysis computer's current Wi-Fi
settings.
If a live run's saved network snapshot falls behind the monitored interface,
the Overview card reads the current interface settings directly. It labels
that result as a live reading and keeps the saved change time visible. The
saved history is updated by the Slips main process when it resumes.

The Current network card also lets you enter a name such as `Home Wi-Fi` or
`Office Ethernet`. Save an empty name to remove it. Names are stored in the
permanent host profile database and appear on both the network card and
matching permanent host profiles. The connected network's saved name also
appears in the top header above the computer's IP addresses and updates when
you save or change it. When the router MAC is known, the name
follows that network across Slips runs. If the router MAC is unavailable,
the card explains that its name is scoped to the current run so two unrelated
private networks are not combined. For a run with no earlier network changes,
the same name is also applied to host records observed before the router MAC
was learned.
Each permanent profile section in the Host workspace has a **Name network**
control for older run-scoped networks that cannot be matched safely to the
current router. Naming one of those sections updates all hosts recorded under
that same network identity.

## Permanent host profiles

Slips keeps identity clues in `host_profiles/hosts.sqlite` inside the configured
`parameters.permanent_dir` (by default `permanent/`). This database survives
individual output directories and Redis expiration. A separate `host_profile`
module reads completed flow rows in small batches and writes this database
asynchronously, including when the web interface is disabled. Host identity
can therefore appear shortly after its traffic, without delaying flow
analysis. The module limits its work rate and drains pending rows briefly
on shutdown.
The dedicated host profile directory is restricted to its owner because
requested URLs can contain private information.

The Host workspace shows up to 50 recently seen network profiles for its IP,
with first and last observation times. It records hostnames learned from DHCP
or profile updates, DNS answers, multicast DNS answers on port 5353, TLS SNI,
HTTP Host, requested HTTP URLs, reverse DNS, ASN, public-IP country, and threat feed
appearances. Each clue has its own first and last observation time and
occurrence count. The Host workspace groups clues by source; each group can
be expanded. Open groups stay open as live data refreshes. Private and
unknown geolocation labels are omitted from the country group, including
labels stored by older runs.

**Network observations** separates verified device identity from an IP address
mentioned in a capture. When the selected device has a MAC, the summary lists
networks with a matching local MAC binding and uses that binding's observation
dates. Reused-IP records with another MAC and records without identity proof
remain in the expanded address history with an explicit warning. Packet
endpoints establish that IP traffic was captured from a network; they do not
by themselves establish that a named device joined it.

DNS answers, including mDNS A/AAAA owner bindings, retain useful address/name
metadata without marking the advertised IP as a packet endpoint. Cached names
and IP information cannot create a named-network visit or advance a host's
traffic observation time. New cached private addresses without a recorded
network are kept under an unidentified run profile.

New endpoint observations are stored separately from legacy observations in
the permanent host database. Earlier versions also counted advertised DNS
addresses, so those older observation rows cannot establish network presence.
They remain available as unverified address history. Reading the page does
not rewrite saved annotations, names, or legacy records. The recording runs in
the existing bounded background host-profile worker.

Public IPs share one profile across runs. Private addresses are grouped by
the observed router MAC when the address belongs to the monitored subnet. If
Slips cannot identify the network, it keeps that address under the run's
output directory identity so unrelated networks do not merge. Local profiles
for the same IP appear as separate network sections in the Host workspace.
Each section heading is explicitly labeled **Network**; its saved network name
is separate from the host's **Custom name** field. The current network's profile
is shown first even if a recent run temporarily missed the router.
The database stores at most 200 distinct values per clue type per host and
network. Existing run history is not imported automatically; new observations
populate the database.

Only one web-enabled Slips run is supported on a host. A new -w run replaces an older listener only after verifying that it is a Slips web server owned by the same user. It never terminates an unrelated program using the port. If another program owns the port, the module reports an error and stops.

When a file or folder analysis finishes naturally, or after the first Ctrl-C stops a web-enabled live analysis, Slips asks `Slips analysis has stopped. Stop the web interface? [y/N]`. Answer `y` or `yes` to stop the page and finish shutdown. Answer `n`, `no`, or press Enter to keep the page and its Redis/SQLite data available; Slips then waits until the page is stopped or you press Ctrl-C. A later web-enabled run can replace a verified older listener.

After Ctrl-C, Slips reports its module shutdown grace period immediately. It
waits no more than 30 seconds for modules to finish, even when
`wait_for_modules_to_finish` is configured for a much longer natural analysis
completion. A second Ctrl-C forces immediate cleanup. If modules exceed the
grace period, Slips reports this and stops them before asking about the web
interface. The web-interface question is also recorded in `slips.log`, so the
log shows when shutdown is waiting for a console answer.

If blocking was enabled with `-p` and the `slipsBlocking` chain contains
Slips-managed rules at shutdown, Slips first asks
`Keep the installed firewall rules? [Y/n]`. Press Enter or answer
`y` to retain enforcement; answer `n` or `delete` to remove the complete Slips
chain and its local recovery records. Non-interactive and forced shutdowns
keep the rules because silently dropping enforcement would be unsafe.

A second Ctrl-C, SIGTERM, SIGHUP, SIGQUIT, daemon stop, core-module failure, and update shutdowns stop the web server with Slips without prompting. SIGKILL and SIGSTOP cannot be caught by any process, so no application can perform cleanup for those signals. In a non-interactive session where Slips cannot read a console answer, the web interface is stopped instead of leaving the command blocked indefinitely.

Every data request checks that Redis still advertises the output directory configured for that server. If Redis belongs to a different run, the API returns HTTP 409 and the page displays a persistent run-mismatch banner instead of mixing runs. Detection producers perform the same ownership check before publishing evidence, so a delayed process from a replaced run cannot write into the new run.

ARP scan evidence requires at least five requests from one source to five distinct destination IPs within 30 seconds. The bundled ARP Zeek script writes a unique synthetic UID into every `arp.log` request and reply. Slips preserves that UID through parsing, storage, and evidence linking; it also assigns a fallback UID when reading legacy or externally generated ARP logs without one. New ARP scan evidence can therefore display every retained contributing request. Older evidence explicitly reports that its linked records were collapsed and states the detector threshold instead of implying that one packet triggered the detection.

Do not enable this interface with -m or for several concurrent Slips instances.

## Storage and retention

The interface separates current state from durable history.

Redis database 0 on this run's assigned port contains current profiles, time windows, process IDs, and counters. Redis expiry is not treated as historical storage.

The run database keeps raw traffic and durable detection relationships:

```text
output/<run>/databases/flows.sqlite
```

It contains recent flows and altflows, normalized evidence with its complete serialized record, evidence UUID to triggering flow UID relationships, and alert UUID to evidence UUID relationships. Evidence and alert relationships are written transactionally when Slips creates them, whether or not a browser is open. During live-interface runs, background retention removes ordinary raw flows after 24 hours and evidence-linked raw flows after 30 days by default, and targets a 512 MiB logical database size. Under size pressure, it prunes raw flows without non-excluded evidence first, then linked raw flows ordered by their latest evidence time. New evidence protects its linked flows even when those flows started earlier. Detection records and their UID relationships remain available when a raw flow expires. Configure these limits in `flow_retention` in `config/slips.yaml`.

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

The canonical error source is output/<run>/errors.log. For older runs, output/<run>/error.log is used only when errors.log does not exist. New lines are tailed from a saved byte offset. On upgrade, the collector scans the current log once to attach traceback continuation lines to previously imported events.

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

For live interfaces, Slips checks SQLite flow retention once per minute in small batches outside the profiler's flow path. Imported captures are left intact. Under size pressure, evidence-linked flows remain protected for at least the configured ordinary-flow age after their newest linked evidence; the size target is allowed to be exceeded when durable evidence alone is larger than the target. Web host traffic and flow charts cover retained raw flows; the Alerts and Evidence tabs can still show older detection records after their linked raw flow expires. The evidence drawer first reads SQLite and then recovers missing linked flows from bounded current or saved Zeek JSON logs when available. The compact web flow index follows raw-flow deletion and reconciles missed deletions after a restart. Overview shows the size of flows.sqlite, free space on the output disk, recent growth, and disk usage. On older databases, deleted rows may not reduce the file's physical size until Slips is stopped and SQLite `VACUUM` is run; allow temporary free disk space for that operation.

Detector lookups by profile and time window use composite indexes on both raw
flow tables. This keeps DNS checks from scanning retained traffic while holding
the shared database lock. After roaming, current-network hosts appear as their
new packet observations reach processing; previous-network hosts remain in
historical views.

New run databases use incremental SQLite vacuuming so deleted raw pages can return to the filesystem. Existing databases reuse freed pages for future writes but do not shrink physically without a separate maintenance vacuum.

Continuous runs also apply `detection_history` in the configuration file. Active
evidence and alerts are kept for up to 90 days, targeting 2 GiB of live pages.
Under size pressure, records older than the protected 24-hour window move
sooner. Full detection records, reviews and relationships are committed to
monthly SQLite archives before removal from the active database. A saved
checkpoint makes interrupted transfers restartable. Raw flow JSON is governed
by `flow_retention` and is not duplicated in detection archives.

Archives live in `databases/archives/detections-YYYY-MM-NNNN.sqlite`, rotate
into segments targeting 256 MiB, and expire 30 days after their last write.
`detection_history.archive_retention_days` configures this one-month policy.
The default 4 GiB archive cap can expire older completed segments sooner.
Size limits are soft while recent records or unfinished transfers are protected.
Copying pauses when less than 1 GiB of disk space is free. Imported captures
are preserved. See [Usage](usage.md) for the complete configuration example.

Use the header's **Detection history** selector to open an archive explicitly.
Archive detection queries are read-only, use the selected file, and do not
filter by the current live network. Related evidence and retained raw flows
can be read from other retained databases. Expired details cannot be restored.
The Overview, live counters and operational panels continue to describe the
active run. Metadata reports maintenance progress and archive storage.

Compact evidence grouping uses exact hourly summaries plus raw rows at the
selected range's boundaries. Updates invalidate affected summaries, and queries
fall back to the time index while those summaries are rebuilt. Maintained
record counters avoid scanning the entire database for each page.

`slips.log`, `errors.log`, `alerts.log`, `alerts.json` and the web server log
rotate at `detection_history.log_max_size_mb` (64 MiB by default). Their rotated
files stay beside the active logs in `rotated/` for the archive retention age,
with at most `log_backup_count` backups each (30 by default). The collector
detects replaced log files by inode as well as size. Live web error events,
minute metrics and transient host snapshots expire after `active_days` in
bounded batches; one-second samples roll up after 24 hours.

The browser never loads a complete run:

- General tables contain at most 100 rows per page.
- Host traffic supports 25, 50, 100, 250, 500, or 1000 rows per page.
- Previous and Next use stable server cursors ordered by the selected column and record ID.
- Search, threat, association, scope, time filters, and column sorting execute on the server.
- Refresh replaces visible rows and chart points; it never appends indefinitely.
- Charts receive server-side aggregates with no more than 1200 points.

Alerts, Evidence, Hosts, and host traffic support Live, 1 hour, 24 hours, 7 days, Full run, and Custom ranges. Custom and past ranges are frozen during investigation. Changing a filter resets pagination. The Alerts and Evidence navigation badges count matching individual records, even when the table groups them by host or type. Each table separately reports its filtered group total and current page size.

For interface, standard-input, and CYST runs, named ranges use the computer's current time as their endpoint. This keeps old detections retained by `--keep-history` out of **Live** after they become more than an hour old. For offline files, named ranges use the newest timestamp in that data source as their endpoint; **Live** evidence means the final hour of evidence in the capture, not the final hour on the computer's wall clock.

Offline file and folder analyses initially open Alerts, Evidence, Hosts, and host traffic at **Full run**, so a short final capture interval cannot make a populated run look empty. Interface, standard-input, and CYST analyses initially open at **Live**. The user can change the range at any time. Capture-relative timestamps are displayed as elapsed values such as `T+07:53:06`, never as misleading dates in 1970.

Only the active tab refreshes every five seconds and only when its range includes the present. Polling pauses while the browser tab is hidden. Returning triggers an immediate refresh. Superseded requests are cancelled, and repeated failures back off exponentially to 60 seconds.

## Tabs

### Overview

Overview puts the run state, alerts grouped by host, system warnings, five key counts, current network, host load, and three Slips performance charts (CPU, resident memory, and flows per second) on one desktop screen. The alert card uses the Alerts tab's selected time range, review state, severity, and search; it reports matching alert and host counts and shows the first four host groups. Its Alerts count card follows the same selection. Each chart shows numeric Y-axis values with its unit, and hovering shows the sampled time and value. When no alerts exist, the status card shows the highest current host score. The four alert-host rows open their host workspace. Network **Rename** opens an inline name editor. **More run details** reveals firewall impact. The sortable Modules table is in Metadata; the **Modules** action in a high-CPU warning opens it there.

Uptime is elapsed wall-clock time since this Slips run started and freezes at the recorded analysis end time for completed runs. The header shows the run name, computer name, monitored interface, network name, version, state, and uptime. Its visible address line lists every current IPv4 and IPv6 address on the monitored interfaces, including IPv6 link-local, local, global, and temporary addresses. Long lists wrap without truncation. Addresses refresh with the lightweight network heartbeat on every tab, so changing networks or IPv6 addresses does not require visiting Overview. **Run details** opens Metadata for the full run facts, including branch and commit. Parsed runtime messages remain in **Logs**.

The first Overview response is deliberately lightweight even when `-p` retains a large Redis history. It reads the constant-time evidence counter and does not scan historical profile/time-window keys. Exact evidence attribution for each module is deferred behind **Load evidence counts** in Metadata; opening **Evidence** likewise loads the retained evidence records only when that tab is requested. Performance-history charts use their separate bounded endpoint.

Overview finds the four leading alert hosts by reading alert totals first and checking linked severity from highest to lowest until the visible rows are known. The grouped Alerts view calculates host totals once and looks up linked severity in indexed batches. Hosts uses the source and destination flow indexes for last-seen sorting and score indexes for past peak values. Existing run databases receive the score indexes when Slips next initializes their SQLite schema.
The ARP view reads its latest evidence in timestamp order from the evidence type index, so opening that tab does not sort every matching record.

The header uses a one-second heartbeat written by the Slips-owned history collector, not HTTP reachability to the retained web server. A clean backend shutdown marks disconnection immediately; an unexpected loss is detected after 15 seconds without a heartbeat. While disconnected, the indicator and last uptime are red, the status reads **Disconnected from backend**, and uptime remains frozen at the final heartbeat even though historical API pages remain available.

Overview also shows the run-wide estimated firewall impact: packets and flows
observed from blocked source IPs during recorded enforcement intervals, plus
evidence created for those IPs while blocked. Zeek captures ingress packets
from the interface before the iptables INPUT hook drops them, so an attempted
connection can be counted without reaching a local service.

The **Current host load** card describes the whole machine, not only the Slips process. **CPU** and **Memory** are the current host-wide utilization percentages. **Load 1 / 5 / 15m** is the operating system load average over the previous 1, 5, and 15 minutes: the average number of tasks that were runnable or waiting in uninterruptible I/O. It is not a percentage. Compare it with the host's logical CPU count; for example, a sustained load of 8 means roughly one task per logical CPU on an 8-CPU machine when the workload is CPU-bound, while it indicates queued work on a 4-CPU machine. The runtime charts below are different: their CPU and resident-memory series measure only the Slips process tree.

**Recent growth** is the short-term increase in this run's `flows.sqlite` file size, displayed as bytes per second. The collector compares the current file size with its preceding storage sample, normally about five seconds earlier, divides the positive size difference by elapsed wall-clock time, and reports zero when the file became smaller. It measures disk-file growth, not flows processed per second, packet throughput, or network bandwidth. SQLite WAL writes and checkpoints can make the value briefly show zero or jump, so use it as a recent disk-consumption estimate rather than an exact sustained rate. **flows.sqlite** is its current file size; **Output disk** reports utilization and remaining free space for the filesystem containing this run's output directory.

The **Current host load** card describes the whole machine, not only the Slips process. **CPU** and **Memory** are the current host-wide utilization percentages. **Load 1 / 5 / 15m** is the operating system load average over the previous 1, 5, and 15 minutes: the average number of tasks that were runnable or waiting in uninterruptible I/O. It is not a percentage. Compare it with the host's logical CPU count; for example, a sustained load of 8 means roughly one task per logical CPU on an 8-CPU machine when the workload is CPU-bound, while it indicates queued work on a 4-CPU machine. The runtime charts below are different: their CPU and resident-memory series measure only the Slips process tree.

**Recent growth** is the short-term increase in this run's `flows.sqlite` file size, displayed as bytes per second. The collector compares the current file size with its preceding storage sample, normally about five seconds earlier, divides the positive size difference by elapsed wall-clock time, and reports zero when the file became smaller. It measures disk-file growth, not flows processed per second, packet throughput, or network bandwidth. SQLite WAL writes and checkpoints can make the value briefly show zero or jump, so use it as a recent disk-consumption estimate rather than an exact sustained rate. **flows.sqlite** is its current file size; **Output disk** reports utilization and remaining free space for the filesystem containing this run's output directory.

Internal worker threads share Redis PID bookkeeping with processes but are not
shown as standalone modules. Their work and resource use belong to the parent
module row.

CPU, resident memory, and processed flows per second are sampled from the complete Slips process tree every second. CPU is a percentage of total host capacity. Exact samples are retained for 24 hours. Complete old minutes are transactionally compacted into permanent average, maximum, and flow-total rollups. Charts support 5 minutes, 15 minutes, 1 hour, 24 hours, and Full run.
Flow totals use exact profiler counter deltas rather than assuming every sample is exactly one second apart. Existing web history databases are upgraded in place when the module starts.

### Alerts

Alerts opens with an **Alerts grouped by host** pane and an empty selection pane. The first divider is resizable immediately. Choose a host to open its **Alerts for this host** timeline, then choose an alert to open its score, network, time window, linked evidence, whitelist control, and original record. Alert rows summarize all linked evidence types and their counts. Selecting an evidence card opens its investigation in a resizable fourth pane beside the alert. **All alerts** shows the individual alert list directly and opens alert and evidence details beside it. Dividers can be dragged or adjusted with the left and right arrow keys. Closing evidence returns to the same alert; closing an alert returns to its list.

Opening an alert fetches its full record by exact alert ID through the indexed
alert lookup. The general search remains available for finding alerts by host,
type, or description, but is not used to load one alert's linked evidence.

The third pane has **Back to alerts** and a close button. Both return to the
selected host's alert timeline at the same scroll position. If an alert is
opened from a full-width evidence record, its drawer offers **Back to
evidence**; the underlying evidence page and its scroll position remain open.
Following an evidence link from that alert and going back restores the alert
drawer and then the original evidence record.

Both alert lists have sort controls and a reverse-order button. Host sorting covers latest alert, address, severity, score, alert and evidence counts, and label. The selected host's alerts can be sorted by time, severity, score, label, evidence count, time window, and ID. These choices apply before cursor paging.

Search, severity chips, time range, and excluded-record visibility stay visible
in the host pane. Time choices include 5 minutes, 15 minutes, Live (the last
hour), longer intervals, Full run, and a custom interval. On the first visit,
if Live has no alert hosts but the run has saved alerts, the tab switches to
24 hours, 7 days, or Full run based on the newest alert time and says so.
Older servers without that timestamp switch to Full run. An empty
range also offers a **Show full run alerts** button. Once the user chooses a
range, Slips keeps that choice. Individual alerts load 50 at a time, with
**Load more** for older alerts. The middle pane includes a short description
from each alert's newest linked evidence without loading every full evidence
record. The selected host and alert stay open while the list refreshes.

Severity chips offer both exact levels and inclusive thresholds such as
**High+** (high and critical), **Low+** (low through critical), and **Info+**
(all levels). The filter applies to the host list and the selected host's
alert timeline before paging.

### Evidence

The Evidence tab keeps the group or record table on the left and a group summary and full-height record list beside it. Before selection, the record pane summarizes evidence types and the highest local host scores from the loaded page; type bars filter the table. Selecting a group opens its newest 50 records, with **Load more** for older records. P2P reputation reports are arranged by reporting peer. Selecting a record from the table or group list opens a resizable third pane with triggering flows, review and whitelist controls, Copy ID, and original JSON. The run header and tabs remain visible; closing the third pane returns to the same group and scroll position. Previous and next move through the loaded records. Evidence selected inside Alerts opens in the fourth Alerts pane; evidence opened from a host retains the full investigation view.

With a record open, the default widths are approximately **25% groups, 25%
records, and 50% details**. Both dividers support dragging and arrow keys.
The browser remembers these widths separately from the two-pane view, across
record changes and page reloads. Old automatically saved 5%/5% widths are
discarded. The inspector stacks its internal columns when space is limited.

**Type** grouping combines matching evidence across hosts. Its alert-link count
uses the selected time range and filters, and only the visible groups are
counted for each page. Recent ranges use the evidence time index so a large
history does not delay the current view. Full-run Type grouping uses a
type-ordered evidence index and counts alert links from two ordered indexes.

The evidence inspector initially loads **20 triggering flow UIDs**. **Load more triggering flows** loads the next page, including related protocol records; evidence with more than 1,000 UIDs remains fully accessible. The count distinguishes loaded, unavailable, and recovered flows. Connection and protocol tab contents are built when selected, and complete JSON is formatted only when expanded. Closing or switching records cancels the previous flow request. A durable record without flow IDs returns immediately instead of scanning Redis history. The browser also renders older unpaged API responses in batches of 20 until the server is restarted. This applies in the Evidence, Alerts, and Hosts workspaces, including Device + type groups.

The evidence page places the detection summary, threat, score, and confidence above the triggering flows. Each flow shows its endpoints and metrics, with tabs for the connection and every related protocol record. Additional stored values appear in a compact table, omitting fields already shown above; empty fields can be revealed and the complete original JSON stays available. The side column retains the evidence ID, timestamps, network, source module, attacker and victim, P2P reporting peers, alert links, and the evidence-specific whitelist editor. The editor offers quick values from the linked flows, including request URIs. Excluded evidence still explains its matching whitelist rule. Flow recovery and missing-flow explanations remain visible when raw records have expired or lack usable UIDs.

ARP protocol cards put **Destination IP** first in a highlighted field, followed
by **Source IP**, operation, and hardware addresses. Both IPs open the host
workspace. They remain visible when only the ARP protocol record was retained;
they are not repeated in the additional-fields table.

The top controls switch between host-and-type, type, host, and individual records. Search, threat, score, alert-link, time-range, and excluded-record filters use the server's bounded queries. The compact group response avoids concatenating evidence IDs and counting linked flows that are not shown in the group table; it retains the persisted exclusion and alert-link counts needed there. The right panel never loads every record in a large group at once.

Evidence and Hosts also offer exact severity levels and inclusive **High+**,
**Medium+**, **Low+**, **Info+**, and **Critical+** filters. Host thresholds
use each host's highest threat level; evidence thresholds include qualifying
records before grouping and pagination.

The range controls initially use **Live** so opening a tab while Overview is still loading cannot accidentally start a full-run query. Once the input source is known, offline captures switch to **Full run** and refresh the active tab. Polling begins after each tab request completes so a slower first response is not canceled and restarted by the refresh timer.

### Metadata

Metadata keeps the run version, branch, and commit beside the monitored device's interface and IPv4/IPv6 addresses. Other captured run fields are available under **More run facts**. The Modules table now lives below these cards and refreshes while this tab is open. It can be sorted and filtered by module name. CPU appears as a percentage and bar, while memory shows MiB with host-memory percentage on hover. **Load evidence counts** adds the Evidence column on demand; it avoids scanning retained evidence during the initial page load. The table scrolls inside the tab without moving the shared header.

### Logs

The Logs tab shows a bounded page of runtime events parsed from the run's
`errors.log`. Select any row to open a console-style investigation panel with
the complete timestamp, module, presentation severity, and raw multiline source
block. Traceback rows also show the final exception when one is available.
Colors highlight severity, paths, and IP addresses
without rewriting the stored log. Keyboard users can open a selected row with
Enter.
Click any table heading to sort all retained events by time, displayed level,
module, or message before the bounded page is selected.

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
Every Firewall table heading sorts the corresponding active blocks or history events before the history page is selected.

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

The P2P tab combines current Redis connectivity with the persistent local P2P trust database. Its compact header shows the local Pigeon identity and listen address, with copy controls. Summary cards show connected and known peers, report and request counts, and average reliability. The peers table retains each peer's ID, IP, connection state, trust, reliability, report count, and last seen time. The adjacent **Peer reliability history** chart plots the same metric as the table's **Reliability** column, with three decimal places on its numeric axis and hover values. It keeps Live, 1-hour, 24-hour, 7-day, and full-history ranges. Full history starts at the peer's first recorded detection and samples the whole reliability timeline, keeping each peer's first and latest measured reliability; no reliability value is invented before the first measurement or for a missing measurement. Selecting a peer filters the message table; selecting it again or clearing the filter restores all peers.
Every peers-table heading is sortable, including connectivity, trust, reliability, report count, and last seen time.

Peer IDs appear shortened in tables, message details, and chart labels; hover
shows the full ID and the copy controls retain it. The IP column prefers an
authenticated TCP endpoint or the newest usable peer IP. Loopback updates
from Pigeon do not replace a known remote address. The table calculates Trust
from the latest stored reliability and local reputation; a dash means those
inputs are unavailable. Reliability is Pigeon's connectivity measure, ranging
from 0 to 1. Trust also includes the local assessment of the peer, so these
columns need not have the same value. With no local assessment (confidence
zero), the current formula gives `Trust = 0.7 × Reliability / 2`: reliability
`1.000` therefore gives trust `0.350`. The chart shows reliability history,
not calculated trust history.

The reports and message activity table combines bounded send/receive telemetry with retained reports from the current run. Filter chips show all messages, reports, requests, or connection changes. The Show menu also keeps received reports, sent reports, and blame reports available. Every column is sortable; Load more exposes the remaining retained rows. Selecting a row opens its content beside the table, including Copy JSON. When only the trust database record survives, the detail view shows its stored report fields and identifies the missing original message. An enabled module with zero connected peers is shown as healthy and listening.

Message counters begin when telemetry-capable P2P code starts. Reliability history can span earlier runs because `permanent/p2p_trust_runtime/trustdb.db` is persistent; both the received-report total and each peer's received-report count include only reports from this run. Previously known peers remain visible as offline until a live authenticated connection is reported.

Pigeon adds the running Slips version to every Go-to-Python message. The P2P module also accepts unversioned messages only on its dedicated local Pigeon channel so an older bundled binary cannot silently disconnect the data pipeline. Authenticated libp2p TCP 5-tuples are stored in Redis as individually expiring records and removed from live state on disconnect. The web tab derives connected/offline status from those same live records, while `peer_info` and the persistent trust database retain historical identity, reliability, peer-IP mappings, and reports. The local identity and listen address come from Pigeon's Redis `multiAddress`, with `p2p.log` used only as a fallback for older runs.

### Configuration

The Configuration tab reads the YAML snapshot copied to
`output/<run>/metadata/` when this run started. It shows six quick facts, a
section navigator, and a compact table with the setting name, captured value,
complete YAML path, explanation, and shipped default where available. Search
matches names, keys, values, and explanations across sections. The All,
Changed, and Secrets filters narrow the section navigator and table. Changed
compares the captured value with the current `config/slips.yaml` file, so the
comparison can change after an update even though the captured value does not.
View YAML opens the captured structure with secret values redacted.
Each configuration table heading sorts the settings in its selected section. Secret values remain redacted during sorting.

This is the configuration supplied to the run, not the current repository
file. A setting omitted from the snapshot can still use a built-in default in
Slips. Values whose names indicate API keys, passwords, private keys, secrets,
authentication tokens, or credentials are shown as configured but are never returned to the
browser.

### Whitelists

The Whitelists tab shows what the run actually parsed. Local IP, request URI,
domain, organization, and MAC rules come from the run's Redis whitelist hashes, with
the captured `metadata/*.conf` file as an offline fallback. Each row explains
whether the rule applies to a source, destination, or either side and whether
it suppresses flows, evidence/alerts, or both. The table is searchable and can
be filtered by rule type.

The source cards also show whether local and online whitelisting were enabled,
the captured local filename, the configured online benign-domain source and
limit, its refresh period, and the number of domains currently present in the
shared cache. The latter is explicitly current cache state because that cache
can be refreshed independently of an already completed run.

While Slips is running, use **Add a whitelist rule** in the Whitelists tab,
or **Whitelist future matches from this evidence** in an individual evidence
drawer. The evidence editor suggests source and destination IPs, exact
IP:port pairs, and `*:port` rules from the evidence and linked flows. A
port-only rule applies to that port on any IP, so choose its source or
destination side carefully. Rules can suppress future evidence and alerts
(the default), flows, or both. Existing evidence and alerts remain in the
record. New IP rules become active in running workers within a few seconds.
Web-added rules appear in the Whitelists table with a **Remove** action.
Choose an **Evidence type** to limit an IP rule to one detection, for example
`192.168.1.10` as source of `ARP_SCAN` evidence. These scoped rules suppress
only that evidence type; they do not hide its flows or other detections.

Choose **Request URI** to suppress an exact URI independently of IP
and port. URI rules drop matching future HTTP records before detection. For
AirPlay discovery, enter `/info?txtAirPlay&txtRAOP RTSP/1.`; Zeek records
this RTSP request in `http.log` as an HTTP/0.9 URI and tags the related
`conn.log` record as `airplay-info`. Slips drops that tagged connection only
when the exact AirPlay URI rule is enabled, preventing connection detectors
from reporting the same request. The rule is saved as
`uri,/info?txtAirPlay&txtRAOP RTSP/1.,both,flows` in the configured whitelist
file. Other traffic to the same host or port remains visible. URI suppression
requires Slips to launch Zeek with its bundled scripts; imported logs cannot
gain the connection tag retroactively.

Zeek `notice.log` records may omit a connection UID. Slips assigns such a
notice a synthetic UID before storing it, so evidence from the notice can
open the notice record. An aggregate notice about many SSH connections still
cannot identify those individual sessions unless Zeek supplies their UIDs.
Raw flow retention protects unlinked flows for at least
`size_min_age_minutes` (60 minutes by default) under size pressure, then
prunes them before evidence-linked flows. Linked flows stay protected for
`ordinary_hours` after their latest evidence. The size target is soft while
these protected flows remain. Existing evidence with an empty UID cannot be
relinked to a specific flow from the notice alone.

The web interface writes these rules into the configured local whitelist file,
between marked comments, so they survive Slips restarts and are visible in the
same file as manually entered rules. On the next edit, any rules from an older
`.web.conf` sidecar are moved into that marked section.
Slips also keeps a private `.bak` copy beside the configured file. If the
configured file disappears, startup or the running process restores that copy
before loading or saving rules.
If neither file exists, startup stops instead of silently running without the
local whitelist. Ordinary `#` comments, including comma-separated explanatory
text, are ignored safely; commented valid rules retain their existing removal
semantics. Startup also stops if the file has lost web-managed rules
that are still in the backup, without overwriting either copy. Web edits
recover from the same copy and never create a new
partial whitelist in place of a missing configured file. Keep an additional
copy of any personal whitelist outside the repository before replacing a
checkout. Existing evidence and alerts are historical records;
new matching evidence is excluded from scoring
and alerts and is hidden by the default **Hide excluded** setting. Saving
changes requires enabled local whitelisting and an active
Slips run. Remote browser connections must use the password-protected web
interface; an unprotected web interface accepts these changes only locally.
The optional fifth column in a local IP whitelist line is the canonical
evidence type, for example `ip,192.168.1.10,src,alerts,ARP_SCAN`.

Evidence threat chips support exact levels and inclusive `High+`, `Medium+`,
and `Low+` filters. The inclusive filters include all more severe levels.

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

Alerts come from durable SQLite. The default view groups alerts by host. **All alerts** shows individual alerts, bounded to 100 rows per page. Each row shows the exact Slips score at threshold crossing and the configured threshold. Grouping by host shows alert count, evidence-link count, latest alert time, highest threat, peak threshold-crossing score, and labels. Selecting a host aggregate shows its newest individual alerts; selecting an individual alert shows related evidence and the counts of every linked detection type.

Alert and Evidence rows show the saved network name where the detection occurred. For live interface capture, the web interface uses the monitored interface's recorded network state at the detection time, including recent network changes. This identifies local detections between host sightings and IPv6 link-local traffic on the captured interface. For older detections, it matches the host and timestamp against permanent host-profile observations, so an address reused on separate networks is attributed to the right network. Detections without a matching network record are labeled **Unknown network (not recorded)**; grouped records that span known network changes show **Multiple networks**.

Evidence also includes records that did not cross the alert threshold. Individual rows show the exact accumulated score Slips recorded when the evidence was processed; grouped rows show the highest recorded score in the group. The default table is **Group by host and type**, bounded to 100 rows per page, and shows evidence, triggering-flow, alert-link, and whitelist-exclusion counts. **Individual evidence** remains available from the display selector. Selecting an aggregate shows its newest individual evidence. Selecting an individual record groups each triggering UID into one primary **flow** (the conn.log-style connection) and a separate **Related protocol flows** section containing alternative-flow records such as DNS, HTTP, TLS, SSH, DHCP, files, and notices. Each available connection and protocol flow shows when it was observed, using the browser's local time for wall-clock timestamps.

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
When sorting the Evidence table by Slips score, excluded rows stay together
after numeric scores in both ascending and descending order, including across
pages. A host/type group with any excluded evidence follows the same rule
because its score cell displays **Excluded**.

The **Hide excluded / Show excluded** selector defaults to **Hide excluded**
and is shared by Alerts, Evidence, the Host workspace, and ARP detections.
New evidence-type rules take effect as soon as they reach Redis, even while a
worker's local IP filter refresh is pending. Existing detections and alerts
remain in the run history. The Alerts tab stays on the selected time range;
when Live has no alerts, use **Show full run alerts** to inspect older ones.
Each Slips run also loads its configured local whitelist into its own Redis
database at startup, even when another run is updating the shared organization
files.
Slips commits each new evidence row to `flows.sqlite` before notifying Evidence
Handler. This ordering lets the handler persist its whitelist decision even
when it processes the notification immediately. Older runs affected by the
previous publish-before-insert race may contain a small number of incorrectly
unexcluded records beside correctly excluded records for the same rule; those
stored decisions require repair separately and are not changed by upgrading
the code alone.
Hiding excluded records filters evidence before
grouping and pagination; a host/type group still appears when it also contains
scored evidence. In the Host workspace, historical traffic linked only to
excluded evidence is hidden as well. Flows linked to scored evidence and flows
with no evidence remain visible. Alerts are already formed only from scored
evidence, so their list is unchanged. Opening an Evidence group keeps the same
filter. The selector changes displayed lists;
stored records and run totals remain available when **Show excluded** is
selected. Flows discarded by the profiler's flow whitelist were never stored
and cannot appear in either view.

New `MALICIOUS_IP_FROM_P2P_NETWORK` evidence names every peer ID that reported
the address in its description. When the trust database has no reporter ID,
the description explicitly says that the reporting peer is unavailable. The
Evidence and Host tables also show **Reporting peers** for both new and older
P2P evidence, using reporter IDs retained in the permanent P2P trust database.
For older evidence, this column identifies peers that reported the same IP;
the original evidence did not record which subset contributed to its score.
Older `P2P_REPORT` descriptions are clarified when served by the web API: the
peer is identified as the sender, the host IP as the subject of its reputation
report, and the absence of victim or attack details is made explicit. Stored
evidence is not rewritten.

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

The Hosts tab opens as a compact inventory sized to the available browser height. It shows every host in the first server page, then loads more pages automatically as you scroll until every host matching the selected time range and filters is visible. **Load more** is also available in the footer. The footer shows how many of the matching hosts have loaded. Sorting stays on the server. Threat and scope chips, search, and **Only with alerts** filter the inventory; the alerts-only filter is applied before server paging. **Columns** reveals hostname, TI feeds, and current score when needed. The table combines MAC with vendor and threat with the past peak score, including a marker for the alert threshold. **Export CSV** exports the loaded rows.
All inventory headings, including the optional TI feeds column, sort the matching hosts before paging. TI feed sorting reads cached feed names only when that column is selected.
The first refreshed page is displayed immediately; revalidating additional
previously loaded pages does not delay it. Finding counts, peak scores, and
threats are aggregated together before sorting. Full-history aggregates use
the existing covering evidence index; bounded ranges use the profile/time
index. These reads add no indexes or work to packet processing.
When already scrolled into a larger inventory, a routine refresh keeps the
rendered rows in place until its loaded pages are ready, preserving the scroll
position. A filter or network change still replaces stale rows.

With **Current network only**, inventory membership and Last seen use actual
flow, detection, or discovery observations. Refreshing cached metadata or
learning a hostname cannot make an old host current. New packet observations
are kept separately in `permanent/host_profiles/hosts.sqlite`; older runs can
still establish activity through retained flows and detections. Refreshing the
inventory replaces every loaded page, so an old row beyond the first page does
not survive a filter or network change. Device view includes only addresses
observed during the selected connection.
For a live interface capture, the operating system verifies which current
IPv4 and IPv6 addresses belong to the monitored interface's MAC. Those
addresses form one Device even after roaming or address rotation leaves more
than 16 historical addresses for its MAC. This includes the interface's own
global IPv6 addresses. A shared next-hop MAC alone does not merge remote hosts.
This verification is confined to web requests and is not used to reassign
historical names or group an ended capture with the computer's current IPs.

The current network identifies where Slips captured the traffic. An endpoint
outside the local subnet can still appear when traffic involving it was
observed from this network; this does not assert that the endpoint belongs to
the local subnet. The Host workspace names the capture network explicitly.
Older network identities remain available under **History · saved identity
clues from all networks**, without supplying the current network summary. A
previously selected host with no observations on the current connection shows
an explanation and empty scoped activity.

Selecting a host opens a three-column workspace. The left column holds identity and permanent network names, the center places the score plot above **Alerts**, **Evidence**, and **Flows** tabs, and the right column holds peers and protocols. The traffic plots sit below the activity tabs. A host with alerts opens on Alerts; otherwise it opens on Evidence when evidence exists, or Flows when neither exists. Alerts and Evidence are filtered to the selected profile IP, use the selected time range, and retain investigation links and cursor paging. Each column scrolls internally so the shared navigation stays visible. **Whitelist** opens a rule editor beside the host, with its IP filled in and **Both sides** selected. Suppression and evidence type remain editable. In Device view, a checkbox can save one rule for each known address; addresses learned later need their own rules. Rules use the existing persistence mechanism and the run's configured whitelist file, including a custom personal whitelist path.

The host activity tabs provide **Group by** and **Threat** controls. Alerts can be grouped by linked evidence type, threat, module, or review state. Evidence can be grouped by type, threat, module, or score handling. Flows can be grouped by protocol, direction, peer, label, state, or linked evidence threat. Group headings and counts describe the loaded page; pagination remains available for the rest of the selected range. Threat filters, including **High+**, **Low+**, and **Info+**, apply to all records in the selected range before paging. For flows, threat means the highest threat of evidence linked to that flow; an unlinked flow has no linked threat and does not match a threat filter. The flow table displays this linked threat. Evidence search matches its displayed type, module, threat, confidence, handling, flow and alert counts, description, and reporting information, including type names entered with spaces instead of underscores.

Opening a host or device from the inventory copies its selected time range,
including custom start and end times, into the detail workspace. The Alerts
and Evidence summary cards, peak score, highest evidence threat, score plot,
and activity tables use that range and the current-network selection.
**Hide excluded** also excludes whitelisted evidence from the peak, threat,
and evidence count. Select **Full run** to inspect earlier findings. The
header separates the current active time-window score from the peak in the
selected range. In Device view, the host header shows every associated IPv4
and IPv6 address in full. It uses the available width and wraps addresses,
identity details, and controls onto additional lines when needed. The address
list updates when the host refreshes, including newly learned IPv6 addresses.

Saved activity search, threat filters, grouping, and sorting remain available
when opening another host. An explicit notice shows active search and threat
filters, the matching count, and the number of records in the selected range.
**Clear activity filters** clears that activity tab's search and threat filter
while retaining grouping and sorting. A medium-threat evidence record can
exist without an alert: an alert requires the accumulated Slips score to
reach its configured threshold.

The host list combines current Redis metadata with persisted last-known identity, so hosts that expired from Redis remain visible when their observations match the selected scope. It shows the MAC vendor beside the MAC address when Slips has identified one; vendor names can be searched. Inventory can be filtered by local/public scope and by the highest evidence threat in its selected time range and network scope. The displayed threat and the threat filter use the same evidence records. **No evidence** is a status for hosts without findings in that scope, not an additional Slips threat level; these hosts appear under All but do not match Info+, Low+, or any other threat filter. Informational evidence is Info, not a benign verdict. The compact threat column shows the highest real score persisted after evidence processing for that exact profile IP in the selected scope. The score bar marks the configured alert threshold, while hovering shows the current active time-window score from Redis. The optional current-score column can be enabled from **Columns**. Both scores are sortable server-side.

An IP mentioned in Evidence can be a destination without its own Slips
profile. Selecting such an IP shows an explanation in the Host workspace;
when the captured configuration uses `analysis_direction: out`, it explains
that Slips profiled only the source of the flow. It does not create a host
profile for an address Slips ignored.

The selected host workspace includes:

- **Review**, **Labels**, **Name**, and **Note** in the Identity card. **Mark or name this host** / **Edit host review and identity** opens the editor for the current permanent profile. Review marks are Unmarked, To analyze, Under review, and Reviewed; up to ten custom labels and an analyst note can be saved. The inventory has sortable Review and Labels columns, a review-mark filter, and search across labels, saved names and notes before paging. These fields are included in its CSV export. Review marks, labels, name and note are saved together in one transaction. Review marks and labels persist across restarts in the permanent host database and follow a verified device MAC; a reused private IP on another network does not inherit another device's mark. Marking a host does not relabel its flows or whitelist its traffic. Editors for older network profiles remain in **Networks and names**. A saved custom name and note remain in `permanent/host_profiles/hosts.sqlite` across Slips runs. When a MAC is known, names and notes are assigned to that MAC across its observed IPv4, IPv6, and network changes. The editor displays the MAC. Reusing the original IP with a different MAC does not transfer the name; a matching mDNS hostname cannot override a different known MAC. When both MACs are unknown, a device mDNS hostname such as `cherry.local` can carry the saved name and note only when address-record owners establish that hostname for both addresses. A DNS question and flat answer list do not establish that relationship. Service discovery names and random UUID names are not used as device identities. Clearing both fields clears the linked device name. Hosts without a usable MAC or device hostname retain names only on their exact network profile;
- the displayed name beside the IP and in the Name row. This may be a saved user name, or a name learned from DNS or another source. A user name always takes priority;
- MAC and vendor metadata, the exact profile IP, hostname, DNS, scope, and cached threat intelligence. Empty Redis fields do not replace saved identity clues. For this computer during a live interface capture, the detail pane reads its MAC from the operating system's monitored interface, and new permanent observations save that MAC for the computer's IPv4 and IPv6 addresses; the host and alert tables also show cached rDNS (or the most related DNS domain) and the TI feeds that contain the IP;
- total and inbound/outbound flow and byte counts, plus packet, evidence, and alert totals;
- inbound/outbound flow and byte plots;
- protocol/application distribution and top peers;
- compact related alerts and a full-width, sortable evidence table showing time, threat, type, module, confidence, triggering-flow count, alert links, and description; its search box matches every stored evidence field, including raw evidence attributes, triggering flow UIDs, and linked alert IDs;
- newest historical flows with cursor navigation into older traffic.

Every related-evidence and flow-table heading is sortable across the selected host and time range. The flow sort uses indexed fields where available and reads stored protocol details when sorting ports, connection state, or duration. The Whitelists table also sorts by every displayed column, including whether a rule can be removed.

IP labels throughout the web interface use the saved user name first, then a
learned hostname, DNS or reverse DNS name, and finally the MAC vendor followed
by “device” when no name is available. The IP stays visible beside the label.

The background host-profile module learns MAC ownership from DHCP, explicit
ARP sender/target hardware fields, and Ethernet endpoints on the captured
local link. A zero ARP target hardware address or broadcast Ethernet address
does not identify the target device. Routed endpoints do not inherit the
gateway's MAC. The monitored computer's operating-system MAC takes precedence
over conflicting capture metadata. Repeated identical MAC observations are
written at most once per minute per network/IP; changes are recorded immediately.
The in-process MAC cache is capped at 4,096 entries. These writes stay in the
background module, outside the main analysis loop.

### MAC address administration

Every structured MAC display uses a small colored **L** (locally administered)
or **U** (universally administered) marker beside the address. Hover over the
marker or address for the full explanation. The inventory gives the vendor
name priority, followed by the MAC and marker. This also applies to host
headers, Identity cards, saved MAC clues, router addresses, whitelist rules,
ARP poisoning tables, and MAC fields in flow details. The host/device APIs
include `mac_address_type`, and the Hosts CSV includes the same field. Search
the inventory for **locally administered** or **universally administered**.
These values are derived from existing MACs, including retained snapshots;
no database migration or external lookup is needed.

IEEE defines the second least significant bit of the first octet as the
Universal/Local (U/L) bit. For `A2:D7:7B:FA:6A:55`, `A2` is binary
`10100010`: `0xA2 & 0x02 = 0x02`, so the address is **Locally administered**.
The least significant bit, I/G, is zero, so it is an individual/unicast
address. Unicast first octets ending in hexadecimal `2`, `6`, `A`, or `E`
have the local bit set.

Local administration can mean a private/randomized Wi-Fi address, a manual
assignment, or a virtual interface. **The bits cannot prove randomization.**
The web explanation makes that limit explicit. With U/L zero, the label is
**Universally administered**; this describes the address format and does not
prove that the address is authentic or unchanged. Group addresses have **B**
(broadcast) or **M** (multicast) markers; all-zero addresses use **0** and invalid
addresses use **?**. Their explanations are also available on hover.

IP Info skips manufacturer-prefix lookup for locally administered and group
addresses; their prefixes do not establish an IEEE hardware manufacturer.
Classification does not change detection scores, whitelists, saved names,
or grouping by an exact observed device MAC. It adds no database writes or
network calls to the main analysis loop.

References: [IEEE EUI/OUI/CID guidelines](https://standards-support.ieee.org/hc/en-us/articles/4888705676564-Guidelines-for-Use-of-Extended-Unique-Identifier-EUI-Organizationally-Unique-Identifier-OUI-and-Company-ID-CID)
and [RFC 9797, Section 2](https://www.rfc-editor.org/rfc/rfc9797.html#section-2).

New live captures load `zeek-scripts/mdns-identity.zeek`, which retains each
mDNS A/AAAA record's owner and address in `slips_mdns_bindings`. Slips uses
these bindings for mDNS identity, independently of the DNS question and the
packet's source. Queries containing known answers and records with zero TTL
cannot establish a binding. Each DNS log record retains at most 64 bindings.
The host profile module stores them as `mdns_hostname` facts; old `mdns_name`
facts remain visible in saved history as question associations with unverified
ownership, and cannot transfer an analyst's name or note to another device.
Explicit names and notes already saved for an exact network profile or MAC
remain intact. With **Current network only**, labels use that network's
annotations; a newer metadata refresh from another network cannot hide the
saved name or lend it to a reused address. Older imported logs without
record-owner fields still support
these explicit names and MAC identities; mDNS name transfer waits for an
owner record on the originally named profile and the new address. The browser
accepts corrected or cleared names from the server instead of keeping an old
cached user name indefinitely.

Identity storage stays in the separate `host_profile` process, using its
existing bounded batches and caches. Replaying retained flow rows selects
network settings at the packet timestamp; if that history is unavailable,
the identity stays on an unidentified run profile instead of being assigned
to today's network. No per-flow identity database access is added to the main
Slips process or profiler. Restart Slips to load the updated Zeek policy.

DNS resolution context is shown as structured fields: domains pointing to the selected IP, the hosts that requested those resolutions, the latest DNS observation and flow UID, and the relevant Slips time windows. Resolver addresses are clickable and open their host workspace.

In the default Host view, traffic, scores, alerts, and evidence match only the selected Slips profile IP. In Device view, local addresses with the same verified MAC are combined for traffic, alerts, and evidence. The score chart continues to show the representative IP's own Slips accumulator. Rows show normalized direction, peer, addresses, ports, protocol/application, state, duration, packets, bytes, label, UID, and expandable raw details.

Selecting a host flow opens the resizable investigation panel with the same flow cards used in evidence details: named source and destination endpoints, ports, connection metrics, compact additional fields, a copyable UID, and expandable complete JSON. Related DNS, HTTP, TLS, and other protocol records sharing that UID load only when the panel opens, in pages of 20. **Load more protocol records** keeps additional records accessible without enlarging the initial host-table response. Protocol tabs and JSON are built only when selected or expanded. Closing or switching the panel cancels the request; connection details remain readable if loading related records fails. The panel supports both themes and narrow widths.

Native horizontal and vertical port-scan evidence links at most 20 contributing
non-established connection UIDs. The interface identifies this limit when a
scan is opened; other evidence types retain all of their triggering-flow links.
Selecting scan evidence therefore shows a bounded sample of attempted connections.

## Historical API

The page uses bounded local endpoints:

```text
GET /api/identity
GET /api/overview
GET /api/metrics?range=...&max_points=...
GET /api/alerts?...filters...&sort=...&order=...&cursor=...
GET /api/evidence?...filters...&sort=...&order=...&cursor=...
GET /api/hosts?...filters...&sort=...&order=...&cursor=...
GET /api/host-names?ip=...
GET /api/hosts/<ip>
GET /api/hosts/<ip>/evidence?sort=...&order=...&cursor=...
GET /api/hosts/<ip>/flows?limit=...&from=...&to=...&cursor=...
GET /api/hosts/<ip>/traffic-summary?from=...&to=...&max_points=...
GET /api/hosts/<ip>/score-history?range=...&from=...&to=...&max_points=...
GET /api/evidence/<uuid>/flows?limit=20&cursor=<last-uid>
POST /api/host-annotation
```

Responses include bounded page metadata and selected ranges. Overview and identity include source freshness and indexing state. Request handlers use short-lived read-only SQLite connections so browser requests do not hold back WAL checkpoints.

### Connection attribution

`DIFFERENT_LOCALNET` describes a connection involving a private address outside the monitored subnet. The source that initiated the connection owns the evidence profile; the destination remains the destination even when it is the outside address. For example, a connection from `192.168.1.163` to `172.17.0.1:6668` is attributed to `192.168.1.163`, not to an attack by `172.17.0.1`. The address `172.17.0.1` commonly belongs to a Docker bridge, but the address and port alone do not establish which process initiated the connection. This correction applies to new detections; stored alerts retain their original attribution and can be reviewed through the usual workflow.

### Optional browser regression check

`tests/unit/zeek_scripts/test_mdns_identity.py` replays isolated packets through
installed Zeek and the Slips parser and identity store. It covers mixed address
record owners, IPv4 and IPv6 aliases, known-answer queries, expired records,
ordinary DNS, and the 64-binding bound. It skips if Zeek or Scapy is unavailable.
It does not capture from a live interface.

`tests/unit/modules/web_interface/test_browser.py` uses Playwright and an installed Chrome to exercise the shipped HTML, JavaScript and styles against isolated API fixtures. It checks a grouped device record with 1,051 linked flows, protocol tabs, lazy JSON, flow paging, close/reopen, and saving host marks, labels and notes. It also checks the contextual host whitelist request and current-network inventory refresh across multiple loaded pages, including the separation of current observations from saved network history. It skips when Playwright or Chrome is unavailable; neither is required to run Slips. The regular server tests verify durable persistence, configured whitelist-file writes, and filtering independently of browser availability.
