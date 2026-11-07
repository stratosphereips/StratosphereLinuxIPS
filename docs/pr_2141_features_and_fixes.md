# PR #2141 — Features and fixes explained

Local review draft for [PR #2141: Cross-platform native Slips for macOS, Linux, and Raspberry Pi](https://github.com/stratosphereips/StratosphereLinuxIPS/pull/2141).

**Snapshot:** 3 November 2026. Branch: `sebas_testing`. Head: `12538216faea54e9e1ae585cf5759145a01e9b3a`. Compared with the PR's `develop` base at `ccd0b1581829d70ff8e60062500c4b03aa2e1982`.

At this snapshot, the PR contains **506 commits and changes 377 files**, with 88,900 added lines and 6,574 removed lines. These totals include tests, documentation, merges and repeated refinements. The explanations below combine those refinements into the resulting features and fixes. They cover committed PR changes; local configuration edits and untracked work are outside this inventory.

Slips is free software for behavioral network intrusion detection that combines protocol analysis, machine learning, threat intelligence and collaboration between peers. This PR expands where it can run, improves long-running monitoring and investigation, adds behavioral detectors, and fixes incorrect findings and lost context across restarts and network changes.

### Defaults worth knowing

| Capability | Repository default at this snapshot |
| --- | --- |
| SMB behavior module | Enabled; individual rules are configurable. |
| Numeric beaconing | Enabled; the legacy RNN is disabled in the default module list. |
| Packet timing inside a TCP connection | Disabled; enable collection before analyzing the capture. |
| Service anomaly learning | Disabled; opt in and allow its learning requirements to complete. |
| Network catch-up | Enabled within local P2P; requires supporting peers and a recognized network. |
| Catch-up-triggered blocking | Requires an already enabled firewall and the additional confirmation policy. |
| Smaller approximately 4 GiB storage profile | Documented configuration recipe, not the global default. |

An existing custom configuration can retain different explicit choices. The sections below describe the features without assuming they are all active in every run.

## Contents

1. [Running, stopping and reopening analyses](#1-running-stopping-and-reopening-analyses)
2. [Native platforms and process reliability](#2-native-platforms-and-process-reliability)
3. [Network changes and persistent device identity](#3-network-changes-and-persistent-device-identity)
4. [History, storage and performance](#4-history-storage-and-performance)
5. [Web investigation and presentation](#5-web-investigation-and-presentation)
6. [Reviews, scoring and whitelists](#6-reviews-scoring-and-whitelists)
7. [P2P communication and trust](#7-p2p-communication-and-trust)
8. [P2P network catch-up](#8-p2p-network-catch-up)
9. [New SMB behavior module](#9-new-smb-behavior-module)
10. [Beaconing and packet timing](#10-beaconing-and-packet-timing)
11. [New service anomaly module](#11-new-service-anomaly-module)
12. [HTTP, TLS and machine-learning changes](#12-http-tls-and-machine-learning-changes)
13. [Scan detection and continuing attacks](#13-scan-detection-and-continuing-attacks)
14. [Other false-positive and attribution fixes](#14-other-false-positive-and-attribution-fixes)
15. [Threat intelligence and integrations](#15-threat-intelligence-and-integrations)
16. [Documentation, tests and upgrade behavior](#16-documentation-tests-and-upgrade-behavior)

## 1. Running, stopping and reopening analyses

- **Find running Slips instances.** `--list-instances` lists accessible runs from the current checkout, including PID, run mode, input, output directory and webpage port. A forked module worker is no longer mistaken for another complete Slips instance on Linux.

- **One clear stop command.** `--stop [PID|all]` provides one interface for shutting down runs and replaces the separate `-S` stop option. It supports stopping one selected instance or all instances from that checkout, including their owned workers.

- **Restart a daemon with its original arguments.** `--restart [PID]` stops a daemon, waits for its workers to finish, and starts it again using its previous command-line arguments. The operator does not have to reconstruct the interface, configuration, output and history options.

- **Choose the webpage port from the command line.** `--web-port PORT` overrides the configured port for that run. This allows a live capture and several PCAP analyses to reuse a configuration while exposing separate webpages.

- **Reopen a saved analysis without analyzing it again.** `--view OUTPUT` opens an existing output directory using its saved databases. It restores the saved Redis snapshot into an isolated viewer instance when needed and does not start capture, Zeek, detection modules, P2P or blocking.

- **Reuse the original webpage port in a saved viewer.** When the original analysis recorded its web port, `--view` uses it again. An explicit `--web-port` can override it; a conflicting recorded port produces a useful error instead of silently opening the wrong analysis elsewhere.

- **Run saved viewers in the background.** `--view OUTPUT -D` supports a background viewer with instance management. Viewing an old output no longer requires manually starting Redis, loading its snapshot and constructing the web-server command.

- **Keep live history across restarts.** `--keep-history` preserves the supported live run's detections, flows and associated context in the same output directory. It also works on the first start: a missing `flows.sqlite` means start fresh, rather than fail and require a different command.

- **Fix false history-port conflicts during restart.** Instance-management commands no longer count as competing history runs. A daemon can restart without incorrectly concluding that its own management process is another analysis using the history Redis port; real concurrent ownership conflicts remain rejected.

- **Run PCAP analysis beside a retained live capture.** Offline runs automatically isolate their configuration, whitelist and permanent state where required, and use separate analysis resources. Users can reuse `-c` without manually duplicating configuration files or contaminating the live run.

- **Keep saved viewers attached to the correct database.** Run identity and resource checks prevent a viewer from accidentally reading the Redis state of a different active analysis. Viewer setup and cleanup also keep unrelated capture resources intact.

- **Explain daemon initialization accurately.** A daemon that takes longer to initialize is reported as still starting, with log paths for progress. Startup confirmation is recorded when initialization completes; a bounded terminal wait is no longer presented as proof that startup failed.

Examples, using the Python environment in which Slips is installed:

```sh
python3 slips.py --list-instances
python3 slips.py --stop 12345
python3 slips.py --stop all
python3 slips.py --restart 12345
python3 slips.py -c config/slips.yaml -f dataset/test7-malicious.pcap -o output/example --web-port 55001 -w
python3 slips.py --view output/example
```

Details: [usage and instance management](usage.md).

## 2. Native platforms and process reliability

- **Native macOS operation alongside Linux and Raspberry Pi.** Installation, startup and runtime handling now support native macOS, including Apple Silicon, while retaining Linux and ARM64 Raspberry Pi support. Platform-specific permissions and dependencies are documented.

- **Modules initialize inside their child process.** The new process wrapper avoids assuming that a child inherits a fully usable parent process. This fixes failures with macOS's `spawn` method and improves compatibility with the supported multiprocessing start methods.

- **Process-local database and logging resources.** Bloom-filter workers reconstruct their connections safely, and logger locks and startup queues belong to the running instance. Workers no longer depend on inherited Redis sockets or unsuitable global synchronization state.

- **Queues respect platform semaphore limits.** Profiler, evidence and lookup queue capacities are constrained by what the platform supports. This prevents startup errors caused by requesting semaphore sizes that work on Linux but exceed macOS limits.

- **Threads use thread synchronization.** Background MAC and CIRCL lookups use thread queues, locks and stop events where appropriate. This removes unnecessary multiprocessing resources and improves shutdown behavior.

- **Correct worker and queue ownership.** AID, evidence and logging queues are passed to the processes that need them and closed during shutdown. Submission-only clients no longer create or manage a second copy of a worker accidentally.

- **Scheduled tasks actually get execution time.** The main asynchronous loop yields so scheduled work can run. Terminal output also avoids waiting indefinitely for a busy print lock, preventing routine output from freezing the main loop.

- **Piped input works under native multiprocessing.** Stdin descriptors and format recognition are handled explicitly. Zeek, Argus and Suricata input can be recognized correctly, including when a same-named local directory exists; EOF triggers normal completion.

- **NetFlow input compatibility.** nfdump uses an explicit compatible CSV format and converts numeric fields correctly. Argus and piped-flow handling preserve the expected flow attributes and can infer local network context without a live capture interface.

- **Bounded, complete shutdown.** Ctrl-C, daemon stop and termination signals coordinate module exits, pending lookups and queue cleanup within a bounded shutdown period. Remaining owned workers can be terminated without extending cleanup forever.

- **Orphan workers stop with their parent.** Workers monitor their owning process and exit when it disappears. Old workers can no longer remain behind to consume traffic intended for a restarted analysis.

- **Clean up only owned Zeek processes.** Process identity checks distinguish the run's Zeek children from unrelated Zeek processes. Cleanup also uses a fixed deadline rather than restarting its entire time allowance on every retry.

- **Stop the associated webpage with the run.** Shutdown and restart handle the run's web server so an old webpage does not remain listening after its Slips instance has stopped. Ownership checks avoid treating an unrelated HTTP listener as a Slips server.

- **Avoid copying Zeek logs onto themselves.** Shutdown recognizes when Zeek already writes into the final `zeek_files` directory, including equivalent paths. This prevents a redundant copy from raising `SameFileError` and interrupting cleanup.

- **Writable Redis PID locations.** Per-instance Redis PID files use writable locations suitable for native installations. This removes dependence on a system lock directory unavailable to an ordinary user.

- **macOS active prevention.** When blocking is explicitly enabled with the required privileges, macOS uses a Slips-owned Packet Filter anchor. Cleanup targets Slips rules; the Linux access-point workflow remains platform-specific.

- **No unnecessary firewall prompt on exit.** A run that never enabled blocking does not ask for firewall privileges merely because it is stopping. Noninteractive shutdown also avoids waiting forever for a web-server prompt.

- **Graceful handling of runtime edge cases.** Empty feeds, malformed domain metadata, Redis errors and late log output receive explicit handling instead of causing secondary failures during startup or shutdown.

Details: [installation](installation.md), [architecture](architecture.md), [contributing](contributing.md).

## 3. Network changes and persistent device identity

- **Live network-state collection.** Slips records interface connectivity, IPv4 and IPv6 addresses, subnet, gateway, DNS information and network name on Linux and macOS. Missing gateways or DNS settings no longer crash collection.

- **Follow the monitored interface when it changes networks.** The web listener can be moved when the monitored interface address changes. The shared page header refreshes current network information without requiring the Overview tab to be opened first.

- **Assign flows to the network where they were captured.** Retained network snapshots and interface evidence help resolve the network at capture time. A flow processed after roaming is no longer automatically compared with the subnet that happens to be current during processing.

- **Identify a network using more than its private range.** Router identity and subnet distinguish networks that both use addresses such as `192.168.1.x`. This prevents history and P2P catch-up from treating every familiar private range as the same network.

- **Persist host identity independently of the Redis cache.** A new host-profile worker saves identity clues in SQLite. Learned names, MAC addresses, vendors, DNS clues and network observations can survive cache expiry, restart and roaming.

- **Keep identity work outside core flow writes.** Host profiling is asynchronous. The core records and routes flows without performing expensive identity aggregation inline for every flow.

- **Group verified addresses into one device.** Device view combines addresses when local identity evidence supports the relationship, including IPv4 and IPv6 addresses. An IP change does not necessarily create an unrelated device in the interface.

- **Avoid merging public hosts through a gateway MAC.** An Ethernet frame's router MAC is not treated as the public destination's device identity. Ambiguous shared-MAC situations also retain separate profiles rather than merging arbitrary hosts.

- **Preserve the meaning of device scores.** Grouped devices show the appropriate member score rather than adding separate IP scores together and manufacturing a larger detection score.

- **Keep user names and notes with the right device.** Manual names, notes and annotations persist across runs and valid address changes. A reused private address does not automatically inherit another device's name when its identity differs.

- **Attribute DNS and mDNS names to their actual owner.** A response name belongs to the address described by the response, rather than every requester or unrelated address in the exchange. Destination-only hosts can receive useful enrichment without becoming falsely recorded as locally observed devices.

- **Collect mDNS address ownership explicitly.** The new [mdns-identity.zeek](../zeek-scripts/mdns-identity.zeek) script logs bounded address-owner bindings from local mDNS replies. This supplies the evidence needed to avoid giving all addresses in one exchange the question's hostname.

- **Separate observed activity from saved clues.** Cached DNS, old metadata and saved identity are shown separately from traffic observed on the current network. A host can retain a known identity while honestly showing no current activity.

- **Distinguish saved networks from the current Wi-Fi.** A host's previously saved network, such as eduroam, is identified as historical metadata. It is not presented as proof that the current capture is connected there.

- **Name networks persistently.** Users can give a recognized network a readable name in the web interface. The name is saved against its network identity for later visits.

- **Show complete local addresses and MAC characteristics.** The header includes the monitored IPv4 and IPv6 addresses, and host views identify locally versus universally administered MAC addresses. Device names take priority over less useful vendor placeholders.

- **Make geolocation meaningful.** Public country information is displayed only when backed by appropriate public-IP metadata. Local addresses and unrelated identity hints are not given invented geographic meaning.

Details: [host identity, network scope and Device view](web_interface.md).

## 4. History, storage and performance

- **Retain detections independently of raw traffic.** Evidence, alerts, reviews and their relationships remain available even when old raw flow records expire. A detector's finding no longer depends on retaining every original flow forever.

- **Bound live raw-flow history.** Age and size settings prune ordinary flows and protocol records in small batches. Cleanup selects the oldest eligible records across both tables instead of allowing one table to keep growing while only the other is pruned.

- **Prioritize useful triggering flows.** Flows linked to retained evidence receive additional protection, and recent evidence can protect a flow that started earlier. Under pressure, retention prioritizes the newest relevant detection context.

- **Rotate detection history into SQLite archives.** Older evidence, alerts, reviews and relationships move into segmented monthly archives. Active history and archives have separate age and size settings, so long-running monitoring does not require one indefinitely growing database.

- **Commit archive copies before deleting active records.** Transfers are resumable and preserve relationships. An interrupted rotation resumes from bounded progress instead of losing the source records before their archive is durable.

- **Protect recent investigations during retention.** A protected recent window and retained alerts can keep their supporting evidence active. Cleanup defers unfinished work instead of deleting records needed for an incomplete transfer.

- **Browse archives explicitly.** The web history selector lists retained detection archives with their actual date ranges. Archived views are read-only and distinguish historical data from the active analysis.

- **Rotate diagnostic and web logs.** Slips, error, alert, web and relevant module logs receive bounded rotation settings. A quiet detector no longer needs to produce an endlessly growing diagnostic log.

- **Document a practical 4 GiB profile.** The usage guide provides a smaller live-monitoring configuration with about 1 GiB of active detection storage, 2 GiB of archives and smaller log backups. This is a configurable target, not a claim that every installation defaults to a hard 4 GiB total limit.

- **Explain database size after cleanup.** SQLite can reuse freed pages without immediately shrinking the file on disk. The documentation separates logical retention, log rotation and offline compaction so a large physical file is not mistaken for failed cleanup.

- **Make maintenance yield to capture.** Cleanup, summaries, archives and checkpoints use bounded work and defer busy database writes. Lock handling and retries favor ongoing capture instead of holding its writer behind a long maintenance transaction.

- **Initialize archives atomically on slower disks.** Archive schema creation uses one transaction rather than repeated expensive commits. This reduces stalls on Raspberry Pi storage and avoids leaving half-created archives after failure.

- **Use indexed evidence and alert lookups.** Time-leading indexes, counters and hourly summaries reduce repeated history scans. Exact boundary queries and fallback paths preserve correct counts when summaries are incomplete or dirty.

- **Reduce the cost of web searches.** Broad evidence searches reject unsuitable records before fetching unnecessary details. Host and Device searches filter and page before expensive aggregation whenever their requested sort allows it.

- **Keep detector state bounded across restart.** Checkpoints for detectors such as beaconing, ARP and service anomalies retain useful progress with age and capacity limits. Busy writes can retry, including on the Python versions used by Raspberry Pis.

- **Bound auxiliary history too.** Old web metrics, temporary host snapshots and P2P reputation rows are cleaned or compacted. Disk limits cover more than the primary flow database.

- **Recover details when retained logs permit it.** Evidence inspectors can retrieve missing linked flow details from saved Zeek JSON in bounded work. When the source is no longer available, the interface distinguishes missing data from data that simply has not loaded yet.

The default detection policy targets 90 days and 2 GiB of active history, with a separate 4 GiB archive cap and archive expiry 30 days after last write. These are soft retention targets while protected records or unfinished transfers remain. Raw flows, logs, Redis snapshots and module state also occupy disk space.

Details: [retention, archives and the smaller storage profile](usage.md), [web history](web_interface.md).

## 5. Web investigation and presentation

- **Useful live-monitoring defaults.** The default appearance is light, with Device view and Current network only enabled for live monitoring. Saved preferences can still preserve the user's chosen presentation.

- **Persist filters without leaking them into a different analysis.** Sorting, grouping, range and other investigation preferences survive appropriate refreshes. Their analysis identity prevents a new PCAP using the same webpage port from inheriting unrelated hidden filters.

- **Keep login sessions across restart.** Persistent signed sessions avoid the unexpected login-required behavior caused by restarting Slips or reopening the browser. Separate credential sets use separate cookies, preventing independent installations on different localhost ports from overwriting each other's login.

- **Show earlier visits to the selected network.** Current network only can include previous visits within the requested seven days or full run. It no longer accidentally means only the latest connection to that network.

- **Add the This connection range.** This short range shows activity since the latest connection to the monitored network. It provides the narrower view explicitly, including in live P2P views, without redefining longer ranges.

- **Use the right clock for time filters.** Live-interface ranges use current wall time; offline analyses use capture time. Old or relative-timestamp captures are not filtered away merely because they do not occur near today's date.

- **Explain record counts and group counts.** A table grouped by device can contain one row with many evidence records. Counts now distinguish groups from individual findings, reducing the misleading appearance that history has disappeared.

- **Sortable and filterable evidence tables.** Group and record tables expose sorting, search, severity, origin and related filters. Users can investigate the records inside a selected group rather than navigating an unfilterable list.

- **Keep severity independent of grouping.** Switching Device, Device + type, Type or None preserves the selected threat threshold. Changing a presentation control no longer silently resets Low+ or another severity filter.

- **Use inclusive threat buttons consistently.** The toolbar keeps All and Critical+, High+, Medium+, Low+ and Info+. The parallel set of exact-only threat buttons has been removed.

- **Flatten and standardize the toolbar.** Alert-link and range filters are available directly when space permits. Excluded visibility is a button rather than a dropdown, and controls use consistent sizing and fonts.

- **Remove the empty panel in ungrouped evidence.** With grouping set to None, the list opens evidence directly in its detail pane. The interface no longer reserves a useless middle panel or shows an empty record list while navigation still works.

- **Preserve investigation context.** Resizable list, group and detail panes support evidence, alerts and host investigations. Closing or navigating a nested detail returns to the relevant investigation rather than discarding its context.

- **Make headers compact and readable.** Repeated IP addresses, duplicate titles and oversized metric cards have been reduced. Device names use a consistent bracketed style and color while retaining source, destination, threat, score, confidence and network information.

- **Collapse technical evidence metadata.** The Evidence record section starts hidden. Opening it reveals identifiers and technical fields without repeating large source and destination cards already shown in the flow.

- **Use consistent evidence names.** Names such as Unknown Port have the same readable capitalization across local and P2P records. Machine-learning names are shorter, and compatibility labels such as “legacy” are removed from the visible evidence name.

- **Remove internal time-window labels.** Normal webpage views no longer repeat `timewindow1` and similar implementation details. Original data can still retain these fields for technical inspection.

- **Use shared flow cards throughout investigations.** Connection and related HTTP, TLS, DNS, ARP and SMB records use consistent layouts. Source appears on the left, destination on the right, with protocol-appropriate fields and observation times.

- **Load large investigations progressively.** Linked flow IDs are paged and related protocol details and JSON are loaded when needed. Evidence with thousands of linked flows no longer requires building every card immediately.

- **Show full dates on hover.** Time labels reveal their full local date, time and timezone in a tooltip. A short clock value no longer hides whether an observation happened today or several days ago.

- **Improve JSON inspection.** JSON has indentation and syntax styling, and each JSON viewer has a copy button. Identifier-copy actions remain available, and untrusted peer descriptions are escaped during rendering.

- **Hide labels that the operator did not supply.** Without an input label file, implicit flow labels are hidden from the normal flow-field presentation. Users are not shown a default label that looks like independent ground truth.

- **Improve the configuration workspace.** The page presents the run's startup configuration and explains settings, score equations and training behavior in plain language. It distinguishes the settings used for the run from later changes to its source file.

- **Keep the selected pane after a review.** Saving a true-positive, false-positive or other verdict updates the investigation in place. It no longer reloads the workspace and returns the user to the main pane.

- **Clarify current versus retained logs.** Logs default to the current run, with an explicit way to inspect retained runs. Multiline errors remain together instead of appearing as unrelated fragments.

- **Improve Overview without losing detail.** Compact summaries work for both quiet runs and alert-heavy runs. CPU, memory and traffic charts have numeric axes and hover values; module status moves to Metadata, and storage or maintenance state remains accessible.

- **Keep live counts and layouts stable.** Browser-title counts, navigation badges and table summaries follow the relevant filters. Loading indicators reserve their space, avoiding repeated page shifts during refresh.

- **Let slow requests complete.** Background polling no longer continually cancels an unfinished table request. Explicit filter changes can replace it, while progressive inventory refreshes preserve scroll and the user's investigation.

- **Keep host activity consistent across views.** Inventory counts, traffic totals, detail tables and evidence links use the same time and network scope. An unrelated stale host-activity filter no longer hides otherwise valid evidence.

Details: [web interface guide](web_interface.md).

## 6. Reviews, scoring and whitelists

- **Store processed evidence scores durably.** Historical records preserve the score calculated when they were processed. The web distinguishes an unavailable score from a real zero instead of filling old rows with a misleading current value.

- **Persist evidence before dependent notifications.** Whitelist and related handling can read a committed evidence record when notified. This closes a race in which a notification arrived before its evidence existed in storage.

- **Preserve analyst decisions.** Alert triage, evidence reviews and host annotations are durable. A busy peer database uses a feedback outbox so a saved review is not silently lost before P2P consumes it.

- **Export reviewed flows.** Export associates flow records with actual analyst verdicts and distinguishes unresolved or conflicting decisions. Model predictions and default flow labels are not substituted for a human review.

- **Create whitelist rules from evidence.** The web editor can suggest the relevant IPs, ports, direction and evidence type. Authenticated remote users can save a rule to the configured whitelist file without rebuilding or replacing the whole personal file.

- **Support IP-and-port conditions.** Rules can constrain IPv4 or IPv6 endpoints by port, including source-to-destination combinations. This allows a specific legitimate service without suppressing every finding involving that host.

- **Scope a rule to one evidence type.** An optional evidence-type column narrows an exception to the unwanted detection. Other findings involving the same endpoints remain visible.

- **Add blocking-only exceptions.** A `blocking` rule preserves flows, evidence, scores and alerts but prevents firewall blocking and ARP poisoning of its specified IP. It is separate from suppressing detection data.

- **Support HTTP URI exceptions.** A known legitimate request, such as a local AirPlay exchange, can be exempted by URI. Operators do not have to whitelist the entire host or service globally.

- **Recognize AirPlay discovery before connection logging.** The new [airplay-info.zeek](../zeek-scripts/airplay-info.zeek) script and its signature tag the relevant `/info` discovery exchange. A targeted exception can therefore work without depending on a particular device IP or temporary port.

- **Whitelist Slips WHOIS destinations precisely.** Default WHOIS exceptions target the destination IP and TCP port 43 used by the lookup. This avoids noisy findings about Slips' own queries without exempting every possible destination on port 43.

- **Fix organization-domain matching.** Domain rules respect exact names and subdomain boundaries. An unrelated domain containing a provider's text is no longer accidentally accepted as that organization.

- **Apply each run's local whitelist reliably.** Shared threat-feed locks do not prevent a run from loading its own local rules. Web changes affect the configured file for that run, including an automatically isolated offline copy where applicable.

- **Protect whitelist files and explain exclusions.** Cleanup cannot delete the configured whitelist, missing custom files receive explicit handling, and edits preserve existing rules and comments. Excluded records are hidden by default, can be shown, and retain an explanation of their exclusion.

- **Document every whitelist column and mode.** The guide explains indicator, value, direction, target mode and optional evidence type with valid examples. It distinguishes `alerts`, `flows`, `both` and `blocking`, including restrictions on blocking-only rules.

Details: [whitelist format and examples](usage.md), [reviews and exports](exporting.md), [scoring signals](evidence_signals.md).

## 7. P2P communication and trust

- **Reconnect known peers.** Persistent peer endpoints and reconnection support let Slips find familiar peers after restart or a temporary disconnect. Legacy saved addresses are migrated before endpoint updates.

- **Discover through the monitored interfaces.** Pigeon can use the relevant local interfaces and refresh advertisements when addresses or networks change. One stale interface choice no longer prevents otherwise reachable peers from meeting.

- **Repair frozen macOS trust measurements.** Shortened gateway MAC octets are normalized before the network eligibility check. Valid local interactions are no longer discarded because macOS wrote a MAC in a different textual format.

- **Separate connectivity from report activity.** A connected peer stays connected between reports. A listening instance with no peers is shown honestly, rather than treating the absence of messages as a failed P2P process.

- **Survive reputation-database contention.** Report compaction and bounded trust queries avoid taking Pigeon offline merely because SQLite is busy. Backups preserve WAL-backed data consistently.

- **Keep persistent peer identity.** Interface changes and restarts preserve the existing identity key. Network measurements remain scoped so time away from a peer's network is not automatically counted as communication failure.

- **Show recognizable peer identities.** Tables, graph details and catch-up history use short peer IDs with known IPs and names where available. Full IDs remain available for technical inspection.

- **Restore report delivery and telemetry.** Blame broadcasts and received reports are recorded with their direction and peer. The P2P page exposes actual requests, replies and reports rather than relying only on a reputation total.

- **Separate reporter, subject and recipient.** A report's sender is distinct from the host it describes and from the peer receiving it. Evidence details explain the reported traffic first, then the P2P delivery path.

- **Keep the original reported detections.** A message containing several detections produces individual evidence records with the supplied detection types and details. The original `P2P_REPORT` envelope remains available, while the trust model still counts the message as one report packet.

- **Prevent report feedback loops and duplicate scoring.** Peer-derived findings are not reshared as independent local observations. Self-reports, stale replies, wrong-network replies and inappropriate group-address targets are guarded against.

- **Align trust with signed assessments.** Local assessments use the intended signed trust scale and distinguish unknown from benign. An informational finding or an implicit benign flow label does not prove that a target is safe.

- **Explain the communication-only trust baseline.** Good reachability alone contributes at most 0.35 under the base formula, so a quiet healthy peer can legitimately remain near 0.3. The web distinguishes this case from frozen measurements and shows when independent agreement adds credit.

- **Learn from independent agreement.** Matching local detections and reports from independent peers can improve report accuracy. Credit is bounded and deduplicated per peer and reported target, so repeating a report does not repeatedly increase trust.

- **Use analyst feedback in peer validation.** True-positive and false-positive reviews, expected behavior and conflicting or cleared decisions can confirm, penalize or retract previous credit. Detector families and versions help avoid counting the same heuristic error as several independent confirmations.

- **Age old accuracy adjustments.** Historical rewards and penalties do not freeze trust permanently at an old value. Their age and the distinction between communication reliability and report accuracy are exposed in the documentation and interface.

- **Plot actual trust beside reliability.** Persistent histories use consistent time bounds, precision and same-timestamp ordering. The chart does not invent historical trust by copying today's value backward, and long histories are sampled with bounded queries.

- **Add a P2P report-delivery graph.** The graph shows reporting peer → reported host → recipient, with filters for direction, peer, evidence type and time. Selecting a route reveals its reports and links to local evidence or alerts; links handle relevant network-history context rather than opening an apparently empty host view.

- **Handle companion-binary compatibility.** Pigeon feature checks and architecture-aware setup support native deployments and older capabilities. Optional catch-up support does not prevent ordinary live P2P communication with an older peer.

Details: [P2P communication and trust](P2P.md).

## 8. P2P network catch-up

- **Ask what happened while the computer was away.** On returning to a recognized network, Slips can ask supporting peers for recent warnings and retained incident history. Catch-up is enabled by default within local P2P, subject to its configuration.

- **Prioritize useful warnings.** Recent observations and withdrawals come first, followed by recent incidents and then older history. Defaults prioritize observations from the last 15 minutes, recent history from 24 hours, and a historical window of seven days.

- **Summarize repeated activity.** Related observations become incident summaries with first seen, last seen and counts. The exchange does not need to resend every evidence record or transfer packet bodies and complete flow histories.

- **Resume bounded transfers.** Persistent cursors track progress for each peer and network. Snapshot-based pages prevent new activity from shifting the list and causing records to be skipped during pagination.

- **Limit CPU, bandwidth and storage.** Defaults contact up to three peers, allow two concurrent pages, and bound a page to 50 records and 64 KiB. Transfer budgets and journal limits prevent a week of absence or a noisy peer from producing an unlimited download.

- **Report incomplete coverage honestly.** Timeouts, transfer budgets and gaps result in partial-history status. An empty reply is not displayed as proof that no attack occurred, and the collection start is visible for networks without pre-upgrade history.

- **Preserve authorship through forwarding.** Original authors sign summaries, and a delivering peer cannot rewrite them or become an extra witness. Router-and-subnet scope, revisions, expiry, quotas and replay state constrain misleading or repeated submissions.

- **Withdraw corrected findings.** A false-positive or conflicting review can produce a newer withdrawn revision from the author. Receivers retain the correction and reject older versions instead of reviving a retracted warning.

- **Keep historical news separate from current scores.** Imported incidents retain their original timestamps, confidence and expiry. Receiving them does not raise current host scores, train a model or earn agreement credit simply because the same history was forwarded again.

- **Require stronger checks for temporary protection.** Catch-up can request short-lived firewall protection only when blocking is already running and freshness, confidence, severity and corroboration requirements pass. Remote-only corroboration requires explicitly enrolled authors; the default empty enrollment list keeps local confirmation necessary.

- **Bound and clean up catch-up protection.** Temporary rules respect whitelists, avoid protecting against the local host or router, and validate current identity for private addresses. Leases are capped and recovered for cleanup; catch-up does not enable ARP poisoning or turn blocking on by itself.

- **Show what was stored versus what was exchanged.** The P2P page separates local summaries available to share, outgoing requests, replies and incidents actually received. Retaining a local summary is no longer presented as though it had already been sent to somebody.

- **Make transfer controls work.** Continue/check-again actions use the supported POST endpoint, fixing the Not found error. Per-peer progress shows accepted or skipped records and transferred bytes, while a failed transfer stays local to that row.

- **Make the P2P page easier to scan.** Clear section titles, table headers and rows distinguish peers, transfer progress, message activity and incident history. Details preserve the original author, delivering peer, expiry and evidence context.

Details: [catch-up behavior, safeguards and settings](p2p_catchup.md).

## 9. New SMB behavior module

The new `smb_analyzer` module consumes Zeek connection and SMB-related records. It correlates activity in its own worker and exposes per-rule enable switches, thresholds, threat levels, confidence, time windows and resource limits.

| Detection | Simple explanation | Default threat / initial confidence |
| --- | --- | --- |
| SMB Scan | One client attempts SMB connections to many servers, with a high proportion of failed fresh connection attempts. | Medium / 85% |
| SMB Share Sweep | A client accesses shares across many servers or requests many distinct share names in a short period. | Medium / 80% |
| SMB Share IP Mismatch | The literal IP in a requested path such as `\\192.168.56.20\IPC$` differs from the server actually contacted. Reports the discrepancy from its first occurrence. | Low / 90% |
| SMB Share Path Mismatch | The same literal share-path IP is reused while connecting to several different server IPs. | Medium / 75% |
| SMB Suspected Propagation | Repeated mismatched paths occur together with broader probing or share access across many hosts. | High / 90% |
| SMB External Connection | Confirmed SMB activity reaches an unapproved globally routable destination. An unanswered attempt to port 445 alone does not satisfy this rule. | Low / 80% |
| Large SMB Session | An SMB-confirmed session sends or receives at least 4 MiB by default. It records the observed session volume. | Info / 95% |
| Large SMB File | SMB metadata identifies a file of at least 100 MiB by default during relevant file operations. | Info / 80% |
| Suspicious SMB Transfer | A substantial client upload is correlated with recent SMB scanning or repeated share-path mismatches. | High / 85% |
| SMB Remote Execution | An executable is written through an administrative share and the same client then requests service creation or start on that server. | High / 85% |
| SMB Password Guessing | Many distinct connections contain explicit authentication failures in a short period. | Medium / 85% |
| SMB Password Spraying | Repeated authentication failures involve several known accounts or servers. | High / 85% |
| Rapid SMB File Changes | Many distinct files are written, renamed or deleted in a short period. | Medium / 80% |
| SMB Ransomware Behavior | A burst combines many file renames with writes or deletions. | High / 85% |

Additional SMB integration changes:

- **Collect richer behavior through Zeek.** [smb-behavior.zeek](../zeek-scripts/smb-behavior.zeek) collects relevant commands, file operations and authentication context. It avoids emitting a separate Slips event for every file-data chunk.

- **Preserve multiple events on one connection.** SMB operation records receive stable identities while retaining their parent connection UID. A later operation does not overwrite all earlier events from that session.

- **Inspect SMB records beside their connection.** Flow cards show requested share paths, service, share type and available file or command context. The mismatch evidence identifies both the connected destination and the requested literal server IP.

- **Detect behavior without a WannaCry address list.** These rules use scanning, path reuse, authentication, transfers and file changes. The same behavior can be detected on other endpoints without matching a particular WannaCry domain or IP.

The scan and share-sweep rules can increase confidence as observations accumulate; other SMB rules keep their configured confidence. Rules requiring commands, file operations or authentication fields need corresponding Zeek records.

Details: [SMB thresholds, input fields and configuration](smb_detection.md).

## 10. Beaconing and packet timing

- **New numeric beaconing module.** The `beaconing` module analyzes recurring timing, sizes and durations without requiring the legacy RNN at runtime. It can examine TCP and UDP connection sequences and identify regular callbacks or repeated bursts.

- **Separate periodicity from suspected command and control.** `PERIODIC_CONNECTION` reports recurring behavior at informational threat. A small numeric classifier can separately produce a low-threat `SUSPECTED_C2_CHANNEL` when a TCP sequence resembles its training patterns.

- **Tolerate realistic timing imperfections.** The detector supports jitter, missed callbacks, duplicates and out-of-order records. Minimum counts and observation spans reduce matches caused by brief ordinary bursts.

- **Protect mature channels from one-off traffic.** Candidate sequences and mature windows have separate bounded capacities. A large number of unrelated first connections no longer evicts every useful sequence immediately.

- **Persist useful live progress.** Changed windows are checkpointed outside the per-flow path with retention and capacity limits. Offline analyses start with their own state rather than inheriting another run's learned channels.

- **Space continuing reports logarithmically.** A stable pattern does not create another evidence record on every evaluation. Connection-count milestones and less frequent stable-pattern evaluation reduce repeated CPU and database work, while an upgrade to suspected C2 can still be reported promptly.

- **Explain channel-capacity warnings.** The warning means older timing context was evicted because the configured capacity was reached. Separate candidates, bounded state and report spacing reduce its impact; the documentation explains the memory-versus-history settings.

- **Provide reproducible numeric-model tools.** Training and evaluation tools use explicit capture groups and held-out data, reject leakage between related captures, and identify the intended C2 endpoints in malicious recordings. Runtime inference does not require installing the training stack.

- **Add optional packet timing inside one TCP flow.** [packet-timing.zeek](../zeek-scripts/packet-timing.zeek) summarizes packet intervals within a long-lived connection. This exposes a sparse heartbeat that connection-level `conn.log` timing cannot reconstruct.

- **Distinguish packet rhythms from suspicious heartbeats.** `PERIODIC_PACKETS` is informational. `SUSPICIOUS_PACKET_HEARTBEAT` requires stronger evidence such as bidirectional application data, stable small exchanges and an unrecognized application on an expected TLS port; ACK timing alone cannot establish the stronger finding.

- **Bound packet collection work.** The script uses fixed-size timing state and sends summaries rather than one Redis message per packet. Retransmissions are excluded from the relevant rhythms, and the feature does not store packet payloads.

- **Make collection opt-in and explicit.** Packet timing is disabled by default under `beaconing.packet_timing`. Enabling it requires a new capture or Zeek replay; reopening old output cannot recover packet-arrival details that were never logged.

- **Repair the existing RNN pipeline.** Preprocessing and training address padding/token collisions and ambiguous labels, with grouped train/validation/test splits. Existing model weights are not silently reinterpreted; a replacement model needs compatible retraining.

Details: [numeric beaconing and model tools](beaconing.md), [packet timing and settings](packet_timing.md), [C2 design rationale](cc_detection_strategy.md).

## 11. New service anomaly module

The optional `anomaly_detection_services` module learns behavior of answering local TCP and UDP services. It is disabled by default and runs separately from the core profiler.

- **Detect a newly answering service.** After an observed host has completed its learning period, a newly answering port can generate a finding. This also works for a previously quiet host that had no answering inbound services during training.

- **Detect an unfamiliar service client.** A learned service can flag a client outside its established client pattern. Known clients and controlled adaptation reduce repeated findings about ordinary users.

- **Detect unusual service hours.** Connection times are compared with the service's learned schedule using the configured timezone. This supports identifying activity outside its usual working pattern.

- **Detect unusual TCP duration.** Completed TCP connections can be compared with a learned duration distribution. Both unusually short and unusually long sessions can be relevant depending on the service.

- **Make training requirements explicit.** Train, detect and automatic modes are configurable. Capture-time learning windows, minimum successful observations and observed-day requirements prevent fast PCAP playback from being confused with many days of learning.

- **Learn from proof that a service answered.** Failed attempts and reversed or incomplete TCP roles do not establish a new service. Clearly malicious training observations are excluded, and host/network identity prevents unrelated devices from sharing a baseline accidentally.

- **Persist bounded baselines.** Service and client models survive restart with expiry, capacity limits and retryable checkpoints. Shared robust statistics also improve maintainability of the existing HTTPS anomaly detector.

Details: [service anomaly configuration and training](service_anomaly_detection.md), [existing HTTPS anomaly module](https_anomaly_detection.md).

## 12. HTTP, TLS and machine-learning changes

- **HTTP Host header containing an IP.** `HTTP_IP_HOST` recognizes literal IPv4 and bracketed IPv6 Host values, including an explicit port. It records direct-IP HTTP access as informational behavior.

- **Binary POST without Content-Type.** `HTTP_BINARY_POST_WITHOUT_CONTENT_TYPE` requires a nonempty POST body, a missing request Content-Type and positive binary-content information from Zeek. Its default threat is medium.

- **Binary response declared as HTML.** `HTTP_BINARY_RESPONSE_AS_HTML` correlates a declared `text/html` response with Zeek's binary-content identification. The medium-threat finding is attributed to the responding server.

- **Collect HTTP metadata without extracting bodies.** [http-content-metadata.zeek](../zeek-scripts/http-content-metadata.zeek) provides the header context needed by the new rules. Transaction correlation avoids combining one request's headers with another response on the same connection; missing metadata alone is not taken as proof of binary content.

- **Executable downloads have medium threat.** The existing executable-MIME download finding is raised to medium, with the observed MIME and endpoints retained. It is no longer presented at the previous lower severity.

- **Detect suspected TLS provider impersonation.** The provider-mismatch rule uses the clearer `TLS_PROVIDER_IMPERSONATION` classification and high threat for the assessed server. The description explains the claimed provider and conflicting endpoint context.

- **Fix legitimate provider/CDN false positives.** Certificate organizations are parsed as actual subject fields, including escaped characters, instead of arbitrary substring matches. Recognized provider domains and valid hosting relationships avoid wrongly flagging legitimate Microsoft or Twitter services merely because they use another delivery network.

- **Display certificate-date results in capture context.** Old captures are not rejudged against today's clock in the interface. When a capture has no reliable original calendar date, date validity is shown as unknown while preserving the original Zeek result for inspection.

- **Keep old evidence readable without internal labels.** Compatibility with stored evidence names is retained, but the interface does not append “legacy” to an evidence name. Reading saved output does not silently recalculate all old findings under a new detector.

- **Clarify existing machine-learning evidence.** The linear and online findings display as ML Suspicious Flow · Linear and ML Suspicious Flow · Online, with ML explained as machine learning. This improves presentation of existing modules rather than claiming that those two models are new in this PR.

Details: [detection modules](detection_modules.md), [TLS and flow alerts](flow_alerts.md), [web evidence presentation](web_interface.md).

## 13. Scan detection and continuing attacks

- **Count fresh horizontal scan attempts.** New outgoing attempts are distinguished from ACKs, FINs, resets and tails of old sessions. A network outage or capture backlog no longer looks like a new scan simply because many old sessions ended together.

- **Support fast and slow horizontal scans.** Separate windows recognize rapid fan-out and more gradual probing. Distinct destinations, failed attempts and target concentration support the result rather than raw packet volume alone.

- **Reduce normal-service and outage matches.** Familiar successful contacts and actual connection outcomes help distinguish scanning from loss of connectivity. Missing handshake history receives more cautious treatment than a confirmed sequence of failed fresh SYNs.

- **Improve vertical scan tracking.** Distinct ports on the same host are tracked with the appropriate connection direction. State for ordinary one-port fan-out does not unnecessarily displace useful multi-port scan context.

- **Allow scan confidence to reach 100%.** Shared progress tracking promotes confidence as enough distinct, qualifying observations accumulate. It typically reaches 95% at twice the initial threshold with at least 20 observations, and 100% at ten times the threshold with at least 100, subject to that scan's quality requirements.

- **Release detailed target sets after confirmation.** At full confidence, supported detectors replace the large exact target set with compact bounded distinct-count state and a small sample of triggering IDs. Confirmed large scans therefore need much less memory to keep tracking.

- **Keep reporting continuing growth.** Confirmation does not end monitoring. Logarithmic milestones report substantial growth, such as roughly 100, 1,000 and 10,000 targets, without writing another evidence record for each new target; post-compaction counts are estimates.

- **Apply progress policy across scan families.** Horizontal, vertical, SMB host/share, ARP and DHCP tracking use the shared policy where applicable. ICMP notice handling can normalize supplied counts, but later milestones depend on Zeek actually emitting later notices.

- **Reset after an actual quiet period.** A separate later scan starts a new collection period after the relevant gap. Old confirmed progress does not suppress all future scan evidence forever.

- **Separate ARP discovery from ARP scanning.** Familiar neighbor resolution, address-conflict probes and announcements are treated differently from broad searches for unfamiliar addresses. Information about normal broad discovery can remain informational, while stronger search patterns support scan findings.

- **Persist and bound ARP context.** Relevant familiarity and scan progress can survive restart without crossing network identities. Capacity warnings are rate-limited and explain lost context rather than flooding logs with the same cumulative condition.

Full confidence depends on observation quality and capacity. If a configured memory limit discards the necessary pre-confirmation context, the detector cannot honestly promote that incomplete observation set to 100%.

Details: [shared confidence and progress](scan_progress.md), [horizontal scans](horizontal_port_scans.md), [ARP behavior](arp_scans.md), [SMB progress](smb_detection.md).

## 14. Other false-positive and attribution fixes

- **ICMP is not a long connection.** Long-connection detection now excludes ICMP and ICMPv6, including their numeric protocol representations. A half-hour sequence of neighbor-discovery or echo traffic is not treated as a half-hour transport session.

- **Broadcast and multicast are not long connections.** Group destinations are excluded using IP, Ethernet destination and captured subnet context where available. Directed broadcasts are evaluated against the real prefix, rather than assuming every address ending in `.255` is a broadcast.

- **Reject those false long-connection reports through P2P too.** Validation also guards incoming and outgoing long-connection reports, including relevant catch-up summaries. The fix applies at the detector and report boundaries rather than only hiding a web label.

- **Ignore expected broadcast/private discovery traffic.** Private-address connection findings exclude relevant group and special-address traffic, including the NetBIOS broadcast case. Recognized legitimate local Apple peer exchanges receive more specific handling.

- **Exclude working DNS resolvers from missing-DNS findings.** Configured or observed responding DNS servers are handled appropriately for DNS service traffic. Slips no longer demands a prior DNS lookup merely to contact the resolver that provides DNS.

- **Avoid local discovery and self-traffic DNS mistakes.** Host-local and mDNS discovery cases, plus Slips-owned lookup and P2P traffic, are excluded where appropriate. Startup grace and observed resolution context reduce findings caused only by incomplete initial visibility.

- **Count distinct failures for DGA detection.** Repeated copies or retries of the same failed DNS query no longer inflate the distinct-failure threshold as if they were many generated names.

- **Recognize linked HTTP before reporting non-HTTP on port 80.** The connection checker consults related HTTP records even if the connection service field is absent or delayed. A parsed HTTP request is not simultaneously called non-HTTP solely because that field was blank.

- **Use actual TCP role evidence.** Handshake and history interpretation avoid reversing connections twice or treating a server reply captured mid-session as a new client service. This corrects endpoint attribution across connection, service and scan checks.

- **Scope device IP-change checks to a network visit.** Moving from one sensible subnet to another does not generate Device Changing IP merely because the same MAC receives a new address. The detector also avoids binding routed public IPs to a gateway's MAC.

- **Use capture-time local networks for Different Localnet.** Delayed flows from a previous network are checked against their observed network, preventing mobile-hotspot traffic from being compared with the later home subnet.

- **Give subnet findings the correct host role.** Related source and destination findings have consistent profiles and directions: the initiating source receives high threat, while merely receiving the connection is informational. Self-connections are ignored and related evidence IDs preserve the relationship.

- **Do not hide an established unknown service after scanning.** A scan classification no longer exempts an established, payload-carrying service from Unknown Port detection. This fixes the case where port 9001 disappeared because the host also scanned.

- **Add Apple service-port knowledge.** TCP 5223 for Apple Push Notification service and the relevant documented Apple port mappings are added, with protocol handling and malformed entries corrected. Organization-specific port allowances still require the appropriate organization context.

- **Fix Macintosh versus Windows user-agent matching.** The letters “NT” inside “Macintosh” no longer trigger a false Windows operating-system interpretation.

- **Limit upload analysis to its configured period.** Upload checks examine the intended observation window rather than repeatedly treating lifetime accumulated traffic as a fresh upload event.

- **Show ICMP type and code correctly.** Zero-valued types/codes remain visible, and ICMP is not formatted as if its values were TCP or UDP ports. Compatible display corrections also apply to relevant saved descriptions and peer metadata.

- **Keep evidence descriptions factual and concise.** Repeated generic disclaimers about benign alternatives or unconfirmed exploitation are removed from evidence prose. Detailed detector assumptions and limits remain in the documentation.

Details: [connection and other detectors](detection_modules.md), [flow alerts](flow_alerts.md), [shared scan behavior](scan_progress.md).

## 15. Threat intelligence and integrations

- **New Threat Intelligence web tab.** A dedicated panel lists configured TI sources, update state, last check/load times and available accepted-indicator counts. Operators can inspect feed freshness without reading each downloader's logs.

- **Track feed results during updates.** Parsers record accepted indicators and update outcomes as they work. The dashboard does not need to rescan all intelligence records repeatedly just to display feed totals; older feeds acquire richer status through subsequent updates.

- **Handle empty feeds and whitelist-cache problems.** Feed parsing and local updates tolerate empty input and recover from relevant Redis type or state errors. Tranco whitelist cache handling preserves the intended ordered and bounded data.

- **Bound enrichment and avoid repeat lookups.** Public-IP metadata is cached appropriately, while MAC and CIRCL requests use background queues and bounded shutdown. Routine enrichment no longer performs the same network lookup repeatedly or delays exit indefinitely.

- **Restore native desktop notifications.** macOS uses the platform notification command, with the documented desktop-session requirements. Notification setup no longer assumes a Linux-only command is available.

- **Complete the Fides service-trust lookup.** The missing peer query filters appropriate known peers by the requested service-trust threshold. Authenticated Redis handling is included in its integration tests.

- **Make native Iris and YARA paths usable.** Iris binary selection and protocol-version compatibility receive native-platform handling, and compiled YARA output uses the module's appropriate location. Redis publishing preserves the required message protocol version.

- **Update companion dependency references.** Pigeon, SlipsWeb and feel_project references point to published revisions needed by the branch. Companion changes and build requirements are documented so fresh clones can fetch the required versions.

Details: [Threat Intelligence and configuration views](web_interface.md), [installation](installation.md), [Fides](fides.md), [Iris](iris_module.md).

## 16. Documentation, tests and upgrade behavior

- **Document native setup and diagnosis.** Installation and usage cover macOS permissions, environments, Redis ownership, Linux and Raspberry Pi operation, instance management and saved viewers. Troubleshooting distinguishes platform limitations from a failed Slips process.

- **Document the new detector settings.** SMB, beaconing, packet timing, service anomalies, ARP and scan progress each have dedicated guides. Settings explain their effects on detection, training time, confidence, memory, CPU and storage.

- **Explain history and configuration ownership.** Guides describe retained live history, archives, isolated offline copies and the whitelist actually edited by the web. Reusing a source YAML does not require manually duplicating files for each PCAP analysis.

- **Keep expensive work in module workers.** Detection and correlation are separated from capture, parsing, profiling and routing. Bounded queues, state limits, checkpoints and background maintenance support the requirement that a slower detector must not stall the core.

- **Add targeted regression coverage.** Tests cover native multiprocessing, stdin and flow formats, shutdown ownership, daemon management, viewer isolation, history retention, network changes, whitelist matching, detector behavior, P2P validation and web interactions.

- **Exercise real browser and Zeek behavior.** Coverage includes responsive light/dark layouts, preserved investigation state, API and database consistency, related protocol records and synthetic Zeek inputs. These checks go beyond asserting a detector's helper function in isolation.

- **Make test execution portable and isolated.** Test packages and fixtures avoid duplicate module-name collection problems, authenticated Redis is supported, and test setup avoids writing into an active production run. Native Zeek/bro availability and Python-version differences are handled in the relevant tests.

- **Distinguish a code change from an old saved finding.** Detector fixes apply when processing new observations. `--view` reopens saved evidence; it does not rerun every detector and rewrite old scores, severities or descriptions as if they had originally been generated by the new code.

- **Restart for Python and configuration changes.** Existing processes keep the code and settings loaded at startup. Loading new backend or module behavior requires restarting the relevant run; changes needing new Zeek fields require collecting or replaying input with the new scripts.

- **Make optional collection requirements visible.** Packet timing is off by default, service anomalies are opt-in, and detailed HTTP/SMB rules depend on available Zeek metadata. Existing HTTPS, linear ML and online ML modules receive improvements but are not newly introduced detectors in this PR.

### Review basis

This inventory was assembled from the committed comparison against the PR base, the branch's commit history, the existing PR description, and the current implementation guides linked throughout this file. Repeated commits and follow-up fixes are described as their final behavior rather than as separate features.

Creating this draft does not constitute a new full-suite test run or a new deployment verification. Test coverage described above is part of the PR; platform validation belongs to the revision tested and should not be read as a guarantee that every optional integration was exercised on every platform at the latest head.
