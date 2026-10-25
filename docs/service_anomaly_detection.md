# Service anomaly detection

`anomaly_detection_services` learns which computers normally connect to a
service, what hours they connect, and how long their connections last. After
learning, it reports connections that differ from what it has seen before.
An unusual connection is a reason to investigate, not proof of an attack.

A **service** is one computer's TCP or UDP port that Slips has seen answer a
connection. A **client** is the computer that starts the connection. For example,
SSH on computer A's TCP port 22 is one service. If computer B usually connects
to it, Slips can later report computer C trying to connect, B connecting at an
unusual hour, or B making a connection that lasts much longer than usual.

It also reports a **newly active service**: a local port first seen answering
after that computer's training window. This check works even when the computer
received no connections during training. It describes what Slips observed;
it cannot tell when the operating system actually opened the port.

**Training means learning what is normal from the connections Slips observes.**
Slips saves this information and uses it to check later connections. In the
code, this saved information is called a model. Slips remembers answering ports
for each host, and separately the usual clients, connection hours and connection
lengths for each service.

The module checks each connection when its Zeek record arrives. It currently
uses TCP and UDP connection records, rather than application-specific details
such as SSH logins or HTTP requests. Length checks currently apply only to
normally completed TCP connections.

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

The default is `enabled: false`. Restart Slips after changing the configuration.
Client, hour and connection-length checks learn separately for each service:
connections to one port do not train another port. The new-service check learns
the set of answering ports for the computer as a whole. This module is separate from the
HTTPS detector; enabling one does not enable the other.

All settings below belong under `anomaly_detection_services` in
`config/slips.yaml`, or in the custom configuration for your run.
Each setting is explained next to its value in the main configuration. When
using a custom file such as `config/slips-sebas.yaml`, edit that file; changes
to the main configuration do not replace values in your custom file. An omitted
service-detector setting uses the default listed below.

### Turn the module on and choose how it learns

| Setting | Default | What it does and why |
| --- | --- | --- |
| `enabled` | `false` | Turns this detector on. Set it to `true` when you want Slips to start learning connections and checking them for changes. |
| `mode` | `auto` | Chooses whether Slips learns, checks connections, or does both. The three choices are explained below so you can decide when to accept changes as normal. |
| `timezone` | `UTC` | The local timezone used to learn usual connection hours and distinguish weekdays from weekends. For example, `Europe/Prague` makes 09:00 mean 09:00 in Prague, including summer/winter clock changes. |

- `auto`: first learn normal connections for each service, then report unusual
  ones. After initial training, normal connections from known clients can
  continue teaching Slips if `adapt_known_clients` is enabled.
- `train`: learn successful connections without producing evidence of unusual
  behavior. Use this to teach Slips about legitimate new clients or changed
  habits, then return to `auto` or `detect`.
- `detect`: check connections using saved learning. Do not accept new ports or
  clients as normal, or change the learned connection hours or lengths. A trained
  host can report a new answering port even without a client list for that port.

### How much to learn for client, hour and length checks

| Setting | Default | What it does and why |
| --- | --- | --- |
| `training_hours` | `168` (7 days) | Hours spent learning before checking for changes. For each service's client, hour and length checks, time starts at its first observed reply. For the new-service check, time starts when the host is first observed; the capture computer starts at capture startup. Longer windows allow more normal services and clients to appear. Fractional hours are allowed; `0.0167` is about one minute. |
| `min_training_connections` | `30` | Successful connections Slips must learn for that service before checking unfamiliar clients, unusual hours or connection lengths. These checks need actual examples, while the new-service check does not. Failed attempts do not count. |
| `min_training_days` | `3` | Different UTC calendar dates with learned successful connections required for the per-service checks. This prevents thirty connections in one busy minute from representing several days of normal activity. It does not delay new-service findings. |

**All three requirements must pass for the per-service checks.** Lowering `training_hours` alone does not
remove the connection-count or observed-day requirements. Setting it to `0`
removes only the elapsed-time wait.

These hours come from **connection timestamps**, not how long Slips has been
running. When analyzing a PCAP, seven recorded days can be processed without
waiting seven real days. Gaps between connections count toward elapsed hours,
but days with no learned connections do not count toward `min_training_days`.
Restarting resumes saved learning; it does not restart the training clock.

During training, Slips assumes the connections it learns are normal. It skips
learning from records explicitly labeled malicious, malware or attack. A TCP
connection can teach a normal client once it is established, even if it has not
finished yet; UDP needs packets in both directions. Failed attempts cannot
teach Slips that a new client is normal.

### When to report a newly active service

| Setting | Default | What it does and why |
| --- | --- | --- |
| `detect_new_services` | `true` | Report a local TCP or UDP port first seen answering after the host's `training_hours` window. This catches services that had no training connections at all. The module itself must also be enabled. Set this to `false` to keep only the client, hour and connection-length checks. |
| `max_hosts` | `1024` | Maximum local computers whose answering ports are remembered. This bounds memory; additional hosts are skipped rather than judged from missing learning. |
| `max_new_services_per_host_hour` | `10` | Maximum new-service evidence records for one computer per UTC hour of connection timestamps, across all its ports. This prevents a burst of new ports from flooding evidence. The usual per-service limit still applies to client, hour and length findings. |

For example, set `training_hours: 0.0167`, leave Cherry without inbound
connections for at least 61 seconds, then connect from the Pi to a previously
unseen answering port. That first answered flow can produce `ANOMALOUS_FLOW`
evidence explaining **newly active service**, even with
`min_training_connections: 5`. Those five connections are required for the
per-service checks, not this host-wide check.

The capture computer starts its clock from capture startup on the current
network, even when it is quiet. Other local computers start when first observed
in an eligible unicast TCP/UDP flow, including outbound activity. An unanswered
probe cannot prove that an otherwise unseen destination exists or has an open
port. Remote Internet servers are excluded from this check. For recorded input,
private hosts start at their first eligible connection timestamp; no real-time
wait is needed.

TCP needs an observed establishment or SYN/SYN-ACK; UDP needs packets in both
directions. A refusal or silent probe does not count. A flow that started during
training stays part of training even if its Zeek record arrives later. Close a
test connection so Zeek can deliver its connection record.

Newly active ports stay unusual until accepted using `mode: train`; they do
not teach Slips a normal client list automatically. Repeated warnings use
`alert_cooldown_seconds` and the host-wide hourly limit above. Changing back to
`auto` or `detect` preserves the ports accepted during explicit training.

Hosts are kept separately for each network and verified local device identity.
IP changes or temporary missing MAC information do not alone make a remembered
port new. Switching networks or replacing a device starts separate learning.
Learning and warning counters survive a restart. Elapsed timestamp gaps do not
prove that capture was continuous; review findings after outages or long gaps.
Existing per-port learning is preserved when upgrading, so a port already learned
by the old detector is not reclassified as new. For a fresh test, choose an
unused port or an isolated test directory; do not delete live learning.

### When to report an unusual hour

Slips remembers connection times in half-hour intervals, separately for
weekdays and weekends. It keeps a record for each known client and a combined
record for the service. A client without its own history can be checked using
the service's history; the evidence description tells you when that happens.

| Setting | Default | What it does and why |
| --- | --- | --- |
| `time_min_days` | `14` | Different local calendar dates with learned connections required before checking whether an hour is unusual. This gives Slips several days of examples of when connections normally happen. Days without connections do not count. |
| `time_min_matching_days` | `3` | Different weekday dates with learned connections required to check a weekday connection, or weekend dates to check a weekend connection. This prevents Slips from calling Saturday activity unusual just because it has only learned Monday-to-Friday habits. |
| `time_probability_threshold` | `0.01` | Slips gives each half-hour a value based on how often it appeared in learned connection times, with some allowance for nearby hours. It reports an unusual hour only below this limit. Raising the limit reports more hours as unusual; lowering it reports fewer. This value is not the probability of an attack. |
| `time_min_concentration` | `0.35` | How strongly learned connection times must gather around particular hours before Slips checks for unusual hours. The range is `0` to `1`. Higher values require a clearer daily routine, reducing warnings for people with irregular hours. `0` removes this requirement, which is useful for short tests. |

The initial service training requirements must also pass. Fourteen dates with
connections do not automatically establish a reliable schedule: those
connections might occur at all hours. Slips avoids reporting an unusual hour
unless the learned hours are consistent enough for `time_min_concentration`.

A burst of connections counts once per half-hour on each date, so a busy minute
cannot establish a daily habit. Neighboring half-hours share some allowance,
including across midnight, so a small shift in connection time is less likely
to cause a warning. Several usual connection times can coexist.

Only dates within `history_days`, up to the connection's start date, contribute
to this check. Missing traffic does not prove that a person was inactive.
Holidays, occasional late work and capture gaps can still cause false alarms;
check the results against later normal traffic, including weekends. Changing
`timezone` clears the learned connection hours so Slips can learn them again;
it preserves learned clients and connection lengths.

### When to report an unusually short or long connection

Here, length means **seconds from the start to the end of a TCP connection** as
reported by Zeek. It does not mean how long someone was logged in to an
application. Slips learns lengths only from normally completed TCP connections
(Zeek state `SF`) with an observed reply. Failed attempts, unfinished TCP
connections and UDP records do not teach or trigger this check.

| Setting | Default | What it does and why |
| --- | --- | --- |
| `duration_min_samples` | `50` | Completed TCP connections whose lengths must be learned before checking for unusual lengths. This avoids deciding what is normal from only one or two examples. It must be at least `10` and no greater than `duration_samples`. |
| `duration_samples` | `128` | Maximum number of learned connection lengths kept for each client and for the service as a whole. More examples use more memory and keep older habits longer; fewer adapt to changes sooner. The allowed range is `10` to `512`. |
| `duration_zscore` | `4.5` | How far a connection length must differ from learned lengths, measured relative to how much those lengths normally vary. Higher values require a larger departure and produce fewer findings. The number is neither seconds nor a length multiplier. This check gives less weight to a few extreme past lengths. |
| `duration_ratio` | `3` | A long connection must exceed the upper end of the learned length range multiplied by this number. A short one must be below the lower end divided by it. This avoids reporting small proportional changes and allows both short and long connections to be normal. |
| `duration_min_difference_seconds` | `30` | Minimum difference in seconds beyond the applicable lower or upper end of the learned range. This avoids reporting tiny absolute changes, such as fractions of a second, even when their ratio is large. |

The three difference checks must **all** pass, in addition to the training and
sample requirements. For example, if the learned upper end is 120 seconds,
`duration_ratio: 3` requires a long connection to exceed 360 seconds. It must
also pass the other two checks. Raising any of the three limits makes length
findings less frequent.

The learned lower and upper ends come from near the shortest and longest past
lengths (the 1st and 99th percentiles). Slips keeps both ends instead of treating
one average as the only normal length. This lets a service normally have both
short and long connections.

### Keep learning and limit memory use

| Setting | Default | What it does and why |
| --- | --- | --- |
| `adapt_known_clients` | `true` | After initial training, keep learning from successful connections by known clients when no unusual behavior was found. This lets normal habits change gradually. `false` stops this automatic learning; `mode: train` still learns. Unfamiliar clients are not added automatically after training. |
| `history_days` | `56` | Days of past connection times kept to learn usual hours. Older times are forgotten so routines can change and memory stays limited. This setting does not delete the list of known clients or the saved connection lengths. |
| `retention_days` | `90` | Forget a service, client or host after this many inactive days, measured using connection timestamps. Answered connections keep a port active; successful connections keep a known client active. Observed host traffic keeps its inventory active; the capture computer also has a quiet-host refresh. Inactive ports expire even on an active host. A returning host needs fresh training; a forgotten port or client may be reported as unfamiliar. |
| `max_services` | `4096` | Maximum service/client baselines, and separately the maximum total ports in the local-host inventory. Each list has this cap. This bounds memory. Full client-model storage skips extra services. A host whose port list is incomplete stops producing new-service findings, rather than misclassifying forgotten ports. |
| `max_clients` | `4096` | Maximum number of client-to-service records across all services. One computer connecting to two services uses two records. This limits total memory spent remembering clients. |
| `max_clients_per_service` | `64` | Maximum clients remembered for one service. This prevents one busy port from using all the available client records. |

If either client limit prevents Slips from remembering everyone for a service,
it stops reporting unfamiliar clients for that service. Otherwise, a missing
entry could falsely make a known client appear new. Checks for unusual hours
and lengths can still work. Slips logs a warning when these limits are reached.

The three minimum observed-day settings must each be between `1` and
`history_days`. Lower limits let checks start sooner but give Slips fewer
examples of normal behavior.

### Limit repeated warnings and save learning to disk

| Setting | Default | What it does and why |
| --- | --- | --- |
| `alert_cooldown_seconds` | `3600` | Wait this many seconds of connection timestamps before repeating evidence for the same client, service and combination of reasons. The module remembers the most recent 16 such combinations per service. For a newly active service, the wait applies to that host and port across all clients. This reduces repeated warnings; `0` removes the wait. |
| `max_alerts_per_service_hour` | `10` | Maximum evidence records for one service per UTC clock hour in connection timestamps. This limits floods of warnings even when many different clients connect. The limit is per service, across all its clients. |
| `flush_interval_seconds` | `30` | Real seconds between saving learned information to disk. A shorter interval loses less learning after a crash but writes to disk more often. Slips also saves on a normal shutdown; an abrupt stop can lose changes since the last save. Connections are checked as they arrive, without waiting for this interval. |

These warning limits do not remove the original connection records. The module
creates one `ANOMALOUS_FLOW` evidence record per reported connection, explaining
all the unusual things found. It includes the original connection identifier
(Zeek UID), client, server, ports and timestamp. Evidence has low severity;
Slips' normal rules decide whether enough evidence exists to create an alert
or take a prevention action. A whitelist `blocking` rule can keep evidence
while preventing firewall blocking or ARP poisoning for the listed computer.

## Short functional tests

Use these overrides in a separate test run:

```yaml
anomaly_detection_services:
  enabled: true
  mode: auto
  timezone: UTC
  training_hours: 0.0167  # Learn for about one minute of connection timestamps.
  detect_new_services: true
  min_training_connections: 10
  min_training_days: 1
  time_min_days: 1
  time_min_matching_days: 1
  time_probability_threshold: 0.03
  time_min_concentration: 0
  duration_min_samples: 10
  alert_cooldown_seconds: 0
```

Learn ten successful connections from client A to one service, spanning about
one minute. A later attempt by client B can then produce evidence, even if the
service does not answer B. If A's ten TCP connections finished normally, they
also allow Slips to check later connection lengths. The normal difference
limits still apply. Ten connections to ten different services do not satisfy
the ten-example requirement for one service.

For the quiet-host case, use the same settings, wait at least 61 seconds after
capture startup without inbound connections to the capture computer, and then
connect to a new answering port. No ten-connection prerequisite applies to this
new-service check. Use a port Slips has not learned previously.

To test unusual hours, replay connections at a regular hour followed by one at
a distant hour on the same date. Recorded timestamps let Slips process this
without waiting for the real clock to reach that hour. These short settings
make it possible to test that the checks work; they do not provide enough
history to learn a person's usual schedule. Use the default learning periods
for normal operation and assess the results with representative traffic.

Finite PCAP runs keep their learned information separate from live capture.
For a separate live test, use a separate `parameters.permanent_dir` along with
the usual separate Redis/output settings. Returning to normal settings does
not erase information learned in a test.

## Which connections and computers are remembered

A successful TCP establishment or an observed SYN followed by SYN-ACK can show
that a port answers. A refusal/reset alone cannot. UDP needs packets in both
directions. Once a service has finished initial training, unfamiliar attempts
can be reported even when unanswered or rejected. Multicast, broadcast, ICMP, self-connections,
invalid ports and TCP records with an unclear connection direction are ignored.
Directed IPv4 broadcasts are also ignored when Slips knows the monitored subnet.

Slips remembers services separately for each network, computer, transport
(TCP/UDP) and port. The router's MAC address and subnet distinguish networks,
including two networks with the same private IP range. A verified local MAC
address can identify a computer across IP changes; a router's MAC address is
never used as the identity of a computer behind that router. Slips uses the
network recorded at the connection's time when connections finish after a
network change.

Without enough information to identify the network, learning belongs only to
the current run. Without a verified local MAC address, Slips identifies the
computer by its IP on that network. If a known computer temporarily loses its
MAC information, or Slips learns its MAC after first knowing only its IP, that
change alone does not justify calling it a new client. A genuinely different
server can need a new training period.

## Where learning is saved and its effect on capture

Live interfaces and growing captures save learned information in
`<parameters.permanent_dir>/anomaly_detection_services/baseline.sqlite`.
Finite analyses save it in their own
`output/<run>/anomaly_detection_services/baseline.sqlite`, so analyzing a PCAP
does not change what the live capture has learned. Slips resumes an existing
file and creates an empty one only when none exists. Only one Slips process can
write each file. If a saved file is corrupt or its format is unsupported, the
module reports an error rather than silently deleting it.

This is a separate SQLite database from the flow and detection-history
databases. If it is busy, saving is postponed rather than waiting and slowing
capture. Service/client counts, saved times, saved lengths and temporary
lookups all have limits. Host inventories and ports use the same single-writer
checkpoint transaction, including clocks for hosts with no answering ports.
The module runs in its own process, adds no Redis
keys, and does not scan all past flows. Checking each new connection still
uses some CPU; measure its cost on the computer that will run the capture.

## Code shared with the HTTPS detector

Both modules use `slips_files/common/anomaly_detection.py`:

- `quantile()` finds a value at a chosen position among sorted past values,
  such as the lower or upper end of usual connection lengths.
- `robust_location_scale()` finds a middle value and how much nearby values
  vary, while limiting the effect of a few extreme observations.

They share these calculations. Each module keeps its own learned information
and decides which behavior to check. Adding another protocol does not require
copying these common calculations or adopting HTTPS-specific rules.
