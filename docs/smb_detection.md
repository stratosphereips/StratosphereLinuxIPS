# SMB behavior detection

The `smb_analyzer` module detects suspicious use of Windows file sharing and
remote administration from Zeek records. It does not inspect packet bodies,
extract files, match malware domains, or classify particular IP addresses as
malicious. It works with live captures, PCAPs and previously generated Zeek logs.

## What the module detects

All findings are attributed to the initiating client. The record identifies the
actual destination, the supporting connection/event IDs and the detection reason.

| Evidence type | Required observations | Default threat / confidence |
| --- | --- | --- |
| `SMB_SCAN` | At least 20 distinct TCP/139 or TCP/445 targets within 60 capture seconds, with at least 80% failing to establish TCP. Requires fresh SYN attempts, not session tails. | Medium / 0.85 |
| `SMB_SHARE_SWEEP` | Share mappings across at least 8 servers, or at least 10 distinct share names, in 60 seconds. | Medium / 0.80 |
| `SMB_SHARE_IP_MISMATCH` | The literal server IP in a requested share path differs from the connected server IP. Reports the first occurrence, independently of session size. | Low / 0.90 |
| `SMB_SHARE_PATH_MISMATCH` | The same literal server IP inside a UNC path differs from at least 3 actual destination IPs. DNS aliases are not compared to IPs. | Medium / 0.75 |
| `SMB_SUSPECTED_PROPAGATION` | Repeated mismatched share paths together with probing or share access involving at least 20 hosts in the same period. | High / 0.90 |
| `SMB_EXTERNAL_CONNECTION` | SMB protocol or a share mapping was observed with a globally routable destination outside explicitly approved external networks. A TCP/445 attempt alone is insufficient. | Low / 0.80 |
| `SMB_LARGE_TRANSFER` | An SMB-confirmed session sent or received at least 4 MiB. This describes session volume, not an individual file transfer. | Info / 0.95 |
| `SMB_LARGE_FILE` | A read/write/close record references a file with a reported size of at least 100 MiB. Its size does not prove that all bytes were transferred. | Info / 0.80 |
| `SMB_SUSPICIOUS_TRANSFER` | At least 4 MiB sent by the client over SMB, together with recent SMB scanning or repeated mismatched share paths across multiple servers. | High / 0.85 |
| `SMB_REMOTE_EXECUTION` | An executable filename was written to an administrative share, then the same client requested service creation/start on that server within 15 minutes. | High / 0.85 |
| `SMB_PASSWORD_GUESSING` | At least 10 distinct connections with explicit authentication failures within 60 seconds. | Medium / 0.85 |
| `SMB_PASSWORD_SPRAYING` | The failure threshold is met across at least 5 known accounts or 5 servers. Password values are unavailable, so reuse of one password is not proven. | High / 0.85 |
| `SMB_RAPID_FILE_CHANGES` | Writes, renames or deletions affect at least 30 distinct files within 60 seconds. | Medium / 0.80 |
| `SMB_RANSOMWARE_BEHAVIOR` | At least 20 distinct files are renamed and at least 10 distinct files are written/deleted within 60 seconds. | High / 0.85 |

These are separate observations. The existing horizontal port-scan module also
continues to work. SMB findings add protocol-specific context; they do not
replace or disable the general scan detector.

## Threat and confidence mean different things

**Threat** describes how serious the observed behavior is. A large ordinary file
copy is informational. Widespread probing followed by substantial data delivery,
or executable writes followed by service requests, is more serious and defaults
to high. IPC$ access by itself is ordinary Windows behavior and does not produce
an attack finding. Bulk changes can also result from backups or authorized IT
work, so bulk changes alone have medium threat.

**Confidence** describes how clearly the records support the named behavior. It
is not a probability that the client is infected, and not a probability that an
exploit succeeded. Direct byte counts have high observation confidence. Share
path differences have lower confidence because translation or unusual server
configuration can explain them. Correlated behaviors have stronger supporting
context, while still leaving the execution/infection result unproven.

Every rule's `enabled`, `threat_level` and `confidence` can be changed under
`smb_analyzer.rules` in `config/slips.yaml`. The global
`DisabledAlerts.disabled_detections` list also accepts every type above. Existing
IP/port/evidence-specific rules in `config/whitelist.conf` remain available for
known authorized activity. `external_allowed_networks` suppresses only the
external-SMB finding; it does not exempt a server from the other checks.

## A share path names a different server IP

In `output/pcap-case-17`, client `192.168.1.112` connects to
`192.168.1.135:445` but requests `\\192.168.56.20\IPC$`. The TCP destination is
`192.168.1.135`; the address inside the path is a value sent in the SMB request.
The path does not show a second connection to `192.168.56.20`.

`SMB_SHARE_IP_MISMATCH` reports this discrepancy immediately with low threat
and confidence 0.90. It identifies the initiating client, connected server and
requested path, and contributes to the client's score through the normal
Evidence Handler. A large session can produce its separate volume evidence too.
Repeated requests by the same client to the same server are limited by
`cooldown_seconds`; another destination can produce its own mismatch finding.

This is suspicious because a client can reuse a hardcoded share path against
unrelated servers. NAT or a server with multiple addresses can also explain a
single discrepancy. Hostnames are excluded from this comparison because a name
can legitimately resolve to the connected IP. Matching literal IPv4/IPv6
addresses are excluded too. This check uses only Zeek SMB metadata and performs
no DNS lookups or core-flow processing.

`mismatch_min_hosts` still controls the stronger `SMB_SHARE_PATH_MISMATCH`
finding: by default, the same path IP must disagree with three distinct server
IPs within `window_seconds`. Propagation and suspicious-transfer rules retain
their additional requirements. Configure, disable or whitelist the new evidence
type independently using the same controls as the other SMB findings.

The share path is carried inside the SMB tree-connect request; see Microsoft's
[SMB2 share connection specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/decadb64-9619-46e5-8892-c634213396d2).

## The example connection to 36.239.158.54

In `output/pcap-case-16`, the client `192.168.1.120` scans many SMB destinations,
then sends 5,410,965 bytes to `36.239.158.54` on a connection Zeek recognizes as
SMB. A share mapping is also recorded for the connection. The module reports the
volume as informational and the combination with scanning as a suspicious
transfer with high threat and 0.85 confidence by default.

A mapping demonstrates that SMB progressed far enough for Zeek to record a
server reply. It does not establish successful malware installation, remote
execution or even that those bytes represent one file. Connection summaries
also cannot measure exactly how many bytes came before/after a particular SMB
operation. No address or domain from this capture is embedded
in a detection rule.

## Input records and future captures

The module consumes `conn.log`, `smb_mapping.log`, `smb_files.log`, `smb_cmd.log`,
`ntlm.log` and `dce_rpc.log`. Both JSON and TSV are supported. Each SMB operation
gets its own stable stored event ID while retaining its original connection UID.
The web joins the individual operations to their connection using indexed
lookups. File operations on one connection cannot overwrite each other.

Slips loads `zeek-scripts/smb-behavior.zeek` for new captures. It adds:

- An actual operation timestamp to SMB file records. Zeek's original `ts` can be
  the time a file was first seen rather than the time of a later action.
- A file-handle identity, including its original open timestamp when available,
  to avoid counting successive renames of one handle as many files.
- At most one read and one write record per file handle, plus a close record.
  Writes are not logged once per data chunk. Rename/delete/open logging follows
  Zeek's normal policies.
- Failed session-setup command replies. Successful/intermediate authentication
  and other SMB commands are excluded from this additional command log.

`log_file_operations` and `log_authentication_failures` control these additions
when Slips starts Zeek. Disabling the module disables the extra logging too.
Existing Zeek directories are read as supplied: Slips cannot recover fields or
operations that were never logged. Rerun the PCAP to obtain the additional
metadata. The current `pcap-case-16` output has share mappings and connection
summaries, but no file-operation or authentication records; it cannot establish
ransomware file changes or password failures from those missing logs.

Only an explicit NTLM failure or a configured `authentication_failure_statuses`
session-setup result counts as an
authentication failure. An absent result, rejected TCP connection, access-denied
file request or unfinished authentication exchange does not count. NTLM and SMB
reports for the same connection count once; the detector conservatively counts
connections, not individual password guesses hidden inside one connection.

SMB file-action records establish that operations were observed; they do not
prove that every requested write, rename or deletion succeeded.
RPC operation names establish that a service operation was requested. Standard
Zeek RPC records do not establish its return code or successful program
execution. SMB encryption, unsupported SMB commands, capture gaps and
local-only filesystem changes can limit visibility. Missing data does not
establish that an action did or did not occur.

## Configuration and resource use

Every option is explained beside its value in `config/slips.yaml`.

- `window_seconds` controls the short behavior counters. `correlation_seconds`
  connects scans to transfers and writes to service requests. These are capture
  seconds; old PCAPs are not compared to today's clock. There is no training step.
- `max_lateness_seconds` accepts records arriving behind the newest capture
  timestamp. Counters still use only their configured time intervals and bounded
  retained context; late data cannot recreate context already discarded.
- The `scan_*`, `share_*`, `mismatch_*`, `propagation_*`, `auth_*`, `spray_*`,
  `file_change_*` and `ransomware_*` options control the counts in the table.
  Counts are distinct hosts, connections or files, rather than packets/chunks.
- `large_transfer_bytes` and `large_file_bytes` are byte thresholds. They have
  different meanings: observed session bytes versus reported file size.
- `ports`, `executable_extensions`, `admin_shares` and
  `remote_service_operations` define which protocol endpoints, filenames and
  administrative actions participate in the rules. They are configurable to
  accommodate different networks and deployment tools.
- `cooldown_seconds` limits repeated findings. Source-wide behaviors use a
  per-source/rule cooldown; external, transfer and service findings also separate
  destination servers. Distinct evidence types have independent cooldowns.
- `evaluation_interval_seconds` limits repeated scan evaluation; another
  `scan_min_hosts` probe observations also causes evaluation, so a fast burst
  does not require a later packet to be detected.
- `max_sources`, `max_events_per_source`, `max_total_events`, `max_sessions` and
  `max_cooldowns` are hard ceilings. Older context is discarded when necessary
  and a rate-limited warning reports that limit. It can reduce detection
  coverage; it does not delete the raw records already saved in the run database.

The module uses one ordinary Slips worker. It merges the connection and SMB
notification queues by capture timestamp, retaining at most one pending record
per queue. An empty queue is checked only once per batch, which avoids extra
per-connection Redis polling. Reopening one filename does not count as many
changed files; observed handle IDs and rename chains preserve file identity.

It adds no Redis keys, per-flow SQL
lookups, checkpoint database, body buffers or payload extraction. In-memory
context is isolated by run/interface/network, bounded, and expires as traffic
advances. After a restart its short correlation windows start empty; saved
findings and raw records remain available. Normal Slips flow retention and
archive policies also apply to the stored SMB events. Supporting event IDs are
linked to evidence so the existing retention policy can preserve them.

For the Zeek field definitions, see the official [SMB reference](https://docs.zeek.org/en/current/scripts/base/protocols/smb/main.zeek.html),
[NTLM reference](https://docs.zeek.org/en/current/scripts/base/protocols/ntlm/main.zeek.html)
and [DCE-RPC reference](https://docs.zeek.org/en/current/scripts/base/protocols/dce-rpc/main.zeek.html).

## Confidence growth and continuing SMB scans

`SMB_SCAN` and `SMB_SHARE_SWEEP` now use the shared [scan progress policy](scan_progress.md).
The configured per-rule confidence is their initial confidence, not a ceiling.
For a host scan, 95% requires at least twice `scan_min_hosts` (minimum 20) with
90% explicit failed SYNs; 100% requires ten times it (minimum 100) and 95%
explicit failures. At defaults, 200 distinct hosts can confirm the pattern.
Unknown packet history and retransmissions cannot supply this support.

Share sweeps count distinct actual servers or distinct share names. Confidence
can reach 95% at twice the respective threshold (minimum 20), then 100% at ten
times it (minimum 100). This supports the observed broad access; authorized
administration remains another explanation, and the threat stays medium.

At confirmation, exact probe/share records are released. A fixed 1 KiB counter
for the confirmed dimension and at most 20 sample IDs replace them. Later
evidence reports approximate growth near 1,000, 10,000, and so on. Stronger
confidence and continuation milestones bypass `cooldown_seconds`; a gap that
long without qualifying probes/mappings starts fresh tracking. Other bounded
SMB correlations continue, including suspicious transfers after scanning.
Disabled scan evidence can still use compact state for these correlations.
Authentication, propagation, remote execution and file-abuse rules retain their
configured confidence; bulk activity does not automatically make those claims certain.
