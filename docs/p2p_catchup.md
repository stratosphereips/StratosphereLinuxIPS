# Learning what happened while a peer was away

When Slips returns to a network, **network catch-up** asks connected Slips peers
for missed warnings. It receives recent malicious observations and corrections
first, followed by compact incident history. It does not replay old blames as
new detections. Enable local P2P as usual; catch-up is enabled by default within
local P2P.

The receiving computer and every source need the updated Python code and Pigeon
submodule. The Pigeon hello advertises catch-up support, and transfers use the
separate `/slips/1.0/catchup/1` stream protocol. Older peers continue exchanging
ordinary live reports and appear as unsupported for catch-up. Slips checks the
installed binary for `-catchup-version` and rebuilds it when necessary. If that
build fails, it disables catch-up while retaining ordinary live P2P.

## What happens on return

1. Authenticate the peer and identify the monitored network by its normalized
   router MAC **and subnet**. Unknown or disconnected networks do not start an
   exchange. A familiar private address range alone is insufficient.
2. Ask up to three supporting peers for current warnings and withdrawals.
   Original authors sign their incident records; a forwarding peer cannot alter
   the signed content or become another independent witness.
3. Fetch history in small pages. Recent incidents precede older incidents;
   higher-threat observations precede lower-threat observations within each
   period. Withdrawals have priority. A stable snapshot keeps pagination from
   skipping records when new detections arrive.
4. Keep a persistent cursor for each peer and network. On a later return,
   request current state again and fetch newly changed historical records.
   Brief disconnects use the configured cooldown. An expired snapshot or changed
   source journal restarts the relevant bounded transfer.

A summary combines repeated observations of the same source, behavior and
service on one network. A known change of source MAC starts a separate summary.
It retains first/last observation times and observation count. Counts are
context, not extra votes. Different protocols, ports and behaviors remain
separate. Source peers retain only their latest revision of each summary.

Catch-up shares detection summaries, not packet bodies or full flow records.
Its incident journal is separate from the capture output's evidence database.
**Imported historical records do not increase current host scores, train a
model, or earn peer agreement credit.** Original observation times, expiry and
confidence remain unchanged when a record is received again or forwarded.

## Freshness, history and corrections

By default, “recently observed” means malicious behavior was observed within
15 minutes. This describes the last observation, not a guarantee that the attack
is still ongoing. A source can renew a summary only when new local malicious
evidence arrives. Forwarding it, reconnecting or retaining an old block does not
renew it.

The default historical window is seven days. An expired warning remains useful
history inside that window, but cannot authorize protection. After a week away,
Slips first receives the newest warnings, then incident summaries for the
available part of the week. It stops at the transfer/storage limits and shows
partial coverage. No response or an empty history does not establish that the
network was safe.

If an analyst marks supporting local evidence as a false positive, expected
behavior, true negative or conflicting, its author publishes a newer withdrawn
revision during catch-up. Only that original author can withdraw that report.
Receivers retain the withdrawal and reject older revisions. Retention preserves
replay/withdrawal state across the entire accepted history window, plus clock
allowance; it does not discard that protection simply to admit more reports.

The journal starts collecting with this feature. Old feedback databases that
lack the router-and-subnet identity are not silently attributed to the current
network. The web shows when collection started, so missing pre-upgrade coverage
is visible. Existing captures and detection archives are not scanned on join.

## Automatic protection

Catch-up can request **temporary firewall protection** when firewall blocking
is already running. It never enables blocking by itself and never requests ARP
poisoning. The default policy requires all of the following:

- Unexpired high/critical reports, with original confidence at least 0.9 and a
  malicious observation no more than five minutes old.
- Either a recent local signature, integrity or honeypot confirmation, with
  maliciousness at least 0.8 and confidence at least 0.9, **or** at least two
  explicitly enrolled author peer IDs contributing independent detector
  families. Repeated copies and multiple versions of the same rule do not
  establish independence.
- For a private target, the report's directly observed local MAC must match the
  receiver's current unicast MAC observation. A routed packet's gateway MAC or
  an old private IP alone cannot identify today's occupant.
- The target is neither this computer nor the current router. The firewall's
  blocking-only whitelist and normal enforcement settings still apply.

The default enrolled list is empty, so discovery or communication reliability
alone cannot authorize remote-only protection. A single accepted source can
still supply visible warnings and history.

Requests last at most five minutes, further limited by the age of the supporting
observations. The firewall stores an ownership marker and expiry using its
existing persistent unblock schedule. A local/manual Slips block takes
precedence; catch-up cannot take ownership of it. A withdrawal or departure
from the network requests removal only of the block owned by that catch-up
decision. Other blocks remain intact. The firewall worker handles expiry even if P2P stops. Normal shutdown releases
catch-up-owned rules. After an abrupt whole-process kill, persistent expiry
metadata is applied when the firewall worker recovers; kernel rules do not
expire themselves while Slips is absent. At most 32 catch-up protection requests
can be active on one network.

A signature proves who supplied a report, not that its contents are true.
Several newly discovered peer IDs can belong to one attacker. Enrolled peers
are an explicit authority decision; colluding enrolled authors remain capable
of lying. The local-confirmation requirement remains available by leaving the
enrolled list empty.

## Configuration

Settings live under `local_p2p.catch_up` in `config/slips.yaml`. Restart Slips to
apply changes. These settings do not change capture or profiling behavior.

| Parameter | Default | What it does and why |
| --- | --- | --- |
| `enabled` | `true` | Start catch-up automatically when local P2P connects. False disables requests, replies and capability advertisement. |
| `fresh_minutes` | `15` | Maximum age of a last malicious observation for the first warning lane. Increasing it shows older warnings early; it does not relax the separate five-minute protection limit. |
| `recent_hours` | `24` | Put incidents from this many hours ahead of older history. This is a transfer priority, not model training or a blocking lifetime. |
| `history_days` | `7` | Request and retain at most this many days of incident history; maximum 30. Increase it for longer absences, at greater storage cost. |
| `max_peers` | `3` | Maximum source peers selected for catch-up. Supported peers take precedence over unsupported peers. More sources provide broader coverage and consume more transfer work. Maximum 16. |
| `parallel_pages` | `2` | Maximum simultaneous outstanding page requests. Lower it to reduce concurrent work on a small computer; maximum 4. |
| `page_records` | `50` | Maximum records in one page. A byte limit can stop it earlier. Smaller pages let live P2P work run between batches; maximum 50. |
| `page_bytes` | `65536` | Maximum decoded catch-up page size, including signature envelopes. Values are clamped to 32768–65536. Go also bounds the encoded frame before buffering it. |
| `record_bytes` | `8192` | Maximum signed incident payload size. This bounds peer-provided descriptions and metadata; maximum 8192. |
| `transfer_kib_per_second` | `64` | Shared outgoing transfer budget in KiB per second, with a bounded page-sized burst. Lower it to reduce catch-up traffic. |
| `initial_transfer_mib` | `2` | Automatic downloaded history budget per source in MiB. Reaching it marks partial history; Resume starts another bounded allowance. |
| `max_records` | `10000` | Maximum retained incident summaries across networks. A separate per-author share limits one author's use. Superseded revisions replace their previous record. Capacity exhaustion declines new records rather than forgetting replay protection. |
| `max_store_mib` | `64` | Maximum allocated incident-journal size before admitting additional incidents. Existing revisions and expiry maintenance remain possible; allow small SQLite/WAL and transfer metadata overhead. |
| `reconnect_cooldown_seconds` | `60` | Delay another automatic exchange after a brief reconnect. This prevents connection flapping from causing repeated full downloads. |
| `protection.enabled` | `true` | Permit the strict protection checks above when a firewall worker is already running. False retains warnings and history without catch-up-triggered enforcement. |
| `protection.peer_ids` | `[]` | Authenticated author IDs explicitly allowed to support remote-only protection. At least two authors and independent detector families are required. Empty keeps local confirmation mandatory. Forwarding peers do not inherit authors' authority. |

## Web interface

Peer labels show the IP address when known and a short peer ID, for example
`192.168.1.170 · QmejkJgt…3GTWQu`. Hover to see the full ID; expandable JSON and
Copy JSON retain the full identities. This applies to progress, requests,
replies and original-author/forwarder details.

Open **P2P → Network catch-up**. It shows per-peer progress, accepted and skipped
records, transferred bytes, collection start and partial/unsupported status.
**Resume** continues a limited or timed-out transfer with another bounded
allowance; **Check again** requests a current update from a completed source.

**Requests and replies** lists incoming and outgoing catch-up messages for the
current run and network: who requested information, whether they asked for recent
warnings or history, and how many records each reply contained. Click a reply
to see the hosts, behaviors and original authors it carried; click a request
to see its history start and request ID. Outgoing messages are labelled as
queued to Pigeon, because queuing alone does not establish delivery. A received
reply establishes that the peer responded. The list uses the newest 100
catch-up messages still present in the existing 1,000-message P2P activity log.

Your own detection summaries are **local summaries available to share**.
Storing them does not send them, and their storage time is not a reception time.
They do not appear in **Incidents received from peers**. With no connected
peers and no exchanges, the panel says so rather than implying a transfer.

The received-incident table separates recently observed, historical/expired and withdrawn
records. It shows original confidence, last observed, author and delivering peer.
Columns are sortable. Clicking a row shows the source and affected host/service,
the author-to-forwarder-to-local delivery path, original and receipt times,
and expandable JSON with Copy JSON. Temporary firewall decisions are labelled
as requests with an expiry, not as proof that rule installation succeeded.

**P2P Graph** includes accepted catch-up deliveries, retaining the original
author separately from the delivering peer. Forwarded copies do not add
witnesses, host score or trust credit. Its existing bounded message history can
expire older delivery edges; durable incident summaries remain in catch-up.

## Files and processing limits

The persistent journal is
`<parameters.permanent_dir>/p2p_trust_runtime/catchup.sqlite`. It contains indexed
incident revisions, short-lived snapshots, per-network/per-peer transfer state
and owned protection decisions. It survives output-folder changes and Slips
restarts. The receiver validates original author signatures in Pigeon using the
libp2p signed-envelope format and a Slips-specific signature domain.

Pigeon imposes encoded/decoded frame limits, read deadlines and per-peer/global
verification limits. Python validates network, request nonce, snapshot position,
record size, original times, expiry and revision before accepting records.
Transfers, queues, snapshots, peer state and storage are bounded. Maintenance
expires data in small batches. All this work runs in P2P and firewall workers;
there are no new lookups, waits or detection hooks in the core per-flow path.

The original design and additional adversarial scenarios are recorded in
[p2p_catchup_plan.md](p2p_catchup_plan.md).

## Validation

On 29 October 2026, the Mac and both StratoGuest RPis (`strato-slips-1` and
`strato-slips-2`) exchanged signed records using real Pigeon processes and
separate test Redis instances. Each RPi supplied a recent observation, a
two-day-old observation and a withdrawal. The Mac received all six, then
disconnected and returned after two additional incidents were added. It retained
the original six without duplication and received the two new incidents.
Forwarded records preserved their original author. Both final transfers
completed. Test processes were removed without stopping the existing live
captures or changing their configurations and whitelists.

The targeted Python regression suite passed 965 tests. The browser test covered
incident states, sorting, original versus forwarding authors, transfer resume
and Copy JSON. Go tests covered signature forgery, forwarding, frame limits
and capability advertisement. Tests use synthetic incident records; these
checks do not measure detection accuracy or full capture throughput.
