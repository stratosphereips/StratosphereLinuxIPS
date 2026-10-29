# Proposed P2P catch-up when returning to a network

Status: design proposal; the protocol and configuration below are not implemented.

## Goal

When a Slips computer returns to a network, learn about recent attacks from
peers that stayed online. Deliver fresh warnings first, retain useful history,
and prevent old or repeated reports from becoming new reasons to block.
Catch-up must run in P2P workers without delaying capture, parsing or profiling.

## What the current implementation provides

- Pigeon discovers peers and uses authenticated libp2p Noise connections over
  TCP. Slips receives authenticated peer identities and connection updates.
- Slips shares local detections and sends blames for locally generated alerts.
  It can request an opinion about a particular IP, but has no network catch-up
  exchange on arrival.
- `GoDirector.process_evaluation_score_confidence()` records incoming reports
  at receipt time. Resending an old blame through this path would not preserve
  its age as the controlling time for evidence and enforcement.
- `ReportValidator.local_report()` normally answers from local observations
  within one hour. Older stored history is not a catch-up feed.
- The trust database compacts older reports into score/count aggregates. Those
  aggregates cannot reconstruct individual incidents, expiry or withdrawals.
- Existing agreement credits, detector dependency groups and analyst feedback
  should be reused. Replaying history must never earn agreement credit again.

Relevant code: `modules/p2p_trust/p2p_trust.py`,
`modules/p2p_trust/utils/go_director.py`,
`modules/p2p_trust/trust/report_validation.py`,
`modules/p2p_trust/trust/trustdb.py`, and `p2p4slips/peer/peer.go`.

## Exchange on arrival

1. Detect an authenticated peer connection on the monitored network. Start a
   catch-up session on first arrival, restart or return to that network. A
   reconnect cooldown prevents brief connection failures from triggering floods.
2. Ask up to three peers for compact inventories: known peers first, with a
   discovery slot for another peer when available. Transfer at most two pages
   concurrently, with a total bandwidth budget shared across all peers.
3. Request current warning state and withdrawals first. Start processing the
   first bounded page immediately; do not wait for all peers or for history.
4. Fetch selected missing incident summaries from the absence period. A
   persisted cursor avoids repeated downloads; a receiver-controlled look-back
   prevents a peer from choosing an unlimited history window.
5. Continue live reports during catch-up. Pause historical transfers when live
   work is queued. Persist accepted progress and resume after interruption.

The exchange is directed to the arriving peer, rather than rebroadcast to the
whole network. Add negotiated protocol support for inventory and page requests
and replies. Unsupported peers retain existing live messaging and are shown as
unable to provide catch-up; they are not penalized for missing this capability.

```mermaid
sequenceDiagram
    participant R as Returning computer
    participant P as Known network peers
    R->>P: Request current warnings and history coverage
    P-->>R: Fresh warnings, corrections and available coverage
    R->>R: Verify author, age, duplicates and trust
    R->>P: Request missing incident summaries in small pages
    P-->>R: Bounded history with original observation times
    R->>R: Show history; evaluate eligible fresh warnings separately
```

An inventory includes the snapshot identifier, original authors represented,
counts by priority, available time coverage, retention gaps, continuation
information and whether the result is truncated. Pages have stable snapshot
ordering and a finite lifetime. A lost or expired cursor requests a fresh
bounded snapshot, not an unlimited replay. A count or signature does not prove
that a malicious sender disclosed everything it knows.

Always fetch current state on return, even when the history cursor is current.
New expiry, correction or withdrawal can change the answer without creating a
new attack. Lower-priority history receives a small reserved transfer share so
that continuing live traffic does not hide corrections indefinitely.

## What is sent

Send compact incident summaries, not every evidence record or triggering flow.
Group repeated local observations by network, target identity, behavior,
protocol and destination service. Keep the victim or affected service when
known. Different behaviors remain separate; a changed target identity starts a
new incident. Incident counts describe observations and never multiply trust.

Each signed record contains:

- Original author peer ID and public-key identity; incident ID and revision.
- Network scope at observation, target IP and available verified host identity.
  Include affected host/service, source/destination roles and direction.
- Evidence type, detector identity/version, confidence, threat and a bounded
  factual description. Link original local evidence/alert IDs when available.
- First and last malicious observation times, issue time, and expiry.
- State: observed, withdrawn or expired. An origin can withdraw its own report
  after correcting a false positive; it cannot withdraw another author's report.
- A signature covering all these fields and a Slips-specific signature domain.

Store receipt time separately. Arrival, reconnection, forwarding or a new
signature does not change the last observation time. Renewal requires new local
evidence of the reported behavior; an ordinary connection or a still-installed
block is not proof that the attack continues.

Forwarded records preserve the original signed bytes. Record both original
author and delivering peer. Ten forwarding peers still represent one source.
Unknown authors can contribute history, but forwarding through a trusted peer
does not inherit that peer's trust. If an origin is reachable, request its
latest revision before considering a relayed record for enforcement.

## Freshness and priorities

Proposed initial policy, to be tested and made configurable:

| Class | Selection | Receiver behavior |
| --- | --- | --- |
| Corrections | New withdrawal/revision affecting a retained record or block | Process promptly and recompute only decisions supported by that record. |
| Fresh warnings | Malicious behavior observed within 15 minutes | Display immediately; eligible for further checks, with stricter freshness for blocking. |
| Recent incidents | Last observed within 24 hours | Fetch high/critical first, then other relevant alerts; warn without automatically blocking from history. |
| Older history | Within seven days | Compact summaries and counts, newest and most severe first; detail on demand. |
| Expired action validity | Past the receiver's allowed validity | Keep as history within retention; never renew action validity just because it was downloaded. |

“Fresh” means recently observed; it does not prove that the attack is still
ongoing. The web must show the last observation time. Lower confidence with age
when calculating current action support, without changing the original saved
confidence or threat. Hard expiry still applies even if the sender claims a
longer lifetime. Reject excessive future timestamps; quarantine clock problems
for display instead of treating them as fresh authority.

After a week away, a receiver might learn that one host scanned the network
yesterday and that another host was observed exploiting SMB two minutes ago.
The second warning is processed first. Thousands of old scan records become one
incident summary per author/behavior/target, with counts and available detail.
An old unresolved report remains visibly unresolved, not automatically ongoing.

If the requested week exceeds retained coverage, explicitly show the missing
interval. No response, expired data, an empty inventory or a partial transfer
does not establish that the network was safe.

## Protection and adversarial peers

Catch-up storage is separate from current local detection scores. Historical
imports do not cross today's host alert threshold, train benign behavior,
reward a peer, or enter all-time score aggregates used for blocking.

One accepted peer report can produce an immediate visible warning. Automatic
protection requires a separate decision using only fresh, unwithdrawn reports
from the current network. Proposed blocking gate: high/critical behavior with
confidence at least 0.9, last malicious observation within five minutes, and
either qualifying local confirmation or sufficiently trusted corroboration
under Slips' existing detector-dependency rules. Two arbitrary peer IDs or two
copies of the same detector output are not sufficient by themselves. Existing
whitelists and operator enforcement settings apply; catch-up does not enable
firewall blocking or ARP poisoning when they are disabled.

Use short receiver-owned block leases, initially five minutes. A lease is a
temporary block tied to a specific decision; it ends unless fresh support renews
it. Refresh only
from new qualifying observations. Expiry or withdrawal recomputes support;
release only the lease owned by this decision, preserving unrelated manual or
local blocks. Until lease ownership and support tracking exist, catch-up should
warn and retain history without automatic enforcement.

Private IPs may have been reassigned during the absence. Old private-IP reports
remain associated with their original network and observed host identity. Use
verified directly observed neighbor identity when available, never a routed
packet's gateway MAC. An old IP alone is insufficient to identify today's
occupant for blocking. Fresh public-IP reports also require expiry because
public addresses can change owners.

Additional controls:

- Verify origin signatures and bind public keys to peer IDs. Bind inventory
  and page replies to the authenticated requester, a random request nonce,
  network context and the expected snapshot. Validate schema, lengths, times
  and quotas before accepting records.
- Deduplicate signed revisions by author and incident. Keep replay rejection
  information and withdrawal records for at least the entire accepted replay
  horizon, including clock allowance. Persist revision/sequence state across
  restarts; a lost journal requires an explicit new generation and full state
  reconciliation. A generation change does not grant new trust.
- Network fingerprints scope records; gateway MAC and subnet are not proof of
  network authenticity. Known peer identities help recognize a returning
  network; managed installations can configure an explicit network identity
  and enrolled peers. Ambiguous matches cannot authorize historical blocking.
- Query multiple peers. Prefer previously known peers without allowing the
  first responder to determine the whole view. Preserve disagreement and
  signed contradictory revisions for inspection. Do not interpret silence as
  a benign vote or a peer's “resolved” claim as a withdrawal of another source.
- Keep transport authentication separate from content trust. A signature proves
  authorship, not truth. Many new peer IDs can belong to one attacker. Strong
  automatic blocking against coordinated fake identities needs enrolled/pinned
  peers or local verification; open discovery alone cannot guarantee it.
- Rate-limit by authenticated peer, connection and global budget, including
  invalid signatures and connection churn. Per-IP limits alone are inadequate
  on shared-address networks. Bad or new peers cannot consume all processing
  or storage ahead of known peers.

Use libp2p's signed-envelope design rather than a new signature format. Its
[signed envelope specification](https://github.com/libp2p/specs/blob/master/RFC/0002-signed-envelopes.md)
defines origin-key verification and signature domain separation.
libp2p's [security considerations](https://libp2p.io/docs/security-considerations/)
distinguish authentication from authorization and explain the fake-identity
problem. Its [Gossipsub security specification](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md)
also provides useful precedents for capped inventories, bounded retransmission
and peer diversity. Pigeon currently uses direct streams; adopting these
principles does not require replacing it with Gossipsub.

## Resource limits and implementation boundaries

Proposed starting limits, not measured performance promises:

| Setting under proposed `local_p2p.catch_up` | Initial value and purpose |
| --- | --- |
| `enabled` | true when local P2P is enabled; catch up automatically. |
| `fresh_minutes` | 15; identify recently observed warnings for the first lane. |
| `recent_hours` | 24; prioritize recent incident detail. |
| `history_days` | 7; bound the default absence window and historical retention. |
| `max_peers` | 3; compare sources without querying the entire network at once. |
| `parallel_pages` | 2; limit concurrent transfer/verification work. |
| `page_records` | 50; cap each page before applying its byte limit. |
| `page_bytes` | 65536 decoded bytes; reject oversized pages before allocation or decoding. |
| `record_bytes` | 8192; bound a signed record, including text and provenance. |
| `transfer_kib_per_second` | 64 total; keep catch-up from dominating network or CPU work. |
| `initial_transfer_mib` | 2; stop automatic historical transfer at a visible, resumable limit. |
| `max_records` | 10000 total across retained networks; prevent indefinite record growth. |
| `max_store_mib` | 64; cap the dedicated catch-up store, including replay/withdrawal state. |
| `reconnect_cooldown_seconds` | 60; avoid full exchanges during connection flapping. |

Enforce per-source and global shares inside these limits. Process small batches
and yield between them. Storage fills by replacing superseded revisions and
expiring old history first, retaining withdrawals/replay protection before
optional history. If essential state cannot fit, decline more imports and show
partial coverage rather than forgetting protection and accepting stale replay.

Keep a bounded incident/transfer journal in the permanent P2P runtime directory
so restart or a new output folder does not forget the network cursor. Index by
network, priority, observation time and author/revision. Do not scan detection
archives on every join or add per-flow lookups to the core. Build summaries from
existing local evidence/alert notifications in the P2P worker. Detectors that
need to renew a continuing incident can emit a bounded update in their own
worker; ordinary packet traffic cannot renew it automatically.

Pigeon must impose wire-size limits and read deadlines before its current
newline-based buffering. Limit encoded size as well as decoded size; do not
allow compressed catch-up payloads initially. Python validation happens too
late to protect an unbounded Go stream reader. Catch-up queues must not delay
live P2P messages or retain unbounded Redis state.

## Web presentation

Add a **Network catch-up** section inside P2P with:

- State: connecting, receiving current warnings, receiving history, up to date
  with responding peers, partial, unsupported, or no peers available.
- Arrival time, requested interval, verified available coverage, source peers,
  counts, bytes, last progress and a cancel/resume or load-more action. “Up to
  date” never promises that every attack on the network is known.
- Fresh warnings above historical incidents. Rows show source, target,
  behavior, affected host/service, threat, original confidence, last observed,
  received, expiry, author count, and action taken with its reason.
- Separate badges for received during catch-up, forwarded, expired, disputed
  and withdrawn. Retain both author and delivering peer.
- One compact diagram for who observed/reported what and to whom. P2P Graph
  can filter catch-up traffic and expand a batch into its incident summaries;
  forwarding edges do not become additional witnesses.
- History is visibly separate from today's local evidence/alert counts. A
  warning promoted to current P2P evidence links to the original signed record
  and preserves both detection and receipt times.

Do not send triggering packet contents or full flow records by default. This
keeps transfer small and avoids turning network catch-up into bulk capture
sharing. Only authenticated peers accepted by the local sharing policy can
request inventories or history.

## Delivery and validation plan

1. Add bounded incident storage, original timestamps, expiry and withdrawals;
   test these independently of network transfers.
2. Add negotiated directed catch-up with bounded framing, signed origins,
   inventories, stable pages, resumable progress and legacy compatibility.
3. Add P2P web progress, coverage, history and graph integration. Ship warning
   and history behavior before allowing catch-up-triggered blocking.
4. Add fresh corroboration, target-identity checks and owned enforcement leases;
   enable automatic protection only after these checks pass.

Test a return after minutes and after a week; no peers; one known peer; many
peers; old/unsupported peers; changing networks with identical private ranges;
DHCP reassignment; restart and lost cursors; author offline with signed relays;
false-positive withdrawal; packet loss; simultaneous returning peers; fake
identities; replay and revision rollback; altered signatures; forged future
times; contradictory reports; oversized frames; slow streams; floods of new
incident IDs; retention gaps; storage exhaustion and partial transfer recovery.

Verify that catch-up and replay cannot repeatedly increase trust or current
host score, renew stale expiry, bypass a whitelist, enable disabled blocking,
or remove an unrelated block. Benchmark capture throughput, queue sizes and
memory during a deliberately large catch-up on Linux, macOS and Raspberry Pi.
Set a measurable acceptable throughput regression before enabling the feature;
the design does not claim a zero overhead result before measurement.
