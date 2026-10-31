# Scan confidence and continuing scans

Port, SMB, ARP and DHCP scan detectors now use the same memory policy: check
exact observations first, then replace their full lists with a small counter
once the scan pattern is fully supported. ICMP uses counts already supplied by
Zeek, so it needs no local target list at all.

Confidence describes support for the named behavior. A 100% scan confidence
means its observation requirements are fully met. It does not prove infection,
unauthorized intent or successful exploitation. Threat levels stay separate:
for example, broad SMB share access remains medium threat, and an ARP scan
remains low threat. Normal neighbour discovery remains informational.

## How confidence grows

Each detector keeps its existing independent checks. Let `N` be its configured
minimum number of distinct observations, `C` its exact observed count, and `Q`
the fraction satisfying its failure or unfamiliar-target requirements, where
applicable:

- Start with that detector's initial confidence once its rule passes.
- Reach at least **95%** when `C >= max(20, 2 × N)` and `Q >= 90%`.
- Reach **100%** when `C >= max(100, 10 × N)` and `Q >= 95%`.

The independent checks must still pass. Missing packet history, possible
connectivity outages, small ACK/FIN-only patterns and familiar ARP neighbours
cannot acquire certainty from volume alone. Repeated packets and retries to
the same target or port do not increase distinct counts.

| Scan | Distinct observation | Additional requirements and default full-confidence count |
| --- | --- | --- |
| Horizontal SYN scan | Destination IP on one port | Fresh outgoing SYNs, failed-target share and repeated rejections or concentrated address coverage; 100 targets in the fast period, or 250 in the slow period. |
| Horizontal empty-connect scan | Destination IP on one port | Completed handshake, no payload, source closes within three seconds, concentrated address coverage; 100 fast targets. |
| Horizontal UDP scan | Destination IP on one port | Unanswered traffic with concentrated address coverage and failed-target share; 100 fast targets. |
| Vertical SYN/UDP scan | Failed destination port on one host | Confirmed SYN attempts or unanswered UDP; 100 ports by default. Success on a port removes its outstanding failed observation. Missing-history/ACK/FIN cases retain lower confidence. |
| SMB host scan | Destination host | At least 95% explicitly failed outgoing SYNs for full confidence; 200 hosts by default. Missing SYN history retains the initial confidence. |
| SMB share sweep | Server IP or share name | Actual share mappings over the configured period; 100 servers or 100 share names by default. The finding describes broad access, which may be authorized administration. |
| ARP scan | Unfamiliar target IP | Existing novelty, network-history and search-pattern requirements; 100 unfamiliar targets by default. At least 95% must be unfamiliar. Truncated context or heavy observed normal use prevents full-confidence promotion. |
| DHCP scan | Requested address of one client | Distinct requested addresses, separated by client MAC, interface and Slips time window; 100 addresses by default. Renewing one address does not add up. |
| ICMP scan | Host count in a Zeek scan notice | Zeek supplies the count and decides when notices exist. Slips normalizes confidence and reports count growth; it cannot create later milestones if Zeek sends no later notices. |

A configured memory limit below the full-confidence count can prevent reaching
that count. A limit warning means observation context was discarded; it does
not mean retained distinct observations are invalid.

## What happens while the scan continues

At full confidence the detector releases the exact scan list. It keeps a fixed
**1 KiB distinct-value counter** and at most **20 representative flow IDs**.
Horizontal port scans additionally hold at most 31 unprocessed probes so Slips
P2P exclusions can be checked in batches. Other detectors update directly from
their validated events.

Continuing scans produce new evidence near **1,000 → 10,000 → 100,000** distinct
observations, rather than every few packets or every cooldown period. These
growth reports keep the confirmation's confidence and threat level. Their
counts are explicitly marked **approximate**, and their period covers the
continuing scan, rather than a new rolling-window check. A vertical scan has at
most 65,535 possible destination ports; repeats cannot generate ever larger
port-count milestones.

The shared counter uses HyperLogLog with 1,024 registers. Typical relative
standard error is about 3.25%, not a guaranteed bound. The counter is used for
continuation totals, not to make initial exact confirmation decisions. Updates
and estimates take constant work; the implementation maintains its register
sum incrementally. See the [algorithm paper](https://dmtcs.episciences.org/en/articles/3545).

After a qualifying-probe-free gap of the relevant cooldown, fresh observations
must qualify again. For ARP, familiar neighbours do not extend the unfamiliar
scan or increase its counter. DHCP also starts fresh in a new Slips time window.
ICMP notices with a smaller host count start a fresh notice episode.

SMB retains the other bounded metadata needed for transfer, authentication,
share-path and file-operation correlations. Confirming a host scan releases
its probe category; confirming a share sweep releases its share category. This
does not delete unrelated correlation data or raw records in the run database.
An ongoing confirmed SMB scan still supports subsequent suspicious-transfer and
propagation checks. The configured confidence is the **initial confidence** for
`SMB_SCAN` and `SMB_SHARE_SWEEP`; it remains fixed for other SMB rules.

All counters and samples live inside module workers. No detection work is added
to capture, parsing, profiling or routing. The profiler stops writing obsolete
vertical-scan indexes and skips established-service lookups for failed/non-TCP
connections. Established unknown-service aggregation is retained. Old index
readers remain for saved data, but fresh detections use incoming events. No new
Redis scan keys are added, and vertical/DHCP detection no longer queries Redis
scan totals.
All group collections have hard limits. The vertical detector allocates a
multi-port group only after a second distinct port: single-port horizontal
fanout rotates a separate bounded first-contact cache without displacing all
active vertical scans or causing misleading scan-context warnings.

For settings and detector-specific limitations, see [port scans](horizontal_port_scans.md),
[SMB detection](smb_detection.md) and [ARP scans](arp_scans.md). Restart or rerun an
analysis to load changed code and configuration. Saved evidence retains the
confidence it had when generated; `--view` does not recalculate it.
