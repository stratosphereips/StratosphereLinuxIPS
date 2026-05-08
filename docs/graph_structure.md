# `graph_structure` Module

The `graph_structure` module stores sparse heterogeneous graphs for Slips
alerts. It is disabled by default and is enabled with:

```yaml
graph_structure:
  enabled: true
```

When enabled, the module writes graph data under:

```text
<output>/graph-structure/
```

## Alert-Bounded Windows

Each graph represents one global alert-bounded event window. The first window
starts when Slips starts. Each later window starts immediately after the
previous `new_alert`. A window closes when the next `new_alert` is generated.

The module buffers all observed flow, protocol event, evidence, and blocking
action messages during the open window. It writes a graph only when an alert
closes that window. On shutdown, an incomplete open window is not written as a
graph; its discarded counts are written to `manifest.json`.

## Sparse Heterogeneous Representation

The canonical representation is sparse JSONL tables. The module stores only
entities and relations that actually appear in the alert-bounded window. It
does not allocate dense adjacency matrices during Slips execution.

Node rows have:

```json
{"graph_id": "...", "node_id": "...", "node_type": "...", "features": {}}
```

Edge rows have:

```json
{
  "graph_id": "...",
  "edge_id": "...",
  "source": "...",
  "target": "...",
  "edge_type": "...",
  "features": {}
}
```

The v1 node types are `profile`, `ip`, `network`, `port`, `domain`, `url`,
`user_agent`, `mac`, `software`, `file`, `flow`, `evidence`, and `alert`.

The v1 edge types include profile-to-IP membership, IP-to-network membership,
flow source and destination relations, port attempts and open ports, DNS
queries and resolutions, HTTP requests and user agents, TLS server names, SSH
sessions, downloaded files, ARP mappings, DHCP requested addresses, software
observations, evidence-to-flow references, evidence entity references, and
alert-to-evidence membership.

## Network Nodes

Local network nodes are derived from Slips local-network state and configured
client IP ranges. If an IP does not belong to a known local network, it is
attached to the canonical `network:internet` node. This keeps the graph small
while preserving the distinction between local networks and the outside world.

## Feature Decisions

The module stores only fields already used by Slips modules or required to
preserve alert/evidence context:

- Flow features keep UID, timestamps, source and destination addresses, ports,
  protocol, state, byte and packet counters, application protocol, interface,
  profile, timewindow, and protocol-specific fields used by existing modules.
- Evidence features keep ID, type, threat level, confidence, timestamp,
  profile, timewindow, referenced UIDs, attacker, victim, ports, protocol, and
  method.
- Alert features keep ID, profile, timewindow, CorrelID, confidence,
  accumulated threat level, last evidence, and alert timing.

This makes the graph usable for later model training without duplicating raw
packet data or unrelated runtime state.

## Output Layout

```text
graph-structure/
├─ schema.json
├─ graphs.jsonl
├─ transitions.jsonl
├─ manifest.json
└─ windows/
   └─ window_<index>_<alert_id>/
      ├─ nodes.jsonl
      ├─ edges.jsonl
      └─ metadata.json
```

`graphs.jsonl` stores one metadata row per graph. `transitions.jsonl` links
consecutive graphs as `from_graph_id -> to_graph_id` and stores actions
observed between the two alert-closing events. Rewards are present as nullable
metadata for future producers; the module does not infer rewards.

## Local Graph Viewer

The graph tables can be explored with the local web viewer:

```bash
python3 scripts/graph_structure_viewer.py output/test-graph-4
```

The argument may be either the Slips output directory or the
`graph-structure/` directory itself. The tool starts a local HTTP server and
opens a browser page with:

- An `All windows` graph that combines every alert-bounded graph and adds
  synthetic `graph_transition` edges between alert nodes.
- A selector for individual alert windows.
- Hover and click inspection for every node, edge, feature dictionary, graph
  metadata row, and transition row.
- Node-type and edge-type filters.
- Controls to relayout, tune link length, node gap, repulsion, gravity,
  component spacing, iteration count, and label size.
- Layout sliders update their values while dragged and recalculate the layout
  when released, preserving the current graph orientation and viewport.
- Controls to focus a node, toggle a node's visible connections, expand one
  hop, hide leaves, and restore the full graph.
- Built-in documentation for the stored schema and feature allowlists.

The webpage uses Cytoscape.js in the browser so the graph stays interactive
without adding a Python runtime dependency.

## Partial Observability

The stored graph is the canonical centralized view. Agent-specific observations
can be derived by filtering node and edge rows using feature fields such as
`profileid`, `interface`, `twid`, and `uid`. The storage helper exposes a
simple row-filtering function for this purpose, and downstream agents can apply
stricter visibility policies on top of the same canonical tables.

## GNN Compatibility

The JSONL node and edge tables are directly convertible into sparse adjacency
structures. Node type, edge type, node features, edge features, graph-level
metadata, and transition metadata remain accessible without parsing human text.
This layout supports heterogeneous GNN encoders, graph-level classifiers,
temporal models over graph sequences, and policy/reward learning over
transitions.
