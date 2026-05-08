/* global cytoscape */
"use strict";

const state = {
  index: null,
  graph: null,
  cy: null,
  selectedElement: null,
  hiddenNodeTypes: new Set(),
  hiddenEdgeTypes: new Set(),
  collapsedNodes: new Set(),
};

const nodeColors = {
  profile: "#7cc7ff",
  ip: "#64d58a",
  network: "#9ca3af",
  port: "#c9a7ff",
  domain: "#f8c471",
  url: "#f39c6b",
  user_agent: "#84d8d8",
  mac: "#95a5a6",
  software: "#b7e07a",
  file: "#d7bde2",
  flow: "#57c7a8",
  evidence: "#f0b35a",
  alert: "#e46e8e",
};

const edgeColors = {
  graph_transition: "#ffffff",
  alert_contains_evidence: "#e46e8e",
  evidence_refs_flow: "#f0b35a",
  evidence_about_entity: "#f0b35a",
  ip_belongs_to_network: "#87919a",
  flow_from_ip: "#57c7a8",
  flow_to_ip: "#57c7a8",
  flow_to_port: "#c9a7ff",
};

function qs(selector) {
  /** Return the first matching DOM element. */
  return document.querySelector(selector);
}

function valueLabel(value) {
  /** Convert a feature value into compact display text. */
  if (value === null || value === undefined || value === "") return "";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function bestNodeLabel(node) {
  /** Pick the most readable label for a graph node row. */
  const features = node.features || {};
  const preferred = [
    "ip",
    "domain",
    "url",
    "port",
    "profileid",
    "uid",
    "id",
    "mac",
    "software",
    "user_agent",
  ];
  for (const key of preferred) {
    if (features[key]) return valueLabel(features[key]);
  }
  return node.node_id;
}

function shortId(id) {
  /** Shorten long graph identifiers for labels. */
  const value = String(id || "");
  if (value.length <= 34) return value;
  return `${value.slice(0, 14)}...${value.slice(-10)}`;
}

function mainFeatureLines(features, limit = 6) {
  /** Return compact feature lines for tooltips. */
  const entries = Object.entries(features || {}).filter(
    ([, value]) => value !== null && value !== undefined && value !== ""
  );
  return entries.slice(0, limit).map(([key, value]) => {
    return `<div><strong>${escapeHtml(key)}</strong>: ${escapeHtml(
      valueLabel(value)
    )}</div>`;
  });
}

function escapeHtml(value) {
  /** Escape text for HTML insertion. */
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function fetchJson(path) {
  /** Fetch one JSON API response. */
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  }
  return response.json();
}

function cytoscapeElements(payload) {
  /** Convert canonical graph rows into Cytoscape elements. */
  const degree = new Map();
  for (const edge of payload.edges) {
    degree.set(edge.source, (degree.get(edge.source) || 0) + 1);
    degree.set(edge.target, (degree.get(edge.target) || 0) + 1);
  }

  const nodes = payload.nodes.map((node) => {
    const label = bestNodeLabel(node);
    const nodeDegree = degree.get(node.node_id) || 0;
    return {
      group: "nodes",
      data: {
        id: node.node_id,
        label: shortId(label),
        fullLabel: label,
        node_type: node.node_type,
        color: nodeColors[node.node_type] || "#b8c1cc",
        size: Math.min(44, 18 + Math.sqrt(nodeDegree) * 4),
        raw: node,
      },
    };
  });

  const edges = payload.edges.map((edge) => {
    return {
      group: "edges",
      data: {
        id: edge.edge_id,
        source: edge.source,
        target: edge.target,
        label: edge.edge_type,
        edge_type: edge.edge_type,
        color: edgeColors[edge.edge_type] || "#63717f",
        raw: edge,
      },
    };
  });

  return [...nodes, ...edges];
}

function createCy(payload) {
  /** Create or replace the Cytoscape graph instance. */
  if (state.cy) state.cy.destroy();
  state.cy = cytoscape({
    container: qs("#graph"),
    elements: cytoscapeElements(payload),
    wheelSensitivity: 0.18,
    minZoom: 0.08,
    maxZoom: 4,
    style: [
      {
        selector: "node",
        style: {
          "background-color": "data(color)",
          "border-color": "#0c0f12",
          "border-width": 1.5,
          color: "#dbe7ef",
          height: "data(size)",
          label: "data(label)",
          "font-size": 10,
          "overlay-opacity": 0,
          "text-background-color": "#0c0f12",
          "text-background-opacity": 0.82,
          "text-background-padding": 2,
          "text-outline-width": 0,
          "text-valign": "bottom",
          width: "data(size)",
        },
      },
      {
        selector: "edge",
        style: {
          "curve-style": "bezier",
          "line-color": "data(color)",
          "target-arrow-color": "data(color)",
          "target-arrow-shape": "triangle",
          "arrow-scale": 0.7,
          opacity: 0.72,
          width: 1.4,
        },
      },
      {
        selector: "edge[edge_type = 'graph_transition']",
        style: {
          "line-style": "dashed",
          width: 2.5,
          opacity: 0.95,
        },
      },
      {
        selector: ":selected",
        style: {
          "border-color": "#ffffff",
          "border-width": 4,
          "line-color": "#ffffff",
          "target-arrow-color": "#ffffff",
          opacity: 1,
        },
      },
      {
        selector: ".faded",
        style: {
          opacity: 0.12,
        },
      },
    ],
  });

  bindGraphEvents();
  runLayout();
}

function runLayout() {
  /** Run a layout appropriate for the current graph size. */
  if (!state.cy) return;
  const nodeCount = state.cy.nodes().length;
  const layoutName = nodeCount > 1200 ? "grid" : "cose";
  state.cy.layout({
    name: layoutName,
    animate: false,
    fit: true,
    padding: 40,
    idealEdgeLength: 85,
    nodeRepulsion: 9000,
    gravity: 0.22,
    numIter: 900,
  }).run();
}

function bindGraphEvents() {
  /** Attach hover and click interactions to the graph. */
  const cy = state.cy;
  cy.on("mouseover", "node, edge", (event) => {
    showTooltip(event.originalEvent, event.target);
  });
  cy.on("mouseout", "node, edge", hideTooltip);
  cy.on("click", "node, edge", (event) => {
    state.selectedElement = event.target;
    renderElementDetails(event.target);
  });
  cy.on("tap", (event) => {
    if (event.target === cy) {
      state.selectedElement = null;
      qs("#selection-details").textContent =
        "Hover or click a node, edge, or transition.";
    }
  });
}

function showTooltip(mouseEvent, element) {
  /** Show a small hover tooltip for one graph element. */
  const raw = element.data("raw");
  const type = raw.node_type || raw.edge_type;
  const id = raw.node_id || raw.edge_id;
  const lines = mainFeatureLines(raw.features, 5).join("");
  const tooltip = qs("#tooltip");
  tooltip.innerHTML = `
    <div><strong>${escapeHtml(type)}</strong></div>
    <div>${escapeHtml(shortId(id))}</div>
    ${lines}
  `;
  tooltip.style.left = `${mouseEvent.clientX + 14}px`;
  tooltip.style.top = `${mouseEvent.clientY + 14}px`;
  tooltip.classList.remove("hidden");
}

function hideTooltip() {
  /** Hide the hover tooltip. */
  qs("#tooltip").classList.add("hidden");
}

function renderElementDetails(element) {
  /** Render details for a selected node or edge. */
  const raw = element.data("raw");
  const isNode = element.isNode();
  const title = isNode ? raw.node_id : raw.edge_id;
  const type = isNode ? raw.node_type : raw.edge_type;
  const relation = isNode
    ? ""
    : `<p>${escapeHtml(raw.source)} -> ${escapeHtml(raw.target)}</p>`;
  qs("#selection-details").innerHTML = `
    <h2>${escapeHtml(type)}</h2>
    <p>${escapeHtml(title)}</p>
    ${relation}
    ${featureTable(raw.features || {})}
  `;
}

function featureTable(features) {
  /** Render a feature dictionary as an HTML table. */
  const rows = Object.entries(features).map(([key, value]) => {
    return `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(
      valueLabel(value)
    )}</td></tr>`;
  });
  if (!rows.length) return "<p>No features stored.</p>";
  return `<table class="kv-table"><tbody>${rows.join("")}</tbody></table>`;
}

function renderStats(payload) {
  /** Render basic graph metrics. */
  const stats = [
    ["Nodes", payload.summary.node_count],
    ["Edges", payload.summary.edge_count],
    ["Node types", Object.keys(payload.summary.node_types).length],
    ["Edge types", Object.keys(payload.summary.edge_types).length],
  ];
  qs("#graph-stats").innerHTML = stats
    .map(
      ([label, value]) => `
        <div class="stat">
          <div class="stat-value">${escapeHtml(value)}</div>
          <div class="stat-label">${escapeHtml(label)}</div>
        </div>
      `
    )
    .join("");
}

function renderTypeFilters(payload) {
  /** Render node and edge type filter chips. */
  renderChipList(
    "#node-type-filters",
    payload.summary.node_types,
    state.hiddenNodeTypes,
    applyVisibility
  );
  renderChipList(
    "#edge-type-filters",
    payload.summary.edge_types,
    state.hiddenEdgeTypes,
    applyVisibility
  );
}

function renderChipList(selector, counts, hiddenSet, onChange) {
  /** Render one list of filter chips. */
  const container = qs(selector);
  container.innerHTML = "";
  for (const [type, count] of Object.entries(counts).sort()) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = `chip ${hiddenSet.has(type) ? "off" : ""}`;
    chip.textContent = `${type} (${count})`;
    chip.addEventListener("click", () => {
      if (hiddenSet.has(type)) hiddenSet.delete(type);
      else hiddenSet.add(type);
      onChange();
      renderTypeFilters(state.graph);
    });
    container.appendChild(chip);
  }
}

function applyVisibility() {
  /** Apply active type filters and collapsed-node state. */
  const cy = state.cy;
  if (!cy) return;

  cy.batch(() => {
    cy.elements().removeClass("faded");
    cy.nodes().forEach((node) => {
      const hidden = state.hiddenNodeTypes.has(node.data("node_type"));
      node.style("display", hidden ? "none" : "element");
    });
    cy.edges().forEach((edge) => {
      const typeHidden = state.hiddenEdgeTypes.has(edge.data("edge_type"));
      const collapsed = state.collapsedNodes.has(edge.source().id())
        || state.collapsedNodes.has(edge.target().id());
      edge.style("display", typeHidden || collapsed ? "none" : "element");
    });
  });
}

function focusSelectedNode() {
  /** Show only the selected node and its visible neighborhood. */
  const selected = selectedNode();
  if (!selected) return;
  const keep = selected.closedNeighborhood();
  state.cy.elements().style("display", "none");
  keep.style("display", "element");
  state.cy.fit(keep, 40);
}

function toggleSelectedConnections() {
  /** Collapse or reopen edges connected to the selected node. */
  const selected = selectedNode();
  if (!selected) return;
  if (state.collapsedNodes.has(selected.id())) {
    state.collapsedNodes.delete(selected.id());
  } else {
    state.collapsedNodes.add(selected.id());
  }
  applyVisibility();
}

function expandSelectedNode() {
  /** Restore one-hop neighbors around the selected node. */
  const selected = selectedNode();
  if (!selected) return;
  selected.closedNeighborhood().style("display", "element");
  selected.connectedEdges().forEach((edge) => {
    if (!state.hiddenEdgeTypes.has(edge.data("edge_type"))) {
      edge.style("display", "element");
    }
  });
  state.collapsedNodes.delete(selected.id());
  state.cy.fit(selected.closedNeighborhood(), 40);
}

function hideLeaves() {
  /** Hide visible leaf nodes to simplify dense graph views. */
  state.cy.nodes().forEach((node) => {
    if (node.connectedEdges(":visible").length <= 1) {
      node.style("display", "none");
    }
  });
}

function showAll() {
  /** Restore all nodes and edges. */
  state.hiddenNodeTypes.clear();
  state.hiddenEdgeTypes.clear();
  state.collapsedNodes.clear();
  state.cy.elements().style("display", "element");
  renderTypeFilters(state.graph);
}

function selectedNode() {
  /** Return the selected node if one is selected. */
  if (!state.selectedElement || !state.selectedElement.isNode()) {
    return null;
  }
  return state.selectedElement;
}

function searchGraph() {
  /** Search nodes and edges by ID, label, type, or feature text. */
  const query = qs("#search-input").value.trim().toLowerCase();
  if (!query || !state.cy) return;
  const match = state.cy.elements().filter((element) => {
    const raw = element.data("raw");
    return JSON.stringify(raw).toLowerCase().includes(query);
  })[0];
  if (!match) return;
  state.cy.elements().unselect();
  match.select();
  state.selectedElement = match;
  renderElementDetails(match);
  state.cy.animate({ center: { eles: match }, zoom: 1.4 }, { duration: 250 });
}

function renderTransitions(transitions) {
  /** Render graph-to-graph transitions in the sidebar. */
  const container = qs("#transition-list");
  if (!transitions || !transitions.length) {
    container.textContent = "No transition rows for this view.";
    return;
  }
  container.innerHTML = "";
  transitions.forEach((transition, index) => {
    const item = document.createElement("div");
    item.className = "transition-item";
    item.innerHTML = `
      <strong>${escapeHtml(shortId(transition.from_graph_id))}</strong>
      <div>to ${escapeHtml(shortId(transition.to_graph_id))}</div>
      <div>actions: ${escapeHtml(transition.action_count || 0)} reward: ${escapeHtml(
        valueLabel(transition.reward)
      ) || "null"}</div>
    `;
    item.addEventListener("click", () => renderTransitionDetails(index, transition));
    container.appendChild(item);
  });
}

function renderTransitionDetails(index, transition) {
  /** Render details for one transition row. */
  qs("#selection-details").innerHTML = `
    <h2>Transition ${escapeHtml(index)}</h2>
    <p>${escapeHtml(transition.from_graph_id)} -> ${escapeHtml(
      transition.to_graph_id
    )}</p>
    ${featureTable(transition)}
  `;
}

function renderDocumentation(index) {
  /** Render schema and interaction documentation. */
  const doc = index.documentation || {};
  const schema = index.schema || {};
  qs("#documentation").innerHTML = `
    <p>${escapeHtml(doc.overview || "")}</p>
    <h2>Interaction</h2>
    <p>${escapeHtml(doc.interaction || "")}</p>
    <h2>Node Types</h2>
    ${simpleList(schema.node_types || [])}
    <h2>Edge Types</h2>
    ${simpleList([...(schema.edge_types || []), "graph_transition"])}
    <h2>Feature Allowlists</h2>
    <pre>${escapeHtml(JSON.stringify(schema.feature_allowlists || {}, null, 2))}</pre>
  `;
}

function simpleList(values) {
  /** Render a simple unordered list. */
  return `<ul>${values
    .map((value) => `<li>${escapeHtml(value)}</li>`)
    .join("")}</ul>`;
}

function populateGraphSelect(index) {
  /** Populate the graph-window selector. */
  const select = qs("#graph-select");
  select.innerHTML = '<option value="all">All windows</option>';
  for (const graph of index.graphs || []) {
    const option = document.createElement("option");
    option.value = String(graph.window_index);
    option.textContent = `Window ${graph.window_index} - ${shortId(
      graph.alert_id
    )} (${graph.node_count} nodes)`;
    select.appendChild(option);
  }
}

async function loadGraph(selector) {
  /** Load and render a graph payload. */
  state.graph = await fetchJson(`/api/graph/${encodeURIComponent(selector)}`);
  state.selectedElement = null;
  state.hiddenNodeTypes.clear();
  state.hiddenEdgeTypes.clear();
  state.collapsedNodes.clear();
  createCy(state.graph);
  renderStats(state.graph);
  renderTypeFilters(state.graph);
  renderTransitions(state.graph.transitions || []);
  qs("#selection-details").innerHTML = metadataDetails(state.graph.metadata);
}

function metadataDetails(metadata) {
  /** Render graph-level metadata for the selection panel. */
  return `
    <h2>Graph Metadata</h2>
    ${featureTable(metadata || {})}
  `;
}

function bindControls() {
  /** Bind sidebar controls. */
  qs("#graph-select").addEventListener("change", (event) => {
    loadGraph(event.target.value);
  });
  qs("#layout-button").addEventListener("click", runLayout);
  qs("#show-all-button").addEventListener("click", showAll);
  qs("#focus-button").addEventListener("click", focusSelectedNode);
  qs("#toggle-connections-button").addEventListener(
    "click",
    toggleSelectedConnections
  );
  qs("#expand-button").addEventListener("click", expandSelectedNode);
  qs("#hide-leaves-button").addEventListener("click", hideLeaves);
  qs("#search-input").addEventListener("keydown", (event) => {
    if (event.key === "Enter") searchGraph();
  });
}

async function init() {
  /** Initialize the graph viewer application. */
  if (!window.cytoscape) {
    qs("#selection-details").textContent =
      "Cytoscape.js did not load. Check browser access to jsDelivr.";
    return;
  }
  state.index = await fetchJson("/api/index");
  qs("#graph-root").textContent = state.index.graph_root;
  populateGraphSelect(state.index);
  renderDocumentation(state.index);
  bindControls();
  await loadGraph("all");
}

init().catch((error) => {
  qs("#selection-details").innerHTML = `<pre>${escapeHtml(error.stack || error)}</pre>`;
});
