"use strict";

const state = {
  activeTab: "overview",
  overview: null,
  metrics: [],
  host: null,
  failures: 0,
  timer: null,
  requests: new Map(),
  drawerHistory: [],
  drawerGeneration: 0,
  runIdentity: null,
  rangesInitialized: false,
  pages: {
    alerts: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
    evidence: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
    hosts: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "last_seen", order: "desc" },
    hostFlows: { items: [], total: 0, next: null, cursors: [null], index: 0 },
    "host-evidence": { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
  },
};

const byId = (id) => document.getElementById(id);
const numeric = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
const compact = (value) => new Intl.NumberFormat(undefined, {
  notation: "compact", maximumFractionDigits: 1,
}).format(numeric(value));
const formatBytes = (value) => {
  const amount = numeric(value);
  if (amount < 1024) return `${amount.toFixed(0)} B`;
  if (amount < 1048576) return `${(amount / 1024).toFixed(1)} KiB`;
  if (amount < 1073741824) return `${(amount / 1048576).toFixed(1)} MiB`;
  return `${(amount / 1073741824).toFixed(1)} GiB`;
};
const formatTime = (value) => {
  const amount = numeric(value);
  if (!amount) return "—";
  if (amount < 946684800) {
    const elapsed = Math.max(0, Math.floor(amount));
    const hours = String(Math.floor(elapsed / 3600)).padStart(2, "0");
    const minutes = String(Math.floor((elapsed % 3600) / 60)).padStart(2, "0");
    const seconds = String(elapsed % 60).padStart(2, "0");
    return `T+${hours}:${minutes}:${seconds}`;
  }
  return new Date(amount * 1000).toLocaleString();
};
const text = (tag, value, className = "") => {
  const element = document.createElement(tag);
  element.textContent = value ?? "—";
  if (className) element.className = className;
  return element;
};
const cell = (value, className = "") => {
  const td = document.createElement("td");
  if (value instanceof Node) td.append(value);
  else td.textContent = value ?? "—";
  if (className) td.className = className;
  return td;
};
const threat = (value) => {
  const level = String(value || "info").toLowerCase();
  return text("span", level, `status threat-${level}`);
};
const escapePath = (value) => encodeURIComponent(String(value));

function showError(message) {
  const banner = byId("error-banner");
  banner.textContent = message;
  banner.hidden = false;
}

function clearError() {
  byId("error-banner").hidden = true;
}

function toast(message) {
  const element = byId("toast");
  element.textContent = message;
  element.classList.add("show");
  window.setTimeout(() => element.classList.remove("show"), 3000);
}

/** Clear run-specific browser state when the local web server is replaced. */
function applyRunIdentity(identity) {
  if (!identity || !identity.output_dir || !identity.server_pid) return;
  const token = `${identity.output_dir}:${identity.server_pid}`;
  if (state.runIdentity && state.runIdentity !== token) {
    closeDrawer();
    closeHost();
    Object.keys(state.pages).forEach((name) => resetPage(name));
    state.overview = null;
    state.metrics = [];
    state.rangesInitialized = false;
    toast("A new Slips run is now active. Investigation state was cleared.");
  }
  state.runIdentity = token;
}

async function api(key, path) {
  state.requests.get(key)?.abort();
  const controller = new AbortController();
  state.requests.set(key, controller);
  try {
    const response = await fetch(path, {
      cache: "no-store", signal: controller.signal,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload.detail || payload.error || `HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    applyRunIdentity(payload.run_identity);
    state.failures = 0;
    clearError();
    return payload;
  } catch (error) {
    if (error.name === "AbortError") return null;
    state.failures += 1;
    showError(error.status === 409
      ? `Run mismatch: ${error.message}. Reload after the current web-enabled Slips run has started.`
      : `Web data unavailable: ${error.message}`);
    throw error;
  } finally {
    if (state.requests.get(key) === controller) state.requests.delete(key);
  }
}

function renderTable(id, rows, columns, onClick = null) {
  const body = document.querySelector(`#${id} tbody`);
  body.replaceChildren();
  if (!rows.length) {
    const row = document.createElement("tr");
    const empty = cell("No matching records.", "empty");
    empty.colSpan = columns.length;
    row.append(empty);
    body.append(row);
    return;
  }
  for (const record of rows) {
    const row = document.createElement("tr");
    if (onClick) {
      row.dataset.clickable = "true";
      row.tabIndex = 0;
      row.addEventListener("click", () => onClick(record));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter") onClick(record);
      });
    }
    columns.forEach((column) => row.append(cell(column(record))));
    body.append(row);
  }
}

function pager(name, targetId, load) {
  const page = state.pages[name];
  const container = byId(targetId);
  container.replaceChildren();
  const previous = text("button", "Previous", "secondary");
  previous.disabled = page.index === 0;
  previous.addEventListener("click", () => {
    if (page.index === 0) return;
    page.index -= 1;
    load();
  });
  const label = text("span", `Page ${page.index + 1} · ${page.items.length} shown`);
  const next = text("button", "Next", "secondary");
  next.disabled = !page.next;
  next.addEventListener("click", () => {
    if (!page.next) return;
    page.cursors[page.index + 1] = page.next;
    page.index += 1;
    load();
  });
  container.append(previous, label, next);
}

function resetPage(name) {
  Object.assign(state.pages[name], {
    items: [], total: 0, next: null, cursors: [null], index: 0,
  });
}

function rangeQuery(prefix) {
  const range = byId(`${prefix}-range`).value;
  const params = new URLSearchParams({ range });
  if (range === "custom") {
    const from = byId(`${prefix}-from`).value;
    const to = byId(`${prefix}-to`).value;
    if (from) params.set("from", String(new Date(from).getTime() / 1000));
    if (to) params.set("to", String(new Date(to).getTime() / 1000));
  }
  return params;
}

function rangeIsLive(prefix) {
  return ["live", "1h", "24h", "7d", "all"].includes(byId(`${prefix}-range`).value);
}

function renderLineChart(id, points, series) {
  const svg = byId(id);
  svg.replaceChildren();
  const width = 600;
  const height = 180;
  const pad = 28;
  if (!points.length) {
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", "300");
    label.setAttribute("y", "92");
    label.setAttribute("text-anchor", "middle");
    label.textContent = "No samples in this range";
    svg.append(label);
    return;
  }
  const values = points.flatMap((point) => series.map((item) => numeric(point[item.key])));
  const maximum = Math.max(...values, 1);
  const minimumTime = numeric(points[0].ts);
  const maximumTime = numeric(points.at(-1).ts);
  const span = Math.max(maximumTime - minimumTime, 1);
  const grid = document.createElementNS("http://www.w3.org/2000/svg", "path");
  grid.setAttribute("d", `M${pad} ${height - pad}H${width - 8}M${pad} 8V${height - pad}`);
  grid.setAttribute("class", "chart-axis");
  svg.append(grid);
  for (const item of series) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    const d = points.map((point, index) => {
      const x = pad + ((numeric(point.ts) - minimumTime) / span) * (width - pad - 8);
      const y = height - pad - (numeric(point[item.key]) / maximum) * (height - pad - 12);
      return `${index ? "L" : "M"}${x.toFixed(2)} ${y.toFixed(2)}`;
    }).join(" ");
    path.setAttribute("d", d);
    path.setAttribute("class", `chart-line ${item.className || ""}`);
    svg.append(path);
  }
  const maxLabel = document.createElementNS("http://www.w3.org/2000/svg", "text");
  maxLabel.setAttribute("x", "4");
  maxLabel.setAttribute("y", "14");
  maxLabel.textContent = maximum.toFixed(maximum < 10 ? 1 : 0);
  svg.append(maxLabel);
}

function renderBars(id, rows) {
  const container = byId(id);
  container.replaceChildren();
  const maximum = Math.max(...rows.map((row) => numeric(row.value)), 1);
  if (!rows.length) {
    container.append(text("p", "No traffic in this range.", "muted"));
    return;
  }
  rows.slice(0, 12).forEach((row) => {
    const item = document.createElement("div");
    item.className = "bar-row";
    const meter = document.createElement("span");
    meter.className = "bar-meter";
    meter.style.width = `${numeric(row.value) / maximum * 100}%`;
    item.append(text("code", row.name || "unknown"), meter, text("strong", compact(row.value)));
    container.append(item);
  });
}

function setSummaryCards(items, target = "summary-cards") {
  const container = byId(target);
  container.replaceChildren();
  items.forEach(([label, value]) => {
    const card = document.createElement("article");
    card.className = "summary-card";
    card.append(text("span", label), text("strong", value));
    container.append(card);
  });
}

function renderOverview() {
  const data = state.overview;
  if (!data) return;
  const run = data.run;
  const outputName = String(run.output_dir || "").split("/").filter(Boolean).at(-1);
  byId("run-name").textContent = outputName || "Current run";
  const metadata = data.run_metadata || {};
  byId("run-meta").textContent = [
    metadata.File || run.input_type || "input",
    metadata.Branch ? `branch ${metadata.Branch}` : "",
    `Redis ${run.redis_port}`,
  ].filter(Boolean).join(" · ");
  byId("run-state").textContent = run.state === "running" ? "Analysis running" : "Analysis complete";
  byId("state-dot").className = `state-dot ${run.state}`;
  byId("updated-at").textContent = `Updated ${new Date(data.updated_at * 1000).toLocaleTimeString()}`;
  byId("alerts-badge").textContent = compact(data.counts.alerts);
  byId("evidence-badge").textContent = compact(data.counts.evidence);
  byId("hosts-badge").textContent = compact(data.counts.hosts);
  setSummaryCards([
    ["Alerts", compact(data.counts.alerts)],
    ["Evidence", compact(data.counts.evidence)],
    ["Hosts", compact(data.counts.hosts)],
    ["Processed flows", compact(data.counts.processed_flows)],
    ["Logged events", compact(data.counts.module_errors)],
  ]);
  const system = data.system;
  const metrics = [
    ["CPU", `${numeric(system.cpu_percent).toFixed(1)}%`],
    ["Memory", `${numeric(system.memory_percent).toFixed(1)}%`],
    ["Load 1 / 5 / 15m", system.load_average.map((value) => numeric(value).toFixed(2)).join(" / ")],
    ["Output disk", `${numeric(system.output_disk_percent).toFixed(1)}% · ${formatBytes(system.output_disk_free)} free${system.disk_warning ? ` · ${system.disk_warning.toUpperCase()}` : ""}`],
    ["flows.sqlite", formatBytes(system.flows_db_size)],
    ["Recent growth", `${formatBytes(system.flows_db_growth_bps)}/s`],
  ];
  const load = byId("system-load");
  load.replaceChildren();
  metrics.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "metric";
    row.append(text("small", label), text("strong", value));
    load.append(row);
  });
  const sources = byId("data-sources");
  sources.replaceChildren();
  Object.entries(data.sources).forEach(([name, value]) => {
    const available = typeof value === "boolean" ? value : Boolean(value);
    const row = document.createElement("div");
    row.className = "source-row";
    row.append(text("span", name.replaceAll("_", " ")),
      text("span", typeof value === "string" ? (value || "unavailable") :
        (available ? "available" : "unavailable"), `status ${available ? "ok" : "bad"}`));
    sources.append(row);
  });
  const runMetadata = byId("run-metadata");
  runMetadata.replaceChildren();
  const metadataOrder = [
    "Slips version", "File", "Branch", "Commit", "Command",
    "Slips start date", "Zeek version",
  ];
  metadataOrder.filter((label) => metadata[label] !== undefined).forEach((label) => {
    const row = document.createElement("div");
    row.className = "source-row";
    row.append(text("span", label), text(
      label === "Commit" || label === "Command" ? "code" : "span",
      metadata[label] || "unavailable",
    ));
    runMetadata.append(row);
  });
  if (!runMetadata.children.length) {
    runMetadata.append(text("p", "metadata/info.txt is not available.", "muted"));
  }
  renderModules(data.modules);
  const errors = byId("errors-list");
  errors.replaceChildren();
  if (!data.recent_errors.length) errors.append(text("li", "No parsed log events for this run."));
  data.recent_errors.forEach((event) => {
    const item = document.createElement("li");
    item.append(text("code", event.module), text("span", event.message));
    errors.append(item);
  });
}

function renderModules(modules) {
  const query = byId("module-search").value.trim().toLowerCase();
  renderTable("modules-table", modules.filter((item) =>
    item.name.toLowerCase().includes(query)), [
    (row) => text("code", row.name),
    (row) => text("span", row.state, `status ${row.running ? "ok" : "warn"}`),
    (row) => row.pid,
    (row) => `${numeric(row.cpu_percent).toFixed(1)}%`,
    (row) => `${numeric(row.memory_mb).toFixed(1)} MiB`,
    (row) => compact(row.flows_per_minute),
    (row) => compact(row.evidence_count),
    (row) => row.error_count,
  ]);
}

async function loadMetrics() {
  const range = byId("metrics-range").value;
  const payload = await api("metrics", `/api/metrics?range=${range}&max_points=1200`);
  if (!payload) return;
  state.metrics = payload.items;
  renderLineChart("cpu-chart", state.metrics, [{ key: "cpu" }, { key: "cpu_max", className: "secondary-line" }]);
  renderLineChart("memory-chart", state.metrics, [{ key: "memory" }, { key: "memory_max", className: "secondary-line" }]);
  renderLineChart("fps-chart", state.metrics, [{ key: "fps" }, { key: "fps_max", className: "secondary-line" }]);
}

/** Choose a useful initial history range for the current input source. */
function initializeRanges(run) {
  if (state.rangesInitialized) return;
  const inputType = String(run.input_type || "").toLowerCase();
  const range = ["interface", "stdin", "cyst"].includes(inputType) ? "live" : "all";
  ["alerts", "evidence", "hosts", "host"].forEach((name) => {
    byId(`${name}-range`).value = range;
  });
  state.rangesInitialized = true;
}

async function loadOverview() {
  const payload = await api("overview", "/api/overview");
  if (!payload) return;
  state.overview = payload;
  initializeRanges(payload.run);
  renderOverview();
  await loadMetrics();
}

function listPath(name) {
  const page = state.pages[name];
  const params = rangeQuery(name);
  params.set("limit", "100");
  params.set("sort", page.sort);
  params.set("order", page.order);
  if (page.cursors[page.index]) params.set("cursor", page.cursors[page.index]);
  const search = byId(`${name}-search`).value.trim();
  if (search) params.set("search", search);
  if (name === "alerts") {
    if (byId("alerts-view").value === "grouped") params.set("group", "host");
    params.set("details", "false");
    const level = byId("alerts-threat").value;
    if (level) params.set("threat", level);
  } else if (name === "evidence") {
    if (byId("evidence-view").value === "grouped") {
      params.set("group", "host_type");
    }
    const level = byId("evidence-threat").value;
    const association = byId("evidence-link").value;
    if (level) params.set("threat", level);
    if (association) params.set("association", association);
  } else {
    const scope = byId("hosts-scope").value;
    const level = byId("hosts-threat").value;
    if (scope) params.set("scope", scope);
    if (level) params.set("threat", level);
  }
  return `/api/${name}?${params}`;
}

function applyPage(name, payload) {
  const page = state.pages[name];
  page.items = payload.items;
  page.total = payload.total;
  page.next = payload.next_cursor;
  if (payload.full_total !== undefined) {
    byId(`${name}-badge`).textContent = compact(payload.full_total);
  }
  byId(`${name}-count`).textContent = `${payload.page_size} shown · ${compact(payload.total)} match`;
  applySortIndicators(name);
}

function applySortIndicators(name) {
  const page = state.pages[name];
  document.querySelectorAll(`#${name}-table th[data-sort]`).forEach((header) => {
    const active = header.dataset.sort === page.sort;
    header.classList.toggle("sorted", active);
    header.dataset.order = active ? page.order : "";
    header.setAttribute("aria-sort", active
      ? (page.order === "asc" ? "ascending" : "descending")
      : "none");
  });
}

function bindTableSort(name, loader) {
  document.querySelectorAll(`#${name}-table th[data-sort]`).forEach((header) => {
    header.tabIndex = 0;
    const changeSort = () => {
      const page = state.pages[name];
      const key = header.dataset.sort;
      if (page.sort === key) page.order = page.order === "desc" ? "asc" : "desc";
      else {
        page.sort = key;
        page.order = ["host", "type", "module", "label", "id", "ip", "scope", "hostname", "mac"]
          .includes(key) ? "asc" : "desc";
      }
      resetPage(name);
      applySortIndicators(name);
      loader().catch(() => {});
    };
    header.addEventListener("click", changeSort);
    header.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        changeSort();
      }
    });
  });
  applySortIndicators(name);
}

/**
 * Rebuild a table header when its display mode changes.
 *
 * @param {string} name Table state and element prefix.
 * @param {string} layout Stable name for the selected layout.
 * @param {Array<Array<string|null>>} headers Label and optional sort key pairs.
 * @param {Function} loader Function used after a sort change.
 */
function configureTable(name, layout, headers, loader) {
  const table = byId(`${name}-table`);
  if (table.dataset.layout === layout) return;
  table.dataset.layout = layout;
  const row = table.querySelector("thead tr");
  row.replaceChildren();
  headers.forEach(([label, sortKey]) => {
    const header = text("th", label);
    if (sortKey) header.dataset.sort = sortKey;
    row.append(header);
  });
  bindTableSort(name, loader);
}

async function loadAlerts() {
  const grouped = byId("alerts-view").value === "grouped";
  configureTable("alerts", grouped ? "grouped" : "individual", grouped ? [
    ["Latest", "time"], ["Host", "host"], ["Highest threat", "threat"],
    ["Alerts", "alerts"], ["Evidence links", "evidence"], ["Labels", "label"],
  ] : [
    ["Time", "time"], ["Host", "host"], ["Threat", "threat"],
    ["Label", "label"], ["Evidence", "evidence"], ["Alert ID", "id"],
  ], loadAlerts);
  byId("alerts-description").textContent = grouped
    ? "Grouped by host. Select a host, then an alert, its evidence, and triggering flows."
    : "Individual durable alerts. Select one to inspect its evidence and triggering flows.";
  const payload = await api("alerts", listPath("alerts"));
  if (!payload) return;
  applyPage("alerts", payload);
  if (grouped) {
    renderTable("alerts-table", payload.items, [
      (row) => formatTime(row.alert_time), (row) => text("code", row.ip_alerted),
      (row) => threat(row.threat_level), (row) => compact(row.alert_count),
      (row) => compact(row.evidence_count), (row) => row.label || "—",
    ], openAlertGroup);
  } else {
    renderTable("alerts-table", payload.items, [
      (row) => formatTime(row.alert_time), (row) => text("code", row.ip_alerted),
      (row) => threat(row.threat_level), (row) => row.label || "—",
      (row) => compact(row.evidence_count), (row) => text("code", row.alert_id),
    ], openAlert);
  }
  pager("alerts", "alerts-pager", loadAlerts);
}

async function loadEvidence() {
  const grouped = byId("evidence-view").value === "grouped";
  configureTable("evidence", grouped ? "grouped" : "individual", grouped ? [
    ["Latest", "time"], ["Host", "host"], ["Highest threat", "threat"],
    ["Type", "type"], ["Module", "module"], ["Evidence", "evidence"],
    ["Flows", "flows"], ["Alert links", "alert"],
  ] : [
    ["Time", "time"], ["Host", "host"], ["Threat", "threat"],
    ["Type", "type"], ["Module", "module"], ["Flows", "flows"],
    ["Alerts", "alert"], ["Description", null],
  ], loadEvidence);
  byId("evidence-description").textContent = grouped
    ? "Grouped by host and type, including records that never formed an alert."
    : "Individual durable evidence, including records that never formed an alert.";
  const payload = await api("evidence", listPath("evidence"));
  if (!payload) return;
  applyPage("evidence", payload);
  if (grouped) {
    renderTable("evidence-table", payload.items, [
      (row) => formatTime(row.timestamp), (row) => text("code", row.profile_ip),
      (row) => threat(row.threat_level), (row) => text("code", row.evidence_type),
      (row) => text("code", row.module), (row) => compact(row.evidence_count),
      (row) => compact(row.flow_count),
      (row) => row.alert_count ? `${compact(row.alert_count)} linked` : "none",
    ], openEvidenceGroup);
  } else {
    renderTable("evidence-table", payload.items, [
      (row) => formatTime(row.timestamp), (row) => text("code", row.profile_ip),
      (row) => threat(row.threat_level), (row) => text("code", row.evidence_type),
      (row) => text("code", row.module), (row) => compact(row.flow_count),
      (row) => row.alert_ids?.length ? compact(row.alert_ids.length) : "none",
      (row) => row.description || "—",
    ], openEvidence);
  }
  pager("evidence", "evidence-pager", loadEvidence);
}

async function loadHosts() {
  const payload = await api("hosts", listPath("hosts"));
  if (!payload) return;
  applyPage("hosts", payload);
  renderTable("hosts-table", payload.items, [
    (row) => text("code", row.ip),
    (row) => text("span", row.scope, `status ${row.scope === "public" ? "warn" : "ok"}`),
    (row) => row.hostname || "—",
    (row) => text("code", row.mac || "—"),
    (row) => threat(row.max_threat_level),
    (row) => compact(row.load?.flows),
    (row) => formatBytes(row.load?.bytes),
    (row) => compact(row.evidence_count),
    (row) => compact(row.alert_count),
    (row) => formatTime(row.load?.last_seen || row.observed_at),
  ], (row) => openHost(row.ip));
  pager("hosts", "hosts-pager", loadHosts);
}

function detailRow(label, value) {
  const row = document.createElement("div");
  row.className = "detail-row";
  row.append(text("strong", label), value instanceof Node ? value : text("span", value));
  return row;
}

/** Build a compact group of labeled investigation values. */
function investigationStats(entries) {
  const grid = document.createElement("div");
  grid.className = "investigation-summary";
  entries.forEach(([label, value, tone = ""]) => {
    const card = document.createElement("div");
    card.className = `investigation-stat ${tone}`.trim();
    card.append(text("small", label), value instanceof Node ? value : text("strong", value));
    grid.append(card);
  });
  return grid;
}

/** Build a heading that explains the contents of an investigation section. */
function investigationHeading(title, explanation = "") {
  const heading = document.createElement("div");
  heading.className = "investigation-section-head";
  heading.append(text("h3", title));
  if (explanation) heading.append(text("p", explanation));
  return heading;
}

/** Navigate from a detection or flow IP to the full host workspace. */
async function inspectHost(ip) {
  if (!ip) return;
  closeDrawer();
  switchTab("hosts");
  await openHost(ip);
}

/** Render an IP as a host-workspace navigation control. */
function hostLink(ip) {
  const button = text("button", ip || "Unknown", "ip-link");
  button.type = "button";
  button.title = ip ? `Open host workspace for ${ip}` : "No host address available";
  button.disabled = !ip;
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    inspectHost(ip).catch(() => {});
  });
  return button;
}

/**
 * Render stored A/AAAA resolution context as labeled, readable fields.
 *
 * @param {Object} dns DNS resolution object stored for the selected IP.
 * @returns {HTMLElement} Structured DNS content for the host workspace.
 */
function renderDnsDetails(dns) {
  const container = document.createElement("div");
  container.className = "dns-details";
  if (!dns || typeof dns !== "object" || Array.isArray(dns) || !Object.keys(dns).length) {
    container.append(text("p", "No stored A or AAAA resolution for this IP.", "muted"));
    return container;
  }
  const asList = (value) => {
    if (Array.isArray(value)) return value.map(String).filter(Boolean);
    return value === undefined || value === null || value === "" ? [] : [String(value)];
  };
  const facts = document.createElement("div");
  facts.className = "dns-facts";
  const addFact = (label, value) => {
    const fact = document.createElement("div");
    fact.className = "dns-fact";
    fact.append(text("small", label), value instanceof Node ? value : text("strong", value));
    facts.append(fact);
  };
  addFact("Last DNS observation", dns.ts ? formatTime(dns.ts) : "Unknown");
  addFact("Latest DNS flow UID", dns.uid ? text("code", dns.uid) : "Unknown");
  container.append(facts);

  const addValues = (label, values, renderer) => {
    if (!values.length) return;
    const section = document.createElement("section");
    section.className = "dns-section";
    const list = document.createElement("div");
    list.className = "dns-values";
    values.forEach((value) => list.append(renderer(value)));
    section.append(text("small", label, "dns-label"), list);
    container.append(section);
  };
  addValues("Domains pointing to this IP", asList(dns.domains), (domain) =>
    text("code", domain, "dns-chip dns-domain"));
  addValues("Hosts that requested the resolution", asList(dns["resolved-by"]), (ip) =>
    hostLink(ip));
  addValues("Observed in time windows", asList(dns.timewindows), (timewindow) =>
    text("code", timewindow, "dns-chip"));

  const knownFields = new Set(["ts", "uid", "domains", "resolved-by", "timewindows"]);
  const additional = Object.entries(dns).filter(([key]) => !knownFields.has(key));
  if (additional.length) {
    const section = document.createElement("section");
    section.className = "dns-section";
    section.append(text("small", "Additional DNS fields", "dns-label"));
    additional.forEach(([key, value]) => section.append(
      detailRow(key.replaceAll("_", " "), typeof value === "object" ? JSON.stringify(value) : value),
    ));
    container.append(section);
  }
  return container;
}

/** Cancel requests whose results belong exclusively to drawer content. */
function cancelDrawerRequests() {
  ["alertDetail", "alertGroup", "evidenceGroup", "evidenceFlows"].forEach((key) =>
    state.requests.get(key)?.abort());
}

/** Show whether the current investigation has a previous drawer panel. */
function updateDrawerBackButton() {
  byId("drawer-back").hidden = state.drawerHistory.length === 0;
}

/** Open a drawer panel and preserve the current panel for Back navigation. */
function openDrawer(kind, title) {
  cancelDrawerRequests();
  const drawer = byId("drawer");
  const body = byId("drawer-body");
  if (drawer.classList.contains("open")) {
    state.drawerHistory.push({
      kind: byId("drawer-kind").textContent,
      title: byId("drawer-title").textContent,
      nodes: Array.from(body.childNodes),
      scrollTop: body.scrollTop,
    });
  } else {
    state.drawerHistory = [];
  }
  state.drawerGeneration += 1;
  byId("drawer-kind").textContent = kind;
  byId("drawer-title").textContent = title;
  body.replaceChildren();
  body.scrollTop = 0;
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  byId("drawer-backdrop").classList.add("open");
  updateDrawerBackButton();
  return state.drawerGeneration;
}

/** Restore the immediately previous drawer panel and its scroll position. */
function backDrawer() {
  const previous = state.drawerHistory.pop();
  if (!previous) return;
  cancelDrawerRequests();
  state.drawerGeneration += 1;
  byId("drawer-kind").textContent = previous.kind;
  byId("drawer-title").textContent = previous.title;
  const body = byId("drawer-body");
  body.replaceChildren(...previous.nodes);
  window.requestAnimationFrame(() => {
    body.scrollTop = previous.scrollTop;
  });
  updateDrawerBackButton();
}

function closeDrawer() {
  cancelDrawerRequests();
  state.drawerGeneration += 1;
  state.drawerHistory = [];
  byId("drawer").classList.remove("open");
  byId("drawer").setAttribute("aria-hidden", "true");
  byId("drawer-backdrop").classList.remove("open");
  byId("drawer-body").replaceChildren();
  updateDrawerBackButton();
}

/** Apply and persist a bounded investigation-panel width. */
function setDrawerWidth(width) {
  const minimum = Math.min(440, window.innerWidth * 0.9);
  const maximum = window.innerWidth * 0.94;
  const bounded = Math.max(minimum, Math.min(Number(width) || 860, maximum));
  byId("drawer").style.width = `${bounded}px`;
  try {
    window.localStorage.setItem("slips-drawer-width", String(Math.round(bounded)));
  } catch (_) {
    // The panel still resizes when browser storage is unavailable.
  }
}

/** Bind pointer and keyboard controls to the drawer's left resize edge. */
function initDrawerResize() {
  const drawer = byId("drawer");
  const handle = byId("drawer-resize");
  try {
    const stored = Number(window.localStorage.getItem("slips-drawer-width"));
    if (stored) setDrawerWidth(stored);
  } catch (_) {
    // Use the stylesheet default when browser storage is unavailable.
  }
  let startX = 0;
  let startWidth = 0;
  const move = (event) => setDrawerWidth(startWidth + startX - event.clientX);
  const stop = () => {
    document.body.classList.remove("drawer-resizing");
    window.removeEventListener("pointermove", move);
    window.removeEventListener("pointerup", stop);
  };
  handle.addEventListener("pointerdown", (event) => {
    event.preventDefault();
    startX = event.clientX;
    startWidth = drawer.getBoundingClientRect().width;
    document.body.classList.add("drawer-resizing");
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", stop);
  });
  handle.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
    event.preventDefault();
    const delta = event.key === "ArrowLeft" ? 40 : -40;
    setDrawerWidth(drawer.getBoundingClientRect().width + delta);
  });
  window.addEventListener("resize", () =>
    setDrawerWidth(drawer.getBoundingClientRect().width));
}

function rawBlock(record, label) {
  const details = document.createElement("details");
  details.className = "json-details";
  const summary = text("summary", `View complete ${label} record (JSON)`);
  const pre = text("pre", JSON.stringify(record, null, 2));
  details.append(summary, pre);
  return details;
}

/** Create one accessible card for an individual alert. */
function alertCard(record) {
  const button = document.createElement("button");
  const level = String(record.threat_level || "info").toLowerCase();
  button.type = "button";
  button.className = `investigation-card threat-${level}`;
  const heading = document.createElement("div");
  heading.className = "investigation-card-head";
  heading.append(
    text("span", formatTime(record.alert_time), "investigation-card-title"),
    threat(level),
  );
  const metadata = document.createElement("div");
  metadata.className = "investigation-card-meta";
  metadata.append(
    text("span", record.label || "Unlabeled alert"),
    text("span", `${compact(record.evidence_count)} related evidence`),
    text("span", `ID ${record.alert_id}`),
  );
  button.append(heading, metadata);
  button.addEventListener("click", () => openAlert(record));
  return button;
}

/** Create one accessible card for an individual evidence record. */
function evidenceCard(record) {
  const button = document.createElement("button");
  const level = String(record.threat_level || "info").toLowerCase();
  button.type = "button";
  button.className = `investigation-card threat-${level}`;
  const heading = document.createElement("div");
  heading.className = "investigation-card-head";
  heading.append(
    text("span", record.evidence_type || "Unknown evidence", "type-chip"),
    threat(level),
  );
  button.append(heading, text("p", record.description || "No description provided."));
  const metadata = document.createElement("div");
  metadata.className = "investigation-card-meta";
  metadata.append(
    text("span", formatTime(record.timestamp)),
    text("span", `${compact(record.flow_count)} triggering flows`),
    text("span", record.module ? `Module: ${record.module}` : "Module unknown"),
  );
  button.append(metadata);
  button.addEventListener("click", () => openEvidence(record));
  return button;
}

/** Render an attacker or victim with its direction and indicator type. */
function evidenceEntity(label, entity) {
  const card = document.createElement("div");
  card.className = "entity-card";
  card.append(text("small", label));
  const value = entity?.value;
  const indicatorType = String(entity?.ioc_type || "").toUpperCase();
  card.append(indicatorType === "IP" ? hostLink(value) : text("code", value || "Unknown"));
  const metadata = document.createElement("div");
  metadata.className = "entity-meta";
  metadata.append(
    text("span", entity?.direction ? `Direction: ${entity.direction}` : "Direction unknown"),
    text("span", indicatorType ? `Indicator: ${indicatorType}` : "Indicator type unknown"),
  );
  card.append(metadata);
  return card;
}

/** Read one normalized field from a stored network or protocol record. */
function flowValue(flow, ...names) {
  for (const name of names) {
    const value = flow?.[name];
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return null;
}

const PROTOCOL_FIELDS = {
  dns: [
    ["Query", ["query"]], ["Query type", ["qtype_name", "qtype"]],
    ["Query class", ["qclass_name", "qclass"]], ["Result", ["rcode_name", "rcode"]],
    ["Answers", ["answers"]], ["TTLs", ["TTLs", "ttls"]],
  ],
  http: [
    ["Method", ["method"]], ["Host", ["host", "hostname"]], ["URI", ["uri", "url"]],
    ["HTTP version", ["version", "http_version"]], ["Status", ["status_code"]],
    ["Status message", ["status_msg"]], ["User agent", ["user_agent"]],
    ["Request body", ["request_body_len"]], ["Response body", ["response_body_len"]],
    ["Response MIME types", ["resp_mime_types"]], ["Response file IDs", ["resp_fuids"]],
  ],
  ssl: [
    ["Server name", ["server_name", "sni"]], ["TLS version", ["version", "sslversion"]],
    ["Validation", ["validation_status"]], ["Cipher", ["cipher"]], ["Curve", ["curve"]],
    ["Certificate subject", ["subject"]], ["Certificate issuer", ["issuer"]],
    ["Valid from", ["notbefore"]], ["Valid until", ["notafter"]],
    ["Session resumed", ["resumed"]], ["Established", ["established"]],
    ["JA3 client", ["ja3"]], ["JA3 server", ["ja3s"]], ["DNS over HTTPS", ["is_DoH"]],
    ["Certificate chain IDs", ["cert_chain_fuids"]],
    ["Client certificate chain IDs", ["client_cert_chain_fuids"]],
  ],
  ssh: [
    ["SSH version", ["version"]], ["Authentication successful", ["auth_success"]],
    ["Authentication attempts", ["auth_attempts"]], ["Client", ["client"]],
    ["Server", ["server"]], ["Cipher", ["cipher_alg"]], ["MAC algorithm", ["mac_alg"]],
    ["Key exchange", ["kex_alg"]], ["Compression", ["compression_alg"]],
    ["Host-key algorithm", ["host_key_alg"]], ["Host key", ["host_key"]],
  ],
  dhcp: [
    ["Client address", ["client_addr"]], ["Server address", ["server_addr"]],
    ["Requested address", ["requested_addr"]], ["Host name", ["host_name"]],
    ["Client MAC", ["smac"]], ["Related UIDs", ["uids"]],
  ],
  ftp: [["Negotiated data port", ["used_port"]]],
  smtp: [["Last server reply", ["last_reply"]]],
  tunnel: [["Tunnel type", ["tunnel_type"]], ["Action", ["action"]]],
  notice: [
    ["Notice", ["note"]], ["Message", ["msg"]], ["Scanner", ["scanning_ip"]],
    ["Scanned port", ["scanned_port"]], ["Destination", ["dst"]],
  ],
  files: [
    ["File size", ["size"]], ["Source analyzer", ["source"]], ["Analyzers", ["analyzers"]],
    ["MD5", ["md5"]], ["SHA1", ["sha1"]], ["Transmitting hosts", ["tx_hosts"]],
    ["Receiving hosts", ["rx_hosts"]],
  ],
  arp: [
    ["Operation", ["operation"]], ["Source MAC", ["smac", "src_hw"]],
    ["Destination MAC", ["dmac", "dst_hw"]], ["Source hardware", ["src_hw"]],
    ["Destination hardware", ["dst_hw"]],
  ],
  software: [
    ["Software", ["software", "software_name"]], ["Version", ["unparsed_version"]],
    ["Major version", ["version_major"]], ["Minor version", ["version_minor"]],
  ],
  weird: [["Anomaly", ["name"]], ["Additional information", ["addl"]]],
  login: [
    ["Protocol", ["proto"]], ["Successful", ["success"]], ["Parser confused", ["confused"]],
    ["User", ["user"]], ["Client user", ["client_user"]], ["Password", ["password"]],
  ],
};

/** Normalize the type stored for one alternative protocol record. */
function protocolType(record) {
  const flow = record?.flow || {};
  const type = String(record?.flow_type || flow.type_ || flow.type || "protocol").toLowerCase();
  if (type === "tls") return "ssl";
  if (type === "file" || type === "fileinfo") return "files";
  return type;
}

/** Return whether a protocol field contains displayable data. */
function hasProtocolValue(value) {
  return value !== undefined && value !== null && value !== "";
}

/** Format arrays, objects, booleans, sizes, and scalar protocol values. */
function protocolValueText(label, value) {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) {
    if (!value.length) return "None";
    return value.map((item) => {
      if (!item || typeof item !== "object") return String(item);
      return Object.entries(item).map(([key, nested]) => key + ": " + nested).join(" · ");
    }).join(", ");
  }
  if (value && typeof value === "object") return JSON.stringify(value);
  if (/body|file size/i.test(label) && Number.isFinite(Number(value))) return formatBytes(value);
  return String(value);
}

/** Build the visible labeled fields for a protocol-specific record. */
function protocolDetails(type, flow) {
  const definitions = PROTOCOL_FIELDS[type] || [];
  const details = definitions.map(([label, names]) => {
    const value = flowValue(flow, ...names);
    return hasProtocolValue(value) ? [label, protocolValueText(label, value)] : null;
  }).filter(Boolean);
  if (details.length || definitions.length) return details;
  const excluded = new Set([
    "uid", "starttime", "endtime", "saddr", "daddr", "sport", "dport", "proto",
    "appproto", "interface", "type", "type_", "flow_source", "ground_truth_label",
    "detailed_ground_truth_label",
  ]);
  return Object.entries(flow).filter(([name, value]) =>
    !excluded.has(name) && hasProtocolValue(value)).slice(0, 16).map(([name, value]) => [
    name.replaceAll("_", " "), protocolValueText(name, value),
  ]);
}

/** Return the protocol outcome shown prominently beside its title. */
function protocolOutcome(type, flow) {
  if (type === "dns") return flowValue(flow, "rcode_name", "rcode");
  if (type === "http") {
    const code = flowValue(flow, "status_code");
    const message = flowValue(flow, "status_msg");
    return [code, message].filter(hasProtocolValue).join(" ");
  }
  if (type === "ssl") return flowValue(flow, "validation_status");
  if (type === "ssh" && hasProtocolValue(flow.auth_success)) {
    return flow.auth_success === true || String(flow.auth_success).toLowerCase() === "true"
      ? "Authentication succeeded" : "Authentication failed";
  }
  return null;
}

/** Render one alternative-flow record as readable protocol activity. */
function protocolFlowCard(record) {
  const flow = record?.flow && typeof record.flow === "object" ? record.flow : record;
  const type = protocolType(record);
  const displayType = type === "ssl" ? "TLS" : type.toUpperCase();
  const card = document.createElement("section");
  card.className = "protocol-card protocol-" + type;
  const heading = document.createElement("div");
  heading.className = "protocol-card-head";
  heading.append(text("h4", displayType + " flow"));
  const outcome = protocolOutcome(type, flow);
  if (outcome) {
    const isFailure = /NXDOMAIN|SERVFAIL|REFUSED|failed|invalid|error/i.test(outcome);
    heading.append(text("span", outcome, "protocol-outcome " + (isFailure ? "failure" : "success")));
  }
  const context = document.createElement("div");
  context.className = "protocol-context";
  const timestamp = flowValue(flow, "starttime", "ts");
  context.append(
    text("span", "Alternative protocol flow: " + displayType),
    text("span", "UID: " + (record.uid || flow.uid || "Unknown")),
  );
  if (timestamp) {
    const observed = numeric(timestamp) ? formatTime(timestamp) : String(timestamp);
    context.append(text("span", "Observed: " + observed));
  }
  const grid = document.createElement("div");
  grid.className = "protocol-details";
  const details = protocolDetails(type, flow);
  if (!details.length) grid.append(text("p", "No parsed protocol fields are available.", "muted"));
  details.forEach(([label, value]) => {
    const field = document.createElement("div");
    field.className = "protocol-field" + (/query|host|uri|server name/i.test(label) ? " important" : "");
    field.append(text("small", label), text("strong", value));
    grid.append(field);
  });
  card.append(heading, context, grid, rawBlock(record, displayType + " protocol flow"));
  return card;
}

/** Create one primary network-flow card and attach its protocol records. */
function flowCard(group) {
  if (group.network_flow === undefined && group.protocol_flows === undefined) {
    group = group.table === "altflows"
      ? { uid: group.uid, network_flow: null, protocol_flows: [group] }
      : { uid: group.uid, network_flow: group, protocol_flows: [] };
  }
  const record = group.network_flow;
  const related = Array.isArray(group.protocol_flows) ? group.protocol_flows : [];
  const flow = record?.flow && typeof record.flow === "object" ? record.flow : {};
  const card = document.createElement("article");
  card.className = "flow-card flow-group";
  const heading = document.createElement("div");
  heading.className = "flow-card-head";
  heading.append(
    text("code", group.uid || record?.uid || flow.uid || "Unknown UID"),
    text("span", "Flow · conn", "type-chip network-flow-chip"),
  );
  if (related.length) heading.append(text(
    "span", String(related.length) + " related protocol flow" + (related.length === 1 ? "" : "s"),
    "count-chip",
  ));
  card.append(heading);
  if (record) {
    const srcIp = flowValue(flow, "saddr", "src_ip", "id.orig_h");
    const dstIp = flowValue(flow, "daddr", "dst_ip", "id.resp_h");
    const srcPort = flowValue(flow, "sport", "src_port", "id.orig_p");
    const dstPort = flowValue(flow, "dport", "dst_port", "id.resp_p");
    const packets = flowValue(flow, "pkts", "packets")
      ?? numeric(flowValue(flow, "spkts")) + numeric(flowValue(flow, "dpkts"));
    const bytes = flowValue(flow, "bytes")
      ?? numeric(flowValue(flow, "sbytes")) + numeric(flowValue(flow, "dbytes"));
    const path = document.createElement("div");
    path.className = "flow-path";
    const source = document.createElement("div");
    source.className = "flow-endpoint";
    source.append(text("small", "Source host"), hostLink(srcIp));
    if (srcPort !== null) source.append(text("div", "Port " + srcPort, "port-label"));
    const destination = document.createElement("div");
    destination.className = "flow-endpoint";
    destination.append(text("small", "Destination host"), hostLink(dstIp));
    if (dstPort !== null) destination.append(text("div", "Port " + dstPort, "port-label"));
    path.append(source, text("span", "→", "flow-arrow"), destination);
    const metrics = document.createElement("div");
    metrics.className = "flow-metrics";
    [
      ["Transport", flowValue(flow, "proto", "protocol") || "—"],
      ["Application", flowValue(flow, "appproto", "app_proto", "service") || "—"],
      ["State", flowValue(flow, "state", "conn_state") || "—"],
      ["Packets", compact(packets)], ["Bytes", formatBytes(bytes)],
      ["Duration", numeric(flowValue(flow, "dur", "duration")).toFixed(3) + " s"],
      ["Label", record.label || flow.label || "—"], ["Interface", flow.interface || "—"],
    ].forEach(([label, value]) => {
      const metric = document.createElement("div");
      metric.className = "flow-metric";
      metric.append(text("small", label), text("strong", value));
      metrics.append(metric);
    });
    card.append(path, metrics, rawBlock(record, "flow"));
  } else {
    card.append(text(
      "p",
      "The primary flow row is unavailable, but related protocol flows were retained.",
      "flow-missing",
    ));
  }
  if (related.length) {
    const section = document.createElement("div");
    section.className = "related-protocols";
    section.append(investigationHeading(
      "Related protocol flows",
      "Alternative protocol records associated by the same flow UID",
    ));
    related.forEach((protocol) => section.append(protocolFlowCard(protocol)));
    card.append(section);
  } else {
    card.append(text("p", "No related protocol flows were recorded for this flow.", "muted protocol-empty"));
  }
  return card;
}

async function openEvidence(record) {
  const generation = openDrawer("EVIDENCE", record.evidence_type || record.id);
  const body = byId("drawer-body");
  const alertCount = record.alert_ids?.length || 0;
  body.append(
    investigationStats([
      ["Detected", formatTime(record.timestamp)],
      ["Profile host", hostLink(record.profile_ip)],
      ["Threat", threat(record.threat_level)],
      ["Confidence", `${Math.round(numeric(record.confidence) * 100)}%`, "accent"],
    ]),
    investigationHeading("Detection summary", record.module ? `Generated by ${record.module}` : ""),
    text("p", record.description || "No description provided.", "description-box"),
  );
  if (record.attacker || record.victim) {
    const entities = document.createElement("div");
    entities.className = "entity-grid";
    if (record.attacker) entities.append(evidenceEntity("Attacker / source", record.attacker));
    if (record.victim) entities.append(evidenceEntity("Victim / destination", record.victim));
    body.append(investigationHeading("Evidence entities"), entities);
  }
  body.append(
    investigationStats([
      ["Evidence ID", record.id],
      ["Time window", record.twid || record.timewindow?.number || "—"],
      ["Method", record.method || "—"],
      ["Signal", record.evidence_signal || "—"],
      ["Protocol", record.proto || "—"],
      ["Source port", record.src_port ?? "—"],
      ["Destination port", record.dst_port ?? "—"],
      ["Alert links", alertCount ? compact(alertCount) : "None"],
    ]),
  );
  if (alertCount) {
    const identifiers = document.createElement("div");
    identifiers.className = "identifier-list";
    record.alert_ids.forEach((id) => identifiers.append(text("code", id)));
    body.append(investigationHeading("Related alert IDs"), identifiers);
  }
  body.append(
    investigationHeading("Triggering flows", "Each flow includes its related parsed protocol flows"),
  );
  try {
    const payload = await api("evidenceFlows", `/api/evidence/${escapePath(record.id)}/flows`);
    if (!payload || generation !== state.drawerGeneration) return;
    if (!payload.items.length) body.append(text("p", "No triggering flow records are available."));
    payload.items.forEach((flow) => body.append(flowCard(flow)));
  } catch (_) {
    if (generation !== state.drawerGeneration) return;
    body.append(text("p", "Triggering flows could not be loaded.", "muted"));
  }
  body.append(
    investigationHeading("Complete evidence data", "Original durable evidence object"),
    rawBlock(record, "evidence"),
  );
}

async function openAlert(record) {
  const generation = openDrawer("ALERT", `Alert on ${record.ip_alerted}`);
  const body = byId("drawer-body");
  if (record.evidence === undefined) {
    body.append(text("p", "Loading alert evidence…", "muted"));
    const params = new URLSearchParams({
      range: "all", limit: "1", search: record.alert_id,
    });
    try {
      const payload = await api("alertDetail", `/api/alerts?${params}`);
      if (!payload || generation !== state.drawerGeneration) return;
      const detailed = payload.items.find((item) => item.alert_id === record.alert_id);
      if (!detailed) {
        body.replaceChildren(text("p", "This alert is no longer available.", "muted"));
        return;
      }
      record = detailed;
    } catch (_) {
      if (generation !== state.drawerGeneration) return;
      body.replaceChildren(text("p", "Alert evidence could not be loaded.", "muted"));
      return;
    }
    body.replaceChildren();
  }
  body.append(
    investigationStats([
      ["Created", formatTime(record.alert_time)],
      ["Affected host", hostLink(record.ip_alerted)],
      ["Highest threat", threat(record.threat_level)],
      ["Evidence", compact(record.evidence_count), "accent"],
    ]),
    investigationStats([
      ["Alert ID", record.alert_id],
      ["Classification", record.label || "—"],
      ["Time window", record.timewindow || "—"],
      ["Window start", record.tw_start || "—"],
    ]),
    investigationHeading("Related evidence", "Select evidence to inspect its triggering flows"),
  );
  if (!record.evidence?.length) body.append(text("p", "No related durable evidence is available."));
  const evidenceList = document.createElement("div");
  evidenceList.className = "investigation-list";
  record.evidence?.forEach((item) => evidenceList.append(evidenceCard(item)));
  body.append(
    evidenceList,
    investigationHeading("Complete alert data", "Original durable alert object and evidence links"),
    rawBlock(record, "alert"),
  );
}

async function openAlertGroup(group) {
  const generation = openDrawer("HOST ALERTS", `Alerts for ${group.ip_alerted}`);
  const body = byId("drawer-body");
  body.append(
    investigationStats([
      ["Host", hostLink(group.ip_alerted)],
      ["Alerts", compact(group.alert_count), "danger"],
      ["Evidence links", compact(group.evidence_count), "accent"],
      ["Highest threat", threat(group.threat_level)],
    ]),
    investigationHeading("Alert timeline", "Newest matching alerts first; select one for evidence"),
  );
  const params = rangeQuery("alerts");
  params.set("profile", group.ip_alerted);
  params.set("limit", "100");
  params.set("sort", "time");
  params.set("order", "desc");
  params.set("details", "false");
  const level = byId("alerts-threat").value;
  const search = byId("alerts-search").value.trim();
  if (level) params.set("threat", level);
  if (search) params.set("search", search);
  try {
    const payload = await api("alertGroup", `/api/alerts?${params}`);
    if (!payload || generation !== state.drawerGeneration) return;
    const list = document.createElement("div");
    list.className = "investigation-list";
    payload.items.forEach((item) => list.append(alertCard(item)));
    body.append(list);
    if (!payload.items.length) body.append(text("p", "No matching alerts.", "muted"));
    if (payload.total > payload.page_size) {
      body.append(text("p", `Showing newest ${payload.page_size} of ${compact(payload.total)} matching alerts.`, "muted"));
    }
  } catch (_) {
    if (generation !== state.drawerGeneration) return;
    body.append(text("p", "Individual alerts could not be loaded.", "muted"));
  }
}

async function openEvidenceGroup(group) {
  const generation = openDrawer("HOST EVIDENCE", group.evidence_type);
  const body = byId("drawer-body");
  body.append(
    investigationStats([
      ["Host", hostLink(group.profile_ip)],
      ["Evidence", compact(group.evidence_count), "accent"],
      ["Triggering flows", compact(group.flow_count)],
      ["Alert links", compact(group.alert_count)],
      ["Highest threat", threat(group.threat_level)],
      ["Module", group.module || "—"],
    ]),
    investigationHeading("Evidence timeline", "Newest matching evidence first; select one for flows"),
  );
  const params = rangeQuery("evidence");
  params.set("profile", group.profile_ip);
  params.set("type", group.evidence_type);
  params.set("limit", "100");
  params.set("sort", "time");
  params.set("order", "desc");
  const level = byId("evidence-threat").value;
  const association = byId("evidence-link").value;
  const search = byId("evidence-search").value.trim();
  if (level) params.set("threat", level);
  if (association) params.set("association", association);
  if (search) params.set("search", search);
  try {
    const payload = await api("evidenceGroup", `/api/evidence?${params}`);
    if (!payload || generation !== state.drawerGeneration) return;
    const list = document.createElement("div");
    list.className = "investigation-list";
    payload.items.forEach((item) => list.append(evidenceCard(item)));
    body.append(list);
    if (!payload.items.length) body.append(text("p", "No matching evidence.", "muted"));
    if (payload.total > payload.page_size) {
      body.append(text("p", `Showing newest ${payload.page_size} of ${compact(payload.total)} matching records.`, "muted"));
    }
  } catch (_) {
    if (generation !== state.drawerGeneration) return;
    body.append(text("p", "Individual evidence could not be loaded.", "muted"));
  }
}

function hostRangeParams() {
  const params = rangeQuery("host");
  return params;
}

function renderHostCards(host) {
  setSummaryCards([
    ["All IPs", compact(host.all_ips?.length || 1)],
    ["Flows", compact(host.load?.flows)],
    ["Inbound flows", compact(host.load?.inbound_flows)],
    ["Outbound flows", compact(host.load?.outbound_flows)],
    ["Traffic", formatBytes(host.load?.bytes)],
    ["Inbound bytes", formatBytes(host.load?.inbound_bytes)],
    ["Outbound bytes", formatBytes(host.load?.outbound_bytes)],
    ["Packets", compact(host.load?.packets)],
    ["Evidence", compact(host.evidence_count)],
    ["Alerts", compact(host.alert_count)],
  ], "host-summary");
  const identity = byId("host-identity");
  identity.replaceChildren(
    detailRow("Addresses", host.all_ips?.join(", ") || host.ip),
    detailRow("Hostname", host.hostname || "Unknown"),
    detailRow("MAC", host.mac || "Unknown"),
    detailRow("Vendor", host.mac_vendor || "Unknown"),
    detailRow("Scope", host.scope || "Unknown"),
    detailRow("Status", host.live ? "Current Redis metadata" : "Last-known persisted metadata"),
    detailRow("DNS", renderDnsDetails(host.dns)),
  );
  byId("host-ti").textContent = Object.keys(host.ti || {}).length
    ? JSON.stringify(host.ti, null, 2) : "No cached threat-intelligence data.";
  byId("host-alerts-title").textContent = "Related alerts · " + host.alert_count;
  const alerts = byId("host-alerts");
  alerts.replaceChildren();
  host.alerts?.slice(0, 100).forEach((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "host-alert-chip";
    button.append(
      threat(item.threat_level),
      text("span", item.label || "Unlabeled alert", "host-alert-label"),
      text("time", formatTime(item.alert_time)),
      text("span", compact(item.evidence_count) + " evidence", "count-chip"),
    );
    button.addEventListener("click", () => openAlert(item));
    alerts.append(button);
  });
  if (!host.alerts?.length) alerts.append(text("p", "No related alerts.", "muted"));
}

async function loadHostEvidence() {
  if (!state.host) return;
  const page = state.pages["host-evidence"];
  const params = new URLSearchParams({
    range: "all",
    limit: "100",
    sort: page.sort,
    order: page.order,
  });
  if (page.cursors[page.index]) params.set("cursor", page.cursors[page.index]);
  const path = "/api/hosts/" + escapePath(state.host.ip) + "/evidence?" + params;
  const payload = await api("hostEvidence", path);
  if (!payload) return;
  page.items = payload.items;
  page.total = payload.total;
  page.next = payload.next_cursor;
  byId("host-evidence-title").textContent = "Related evidence · " + payload.total;
  byId("host-evidence-count").textContent =
    payload.page_size + " shown · " + compact(payload.total) + " evidence records";
  renderTable("host-evidence-table", payload.items, [
    (row) => formatTime(row.timestamp),
    (row) => threat(row.threat_level),
    (row) => text("code", row.evidence_type),
    (row) => text("code", row.module || "—"),
    (row) => Math.round(numeric(row.confidence) * 100) + "%",
    (row) => compact(row.flow_count),
    (row) => row.alert_ids?.length ? compact(row.alert_ids.length) : "none",
    (row) => {
      const description = text("span", row.description || "—", "host-evidence-description");
      description.title = row.description || "";
      return description;
    },
  ], openEvidence);
  applySortIndicators("host-evidence");
  pager("host-evidence", "host-evidence-pager", loadHostEvidence);
}

async function loadHostFlows() {
  if (!state.host) return;
  const page = state.pages.hostFlows;
  const params = hostRangeParams();
  params.set("limit", byId("host-flow-limit").value);
  if (page.cursors[page.index]) params.set("cursor", page.cursors[page.index]);
  const path = `/api/hosts/${escapePath(state.host.ip)}/flows?${params}`;
  const payload = await api("hostFlows", path);
  if (!payload) return;
  page.items = payload.items;
  page.total = payload.total;
  page.next = payload.next_cursor;
  byId("host-flow-count").textContent =
    `${payload.page_size} shown · ${compact(payload.total)} flows match this range`;
  renderTable("host-flows-table", payload.items, [
    (row) => formatTime(row.event_time),
    (row) => text("span", row.direction, `status ${row.direction === "inbound" ? "ok" : "warn"}`),
    (row) => text("code", row.peer),
    (row) => [row.proto, row.app_proto].filter(Boolean).join(" / "),
    (row) => `${row.src_port ?? "—"} → ${row.dst_port ?? "—"}`,
    (row) => row.state || "—",
    (row) => compact(row.packets),
    (row) => formatBytes(row.bytes),
    (row) => `${numeric(row.duration).toFixed(3)} s`,
    (row) => row.label || "—",
  ], (row) => {
    openDrawer("FLOW", row.uid);
    byId("drawer-body").append(
      detailRow("Direction", row.direction),
      detailRow("Peer", row.peer),
      detailRow("Source", hostLink(row.src_ip)),
      detailRow("Destination", hostLink(row.dst_ip)),
      detailRow("Ports", `${row.src_port ?? "—"} → ${row.dst_port ?? "—"}`),
      rawBlock(row.raw, "flow"),
    );
  });
  pager("hostFlows", "host-flows-pager", loadHostFlows);
}

async function loadHostSummary() {
  if (!state.host) return;
  const params = hostRangeParams();
  params.set("max_points", "600");
  const payload = await api("hostSummary",
    `/api/hosts/${escapePath(state.host.ip)}/traffic-summary?${params}`);
  if (!payload) return;
  renderLineChart("host-flow-chart", payload.timeline, [
    { key: "inbound_flows" }, { key: "outbound_flows", className: "secondary-line" },
  ]);
  renderLineChart("host-byte-chart", payload.timeline, [
    { key: "inbound_bytes" }, { key: "outbound_bytes", className: "secondary-line" },
  ]);
  renderBars("host-protocols", payload.protocols);
  renderBars("host-peers", payload.peers);
}

async function openHost(ip) {
  const host = await api("host", `/api/hosts/${escapePath(ip)}`);
  if (!host) return;
  state.host = host;
  resetPage("hostFlows");
  resetPage("host-evidence");
  byId("hosts-list-view").hidden = true;
  byId("host-detail-view").hidden = false;
  byId("host-title").textContent = host.ip;
  byId("host-subtitle").textContent =
    `${host.hostname || "Unnamed host"} · ${host.scope} · ${host.live ? "current" : "last known"}`;
  renderHostCards(host);
  await Promise.all([loadHostFlows(), loadHostSummary(), loadHostEvidence()]);
}

async function refreshHostWorkspace() {
  if (!state.host) return;
  const host = await api("host", `/api/hosts/${escapePath(state.host.ip)}`);
  if (!host) return;
  state.host = host;
  renderHostCards(host);
  await Promise.all([loadHostFlows(), loadHostSummary(), loadHostEvidence()]);
}

function closeHost() {
  state.host = null;
  state.requests.get("hostFlows")?.abort();
  state.requests.get("hostSummary")?.abort();
  state.requests.get("hostEvidence")?.abort();
  byId("host-detail-view").hidden = true;
  byId("hosts-list-view").hidden = false;
}

function tabLoader(name) {
  return { overview: loadOverview, alerts: loadAlerts, evidence: loadEvidence, hosts: loadHosts }[name];
}

function currentLoader() {
  if (state.activeTab === "hosts" && state.host) return refreshHostWorkspace;
  return tabLoader(state.activeTab);
}

async function refreshActive() {
  if (document.hidden) return;
  const loader = currentLoader();
  try {
    await loader();
  } catch (_) {
    // Persistent banner and polling backoff handle data-source failures.
  } finally {
    schedulePoll();
  }
}

function activeRangeIsLive() {
  if (state.activeTab === "overview") return true;
  if (state.activeTab === "hosts" && state.host) {
    return rangeIsLive("host") && state.pages.hostFlows.index === 0;
  }
  return rangeIsLive(state.activeTab) && state.pages[state.activeTab].index === 0;
}

function schedulePoll() {
  window.clearTimeout(state.timer);
  if (document.hidden || !activeRangeIsLive()) return;
  const delay = Math.min(5000 * (2 ** state.failures), 60000);
  state.timer = window.setTimeout(refreshActive, delay);
}

function switchTab(name) {
  state.activeTab = name;
  document.querySelectorAll(".tab").forEach((tab) =>
    tab.classList.toggle("active", tab.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((panel) =>
    panel.classList.toggle("active", panel.id === name));
  currentLoader()().catch(() => {});
  schedulePoll();
}

function bindFilters(name, controls, loader) {
  controls.forEach((id) => {
    const element = byId(id);
    const eventName = element.type === "search" ? "input" : "change";
    let timer;
    element.addEventListener(eventName, () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        resetPage(name);
        loader().catch(() => {});
        schedulePoll();
      }, element.type === "search" ? 250 : 0);
    });
  });
}

/**
 * Reset sorting and pagination when a table changes between record and aggregate mode.
 *
 * @param {string} name Table state and element prefix.
 * @param {Function} loader Function that refreshes the selected table.
 */
function bindView(name, loader) {
  byId(`${name}-view`).addEventListener("change", () => {
    const page = state.pages[name];
    page.sort = "time";
    page.order = "desc";
    resetPage(name);
    loader().catch(() => {});
    schedulePoll();
  });
}

function bindRange(prefix, pageName, loader) {
  const select = byId(`${prefix}-range`);
  const update = () => {
    const custom = select.value === "custom";
    byId(`${prefix}-from`).hidden = !custom;
    byId(`${prefix}-to`).hidden = !custom;
    resetPage(pageName);
    loader().catch(() => {});
    schedulePoll();
  };
  select.addEventListener("change", update);
  [byId(`${prefix}-from`), byId(`${prefix}-to`)].forEach((input) =>
    input.addEventListener("change", update));
}

document.querySelectorAll(".tab").forEach((tab) =>
  tab.addEventListener("click", () => switchTab(tab.dataset.tab)));
document.querySelectorAll(".refresh-list").forEach((button) =>
  button.addEventListener("click", () => tabLoader(button.dataset.target)().catch(() => {})));
byId("refresh-overview").addEventListener("click", () => loadOverview().catch(() => {}));
byId("metrics-range").addEventListener("change", () => loadMetrics().catch(() => {}));
byId("module-search").addEventListener("input", () =>
  state.overview && renderModules(state.overview.modules));
byId("drawer-close").addEventListener("click", closeDrawer);
byId("drawer-back").addEventListener("click", backDrawer);
byId("drawer-backdrop").addEventListener("click", closeDrawer);
byId("host-back").addEventListener("click", closeHost);
byId("host-flow-limit").addEventListener("change", () => {
  resetPage("hostFlows");
  loadHostFlows().catch(() => {});
});

bindFilters("alerts", ["alerts-search", "alerts-threat"], loadAlerts);
bindFilters("evidence", ["evidence-search", "evidence-threat", "evidence-link"], loadEvidence);
bindFilters("hosts", ["hosts-search", "hosts-scope", "hosts-threat"], loadHosts);
bindView("alerts", loadAlerts);
bindView("evidence", loadEvidence);
bindRange("alerts", "alerts", loadAlerts);
bindRange("evidence", "evidence", loadEvidence);
bindRange("hosts", "hosts", loadHosts);
bindRange("host", "hostFlows", async () => {
  await Promise.all([loadHostFlows(), loadHostSummary(), loadHostEvidence()]);
});
bindTableSort("hosts", loadHosts);
bindTableSort("host-evidence", loadHostEvidence);

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    window.clearTimeout(state.timer);
    state.requests.forEach((controller) => controller.abort());
  } else {
    refreshActive();
  }
});
window.addEventListener("beforeunload", () =>
  state.requests.forEach((controller) => controller.abort()));

initDrawerResize();
loadOverview().then(schedulePoll).catch(schedulePoll);
