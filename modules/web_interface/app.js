"use strict";

const state = {
  activeTab: "overview",
  overview: null,
  metrics: [],
  configuration: null,
  whitelists: null,
  arpPoisoning: null,
  host: null,
  failures: 0,
  connected: false,
  lastSuccessfulRequest: null,
  timer: null,
  requests: new Map(),
  drawerHistory: [],
  drawerGeneration: 0,
  runIdentity: null,
  rangesInitialized: false,
  titleCounts: { alerts: 0, hosts: 0 },
  localSorts: {
    "arp-poisoning-hosts-table": { key: "ip", order: "asc" },
    "arp-poisoning-events-table": { key: "timestamp", order: "desc" },
    "arp-poisoning-evidence-table": { key: "timestamp", order: "desc" },
  },
  pages: {
    alerts: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
    evidence: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
    hosts: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "last_seen", order: "desc" },
    modules: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "cpu_percent", order: "desc" },
    firewall: { items: [], total: 0, next: null, cursors: [null], index: 0 },
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
const formatDuration = (value) => {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0) return "—";
  const elapsed = Math.floor(amount);
  const days = Math.floor(elapsed / 86400);
  const hours = String(Math.floor((elapsed % 86400) / 3600)).padStart(2, "0");
  const minutes = String(Math.floor((elapsed % 3600) / 60)).padStart(2, "0");
  const seconds = String(elapsed % 60).padStart(2, "0");
  const clock = `${hours}:${minutes}:${seconds}`;
  return days ? `${days}d ${clock}` : clock;
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
/** Convert standalone Unix timestamps to localized, human-readable text. */
function displayValue(value) {
  const candidate = typeof value === "string" ? value.trim() : value;
  const numericTimestamp = typeof candidate === "number"
    || (typeof candidate === "string" && /^\d{10}(?:\.\d+)?$/.test(candidate));
  if (numericTimestamp) {
    const amount = Number(candidate);
    if (Number.isFinite(amount) && amount >= 946684800 && amount <= 4102444800) {
      return formatTime(amount);
    }
  }
  const millisecondTimestamp = typeof candidate === "number"
    || (typeof candidate === "string" && /^\d{13}$/.test(candidate));
  if (millisecondTimestamp) {
    const amount = Number(candidate);
    if (Number.isFinite(amount) && amount >= 946684800000 && amount <= 4102444800000) {
      return formatTime(amount / 1000);
    }
  }
  return value ?? "—";
}
/** Recursively humanize timestamps inside arrays and structured detail data. */
function displayData(value) {
  if (Array.isArray(value)) return value.map((item) => displayData(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, displayData(item)]),
    );
  }
  return displayValue(value);
}
const text = (tag, value, className = "") => {
  const element = document.createElement(tag);
  element.textContent = displayValue(value);
  if (className) element.className = className;
  return element;
};
const cell = (value, className = "") => {
  const td = document.createElement("td");
  if (value instanceof Node) td.append(value);
  else td.textContent = displayValue(value);
  if (className) td.className = className;
  return td;
};
const threat = (value) => {
  const level = String(value || "info").toLowerCase();
  return text("span", level, `status threat-${level}`);
};
const slipsScore = (record) => {
  if (record.whitelisted) {
    const excluded = text("span", "Excluded", "slips-score whitelisted");
    excluded.title = "Slips matched a whitelist rule and deliberately excluded this evidence from scoring.";
    return excluded;
  }
  const score = Number(record.alert_score);
  const threshold = Number(record.alert_threshold);
  if (!Number.isFinite(score) || !Number.isFinite(threshold)) {
    const unavailable = text("span", "Pending", "slips-score unavailable");
    unavailable.title = "Waiting for Slips to persist this detector score.";
    return unavailable;
  }
  const ratio = threshold > 0 ? score / threshold : 0;
  const tone = ratio >= 1 ? "reached" : ratio >= 0.75 ? "near" : "below";
  const formatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 3 });
  const element = text(
    "span",
    `${formatter.format(score)} / ${formatter.format(threshold)}`,
    `slips-score ${tone}`,
  );
  element.title = `${record.alert_score_mode || "Slips"} · ${record.alert_score_basis || "detector accumulator"}`;
  return element;
};

/** Render the highest persisted real Slips score for one host. */
function pastPeakSlipsScore(record) {
  if (record.peak_alert_score === null || record.peak_alert_score === undefined) {
    const unavailable = text("span", "No samples", "slips-score unavailable");
    unavailable.title = "No persisted Slips score sample exists for this host yet.";
    return unavailable;
  }
  return slipsScore({
    ...record,
    alert_score: record.peak_alert_score,
    alert_score_basis: "highest persisted score in the full run",
  });
}
const whitelistHandling = (record) => {
  if (!record.whitelisted) return text("span", "Scored", "status neutral");
  const count = numeric(record.whitelisted_count);
  const label = count ? `${compact(count)} excluded` : "Whitelisted";
  const marker = text("span", label, "status whitelisted");
  marker.title = "Slips excluded this evidence from score accumulation because a whitelist rule matched.";
  return marker;
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

/**
 * Show whether the browser can currently reach the local web server.
 *
 * @param {boolean} connected True after a successful API response.
 */
function renderConnectionState(connected) {
  state.connected = connected;
  const dot = byId("state-dot");
  const label = byId("run-state");
  const updated = byId("updated-at");
  if (!connected) {
    dot.className = "state-dot error";
    label.textContent = "Web disconnected";
    updated.textContent = state.lastSuccessfulRequest
      ? `Last update ${state.lastSuccessfulRequest.toLocaleTimeString()}`
      : "No connection";
    return;
  }
  const runState = state.overview?.run?.state;
  dot.className = `state-dot ${runState || "running"}`;
  label.textContent = runState
    ? (runState === "running" ? "Analysis running" : "Analysis complete")
    : "Web connected";
  updated.textContent = `Updated ${state.lastSuccessfulRequest.toLocaleTimeString()}`;
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
    state.lastSuccessfulRequest = new Date();
    renderConnectionState(true);
    clearError();
    return payload;
  } catch (error) {
    if (error.name === "AbortError") return null;
    state.failures += 1;
    renderConnectionState(false);
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

/** Sort one bounded client-side table and update its accessible indicators. */
function sortLocalRows(id, rows) {
  const sort = state.localSorts[id];
  if (!sort) return [...rows];
  document.querySelectorAll(`#${id} th[data-sort]`).forEach((header) => {
    const active = header.dataset.sort === sort.key;
    header.classList.toggle("sorted", active);
    header.dataset.order = active ? sort.order : "";
    header.setAttribute("aria-sort", active
      ? (sort.order === "asc" ? "ascending" : "descending") : "none");
  });
  const direction = sort.order === "asc" ? 1 : -1;
  return [...rows].sort((left, right) => {
    const first = left[sort.key];
    const second = right[sort.key];
    if (first === null || first === undefined) return 1;
    if (second === null || second === undefined) return -1;
    const firstNumber = Number(first);
    const secondNumber = Number(second);
    if (Number.isFinite(firstNumber) && Number.isFinite(secondNumber)) {
      return (firstNumber - secondNumber) * direction;
    }
    return String(first).localeCompare(String(second), undefined, {
      numeric: true, sensitivity: "base",
    }) * direction;
  });
}

/** Bind keyboard and pointer sorting to one bounded client-side table. */
function bindLocalTableSort(id, rerender) {
  document.querySelectorAll(`#${id} th[data-sort]`).forEach((header) => {
    header.tabIndex = 0;
    const changeSort = () => {
      const sort = state.localSorts[id];
      const key = header.dataset.sort;
      if (sort.key === key) sort.order = sort.order === "asc" ? "desc" : "asc";
      else {
        sort.key = key;
        sort.order = ["ip", "status", "mac", "action", "current_tw", "release_tw",
          "profile_ip", "threat_level", "evidence_type", "description"].includes(key)
          ? "asc" : "desc";
      }
      rerender();
    };
    header.addEventListener("click", changeSort);
    header.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        changeSort();
      }
    });
  });
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

/** Format a chart-axis numeric value without adding an unnecessary unit. */
function formatChartValue(value, maximum) {
  const amount = numeric(value);
  if (maximum < 10) return amount.toFixed(1);
  if (maximum < 100) return amount.toFixed(0);
  return compact(amount);
}

/** Format a memory-chart axis value using binary units. */
function formatMemoryChartValue(value) {
  const mib = numeric(value);
  if (mib < 1024) return `${formatChartValue(mib, mib)} MiB`;
  const gib = mib / 1024;
  return `${formatChartValue(gib, gib)} GiB`;
}

/** Format a CPU-chart axis value as a percentage of total host capacity. */
function formatCpuChartValue(value, maximum) {
  return `${formatChartValue(value, maximum)}%`;
}

/** Format a compact, readable timestamp for a performance-chart x-axis. */
function formatChartTime(value, span) {
  const timestamp = numeric(value);
  if (timestamp < 946684800) return formatTime(timestamp).replace("T+", "");
  const options = span >= 86400
    ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }
    : { hour: "2-digit", minute: "2-digit", second: "2-digit" };
  return new Date(timestamp * 1000).toLocaleString([], options);
}

/** Render a performance chart with numeric and time axes. */
function renderLineChart(id, points, series, formatValue = formatChartValue) {
  const svg = byId(id);
  svg.replaceChildren();
  const height = numeric(svg.viewBox?.baseVal?.height) || 180;
  const renderedWidth = numeric(svg.clientWidth);
  const renderedHeight = numeric(svg.clientHeight);
  const width = renderedWidth > 0 && renderedHeight > 0
    ? height * renderedWidth / renderedHeight
    : numeric(svg.viewBox?.baseVal?.width) || 600;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  const left = 42;
  const right = 10;
  const top = 12;
  const bottom = 30;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  if (!points.length) {
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", String(width / 2));
    label.setAttribute("y", String(height / 2 + 2));
    label.setAttribute("text-anchor", "middle");
    label.textContent = "No samples in this range";
    svg.append(label);
    return;
  }
  const hasValue = (point, key) => point[key] !== null
    && point[key] !== undefined
    && Number.isFinite(Number(point[key]));
  const values = points.flatMap((point) => series
    .filter((item) => hasValue(point, item.key))
    .map((item) => numeric(point[item.key])));
  const maximum = Math.max(...values, 1);
  const minimumTime = numeric(points[0].ts);
  const maximumTime = numeric(points.at(-1).ts);
  const span = Math.max(maximumTime - minimumTime, 1);
  const grid = document.createElementNS("http://www.w3.org/2000/svg", "path");
  grid.setAttribute("d", `M${left} ${height - bottom}H${width - right}M${left} ${top}V${height - bottom}`);
  grid.setAttribute("class", "grid-line");
  svg.append(grid);
  [0, 0.5, 1].forEach((ratio) => {
    const y = height - bottom - ratio * plotHeight;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", String(left));
    line.setAttribute("x2", String(width - right));
    line.setAttribute("y1", String(y));
    line.setAttribute("y2", String(y));
    line.setAttribute("class", "grid-line chart-grid-line");
    svg.append(line);
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", String(left - 6));
    label.setAttribute("y", String(y + 3));
    label.setAttribute("text-anchor", "end");
    label.setAttribute("class", "chart-label");
    label.textContent = formatValue(maximum * ratio, maximum);
    svg.append(label);
  });
  [0, 0.5, 1].forEach((ratio) => {
    const x = left + ratio * plotWidth;
    const timestamp = minimumTime + ratio * span;
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", String(x));
    label.setAttribute("y", String(height - 8));
    label.setAttribute("text-anchor", ratio === 0 ? "start" : ratio === 1 ? "end" : "middle");
    label.setAttribute("class", "chart-label");
    label.textContent = formatChartTime(timestamp, span);
    svg.append(label);
  });
  for (const item of series) {
    const seriesPoints = points.filter((point) => hasValue(point, item.key));
    if (!seriesPoints.length) continue;
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    const d = seriesPoints.map((point, index) => {
      const x = left + ((numeric(point.ts) - minimumTime) / span) * plotWidth;
      const y = height - bottom - (numeric(point[item.key]) / maximum) * plotHeight;
      return `${index ? "L" : "M"}${x.toFixed(2)} ${y.toFixed(2)}`;
    }).join(" ");
    path.setAttribute("d", d);
    path.setAttribute("class", `chart-line ${item.className || ""}`);
    if (item.label) {
      const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
      title.textContent = item.label;
      path.append(title);
    }
    svg.append(path);
    if (seriesPoints.length === 1) {
      const point = seriesPoints[0];
      const marker = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      marker.setAttribute("cx", String(left + ((numeric(point.ts) - minimumTime) / span) * plotWidth));
      marker.setAttribute("cy", String(height - bottom - (numeric(point[item.key]) / maximum) * plotHeight));
      marker.setAttribute("r", "3");
      marker.setAttribute("class", `chart-point ${item.className || ""}`);
      svg.append(marker);
    }
  }
  points.filter((point) => point.reset_reason).forEach((point) => {
    const x = left + ((numeric(point.ts) - minimumTime) / span) * plotWidth;
    const marker = document.createElementNS("http://www.w3.org/2000/svg", "line");
    marker.setAttribute("x1", String(x));
    marker.setAttribute("x2", String(x));
    marker.setAttribute("y1", String(top));
    marker.setAttribute("y2", String(height - bottom));
    marker.setAttribute("class", "chart-reset-line");
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    title.textContent = `${formatTime(point.ts)} · ${point.reset_reason}`;
    marker.append(title);
    svg.append(marker);
  });
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
    const valueElement = document.createElement("strong");
    card.className = "summary-card";
    if (value instanceof Node) valueElement.append(value);
    else valueElement.textContent = displayValue(value);
    card.append(text("span", label), valueElement);
    container.append(card);
  });
}

/**
 * Keep the browser title focused on the two primary detection totals.
 *
 * @param {Object} counts Updated alert or host totals.
 */
function updatePageTitle(counts = {}) {
  state.titleCounts = { ...state.titleCounts, ...counts };
  document.title = `Slips ${compact(state.titleCounts.alerts)} alerts · ${compact(state.titleCounts.hosts)} hosts`;
}

/**
 * Render run identity shared by every top-level tab.
 *
 * @param {Object} data Current overview API payload.
 */
function renderRunContext(data) {
  const run = data.run;
  const outputName = String(run.output_dir || "").split("/").filter(Boolean).at(-1);
  byId("run-name").textContent = outputName || "Current run";
  const metadata = data.run_metadata || {};
  byId("run-meta").textContent = [
    metadata.File || run.input_type || "input",
    metadata.Branch ? `branch ${metadata.Branch}` : "",
    metadata["Slips version"] ? `Slips ${metadata["Slips version"]}` : "",
    metadata.Commit ? `commit ${metadata.Commit}` : "",
  ].filter(Boolean).join(" · ");
  renderConnectionState(true);
  byId("alerts-badge").textContent = compact(data.counts.alerts);
  byId("evidence-badge").textContent = compact(data.counts.evidence);
  byId("hosts-badge").textContent = compact(data.counts.hosts);
  byId("logs-badge").textContent = compact(data.counts.module_errors);
  updatePageTitle({ alerts: data.counts.alerts, hosts: data.counts.hosts });
}

/** Render the operational overview without supporting metadata or logs. */
function renderOverview() {
  const data = state.overview;
  if (!data) return;
  renderRunContext(data);
  const firewall = data.firewall || {};
  setSummaryCards([
    ["Alerts", compact(data.counts.alerts)],
    ["Hosts", compact(data.counts.hosts)],
    ["Uptime", formatDuration(data.run.uptime_seconds)],
    ["Evidence", compact(data.counts.evidence)],
    ["Processed flows", compact(data.counts.processed_flows)],
    ["FW active", compact(firewall.current)],
    ["FW added", compact(firewall.added)],
    ["FW discarded", compact(firewall.discarded)],
  ]);
  const firewallImpact = data.firewall_impact || {};
  setSummaryCards([
    ["Packets stopped (estimated)", compact(firewallImpact.packets)],
    ["Flows stopped (estimated)", compact(firewallImpact.flows)],
    ["Evidence while blocked", compact(firewallImpact.evidence)],
  ], "overview-firewall-impact");
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
  renderModules(data.modules);
}

/**
 * Render the metadata captured for this run.
 *
 * @param {Object} metadata Parsed metadata labels and values.
 */
function renderMetadata(metadata) {
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
}

/** Infer a display severity without changing the retained raw log line. */
function logSeverity(record) {
  const content = `${record.message || ""} ${record.line || ""}`.toLowerCase();
  if (/\b(critical|fatal|panic|traceback|exception)\b/.test(content)) return "critical";
  if (/\b(warning|warn)\b/.test(content)) return "warning";
  if (/\b(debug)\b/.test(content)) return "debug";
  if (/\b(info|notice)\b/.test(content)) return "info";
  return "error";
}

/** Append safe, lightly highlighted log text to a console line. */
function appendHighlightedLogText(container, value) {
  const content = String(value || "");
  const tokenPattern = /(\b(?:critical|fatal|panic|traceback|exception|error|failed|failure|warning|warn)\b|(?:\/[\w.@-]+)+(?:\.py)?(?::\d+)?|\b(?:\d{1,3}\.){3}\d{1,3}\b)/gi;
  let offset = 0;
  for (const match of content.matchAll(tokenPattern)) {
    if (match.index > offset) {
      container.append(document.createTextNode(content.slice(offset, match.index)));
    }
    const token = match[0];
    const className = token.startsWith("/") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(token)
      ? "log-token-reference" : "log-token-alert";
    container.append(text("span", token, className));
    offset = match.index + token.length;
  }
  if (offset < content.length) {
    container.append(document.createTextNode(content.slice(offset)));
  }
}

/** Open one retained runtime event in a console-style investigation drawer. */
function openLog(record) {
  const severity = logSeverity(record);
  openDrawer("RUNTIME LOG", record.module || "Slips");
  const body = byId("drawer-body");
  body.append(investigationStats([
    ["Time", formatTime(record.event_time)],
    ["Module", record.module || "unknown"],
    ["Level", text("span", severity, `log-level ${severity}`)],
  ]));
  const terminal = document.createElement("section");
  terminal.className = `log-console ${severity}`;
  const titlebar = document.createElement("div");
  titlebar.className = "log-console-titlebar";
  const lights = document.createElement("span");
  lights.className = "log-console-lights";
  lights.setAttribute("aria-hidden", "true");
  lights.append(text("i", ""), text("i", ""), text("i", ""));
  titlebar.append(lights, text("code", `${record.module || "Slips"} · errors.log`));
  const output = document.createElement("div");
  output.className = "log-console-output";
  const line = document.createElement("div");
  line.className = "log-console-line";
  line.append(
    text("span", formatTime(record.event_time), "log-console-time"),
    text("span", `[${record.module || "unknown"}]`, "log-console-module"),
    text("strong", severity, `log-console-level ${severity}`),
  );
  const message = document.createElement("span");
  message.className = "log-console-message";
  appendHighlightedLogText(message, record.message);
  line.append(message);
  const raw = document.createElement("div");
  raw.className = "log-console-raw";
  raw.append(
    text("small", "RAW SOURCE"),
    text("pre", record.line || record.message || "No source line retained."),
  );
  output.append(line, raw);
  terminal.append(titlebar, output);
  body.append(terminal);
}

/**
 * Render the latest parsed runtime log messages.
 *
 * @param {Object} payload Bounded log records and their total count.
 */
function renderLogs(payload) {
  const errors = payload.items || [];
  byId("logs-badge").textContent = compact(payload.total);
  byId("logs-count").textContent = `${errors.length} shown · ${compact(payload.total)} total`;
  renderTable("logs-table", errors, [
    (row) => formatTime(row.event_time),
    (row) => text("span", logSeverity(row), `log-level ${logSeverity(row)}`),
    (row) => text("code", row.module, "log-module"),
    (row) => text("span", row.message, `log-message ${logSeverity(row)}`),
  ], openLog);
}

/** Render a module resource value with a 0–100 red heat-map background. */
function usageCell(percentage, label, resource) {
  const actual = Math.max(0, numeric(percentage));
  const intensity = Math.min(actual, 100);
  const element = text("span", label, "usage-cell");
  element.style.backgroundColor = `rgba(239, 107, 115, ${intensity / 100})`;
  element.title = `${actual.toFixed(1)}% of ${resource}`;
  return element;
}

function renderModules(modules) {
  const query = byId("module-search").value.trim().toLowerCase();
  const sort = state.pages.modules;
  const numericColumns = new Set([
    "pid", "cpu_percent", "memory_mb", "flows_per_minute", "evidence_count", "error_count",
  ]);
  const rows = modules.filter((item) => item.name.toLowerCase().includes(query));
  rows.sort((left, right) => {
    const key = sort.sort;
    const comparison = numericColumns.has(key)
      ? numeric(left[key]) - numeric(right[key])
      : String(left[key] || "").localeCompare(String(right[key] || ""));
    if (comparison) return sort.order === "asc" ? comparison : -comparison;
    return left.name.localeCompare(right.name);
  });
  renderTable("modules-table", rows, [
    (row) => text("code", row.name),
    (row) => text("span", row.state, `status ${row.running ? "ok" : "warn"}`),
    (row) => row.pid,
    (row) => usageCell(
      row.cpu_percent, `${numeric(row.cpu_percent).toFixed(1)}%`, "one CPU core",
    ),
    (row) => usageCell(
      row.memory_percent, `${numeric(row.memory_mb).toFixed(1)} MiB`, "host memory",
    ),
    (row) => compact(row.flows_per_minute),
    (row) => compact(row.evidence_count),
    (row) => row.error_count,
  ]);
  applySortIndicators("modules");
}

async function loadMetrics() {
  const range = byId("metrics-range").value;
  const payload = await api("metrics", `/api/metrics?range=${range}&max_points=1200`);
  if (!payload) return;
  state.metrics = payload.items;
  renderLineChart(
    "cpu-chart", state.metrics,
    [{ key: "cpu" }, { key: "cpu_max", className: "secondary-line" }],
    formatCpuChartValue,
  );
  renderLineChart(
    "memory-chart", state.metrics,
    [{ key: "memory" }, { key: "memory_max", className: "secondary-line" }],
    formatMemoryChartValue,
  );
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

/** Load the operational overview and its history charts. */
async function loadOverview() {
  const payload = await api("overview", "/api/overview");
  if (!payload) return;
  state.overview = payload;
  initializeRanges(payload.run);
  renderOverview();
  await loadMetrics();
}

/** Load and render run metadata in its dedicated tab. */
async function loadMetadata() {
  const payload = await api("metadata", "/api/metadata");
  if (!payload) return;
  renderMetadata(payload.items || {});
}

/** Load and render parsed runtime messages in their dedicated tab. */
async function loadLogs() {
  const payload = await api("logs", "/api/logs");
  if (!payload) return;
  renderLogs(payload);
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
    if (["alerts", "hosts"].includes(name)) {
      updatePageTitle({ [name]: payload.full_total });
    }
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
    ["Peak Slips score", "score"],
    ["Name / domain", null], ["TI feeds", null],
    ["Alerts", "alerts"], ["Evidence links", "evidence"], ["Labels", "label"],
  ] : [
    ["Time", "time"], ["Host", "host"], ["Threat", "threat"],
    ["Slips score", "score"],
    ["TW", "tw"], ["Window start", "tw_start"], ["Window end", "tw_end"],
    ["Name / domain", null], ["TI feeds", null], ["Label", "label"],
    ["Evidence", "evidence"], ["Alert ID", "id"],
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
      (row) => threat(row.threat_level), (row) => slipsScore(row),
      (row) => contextName(row),
      (row) => tiFeeds(row), (row) => compact(row.alert_count),
      (row) => compact(row.evidence_count), (row) => row.label || "—",
    ], openAlertGroup);
  } else {
    renderTable("alerts-table", payload.items, [
      (row) => formatTime(row.alert_time), (row) => text("code", row.ip_alerted),
      (row) => threat(row.threat_level),
      (row) => slipsScore(row),
      (row) => text("code", row.timewindow || "—"),
      (row) => row.tw_start || "—", (row) => row.tw_end || "—",
      (row) => contextName(row), (row) => tiFeeds(row), (row) => row.label || "—",
      (row) => compact(row.evidence_count), (row) => text("code", row.alert_id),
    ], openAlert);
  }
  pager("alerts", "alerts-pager", loadAlerts);
}

async function loadEvidence() {
  const grouped = byId("evidence-view").value === "grouped";
  configureTable("evidence", grouped ? "grouped" : "individual", grouped ? [
    ["Latest", "time"], ["Host", "host"], ["Highest threat", "threat"],
    ["Peak Slips score", "score"],
    ["Type", "type"], ["Module", "module"], ["Evidence", "evidence"],
    ["Flows", "flows"], ["Alert links", "alert"], ["Score handling", null],
  ] : [
    ["Time", "time"], ["Host", "host"], ["Threat", "threat"],
    ["Slips score", "score"],
    ["Type", "type"], ["Module", "module"], ["Score handling", null], ["Flows", "flows"],
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
      (row) => threat(row.threat_level), (row) => slipsScore(row),
      (row) => text("code", row.evidence_type),
      (row) => text("code", row.module), (row) => compact(row.evidence_count),
      (row) => compact(row.flow_count),
      (row) => row.alert_count ? `${compact(row.alert_count)} linked` : "none",
      (row) => whitelistHandling(row),
    ], openEvidenceGroup);
  } else {
    renderTable("evidence-table", payload.items, [
      (row) => formatTime(row.timestamp), (row) => text("code", row.profile_ip),
      (row) => threat(row.threat_level), (row) => slipsScore(row),
      (row) => text("code", row.evidence_type),
      (row) => text("code", row.module), (row) => whitelistHandling(row),
      (row) => compact(row.flow_count),
      (row) => row.alert_ids?.length ? compact(row.alert_ids.length) : "none",
      (row) => row.description || "—",
    ], openEvidence);
  }
  pager("evidence", "evidence-pager", loadEvidence);
}

function renderConfiguration() {
  const payload = state.configuration;
  if (!payload) return;
  const query = byId("configuration-search").value.trim().toLowerCase();
  const container = byId("configuration-sections");
  container.replaceChildren();
  let shown = 0;
  (payload.sections || []).forEach((section) => {
    const settings = (section.settings || []).filter((setting) => !query || [
      section.title, section.description, setting.key, setting.label,
      setting.explanation, JSON.stringify(setting.value),
    ].join(" ").toLowerCase().includes(query));
    if (!settings.length) return;
    shown += settings.length;
    const details = document.createElement("details");
    details.className = "surface config-section";
    details.open = Boolean(query) || ["parameters", "detection", "whitelists", "web_interface"]
      .includes(section.key);
    const summary = document.createElement("summary");
    const heading = document.createElement("div");
    heading.append(text("h3", section.title), text("p", section.description));
    summary.append(heading, text("span", `${settings.length} settings`, "count-chip"));
    const grid = document.createElement("div");
    grid.className = "config-settings";
    settings.forEach((setting) => {
      const card = document.createElement("article");
      card.className = "config-setting";
      const value = setting.value && typeof setting.value === "object"
        ? JSON.stringify(displayData(setting.value)) : displayValue(setting.value);
      card.append(
        text("small", `${section.key}.${setting.key}`, "config-key"),
        text("h4", setting.label),
        text("code", value === "" ? "Empty" : value, setting.sensitive ? "redacted" : ""),
        text("p", setting.explanation),
      );
      grid.append(card);
    });
    details.append(summary, grid);
    container.append(details);
  });
  byId("configuration-count").textContent = `${shown} shown · ${payload.total} captured settings`;
  if (!shown) container.append(text("p", "No settings match this search.", "surface empty-state"));
}

async function loadConfiguration() {
  const payload = await api("configuration", "/api/configuration");
  if (!payload) return;
  state.configuration = payload;
  byId("configuration-status").textContent = payload.captured
    ? `${payload.total} settings from the immutable run snapshot.`
    : "No configuration snapshot was captured for this run.";
  byId("configuration-source").textContent = payload.source
    ? `${payload.source} was copied into this run when Slips started. Values below are parsed, grouped, and explained; this is not a dump of the YAML text.`
    : "Run metadata did not contain a YAML configuration snapshot.";
  renderConfiguration();
}

function renderWhitelists() {
  const payload = state.whitelists;
  if (!payload) return;
  const query = byId("whitelists-search").value.trim().toLowerCase();
  const type = byId("whitelists-type").value;
  const rows = (payload.rules || []).filter((rule) =>
    (!type || rule.type === type) && (!query || JSON.stringify(rule).toLowerCase().includes(query)));
  byId("whitelists-count").textContent = `${rows.length} shown · ${payload.total} parsed local rules`;
  renderTable("whitelists-table", rows, [
    (row) => text("span", row.type, "type-chip"),
    (row) => text("code", row.value),
    (row) => row.direction === "both" ? "Source or destination" : row.direction === "src" ? "Source" : "Destination",
    (row) => row.ignore === "both" ? "Flows and alerts" : row.ignore === "alerts" ? "Evidence and alerts" : "Flows",
    (row) => row.effect,
    (row) => row.source,
  ]);
}

async function loadWhitelists() {
  const payload = await api("whitelists", "/api/whitelists");
  if (!payload) return;
  state.whitelists = payload;
  byId("whitelists-badge").textContent = compact(payload.total);
  byId("whitelists-status").textContent = `${payload.total} local rules were parsed for this run. Evidence marked “Whitelisted” was excluded by Slips before score accumulation.`;
  setSummaryCards([
    ["Parsed local rules", compact(payload.total)],
    ["IP addresses", compact(payload.counts?.["IP address"])],
    ["Domains", compact(payload.counts?.Domain)],
    ["Organizations", compact(payload.counts?.Organization)],
    ["Online domains loaded", compact(payload.online_domains_loaded)],
  ], "whitelists-summary");
  byId("whitelists-local-source").replaceChildren(
    detailRow("Enabled", payload.local_enabled ? "Yes" : "No"),
    detailRow("Captured source", payload.local_source || "Not captured"),
    detailRow("Runtime result", `${payload.total} parsed rules`),
  );
  byId("whitelists-online-source").replaceChildren(
    detailRow("Enabled", payload.online_enabled ? "Yes" : "No"),
    detailRow("Source", payload.online_source || "Not configured"),
    detailRow("Configured limit", payload.online_domain_limit ?? "Not configured"),
    detailRow("Loaded now", `${compact(payload.online_domains_loaded)} domains`),
    detailRow("Refresh period", payload.online_update_period
      ? formatDuration(payload.online_update_period) : "Not configured"),
  );
  renderWhitelists();
}

async function loadFirewall() {
  const search = byId("firewall-search").value.trim();
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  const historyPage = state.pages.firewall;
  const historyCursor = historyPage.cursors[historyPage.index];
  if (historyCursor) params.set("history_offset", historyCursor);
  const payload = await api("firewall", `/api/firewall?${params}`);
  if (!payload) return;
  byId("firewall-badge").textContent = compact(payload.total);
  byId("firewall-count").textContent = `${payload.page_size} active enforcement record${payload.page_size === 1 ? "" : "s"}`;
  const impact = payload.impact || {};
  setSummaryCards([
    ["Packets stopped (estimated)", compact(impact.packets)],
    ["Flows stopped (estimated)", compact(impact.flows)],
    ["Evidence while blocked", compact(impact.evidence)],
  ], "firewall-impact-summary");
  renderTable("firewall-table", payload.items, [
    (row) => text("code", row.ip),
    (row) => text("span", row.status, `status ${["blocked", "overdue", "stale"].includes(row.status) ? "bad" : "warn"}`),
    (row) => row.recovered
      ? `${row.recovery_status || "Recovered"}${row.origin_run ? ` · ${row.origin_run}` : ""}`
      : "Current run",
    (row) => formatTime(row.blocked_at),
    (row) => row.unblock_at ? formatTime(row.unblock_at) : "Schedule unavailable",
    (row) => row.remaining_seconds === null ? "Schedule unavailable" : formatDuration(row.remaining_seconds),
    (row) => row.remaining_timewindows === null ? "—" : row.remaining_timewindows,
    (row) => compact(row.stopped_packets),
    (row) => compact(row.stopped_flows),
    (row) => compact(row.evidence_while_blocked),
    (row) => compact(row.evidence_count),
    (row) => compact(row.alert_count),
  ], (row) => openHost(row.ip));
  const history = payload.history || [];
  historyPage.items = history;
  historyPage.total = payload.history_total || 0;
  historyPage.next = payload.history_next_cursor || null;
  byId("firewall-history-count").textContent = `${payload.history_total || 0} block/unblock event${payload.history_total === 1 ? "" : "s"} match this view.`;
  renderTable("firewall-history-table", history, [
    (row) => formatTime(row.timestamp),
    (row) => text("code", row.ip),
    (row) => text("span", row.action, `status ${row.action === "unblocked" ? "ok" : "bad"}`),
    (row) => row.details || "—",
  ], (row) => openHost(row.ip));
  pager("firewall", "firewall-history-pager", loadFirewall);
}

/** Render ARP poisoner host state, transitions, and detector evidence. */
function renderArpPoisoning() {
  const payload = state.arpPoisoning;
  if (!payload) return;
  const search = byId("arp-poisoning-search").value.trim().toLowerCase();
  const matches = (row) => !search
    || JSON.stringify(row).toLowerCase().includes(search);
  const hosts = (payload.hosts || []).filter(matches);
  const events = (payload.events || []).filter(matches);
  const evidence = (payload.evidence || []).filter(matches);
  byId("arp-poisoning-count").textContent = `${hosts.length} shown · ${payload.counts.hosts} hosts`;
  renderTable("arp-poisoning-hosts-table",
    sortLocalRows("arp-poisoning-hosts-table", hosts), [
      (row) => text("code", row.ip),
      (row) => text("span", row.status,
        `status ${row.status === "released" ? "ok" : "bad"}`),
      (row) => formatTime(row.poisoned_at),
      (row) => formatTime(row.unblock_at),
      (row) => formatTime(row.released_at),
      (row) => row.remaining_seconds === null
        ? "—" : formatDuration(row.remaining_seconds),
      (row) => row.current_tw ?? "—",
      (row) => row.release_tw ?? "—",
      (row) => row.extra_timewindows ?? "—",
      (row) => text("code", row.mac || "—"),
    ], (row) => openHost(row.ip));
  renderTable("arp-poisoning-events-table",
    sortLocalRows("arp-poisoning-events-table", events), [
      (row) => formatTime(row.timestamp),
      (row) => text("code", row.ip),
      (row) => text("span", row.action,
        `status ${row.action === "released" ? "ok" : "bad"}`),
      (row) => row.current_tw ?? "—",
      (row) => row.release_tw ?? "—",
      (row) => formatTime(row.unblock_at),
      (row) => row.extra_timewindows ?? "—",
      (row) => row.details || "—",
    ], (row) => openHost(row.ip));
  renderTable("arp-poisoning-evidence-table",
    sortLocalRows("arp-poisoning-evidence-table", evidence), [
      (row) => formatTime(row.timestamp),
      (row) => text("code", row.profile_ip),
      (row) => threat(row.threat_level),
      (row) => text("code", row.evidence_type),
      (row) => `${Math.round(numeric(row.confidence) * 100)}%`,
      (row) => compact(row.flow_count),
      (row) => compact(row.alert_count),
      (row) => row.description || "—",
    ], (row) => openHost(row.profile_ip));
}

/** Load the bounded, run-scoped ARP poisoner and detector view. */
async function loadArpPoisoning() {
  const payload = await api("arpPoisoning", "/api/arp-poisoning");
  if (!payload) return;
  state.arpPoisoning = payload;
  const counts = payload.counts || {};
  const module = payload.module || {};
  byId("arp-poisoning-badge").textContent = compact(counts.active);
  byId("arp-poisoning-status").textContent = module.enabled
    ? `arp_poisoner is ${module.state}${module.pid ? ` · PID ${module.pid}` : ""}.`
    : "arp_poisoner did not start in this run.";
  setSummaryCards([
    ["Module", module.state || "not started"],
    ["Poisoned now", compact(counts.active)],
    ["Released", compact(counts.released)],
    ["Transitions", compact(counts.transitions)],
    ["ARP evidence", compact(counts.evidence)],
  ], "arp-poisoning-summary");
  renderArpPoisoning();
}

/** Render one compact reliability-history line for every known P2P peer. */
function renderP2PTrustChart(history, peers) {
  const rows = history.filter((row) => Number.isFinite(Number(row.timestamp))
    && Number.isFinite(Number(row.reliability)));
  const peerIds = [...new Set(rows.map((row) => String(row.peer_id)))];
  const peerIndexes = new Map(peerIds.map((peerId, index) => [peerId, index]));
  const peerIps = new Map(peers.map((peer) => [String(peer.peer_id), peer.ip]));
  const points = rows.map((row) => ({
    ts: numeric(row.timestamp),
    [`peer_${peerIndexes.get(String(row.peer_id))}`]: numeric(row.reliability),
  })).sort((left, right) => left.ts - right.ts);
  const series = peerIds.map((peerId, index) => ({
    key: `peer_${index}`,
    className: `peer-trust-line-${index % 8}`,
    label: peerIps.get(peerId) || peerId,
  }));
  renderLineChart(
    "p2p-trust-chart",
    points,
    series,
    (value) => numeric(value).toFixed(2),
  );
  const legend = byId("p2p-trust-legend");
  legend.replaceChildren();
  peerIds.forEach((peerId, index) => {
    const item = text(
      "span",
      peerIps.get(peerId) || peerId,
      "p2p-trust-legend-item",
    );
    const marker = document.createElement("i");
    marker.className = `peer-trust-key peer-trust-line-${index % 8}`;
    item.prepend(marker);
    item.title = peerId;
    legend.append(item);
  });
}

async function loadP2P() {
  const range = byId("p2p-range").value;
  const payload = await api("p2p", `/api/p2p?range=${encodeURIComponent(range)}`);
  if (!payload) return;
  const counts = payload.counts || {};
  byId("p2p-badge").textContent = compact(counts.connected);
  byId("p2p-status").textContent = payload.enabled
    ? (counts.connected ? `${counts.connected} peer${counts.connected === 1 ? "" : "s"} connected now.` : "P2P is running and listening; no peers are connected now.")
    : "P2P is not running for this Slips run.";
  setSummaryCards([
    ["Connected peers", compact(counts.connected)],
    ["Known peers", compact(counts.known)],
    ["Reports sent", compact(counts.reports_sent)],
    ["Reports received", compact(counts.reports_received)],
    ["Requests sent / received", `${compact(counts.requests_sent)} / ${compact(counts.requests_received)}`],
  ], "p2p-summary");
  const identity = byId("p2p-identity");
  identity.replaceChildren(
    detailRow("Local peer ID", payload.local_peer_id || "Waiting for Pigeon identity"),
    detailRow("Listen address", payload.listener || "Waiting for listener announcement"),
  );
  renderP2PTrustChart(payload.trust_history || [], payload.peers || []);
  renderTable("p2p-peers-table", payload.peers || [], [
    (row) => text("code", row.peer_id),
    (row) => text("code", row.ip || "—"),
    (row) => text("span", row.connected ? "connected" : "offline", `status ${row.connected ? "ok" : "warn"}`),
    (row) => row.trust === null ? "—" : numeric(row.trust).toFixed(3),
    (row) => row.reliability === null ? "—" : numeric(row.reliability).toFixed(3),
    (row) => compact(row.reports_received),
    (row) => formatTime(row.last_seen),
  ]);
  renderTable("p2p-trust-table", (payload.trust_history || []).slice(0, 100), [
    (row) => formatTime(row.timestamp),
    (row) => text("code", row.peer_id),
    (row) => numeric(row.reliability).toFixed(3),
  ]);
  renderTable("p2p-reports-table", payload.reports || [], [
    (row) => formatTime(row.timestamp),
    (row) => text("code", row.peer_id),
    (row) => text("code", row.target),
    (row) => numeric(row.score).toFixed(3),
    (row) => numeric(row.confidence).toFixed(3),
  ]);
  renderTable("p2p-activity-table", payload.activity || [], [
    (row) => formatTime(row.timestamp),
    (row) => row.direction || "—",
    (row) => row.message_type || "unknown",
    (row) => text("code", row.peer || "—"),
    (row) => text("code", row.target || "—"),
  ]);
}

async function loadHosts() {
  const payload = await api("hosts", listPath("hosts"));
  if (!payload) return;
  applyPage("hosts", payload);
  renderTable("hosts-table", payload.items, [
    (row) => text("code", row.ip),
    (row) => text("span", row.scope, `status ${row.scope === "public" ? "warn" : "ok"}`),
    (row) => row.hostname || "—",
    (row) => contextName(row),
    (row) => tiFeeds(row),
    (row) => text("code", row.mac || "—"),
    (row) => threat(row.max_threat_level),
    (row) => slipsScore(row),
    (row) => pastPeakSlipsScore(row),
    (row) => compact(row.load?.flows),
    (row) => formatBytes(row.load?.bytes),
    (row) => compact(row.evidence_count),
    (row) => compact(row.alert_count),
    (row) => formatTime(row.load?.last_seen || row.observed_at),
  ], (row) => openHost(row.ip, row));
  pager("hosts", "hosts-pager", loadHosts);
}

/** Render cached rDNS or the most recently associated DNS domain. */
function contextName(record) {
  const value = record.dns_name || "—";
  const source = record.dns_name_source || "No cached DNS context";
  const element = text("code", value);
  element.title = source;
  return element;
}

/** Render names of threat-intelligence feeds that contain this IP. */
function tiFeeds(record) {
  const feeds = Array.isArray(record.ti_feeds) ? record.ti_feeds : [];
  const element = text("span", feeds.length ? feeds.join(", ") : "—");
  element.title = feeds.length
    ? `${feeds.length} matching threat-intelligence feed${feeds.length === 1 ? "" : "s"}`
    : "No cached threat-intelligence feed match";
  return element;
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
      detailRow(
        key.replaceAll("_", " "),
        typeof value === "object" ? JSON.stringify(displayData(value)) : value,
      ),
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
  const pre = text("pre", JSON.stringify(displayData(record), null, 2));
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
    text("span", `TW: ${record.twid || record.timewindow?.number || "—"}`),
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
      if (!item || typeof item !== "object") return String(displayValue(item));
      return Object.entries(item)
        .map(([key, nested]) => key + ": " + JSON.stringify(displayData(nested)))
        .join(" · ");
    }).join(", ");
  }
  if (value && typeof value === "object") return JSON.stringify(displayData(value));
  if (/body|file size/i.test(label) && Number.isFinite(Number(value))) return formatBytes(value);
  return String(displayValue(value));
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
  if (record.whitelisted) {
    const notice = document.createElement("section");
    notice.className = "whitelist-notice";
    notice.append(
      text("h3", "Excluded from scoring by whitelist"),
      text("p", "Slips detected and retained this evidence for visibility, but a whitelist rule matched an entity inside it. Evidence Handler therefore did not add it to the host score or use it to form an alert."),
    );
    const matches = Array.isArray(record.whitelist_matches)
      ? record.whitelist_matches : [];
    if (matches.length) {
      const list = document.createElement("ul");
      matches.forEach((match) => {
        list.append(text(
          "li",
          `${match.entity} ${match.type.toLowerCase()} ${match.value} matched rule ${match.rule} (${match.direction}; suppress ${match.ignore}).`,
        ));
      });
      notice.append(list);
    } else {
      notice.append(text(
        "p",
        "The whitelist decision is recorded, but the exact matching entity cannot be reconstructed from the retained evidence data.",
        "muted",
      ));
    }
    body.append(notice);
  }
  body.append(
    investigationStats([
      ["Detected", formatTime(record.timestamp)],
      ["Profile host", hostLink(record.profile_ip)],
      ["Threat", threat(record.threat_level)],
      ["Slips score", slipsScore(record), "accent"],
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
  const portScanEvidence = ["HORIZONTAL_PORT_SCAN", "VERTICAL_PORT_SCAN"].includes(
    String(record.evidence_type).toUpperCase(),
  );
  const arpScanEvidence = String(record.evidence_type).toUpperCase() === "ARP_SCAN";
  if (arpScanEvidence) {
    const retainedFlowCount = numeric(record.flow_count);
    const retainedLabel = `${retainedFlowCount} linked ARP record${retainedFlowCount === 1 ? "" : "s"}`;
    const retentionMessage = retainedFlowCount < 5
      ? `This legacy evidence retains only ${retainedLabel} because its ARP records had no unique UIDs. It was not detected from one packet.`
      : `This evidence retains ${retainedLabel}; the contributing requests are listed below.`;
    body.append(text(
      "p",
      `ARP scan rule: at least 5 requests to 5 distinct destination IPs within 30 seconds. ${retentionMessage}`,
      retainedFlowCount < 5 ? "flow-missing" : "description-box",
    ));
  }
  body.append(
    investigationHeading(
      "Triggering flows",
      portScanEvidence
        ? "Port-scan evidence links at most 20 flows; each includes related parsed protocol flows."
        : "Each flow includes its related parsed protocol flows.",
    ),
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
      ["Slips score", slipsScore(record), "danger"],
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
  const exactAggregates = host.exact_aggregates !== false;
  setSummaryCards([
    ["Flows", exactAggregates ? compact(host.load?.flows) : "—"],
    ["Inbound flows", exactAggregates ? compact(host.load?.inbound_flows) : "—"],
    ["Outbound flows", exactAggregates ? compact(host.load?.outbound_flows) : "—"],
    ["Traffic", exactAggregates ? formatBytes(host.load?.bytes) : "—"],
    ["Inbound bytes", exactAggregates ? formatBytes(host.load?.inbound_bytes) : "—"],
    ["Outbound bytes", exactAggregates ? formatBytes(host.load?.outbound_bytes) : "—"],
    ["Packets", exactAggregates ? compact(host.load?.packets) : "—"],
    ["Current Slips score", slipsScore(host)],
    ["Evidence", exactAggregates ? compact(host.evidence_count) : "—"],
    ["Alerts", exactAggregates ? compact(host.alert_count) : "—"],
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
    ? JSON.stringify(displayData(host.ti), null, 2)
    : "No cached threat-intelligence data.";
  byId("host-alerts-title").textContent = exactAggregates
    ? "Related alerts · " + host.alert_count
    : "Related alerts · exact profile IP only";
  const alerts = byId("host-alerts");
  alerts.replaceChildren();
  const exactAlerts = host.alerts?.filter((item) => item.ip_alerted === host.ip) || [];
  exactAlerts.slice(0, 100).forEach((item) => {
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
  if (!exactAlerts.length) alerts.append(text("p", "No related alerts.", "muted"));
}

async function loadHostEvidence() {
  if (!state.host) return;
  const page = state.pages["host-evidence"];
  const params = hostRangeParams();
  params.set("limit", "100");
  params.set("sort", page.sort);
  params.set("order", page.order);
  const search = byId("host-evidence-search").value.trim();
  if (search) params.set("search", search);
  if (page.cursors[page.index]) params.set("cursor", page.cursors[page.index]);
  params.set("profile", state.host.ip);
  params.set("details", "false");
  const path = "/api/evidence?" + params;
  const payload = await api("hostEvidence", path);
  if (!payload) return;
  page.items = payload.items;
  page.total = payload.total;
  page.next = payload.next_cursor;
  byId("host-evidence-title").textContent = "Related evidence · " + payload.total;
  byId("host-evidence-count").textContent =
    payload.page_size + " shown · " + compact(payload.total) + " evidence records" +
    (search ? " matching search" : "");
  renderTable("host-evidence-table", payload.items, [
    (row) => formatTime(row.timestamp),
    (row) => threat(row.threat_level),
    (row) => text("code", row.evidence_type),
    (row) => text("code", row.module || "—"),
    (row) => whitelistHandling(row),
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
  const exactItems = payload.items.filter((row) =>
    row.src_ip === state.host.ip || row.dst_ip === state.host.ip);
  const discarded = payload.items.length - exactItems.length;
  page.items = exactItems;
  page.total = discarded ? exactItems.length : payload.total;
  page.next = payload.next_cursor;
  byId("host-flow-count").textContent =
    `${exactItems.length} shown · exact profile IP only` +
    (discarded ? ` · ${discarded} stale MAC-alias rows discarded` :
      ` · ${compact(payload.total)} flows match this range`);
  renderTable("host-flows-table", exactItems, [
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
  const includesAliases = Array.isArray(payload.host_ips)
    && payload.host_ips.some((address) => address !== state.host.ip);
  const status = byId("host-traffic-status");
  if (includesAliases) {
    status.textContent = "Traffic aggregates withheld because the running backend grouped unrelated addresses through a shared next-hop MAC. Historical rows below are filtered to the exact profile IP.";
    renderLineChart("host-flow-chart", [], [{ key: "inbound_flows" }]);
    renderLineChart("host-byte-chart", [], [{ key: "inbound_bytes" }]);
    renderBars("host-protocols", []);
    renderBars("host-peers", []);
    return;
  }
  status.textContent = "Traffic and peers match the exact profile IP only.";
  renderLineChart("host-flow-chart", payload.timeline, [
    { key: "inbound_flows" }, { key: "outbound_flows", className: "secondary-line" },
  ]);
  renderLineChart("host-byte-chart", payload.timeline, [
    { key: "inbound_bytes" }, { key: "outbound_bytes", className: "secondary-line" },
  ]);
  renderBars("host-protocols", payload.protocols);
  renderBars("host-peers", payload.peers);
}

/** Render score history and explain how much evidence has a persisted score. */
function renderHostScoreHistory(payload) {
  let points = Array.isArray(payload.timeline) ? payload.timeline : [];
  if (points.length === 1) {
    points = [{ ...points[0], ts: numeric(points[0].ts) - 1 }, points[0]];
  }
  renderLineChart("host-score-chart", points, [
    { key: "score" },
    { key: "peak_score", className: "secondary-line" },
    { key: "threshold", className: "threshold-line" },
  ]);
  const total = numeric(payload.evidence_total);
  const scored = numeric(payload.scored_evidence);
  const status = byId("host-score-history-status");
  if (payload.history_unavailable) {
    const selectedRange = byId("host-range").selectedOptions[0]?.textContent || "selected range";
    const current = payload.current_score === null || payload.current_score === undefined
      ? "unavailable"
      : `${numeric(payload.current_score).toFixed(3)} / ${numeric(payload.threshold).toFixed(3)}`;
    status.textContent = `No persisted score history is available for ${selectedRange} from the currently running web backend. Current score: ${current}. Restart only the web interface to load the updated history endpoint; Slips analysis does not need to restart.`;
  } else if (payload.compatibility_source) {
    const inspected = numeric(payload.inspected_evidence);
    const rangeLabel = byId("host-range").selectedOptions[0]?.textContent || "selected range";
    const completeness = payload.compatibility_limited
      ? `newest ${compact(inspected)} of ${compact(total)} evidence records`
      : `all ${compact(total)} evidence records`;
    status.textContent = `${compact(scored)} real ${payload.mode} score samples from ${completeness} in ${rangeLabel} · peak ${numeric(payload.peak_score).toFixed(3)} / ${numeric(payload.threshold).toFixed(3)} · ${compact(payload.reset_count)} detected resets${payload.compatibility_limited ? " · partial compatibility history until the web backend next starts" : ""}.`;
  } else if (total > 0 && scored === 0) {
    status.textContent = `${compact(total)} evidence records exist, but none has a persisted processed-score sample. They may still be queued for the Evidence Handler or predate score persistence.`;
  } else if (total > scored) {
    status.textContent = `${compact(scored)} of ${compact(total)} evidence records have real ${payload.mode} samples · peak ${numeric(payload.peak_score).toFixed(3)} / ${numeric(payload.threshold).toFixed(3)} · ${compact(payload.reset_count)} detected resets.`;
  } else {
    status.textContent = `${compact(scored)} processed score samples · peak ${numeric(payload.peak_score).toFixed(3)} / ${numeric(payload.threshold).toFixed(3)} · ${compact(payload.reset_count)} detected resets.`;
  }
}

/** Recover bounded, range-aware score samples through an older evidence API. */
async function loadLegacyScoreHistory(params) {
  const evidenceLimit = 600;
  const records = [];
  let cursor = "";
  let total = 0;
  do {
    const query = new URLSearchParams(params);
    query.set("profile", state.host.ip);
    query.set("limit", String(Math.min(100, evidenceLimit - records.length)));
    query.set("sort", "time");
    query.set("order", "desc");
    query.set("details", "false");
    if (cursor) query.set("cursor", cursor);
    const response = await fetch(`/api/evidence?${query}`, { cache: "no-store" });
    const page = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(page.detail || page.error || `HTTP ${response.status}`);
    }
    total = numeric(page.total);
    records.push(...(Array.isArray(page.items) ? page.items : []));
    cursor = page.next_cursor || "";
  } while (cursor && records.length < evidenceLimit);

  const timeline = records
    .filter((row) => row.alert_score !== null
      && row.alert_score !== undefined
      && Number.isFinite(Number(row.alert_score)))
    .map((row) => ({
      ts: numeric(row.timestamp),
      timewindow: row.twid || "",
      score: Number(row.alert_score),
      peak_score: Number(row.alert_score),
      threshold: Number(row.alert_threshold),
    }))
    .sort((left, right) => left.ts - right.ts);
  let previous = null;
  let resetCount = 0;
  timeline.forEach((point) => {
    point.reset_reason = previous && point.timewindow !== previous.timewindow
      ? "time window changed"
      : previous && point.score < previous.score
        ? "score reset after an alert"
        : "";
    if (point.reset_reason) resetCount += 1;
    previous = point;
  });
  const threshold = timeline.find((point) => Number.isFinite(point.threshold))?.threshold
    ?? numeric(state.host.alert_threshold);
  timeline.forEach((point) => { point.threshold = threshold; });
  return {
    timeline,
    threshold,
    mode: state.host.alert_score_mode || "Slips",
    peak_score: Math.max(...timeline.map((point) => point.score), 0),
    evidence_total: total,
    inspected_evidence: records.length,
    scored_evidence: timeline.length,
    reset_count: resetCount,
    compatibility_source: true,
    compatibility_limited: total > records.length,
  };
}

/** Load bounded score history without fabricating a timeline on older servers. */
async function loadHostScoreHistory() {
  if (!state.host) return;
  const params = hostRangeParams();
  params.set("max_points", "600");
  const path = `/api/hosts/${escapePath(state.host.ip)}/score-history?${params}`;
  try {
    const response = await fetch(path, { cache: "no-store" });
    if (response.status === 404) {
      renderHostScoreHistory(await loadLegacyScoreHistory(params));
      return;
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
    applyRunIdentity(payload.run_identity);
    renderHostScoreHistory(payload);
  } catch (error) {
    showError(`Score history unavailable: ${error.message}`);
  }
}

async function openHost(ip, summary = null) {
  const detail = await api("host", `/api/hosts/${escapePath(ip)}`);
  if (!detail) return;
  const detailHasScore = detail.alert_score !== null
    && detail.alert_score !== undefined
    && Number.isFinite(Number(detail.alert_score))
    && detail.alert_threshold !== null
    && detail.alert_threshold !== undefined
    && Number.isFinite(Number(detail.alert_threshold));
  let scoreSource = summary;
  const summaryHasScore = scoreSource?.alert_score !== null
    && scoreSource?.alert_score !== undefined
    && Number.isFinite(Number(scoreSource.alert_score))
    && scoreSource?.alert_threshold !== null
    && scoreSource?.alert_threshold !== undefined
    && Number.isFinite(Number(scoreSource.alert_threshold));
  if (!detailHasScore && !summaryHasScore) {
    const params = new URLSearchParams({ range: "all", search: ip, limit: "100" });
    const hostPage = await api("hostScore", `/api/hosts?${params}`);
    scoreSource = hostPage?.items?.find((row) => row.ip === ip) || null;
  }
  const host = { ...(scoreSource || {}), ...detail };
  if (!detailHasScore && scoreSource) {
    ["alert_score", "alert_threshold", "alert_score_mode", "alert_score_basis"]
      .forEach((key) => { host[key] = scoreSource[key]; });
  }
  const staleAliases = Array.isArray(detail.all_ips)
    ? detail.all_ips.filter((address) => address !== ip)
    : [];
  host.exact_aggregates = staleAliases.length === 0;
  host.ignored_aliases = staleAliases;
  host.all_ips = [ip];
  state.host = host;
  resetPage("hostFlows");
  resetPage("host-evidence");
  byId("hosts-list-view").hidden = true;
  byId("host-detail-view").hidden = false;
  byId("host-title").textContent = host.ip;
  byId("host-subtitle").textContent =
    `${host.hostname || "Unnamed host"} · ${host.scope} · ${host.live ? "current" : "last known"}`;
  renderHostCards(host);
  await Promise.all([
    loadHostFlows(), loadHostSummary(), loadHostScoreHistory(), loadHostEvidence(),
  ]);
}

async function refreshHostWorkspace() {
  if (!state.host) return;
  const detail = await api("host", `/api/hosts/${escapePath(state.host.ip)}`);
  if (!detail) return;
  const staleAliases = Array.isArray(detail.all_ips)
    ? detail.all_ips.filter((address) => address !== state.host.ip)
    : [];
  const host = {
    ...state.host,
    ...detail,
    all_ips: [state.host.ip],
    exact_aggregates: staleAliases.length === 0,
    ignored_aliases: staleAliases,
  };
  state.host = host;
  renderHostCards(host);
  await Promise.all([
    loadHostFlows(), loadHostSummary(), loadHostScoreHistory(), loadHostEvidence(),
  ]);
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
  return {
    overview: loadOverview,
    alerts: loadAlerts,
    evidence: loadEvidence,
    firewall: loadFirewall,
    "arp-poisoning": loadArpPoisoning,
    p2p: loadP2P,
    logs: loadLogs,
    configuration: loadConfiguration,
    whitelists: loadWhitelists,
    metadata: loadMetadata,
    hosts: loadHosts,
  }[name];
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
  if (["configuration", "whitelists", "metadata"].includes(state.activeTab)) return false;
  if (["firewall", "arp-poisoning", "p2p", "logs"].includes(state.activeTab)) return true;
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
byId("p2p-range").addEventListener("change", () => loadP2P().catch(() => {}));
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

bindFilters("firewall", ["firewall-search"], loadFirewall);
bindFilters("host-evidence", ["host-evidence-search"], loadHostEvidence);
byId("arp-poisoning-search").addEventListener("input", renderArpPoisoning);
["arp-poisoning-hosts-table", "arp-poisoning-events-table",
  "arp-poisoning-evidence-table"].forEach((id) =>
  bindLocalTableSort(id, renderArpPoisoning));
bindFilters("alerts", ["alerts-search", "alerts-threat"], loadAlerts);
bindFilters("evidence", ["evidence-search", "evidence-threat", "evidence-link"], loadEvidence);
bindFilters("hosts", ["hosts-search", "hosts-scope", "hosts-threat"], loadHosts);
byId("configuration-search").addEventListener("input", renderConfiguration);
byId("whitelists-search").addEventListener("input", renderWhitelists);
byId("whitelists-type").addEventListener("change", renderWhitelists);
bindView("alerts", loadAlerts);
bindView("evidence", loadEvidence);
bindRange("alerts", "alerts", loadAlerts);
bindRange("evidence", "evidence", loadEvidence);
bindRange("hosts", "hosts", loadHosts);
bindRange("host", "hostFlows", async () => {
  resetPage("host-evidence");
  await Promise.all([
    loadHostFlows(), loadHostSummary(), loadHostScoreHistory(), loadHostEvidence(),
  ]);
});
bindTableSort("modules", async () => {
  if (state.overview) renderModules(state.overview.modules);
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
