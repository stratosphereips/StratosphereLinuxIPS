"use strict";

const state = {
  activeTab: "overview",
  hideExcluded: true,
  overview: null,
  overviewEvidence: null,
  overviewEvidenceLoading: false,
  metadata: null,
  metrics: [],
  configuration: null,
  whitelists: null,
  arpPoisoning: null,
  p2p: null,
  host: null,
  alertsWorkspace: {
    severity: "", host: null, alert: null, items: [], next: null,
    total: 0, listGeneration: 0, detailGeneration: 0,
    listLoadedAt: 0, listSignature: "",
  },
  evidenceWorkspace: {
    group: null, record: null, records: [], next: null, total: 0, typeFilter: "",
    generation: 0, listLoadedAt: 0, listSignature: "", threatCounts: null,
  },
  hostNames: new Map(),
  pendingHostNames: new Set(),
  hostNamesLoading: false,
  hostNamesScheduled: false,
  networkNameDrafts: new Map(),
  networkNameEditorOpen: new Set(),
  hostAnnotationDrafts: new Map(),
  hostAnnotationEditorOpen: new Set(),
  ownAddresses: new Set(),
  computerName: "",
  failures: 0,
  connected: false,
  lastSuccessfulRequest: null,
  runUptimeSeconds: null,
  runUptimeObservedAt: 0,
  runUptimeRunning: false,
  timer: null,
  statusTimer: null,
  requests: new Map(),
  drawerHistory: [],
  drawerGeneration: 0,
  runIdentity: null,
  rangesInitialized: false,
  localSorts: {
    "arp-poisoning-hosts-table": { key: "ip", order: "asc" },
    "arp-poisoning-events-table": { key: "timestamp", order: "desc" },
    "arp-poisoning-evidence-table": { key: "timestamp", order: "desc" },
    "p2p-activity-table": { key: "timestamp", order: "desc" },
  },
  pages: {
    alerts: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
    evidence: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
    hosts: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "peak_score", order: "desc", visible: 14 },
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
/** Format a recent event as a short age for the Overview alert list. */
function formatAge(value) {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - numeric(value)));
  if (!numeric(value)) return "—";
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
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

/** Set the visible name for one rendered IP address. */
function updateHostLabel(element) {
  const ip = element.dataset.hostIp;
  const own = state.ownAddresses.has(ip);
  element.classList.toggle("own-host", own);
  const identity = state.hostNames.get(ip);
  const name = own
    ? `This device${identity?.source === "User name"
      ? ` · ${identity.name}`
      : state.computerName ? ` · ${state.computerName}` : ""}`
    : identity?.name || "Name unknown";
  const source = own && identity?.source !== "User name"
    ? "Monitored computer" : identity?.source || "No stored hostname";
  element.querySelector(".host-name").textContent = name;
  element.title = `${ip} · ${source}: ${name}`;
}

/** Update all visible host labels after identity information changes. */
function refreshHostLabels() {
  document.querySelectorAll("[data-host-ip]").forEach(updateHostLabel);
  const displayedName = byId("host-displayed-name");
  if (displayedName && state.host?.ip) {
    const identity = state.hostNames.get(state.host.ip);
    const source = identity?.source === "rDNS" ? "reverse DNS" : identity?.source;
    displayedName.textContent = identity?.name
      ? `${identity.name} · ${source || "stored name"}` : "—";
  }
}

/** Keep a learned name without replacing it with missing metadata. */
function rememberHostName(ip, name, source) {
  if (!ip || !name) return;
  const existing = state.hostNames.get(ip);
  if (existing?.name && hostNamePriority(existing.source) > hostNamePriority(source)) return;
  state.hostNames.set(ip, { name, source, checkedAt: Date.now() });
}

/** Rank user names above learned names and vendor fallback. */
function hostNamePriority(source) {
  return { "User name": 4, Hostname: 3, DNS: 2, rDNS: 2, "MAC vendor": 1 }[source] || 0;
}

/** Remember the best currently available identity from a Host record. */
function rememberHostRecord(record) {
  if (!record?.ip) return;
  if (record.user_name) rememberHostName(record.ip, record.user_name, "User name");
  else if (record.hostname) rememberHostName(record.ip, record.hostname, "Hostname");
  else if (record.dns_name) rememberHostName(record.ip, record.dns_name, record.dns_name_source || "DNS");
  else if (record.mac_vendor) rememberHostName(record.ip, `${record.mac_vendor} device`, "MAC vendor");
}

/** Fetch names for visible addresses in bounded batches. */
async function loadHostNames() {
  if (state.hostNamesLoading) return;
  state.hostNamesLoading = true;
  try {
    while (state.pendingHostNames.size) {
      const ips = Array.from(state.pendingHostNames).slice(0, 100);
      ips.forEach((ip) => state.pendingHostNames.delete(ip));
      const params = new URLSearchParams();
      ips.forEach((ip) => params.append("ip", ip));
      const response = await fetch(`/api/host-names?${params}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      applyRunIdentity(payload.run_identity);
      ips.forEach((ip) => {
        const fetched = payload.names?.[ip] || {};
        const existing = state.hostNames.get(ip);
        if (existing?.name && (!fetched.name
            || hostNamePriority(existing.source) > hostNamePriority(fetched.source))) return;
        state.hostNames.set(ip, { ...fetched, checkedAt: Date.now() });
      });
      refreshHostLabels();
    }
  } catch (_) {
    // Keep addresses visible when optional name metadata is unavailable.
  } finally {
    state.hostNamesLoading = false;
    if (state.pendingHostNames.size) {
      window.setTimeout(loadHostNames, 1000);
    }
  }
}

/** Render an IP and its stored name together. */
function hostIdentity(ip) {
  const element = document.createElement("span");
  element.className = "host-label";
  if (!ip) {
    element.append(text("code", "Unknown"));
    return element;
  }
  element.dataset.hostIp = String(ip);
  element.append(text("code", ip), text("small", "Name unknown", "host-name"));
  updateHostLabel(element);
  const cached = state.hostNames.get(String(ip));
  if ((!cached || Date.now() - cached.checkedAt > 60000)
      && !state.ownAddresses.has(String(ip))) {
    state.pendingHostNames.add(String(ip));
    if (!state.hostNamesScheduled) {
      state.hostNamesScheduled = true;
      window.setTimeout(() => {
        state.hostNamesScheduled = false;
        loadHostNames();
      }, 0);
    }
  }
  return element;
}

/** Add host names beside addresses mentioned in a detection description. */
function hostDescription(record, className = "") {
  const description = String(record.description || "—");
  const addresses = new Set(description.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []);
  [record.attacker, record.victim].forEach((entity) => {
    if (String(entity?.ioc_type || "").toUpperCase() === "IP"
        && description.includes(entity.value)) addresses.add(entity.value);
  });
  const element = document.createElement("span");
  if (className) element.className = className;
  if (!addresses.size) {
    element.textContent = description;
    return element;
  }
  const escaped = Array.from(addresses).sort((left, right) => right.length - left.length)
    .map((ip) => ip.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const matcher = new RegExp(`(${escaped.join("|")})`, "g");
  description.split(matcher).forEach((part) => {
    if (addresses.has(part)) element.append(hostIdentity(part));
    else element.append(part);
  });
  return element;
}

/** Show an indicator as a named host when it is an IP address. */
function hostOrText(value) {
  const candidate = String(value || "");
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(candidate);
  const ipv6 = /^[0-9a-fA-F:.]+$/.test(candidate)
    && (candidate.includes("::") || candidate.split(":").length === 8);
  return ipv4 || ipv6 ? hostIdentity(candidate) : text("code", value || "—");
}
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
/**
 * Show the peer IDs that reported an IP in P2P evidence.
 *
 * @param {Object} record Evidence or grouped evidence row.
 * @returns {Node|string} Reporter IDs, or an unavailable marker.
 */
function reportingPeers(record) {
  if (record.evidence_type !== "MALICIOUS_IP_FROM_P2P_NETWORK") return "—";
  const peers = record.reporting_peers || [];
  return peers.length ? text("code", peers.join(", ")) : "Unavailable";
}
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
 * Show whether the retained page is connected to the Slips backend.
 *
 * @param {boolean} connected True while the backend heartbeat is fresh.
 */
function renderConnectionState(connected) {
  if (!connected && state.connected && state.runUptimeRunning
      && state.runUptimeSeconds !== null) {
    state.runUptimeSeconds += Math.max(
      0, (Date.now() - state.runUptimeObservedAt) / 1000,
    );
    state.runUptimeObservedAt = Date.now();
  }
  state.connected = connected;
  const dot = byId("state-dot");
  const label = byId("run-state");
  const updated = byId("updated-at");
  if (!connected) {
    state.runUptimeRunning = false;
    dot.className = "state-dot error";
    label.textContent = "Disconnected from backend";
    updated.textContent = state.lastSuccessfulRequest
      ? `Last update ${state.lastSuccessfulRequest.toLocaleTimeString()}`
      : "No connection";
    renderHeaderUptime();
    return;
  }
  const runState = state.overview?.run?.state;
  dot.className = `state-dot ${runState || "running"}`;
  label.textContent = runState
    ? (runState === "running" ? "Analysis running" : "Analysis complete")
    : "Web connected";
  updated.textContent = state.lastSuccessfulRequest
    ? `Updated ${state.lastSuccessfulRequest.toLocaleTimeString()}`
    : "Connected";
  renderHeaderUptime();
}

/** Update the top-right uptime from the latest server-provided baseline. */
function renderHeaderUptime() {
  const element = byId("run-uptime");
  const disconnected = !state.connected;
  const prefix = disconnected ? "Last uptime" : "Uptime";
  element.classList.toggle("error", disconnected);
  if (state.runUptimeSeconds === null) {
    element.textContent = `${prefix} —`;
    return;
  }
  const elapsed = state.runUptimeRunning && state.connected
    ? Math.max(0, (Date.now() - state.runUptimeObservedAt) / 1000)
    : 0;
  element.textContent = `${prefix} ${formatDuration(
    state.runUptimeSeconds + elapsed
  )}`;
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
    Object.assign(state.evidenceWorkspace, {
      group: null, record: null, records: [], next: null, total: 0,
      typeFilter: "", listLoadedAt: 0, listSignature: "", threatCounts: null,
      generation: state.evidenceWorkspace.generation + 1,
    });
    renderEvidenceEmptyState();
    state.overview = null;
    state.overviewEvidence = null;
    state.overviewEvidenceLoading = false;
    state.metadata = null;
    state.metrics = [];
    state.configuration = null;
    state.rangesInitialized = false;
    state.hostNames.clear();
    state.pendingHostNames.clear();
    state.networkNameDrafts.clear();
    state.networkNameEditorOpen.clear();
    state.ownAddresses.clear();
    state.computerName = "";
    toast("A new Slips run is now active. Investigation state was cleared.");
  }
  state.runIdentity = token;
}

async function api(key, path, trackFailures = true, allowNotFound = false) {
  state.requests.get(key)?.abort();
  const controller = new AbortController();
  state.requests.set(key, controller);
  try {
    const response = await fetch(path, {
      cache: "no-store", signal: controller.signal,
    });
    const payload = await response.json().catch(() => ({}));
    if (allowNotFound && response.status === 404) return { not_found: true };
    if (!response.ok) {
      const error = new Error(payload.detail || payload.error || `HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    applyRunIdentity(payload.run_identity);
    if (trackFailures) state.failures = 0;
    state.lastSuccessfulRequest = new Date();
    renderConnectionState(payload.backend_status?.connected === true);
    if (trackFailures) clearError();
    return payload;
  } catch (error) {
    if (error.name === "AbortError") return null;
    if (trackFailures) state.failures += 1;
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
    if (first === null || first === undefined) {
      return second === null || second === undefined ? 0 : 1;
    }
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
  if (name === "hosts") state.pages.hosts.visible = 14;
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

/** Find the plotted sample nearest a time along one sorted series.
 * @param {Array<object>} points - Samples with Unix-second timestamps.
 * @param {number} timestamp - Time under the pointer, in Unix seconds.
 * @returns {object} The nearest plotted sample.
 */
function nearestChartPoint(points, timestamp) {
  let low = 0;
  let high = points.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (numeric(points[middle].ts) < timestamp) low = middle + 1;
    else high = middle;
  }
  if (low === 0) return points[0];
  if (low === points.length) return points.at(-1);
  return timestamp - numeric(points[low - 1].ts) <= numeric(points[low].ts) - timestamp
    ? points[low - 1] : points[low];
}

/** Reuse one HTML hover label outside the SVG drawing area.
 * @param {SVGElement} svg - Chart whose parent holds the label.
 * @returns {HTMLElement} The chart's hover label.
 */
function chartTooltip(svg) {
  const container = svg.parentElement;
  let tooltip = container.querySelector(".chart-tooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.className = "chart-tooltip";
    tooltip.hidden = true;
    container.append(tooltip);
  }
  return tooltip;
}

/** Show the exact sample time and value while a line or point is hovered.
 * @param {SVGElement} svg - Rendered chart.
 * @param {SVGElement} target - Wide hit area over a series.
 * @param {Array<object>} points - Chronologically sorted samples in the series.
 * @param {object} item - Series key and optional display label.
 * @param {Function} formatValue - Value formatter for this chart.
 * @param {number} maximum - Highest value on the chart.
 * @param {number} left - Plot's left coordinate.
 * @param {number} plotWidth - Plot's SVG width.
 * @param {number} minimumTime - Earliest chart timestamp.
 * @param {number} span - Chart time span in seconds.
 */
function bindChartHover(svg, target, points, item, formatValue, maximum, left, plotWidth, minimumTime, span) {
  const tooltip = chartTooltip(svg);
  target.addEventListener("pointermove", (event) => {
    const bounds = svg.getBoundingClientRect();
    if (!bounds.width) return;
    const x = (event.clientX - bounds.left) * svg.viewBox.baseVal.width / bounds.width;
    const timestamp = minimumTime + Math.max(0, Math.min(1, (x - left) / plotWidth)) * span;
    const point = nearestChartPoint(points, timestamp);
    const label = item.label || item.key.replaceAll("_", " ");
    tooltip.textContent = `${label}: ${formatValue(point[item.key], maximum)}\n${formatTime(point.ts)}`;
    tooltip.hidden = false;
    const containerBounds = svg.parentElement.getBoundingClientRect();
    tooltip.style.left = `${Math.max(4, Math.min(event.clientX - containerBounds.left + 12,
      containerBounds.width - tooltip.offsetWidth - 4))}px`;
    tooltip.style.top = `${Math.max(4, Math.min(event.clientY - containerBounds.top + 12,
      containerBounds.height - tooltip.offsetHeight - 4))}px`;
  });
  target.addEventListener("pointerleave", () => { tooltip.hidden = true; });
}

/** Render a performance chart with numeric and time axes. */
function renderLineChart(id, points, series, formatValue = formatChartValue) {
  const svg = byId(id);
  svg.replaceChildren();
  chartTooltip(svg).hidden = true;
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
    svg.append(path);
    const hitArea = document.createElementNS("http://www.w3.org/2000/svg", "path");
    hitArea.setAttribute("d", d);
    hitArea.setAttribute("class", "chart-hit-line");
    svg.append(hitArea);
    bindChartHover(svg, hitArea, seriesPoints, item, formatValue, maximum,
      left, plotWidth, minimumTime, span);
    if (seriesPoints.length === 1) {
      const point = seriesPoints[0];
      const marker = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      marker.setAttribute("cx", String(left + ((numeric(point.ts) - minimumTime) / span) * plotWidth));
      marker.setAttribute("cy", String(height - bottom - (numeric(point[item.key]) / maximum) * plotHeight));
      marker.setAttribute("r", "3");
      marker.setAttribute("class", `chart-point ${item.className || ""}`);
      svg.append(marker);
      const hitPoint = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      hitPoint.setAttribute("cx", marker.getAttribute("cx"));
      hitPoint.setAttribute("cy", marker.getAttribute("cy"));
      hitPoint.setAttribute("r", "10");
      hitPoint.setAttribute("class", "chart-hit-point");
      svg.append(hitPoint);
      bindChartHover(svg, hitPoint, seriesPoints, item, formatValue, maximum,
        left, plotWidth, minimumTime, span);
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
    item.append(id === "host-peers" ? hostIdentity(row.name) : text("code", row.name || "unknown"),
      meter, text("strong", compact(row.value)));
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
 * Show alert and host totals from the rolling live window in the tab title.
 *
 * @param {Object} counts Live alert and host totals.
 */
function updatePageTitle(counts) {
  document.title = `Slips ${compact(counts.alerts)} alerts · ${compact(counts.hosts)} hosts`;
}

/** Refresh live title totals independently of the selected tab and filters. */
async function loadLiveTitleCounts() {
  const payload = await api("liveTitleCounts", "/api/live-counts", false, true);
  if (payload && !payload.not_found) updatePageTitle(payload);
}

/**
 * Render run identity shared by every top-level tab.
 *
 * @param {Object} data Current overview API payload.
 */
function renderRunContext(data) {
  const run = data.run;
  const backendConnected = data.backend_status?.connected === true;
  state.runUptimeSeconds = Number.isFinite(Number(run.uptime_seconds))
    ? Number(run.uptime_seconds) : null;
  state.runUptimeObservedAt = Date.now();
  state.runUptimeRunning = run.state === "running" && backendConnected;
  renderHeaderUptime();
  const outputName = String(run.output_dir || "").split("/").filter(Boolean).at(-1);
  byId("run-name").textContent = outputName || "Current run";
  const metadata = data.run_metadata || {};
  const connectedNetwork = (data.network_states || []).find((network) =>
    network.connected && network.interface === run.interface)
    || (data.network_states || []).find((network) => network.connected);
  const primaryIp = data.host_addresses?.ipv4?.[0] || data.host_addresses?.ipv6?.[0];
  const detailsLink = text("button", "run details", "overview-link");
  detailsLink.type = "button";
  detailsLink.addEventListener("click", () => switchTab("metadata"));
  byId("run-meta").replaceChildren(
    text("span", [
      run.interface || metadata.File || run.input_type || "input",
      connectedNetwork?.name || "",
      primaryIp || "",
      metadata["Slips version"] ? `Slips ${metadata["Slips version"]}` : "",
    ].filter(Boolean).join(" · ")),
    text("span", " · "), detailsLink,
  );
  const addresses = data.host_addresses || {};
  const computerAddresses = data.computer_addresses || {};
  state.computerName = data.computer_name || "";
  byId("run-device").textContent = state.computerName
    || addresses.ipv4?.[0] || addresses.ipv6?.[0] || "Name unavailable";
  state.ownAddresses = new Set([
    ...(addresses.ipv4 || []), ...(addresses.ipv6 || []),
    ...(computerAddresses.ipv4 || []), ...(computerAddresses.ipv6 || []),
    "127.0.0.1", "::1",
  ]);
  const addressLine = byId("run-addresses");
  addressLine.replaceChildren();
  [["IPv4", addresses.ipv4 || []], ["IPv6", addresses.ipv6 || []]]
    .filter(([, ips]) => ips.length).forEach(([kind, ips], index) => {
      if (index) addressLine.append(" · ");
      addressLine.append(`${kind}: `);
      ips.forEach((ip, position) => {
        if (position) addressLine.append(", ");
        addressLine.append(hostIdentity(ip));
      });
    });
  addressLine.hidden = !addressLine.childNodes.length;
  refreshHostLabels();
  renderConnectionState(backendConnected);
  byId("alerts-badge").textContent = compact(data.counts.alerts);
  byId("evidence-badge").textContent = compact(data.counts.evidence);
  byId("hosts-badge").textContent = compact(data.counts.hosts);
  byId("logs-badge").textContent = compact(data.counts.module_errors);
  byId("firewall-badge").textContent = (data.modules || []).some((module) => module.name === "blocking")
    ? compact(data.firewall?.current) : "off";
}

/** Render the operational overview without supporting metadata or logs. */
function renderOverview() {
  const data = state.overview;
  if (!data) return;
  renderRunContext(data);
  renderNetworkStates(data.network_states || []);
  renderOverviewStatus(data);
  renderOverviewSystem(data);
  const firewall = data.firewall || {};
  setSummaryCards([
    ["Alerts", compact(data.counts.alerts)],
    ["Evidence", compact(data.counts.evidence)],
    ["Hosts seen", compact(data.counts.hosts)],
    ["Flows processed", compact(data.counts.processed_flows)],
    ["Firewall blocks", firewall.current ? compact(firewall.current)
      : (data.modules || []).some((module) => module.name === "blocking") ? "0" : "off"],
  ]);
  byId("summary-cards").classList.toggle("has-alerts", numeric(data.counts.alerts) > 0);
  const firewallImpact = data.firewall_impact || {};
  setSummaryCards([
    ["Packets stopped (estimated)", compact(firewallImpact.packets)],
    ["Flows stopped (estimated)", compact(firewallImpact.flows)],
    ["Evidence while blocked", compact(firewallImpact.evidence)],
  ], "overview-firewall-impact");
  const system = data.system;
  const metrics = [
    ["CPU", numeric(system.cpu_percent), `${numeric(system.cpu_percent).toFixed(1)}%`],
    ["Memory", numeric(system.memory_percent), `${numeric(system.memory_percent).toFixed(1)}%`],
    ["Output disk", numeric(system.output_disk_percent),
      `${numeric(system.output_disk_percent).toFixed(1)}% · ${formatBytes(system.output_disk_free)} free`],
  ];
  const load = byId("system-load");
  load.replaceChildren();
  metrics.forEach(([label, percent, value]) => {
    const row = document.createElement("div");
    row.className = `metric ${percent >= 90 ? "danger" : percent >= 75 ? "warning" : ""}`;
    const heading = document.createElement("div");
    heading.className = "metric-heading";
    heading.append(text("span", label), text("strong", value));
    const track = text("span", "", "metric-track");
    const fill = text("span", "", "metric-fill");
    fill.style.width = `${Math.min(Math.max(percent, 0), 100)}%`;
    track.append(fill);
    row.append(heading, track);
    load.append(row);
  });
  load.append(text("p", `load ${(system.load_average || []).map((value) => numeric(value).toFixed(2)).join(" / ")} · flows.sqlite ${formatBytes(system.flows_db_size)}`, "overview-load-foot"));
  const evidenceButton = byId("load-module-evidence");
  evidenceButton.disabled = state.overviewEvidenceLoading;
  evidenceButton.textContent = state.overviewEvidenceLoading
    ? "Loading evidence counts…"
    : (data.evidence_details_loaded
      ? "Refresh evidence counts" : "Load evidence counts");
  renderModules(data.modules);
}

/** Show either the quiet state or the hosts with the highest severity alerts. */
function renderOverviewStatus(data) {
  const hasAlerts = numeric(data.counts.alerts) > 0;
  const panel = byId("overview-status");
  panel.classList.toggle("has-alerts", hasAlerts);
  byId("overview-alerts-link").hidden = !hasAlerts;
  byId("overview-status-description").hidden = hasAlerts;
  const list = byId("overview-alert-hosts");
  list.replaceChildren();
  if (!hasAlerts) {
    byId("overview-status-title").textContent = "No alerts in this run";
    const top = data.highest_score;
    const threshold = numeric(data.alert_threshold) || 5;
    byId("overview-status-description").textContent =
      `${compact(data.counts.evidence)} evidence records from ${compact(data.counts.hosts)} hosts. `
      + `No host crossed the alert threshold (${threshold}).`
      + (top?.ip && top.score !== null ? ` Highest current score: ${numeric(top.score).toFixed(2)} on ${top.ip}.` : "");
    return;
  }
  const summary = data.alert_hosts || {};
  const total = numeric(summary.total);
  byId("overview-status-title").textContent = total
    ? `${total} ${total === 1 ? "host is" : "hosts are"} generating alerts`
    : `${compact(data.counts.alerts)} alerts in this run`;
  (summary.items || []).slice(0, 4).forEach((host) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "overview-alert-row";
    const level = host.threat_level || "info";
    row.append(text("span", level, `overview-alert-severity threat-${level}`),
      hostIdentity(host.ip_alerted),
      text("span", `${compact(host.alert_count)} alerts`, "overview-alert-count"),
      text("span", host.alert_score == null ? "—" : numeric(host.alert_score).toFixed(2), "overview-alert-score"),
      text("span", formatAge(host.alert_time), "overview-alert-time"));
    row.title = `Last alert ${formatTime(host.alert_time)}`;
    row.addEventListener("click", () => inspectHost(host.ip_alerted).catch(() => {}));
    list.append(row);
  });
}

/** Summarize actionable resource and runtime problems in the Overview. */
function renderOverviewSystem(data) {
  const system = data.system || {};
  const items = byId("overview-system-items");
  items.replaceChildren();
  const warnings = [];
  if (system.disk_warning) warnings.push({
    text: `Output disk ${numeric(system.output_disk_percent).toFixed(1)}% full · ${formatBytes(system.output_disk_free)} free`,
    tone: system.disk_warning === "critical" ? "danger" : "warning",
  });
  if (numeric(system.cpu_percent) >= 90) warnings.push({
    text: `Host CPU ${numeric(system.cpu_percent).toFixed(1)}% · load ${numeric(system.load_average?.[0]).toFixed(2)}`,
    tone: "danger", action: "Modules", open: () => {
      switchTab("metadata");
      byId("modules-table").scrollIntoView({ block: "nearest" });
    },
  });
  if (numeric(system.memory_percent) >= 90) warnings.push({
    text: `Host memory ${numeric(system.memory_percent).toFixed(1)}%`, tone: "warning",
  });
  if (numeric(data.counts.module_errors)) warnings.push({
    text: `${compact(data.counts.module_errors)} errors in logs`, tone: "warning",
    action: "Logs", open: () => switchTab("logs"),
  });
  byId("overview-system-label").textContent = warnings.length
    ? `SYSTEM NEEDS ATTENTION · ${warnings.length}` : "SYSTEM";
  byId("overview-system").classList.toggle("needs-attention", warnings.length > 0);
  if (!warnings.length) {
    const running = (data.modules || []).filter((module) => module.running).length;
    warnings.push({ text: data.run.state === "complete"
      ? "Analysis complete · resources normal"
      : `${running} modules running · resources normal`, tone: "ok" });
    if (!(data.modules || []).some((module) => module.name === "blocking")) warnings.push({
      text: "Firewall blocking is off", tone: "muted",
      action: "How to enable", open: () => switchTab("configuration"),
    });
  }
  warnings.slice(0, 4).forEach((warning) => {
    const row = text("div", "", `overview-system-row ${warning.tone}`);
    row.append(text("span", warning.text));
    if (warning.action) {
      const action = text("button", warning.action, "overview-link");
      action.type = "button";
      action.addEventListener("click", warning.open);
      row.append(action);
    }
    items.append(row);
  });
}

/** Show the monitored network and its editable name in one compact card. */
function renderNetworkStates(networkStates) {
  const runNetwork = byId("run-network");
  runNetwork.hidden = true;
  const container = byId("network-states");
  if (container.contains(document.activeElement)
      && document.activeElement.closest(".network-name-form")) return;
  container.replaceChildren();
  if (!networkStates.length) {
    container.append(text("p", "Live network settings are available when Slips monitors an interface.", "muted"));
    return;
  }
  const monitored = networkStates.find((network) =>
    network.interface === state.overview?.run?.interface && network.connected)
    || networkStates.find((network) => network.connected)
    || networkStates[0];
  [monitored].forEach((network) => {
    const card = document.createElement("div");
    card.className = "network-state";
    const head = text("div", "", "overview-card-head");
    head.append(text("h3", `${network.name || network.interface} · ${network.connected ? "connected" : "disconnected"}`));
    const rename = text("button", "Rename", "overview-link");
    rename.type = "button";
    rename.disabled = !network.connected || !network.network_id;
    rename.addEventListener("click", () => {
      if (form.hidden) state.networkNameEditorOpen.add(network.network_id);
      else state.networkNameEditorOpen.delete(network.network_id);
      form.hidden = !form.hidden;
      if (!form.hidden) input.focus();
    });
    head.append(rename);
    card.append(head);
    const form = document.createElement("form");
    form.className = "network-name-form";
    form.hidden = !state.networkNameEditorOpen.has(network.network_id);
    const label = text("label", "Network name");
    const input = document.createElement("input");
    input.type = "text";
    input.maxLength = 80;
    input.placeholder = "e.g. Home Wi-Fi";
    input.autocomplete = "off";
    input.value = state.networkNameDrafts.get(network.network_id)
      ?? network.name ?? "";
    input.disabled = !network.connected || !network.network_id;
    input.addEventListener("input", () => {
      state.networkNameDrafts.set(network.network_id, input.value);
    });
    label.append(input);
    const save = text("button", "Save name", "secondary");
    save.type = "submit";
    save.disabled = input.disabled;
    form.append(label, save);
    if (!network.network_id) {
      form.append(text("small", "Restart Slips to enable network naming.", "muted"));
    } else if (!network.connected) {
      form.append(text("small", "Connect to this network to edit its name.", "muted"));
    } else if (network.name_scope === "run") {
      form.append(text("small", "Router identity unavailable; this name applies to the current run.", "muted"));
    }
    const feedback = text("small", "", "network-name-feedback");
    form.append(feedback);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      save.disabled = true;
      feedback.textContent = "Saving…";
      try {
        const response = await fetch("/api/network-name", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            interface: network.interface,
            network_id: network.network_id,
            name: input.value,
          }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
        network.name = payload.name;
        state.networkNameDrafts.delete(network.network_id);
        state.networkNameEditorOpen.delete(network.network_id);
        document.activeElement?.blur();
        if (state.overview) renderRunContext(state.overview);
        renderNetworkStates(networkStates);
        toast(payload.name ? "Network name saved." : "Network name removed.");
      } catch (error) {
        feedback.textContent = error.message;
        save.disabled = false;
      }
    });
    card.append(form);
    const facts = text("div", "", "network-facts");
    const computer = text("div", "", "network-fact");
    computer.append(text("span", "This computer"), hostIdentity(network.host_ip));
    facts.append(computer);
    const local = text("div", "", "network-fact");
    local.append(text("span", "Local network"), text("code", network.local_network || "Unknown"));
    facts.append(local);
    const router = text("div", "", "network-fact");
    router.append(text("span", "Router"), hostIdentity(network.gateway_ip));
    facts.append(router);
    const mac = text("div", "", "network-fact");
    mac.append(text("span", "Router MAC"), text("code", network.gateway_mac || "Unknown"));
    facts.append(mac);
    const dns = text("div", "", "network-fact");
    dns.append(text("span", "DNS"));
    const servers = text("span", "");
    (network.dns_servers || []).forEach((ip, index) => {
      if (index) servers.append(", ");
      servers.append(hostIdentity(ip));
    });
    if (!(network.dns_servers || []).length) servers.append("Unknown");
    dns.append(servers);
    facts.append(dns);
    card.append(facts);
    container.append(card);
  });
}

/**
 * Render the metadata captured for this run.
 *
 * @param {Object} metadata Parsed metadata labels and values.
 * @param {Object|null} overview Current run and interface details.
 */
function renderMetadata(metadata, overview = null) {
  const runMetadata = byId("run-metadata");
  runMetadata.replaceChildren();
  const version = metadata["Slips version"] || overview?.run_metadata?.["Slips version"] || "";
  runMetadata.append(
    metadataRow("Version", version ? (/^slips\b/i.test(version) ? version : `Slips ${version}`) : "Unavailable"),
    metadataRow("Branch", metadata.Branch || overview?.run_metadata?.Branch || "Unavailable"),
    metadataRow("Commit", metadata.Commit || overview?.run_metadata?.Commit || "Unavailable"),
  );
  const extras = ["File", "Command", "Slips start date", "Zeek version"]
    .filter((label) => metadata[label] !== undefined);
  if (extras.length) {
    const details = document.createElement("details");
    details.className = "metadata-more";
    details.append(text("summary", "More run facts"));
    extras.forEach((label) => details.append(metadataRow(label, metadata[label] || "Unavailable")));
    runMetadata.append(details);
  }
  const device = byId("metadata-device");
  device.replaceChildren();
  const addresses = overview?.host_addresses || {};
  const name = overview?.computer_name || "This device";
  byId("metadata-device-title").textContent = `This device · ${name}`;
  device.append(metadataRow("Interface", overview?.run?.interface || "Unavailable"));
  [["IPv4", addresses.ipv4 || []], ["IPv6", addresses.ipv6 || []]].forEach(([label, values]) => {
    device.append(metadataRow(label, values.length ? values.join("\n") : "None"));
  });
}

/**
 * Build one compact, accessible metadata label and value.
 *
 * @param {string} label Label shown at the left of the row.
 * @param {string} value Metadata value to display.
 * @returns {HTMLElement} The labeled metadata row.
 */
function metadataRow(label, value) {
  const row = document.createElement("div");
  row.className = "metadata-row";
  row.append(text("span", label), text("code", value));
  return row;
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

/**
 * Draw one module's CPU share as a bounded bar and readable percentage.
 *
 * @param {number} percentage CPU share of one core.
 * @returns {HTMLElement} The percentage bar.
 */
function moduleCpuUsage(percentage) {
  const actual = Math.max(0, numeric(percentage));
  const element = document.createElement("span");
  element.className = `module-cpu ${actual >= 50 ? "hot" : ""}`;
  const track = text("span", "", "module-cpu-track");
  const fill = text("span", "", "module-cpu-fill");
  fill.style.width = `${Math.min(actual, 100)}%`;
  track.append(fill);
  element.append(track, text("strong", `${actual.toFixed(1)}%`));
  element.title = `${actual.toFixed(1)}% of one CPU core`;
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
    (row) => moduleCpuUsage(row.cpu_percent),
    (row) => {
      const value = text("span", `${numeric(row.memory_mb).toFixed(1)} MiB`, "module-memory");
      value.title = `${numeric(row.memory_percent).toFixed(1)}% of host memory`;
      return value;
    },
    (row) => compact(row.flows_per_minute),
    (row) => row.evidence_count === null || row.evidence_count === undefined
      ? text("span", "Not loaded", "muted") : compact(row.evidence_count),
    (row) => row.error_count,
  ]);
  byId("modules-table").classList.toggle("show-evidence", Boolean(state.overview?.evidence_details_loaded));
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
  const activeRange = ["alerts", "evidence", "hosts"].includes(state.activeTab)
    ? byId(`${state.activeTab}-range`) : null;
  const refreshActiveRange = activeRange && activeRange.value !== range;
  ["alerts", "evidence", "hosts", "host"].forEach((name) => {
    byId(`${name}-range`).value = range;
  });
  state.rangesInitialized = true;
  if (refreshActiveRange) {
    resetPage(state.activeTab);
    currentLoader()().catch(() => {}).finally(schedulePoll);
  }
}

/** Apply explicitly requested evidence details to a fast Overview payload. */
function applyOverviewEvidence(payload) {
  if (!state.overviewEvidence || !payload) return;
  payload.counts.evidence = state.overviewEvidence.evidence;
  const moduleCounts = state.overviewEvidence.modules || {};
  payload.modules.forEach((module) => {
    module.evidence_count = numeric(moduleCounts[module.name]);
  });
  payload.evidence_details_loaded = true;
}

/** Load the operational overview and its bounded history charts. */
async function loadOverview() {
  const payload = await api("overview", "/api/overview");
  if (!payload) return;
  applyOverviewEvidence(payload);
  state.overview = payload;
  initializeRanges(payload.run);
  renderOverview();
  await loadMetrics();
}

/** Load exact retained evidence attribution only after a user asks for it. */
async function loadOverviewEvidenceCounts() {
  if (state.overviewEvidenceLoading) return;
  state.overviewEvidenceLoading = true;
  renderOverview();
  try {
    const payload = await api(
      "overviewEvidence", "/api/overview/evidence-counts",
    );
    if (!payload) return;
    state.overviewEvidence = payload;
    applyOverviewEvidence(state.overview);
    renderOverview();
    toast(`Loaded exact evidence counts from ${payload.source}.`);
  } finally {
    state.overviewEvidenceLoading = false;
    renderOverview();
  }
}

/** Load and render run metadata in its dedicated tab. */
async function loadMetadata() {
  if (state.overview) {
    renderMetadata(state.metadata?.items || {}, state.overview);
  }
  const [metadata, overview] = await Promise.all([
    state.metadata || api("metadata", "/api/metadata"),
    api("metadataOverview", "/api/overview"),
  ]);
  if (!metadata) return;
  state.metadata = metadata;
  if (overview) {
    applyOverviewEvidence(overview);
    state.overview = overview;
    renderOverview();
  }
  renderMetadata(metadata.items || {}, overview || state.overview);
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
  if (state.hideExcluded && ["alerts", "evidence"].includes(name)) {
    params.set("hide_excluded", "1");
  }
  if (page.cursors[page.index]) params.set("cursor", page.cursors[page.index]);
  const search = byId(`${name}-search`).value.trim();
  if (search) params.set("search", search);
  if (name === "alerts") {
    params.set("group", "host");
    params.set("details", "false");
  } else if (name === "evidence") {
    const mode = byId("evidence-view").value;
    if (mode !== "individual") {
      params.set("group", mode === "grouped" ? "host_type" : mode);
      params.set("compact", "1");
    }
    const level = byId("evidence-threat").value;
    const association = byId("evidence-link").value;
    if (level) params.set("threat", level);
    if (association) params.set("association", association);
    if (byId("evidence-scored-only").checked) params.set("scored_only", "1");
    if (state.evidenceWorkspace.typeFilter) params.set("type", state.evidenceWorkspace.typeFilter);
  } else {
    const scope = byId("hosts-scope").value;
    const level = byId("hosts-threat").value;
    if (scope) params.set("scope", scope);
    if (level) params.set("threat", level);
    if (byId("hosts-alerts-only").checked) params.set("alerts_only", "1");
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

/** Fit the Alerts workspace below the shared navigation. */
function updateAlertViewportHeight() {
  const bottom = document.querySelector(".tabs").getBoundingClientRect().bottom;
  byId("alerts").style.setProperty("--alerts-panel-height", `${Math.max(380, window.innerHeight - bottom)}px`);
}

/** Reveal only the panes reached by the current host and alert selection. */
function setAlertPaneCount(count) {
  const workspace = byId("alerts-workspace");
  if (Number(workspace.dataset.panes) !== count) {
    workspace.style.setProperty("--alerts-host-width", count === 2 ? "38%" : "26%");
    workspace.style.setProperty("--alerts-list-width", "26%");
  }
  workspace.dataset.panes = String(count);
  byId("alerts-host-divider").hidden = count < 2;
  byId("alerts-list-pane").hidden = count < 2;
  byId("alerts-detail-divider").hidden = count < 3;
  byId("alerts-detail-pane").hidden = count < 3;
}

/** Render severity chips from the currently loaded host page. */
function renderAlertSeverityFilters() {
  const page = state.pages.alerts;
  const selected = state.alertsWorkspace.severity;
  const counts = new Map();
  (page.items || []).forEach((item) => {
    const level = String(item.threat_level || "info").toLowerCase();
    counts.set(level, (counts.get(level) || 0) + 1);
  });
  const container = byId("alerts-severity-filters");
  container.replaceChildren();
  [["", "All", page.total], ...["critical", "high", "medium", "low", "info"]
    .filter((level) => counts.get(level) || selected === level)
    .map((level) => [level, level[0].toUpperCase() + level.slice(1), counts.get(level) || 0])]
    .forEach(([level, label, count]) => {
      const button = text("button", `${label} ${compact(count)}`, "alerts-filter");
      button.type = "button";
      button.dataset.level = level;
      button.classList.toggle("active", selected === level);
      button.setAttribute("aria-pressed", String(selected === level));
      button.addEventListener("click", () => {
        state.alertsWorkspace.severity = level;
        if (state.alertsWorkspace.host && level
            && state.alertsWorkspace.host.threat_level !== level) {
          closeAlertHostPane();
        }
        renderAlertSeverityFilters();
        renderAlertHostList();
      });
      container.append(button);
    });
}

/** Render the grouped host list without opening another overlay. */
function renderAlertHostList() {
  const container = byId("alerts-host-list");
  const selected = state.alertsWorkspace.host?.ip_alerted;
  const level = state.alertsWorkspace.severity;
  const rows = (state.pages.alerts.items || []).filter((item) =>
    !level || String(item.threat_level || "info").toLowerCase() === level);
  container.replaceChildren();
  if (!rows.length) {
    container.append(text("p", "No matching hosts in this page.", "empty-state"));
    return;
  }
  rows.forEach((host) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "alerts-host-row";
    row.classList.toggle("selected", host.ip_alerted === selected);
    row.append(
      hostIdentity(host.ip_alerted),
      text("span", host.alert_score == null ? "—" : numeric(host.alert_score).toFixed(2),
        `alerts-host-score threat-${host.threat_level || "info"}`),
      text("span", `${compact(host.alert_count)} · ${formatAge(host.alert_time)}`, "alerts-host-meta"),
    );
    row.title = `${host.alert_count} alerts · ${host.evidence_count} evidence links`;
    row.addEventListener("click", () => selectAlertHostPane(host));
    container.append(row);
  });
}

/** Show one host in the middle pane and load its individual alerts. */
function selectAlertHostPane(host) {
  const workspace = state.alertsWorkspace;
  const changed = workspace.host?.ip_alerted !== host.ip_alerted;
  workspace.host = host;
  if (changed) {
    workspace.alert = null;
    workspace.items = [];
    workspace.next = null;
    workspace.detailGeneration += 1;
    byId("alerts-detail").replaceChildren();
  }
  setAlertPaneCount(workspace.alert ? 3 : 2);
  renderAlertHostList();
  renderAlertSelectedHost();
  if (changed || !workspace.items.length) loadAlertHostAlerts(true).catch(() => {});
}

/** Close the selected host and return to the first pane. */
function closeAlertHostPane() {
  const workspace = state.alertsWorkspace;
  workspace.host = null;
  workspace.alert = null;
  workspace.items = [];
  workspace.next = null;
  workspace.listGeneration += 1;
  workspace.detailGeneration += 1;
  setAlertPaneCount(1);
  renderAlertHostList();
}

/** Render the host heading above its individual alert timeline. */
function renderAlertSelectedHost() {
  const host = state.alertsWorkspace.host;
  const container = byId("alerts-selected-host");
  container.replaceChildren();
  if (!host) return;
  const close = text("button", "×", "alerts-pane-close");
  close.type = "button";
  close.title = "Close this host";
  close.setAttribute("aria-label", "Close host alerts pane");
  close.addEventListener("click", closeAlertHostPane);
  container.append(close, text("strong", host.ip_alerted));
  container.append(hostIdentity(host.ip_alerted));
  const meta = document.createElement("div");
  meta.className = "alerts-selected-meta";
  meta.append(threat(host.threat_level), text("span", `${compact(host.alert_count)} alerts`),
    text("span", `${compact(host.evidence_count)} evidence`));
  container.append(meta);
}

/** Fetch one bounded page of alerts for the selected host. */
async function loadAlertHostAlerts(reset = true, quiet = false) {
  const workspace = state.alertsWorkspace;
  const host = workspace.host?.ip_alerted;
  if (!host) return;
  const generation = ++workspace.listGeneration;
  const params = rangeQuery("alerts");
  params.set("profile", host);
  params.set("limit", "50");
  params.set("sort", "time");
  params.set("order", "desc");
  params.set("details", "false");
  params.set("summary", "1");
  if (state.hideExcluded) params.set("hide_excluded", "1");
  if (!reset && workspace.next) params.set("cursor", workspace.next);
  if (reset && !quiet) {
    workspace.items = [];
    workspace.next = null;
    byId("alerts-list").replaceChildren(text("p", "Loading alerts…", "empty-state"));
  }
  const payload = await api("alertPaneList", `/api/alerts?${params}`);
  if (!payload || generation !== workspace.listGeneration || workspace.host?.ip_alerted !== host) return;
  workspace.items = reset ? payload.items : [...workspace.items, ...payload.items];
  workspace.next = payload.next_cursor;
  workspace.total = payload.total;
  workspace.listLoadedAt = Date.now();
  workspace.listSignature = `${rangeQuery("alerts")}&${state.hideExcluded}`;
  renderAlertTimeline();
}

/** Render the middle-pane timeline and its bounded next-page control. */
function renderAlertTimeline() {
  const workspace = state.alertsWorkspace;
  const container = byId("alerts-list");
  container.replaceChildren();
  if (!workspace.items.length) {
    container.append(text("p", "No alerts in this range for this host.", "empty-state"));
  }
  workspace.items.forEach((record) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "alerts-alert-row";
    row.classList.toggle("selected", record.alert_id === workspace.alert?.alert_id);
    const top = document.createElement("div");
    top.className = "alerts-alert-row-top";
    top.append(text("span", formatTime(record.alert_time)),
      text("span", numeric(record.alert_score).toFixed(2), `threat-${record.threat_level}`));
    const title = record.summary || record.evidence_type?.replaceAll("_", " ")
      || record.label || "Alert";
    row.append(top, text("span", title, "alerts-alert-row-title"),
      text("span", `${compact(record.evidence_count)} evidence · ${record.evidence_type || record.label || "Alert"}`, "alerts-alert-row-meta"));
    row.addEventListener("click", () => selectAlertDetailPane(record).catch(() => {}));
    container.append(row);
  });
  const more = byId("alerts-list-more");
  more.replaceChildren();
  if (workspace.next) {
    const button = text("button", `Load more · ${compact(workspace.items.length)} of ${compact(workspace.total)}`, "secondary");
    button.type = "button";
    button.addEventListener("click", () => loadAlertHostAlerts(false).catch(() => {}));
    more.append(button);
  }
}

/** Render an individual alert and its evidence in the right pane. */
function renderAlertDetailPane(record) {
  const container = byId("alerts-detail");
  container.replaceChildren();
  const firstEvidence = record.evidence?.[0] || {};
  const header = document.createElement("div");
  header.className = "alerts-detail-head";
  const context = document.createElement("div");
  context.append(threat(record.threat_level),
    text("small", `alert · ${formatTime(record.alert_time)} · ${record.label || "unclassified"}`));
  const actions = document.createElement("div");
  actions.className = "alerts-detail-actions";
  const whitelist = text("button", "Whitelist", "secondary");
  whitelist.type = "button";
  const close = text("button", "×", "secondary");
  close.type = "button";
  close.title = "Close alert details";
  close.setAttribute("aria-label", "Close alert details pane");
  close.addEventListener("click", () => {
    state.alertsWorkspace.alert = null;
    setAlertPaneCount(2);
    renderAlertTimeline();
  });
  actions.append(whitelist, close);
  header.append(context, actions);
  const title = record.summary?.split(". ")[0].slice(0, 110)
    || firstEvidence.evidence_type?.replaceAll("_", " ") || "Alert details";
  container.append(header, text("h3", title));
  if (firstEvidence.description) container.append(text("p", firstEvidence.description, "alerts-detail-summary"));
  container.append(investigationStats([
    ["Score / threshold", slipsScore(record), "danger"],
    ["Network", networkContext(record)],
    ["Time window", record.timewindow || "—"],
    ["Evidence", compact(record.evidence_count)],
  ]));
  const editor = whitelistEditor("alert-pane", firstEvidence.profile_ip
    ? firstEvidence : { profile_ip: record.ip_alerted });
  editor.hidden = true;
  whitelist.addEventListener("click", () => {
    editor.hidden = !editor.hidden;
    whitelist.setAttribute("aria-expanded", String(!editor.hidden));
  });
  container.append(editor, investigationHeading("Related evidence", "Select evidence to inspect its triggering flows"));
  const evidence = document.createElement("div");
  evidence.className = "investigation-list";
  (record.evidence || []).forEach((item) => evidence.append(evidenceCard(item)));
  if (!record.evidence?.length) evidence.append(text("p", "No related evidence is available.", "muted"));
  container.append(evidence, investigationHeading("Identifiers"),
    text("p", record.alert_id, "mono"), rawBlock(record, "alert"));
}

/** Open one alert in the right pane and load its linked evidence. */
async function selectAlertDetailPane(record) {
  const workspace = state.alertsWorkspace;
  workspace.alert = record;
  const generation = ++workspace.detailGeneration;
  setAlertPaneCount(3);
  renderAlertTimeline();
  byId("alerts-detail").replaceChildren(text("p", "Loading alert evidence…", "empty-state"));
  const params = new URLSearchParams({ range: "all", limit: "1", search: record.alert_id });
  const payload = await api("alertPaneDetail", `/api/alerts?${params}`);
  if (!payload || generation !== workspace.detailGeneration
      || workspace.alert?.alert_id !== record.alert_id) return;
  const detailed = payload.items.find((item) => item.alert_id === record.alert_id);
  if (!detailed) {
    byId("alerts-detail").replaceChildren(text("p", "This alert is no longer available.", "empty-state"));
    return;
  }
  workspace.alert = { ...detailed, summary: record.summary };
  renderAlertDetailPane(workspace.alert);
}

/** Resize the pane immediately before a draggable Alerts divider. */
function resizeAlertPane(kind, desiredWidth) {
  const workspace = byId("alerts-workspace");
  const total = workspace.getBoundingClientRect().width;
  const host = document.querySelector(".alerts-host-pane").getBoundingClientRect().width;
  const middle = byId("alerts-list-pane").getBoundingClientRect().width;
  const panes = Number(workspace.dataset.panes);
  if (kind === "host") {
    const remaining = panes === 3 ? middle + 320 + 16 : 240 + 8;
    const width = Math.max(240, Math.min(desiredWidth, total - remaining));
    workspace.style.setProperty("--alerts-host-width", `${Math.round(width)}px`);
  } else if (panes === 3) {
    const width = Math.max(240, Math.min(desiredWidth, total - host - 320 - 16));
    workspace.style.setProperty("--alerts-list-width", `${Math.round(width)}px`);
  }
}

/** Enable pointer and keyboard resizing between visible Alerts panes. */
function initAlertPaneResize() {
  [["alerts-host-divider", "host", ".alerts-host-pane"],
    ["alerts-detail-divider", "detail", "#alerts-list-pane"]]
    .forEach(([id, kind, paneSelector]) => {
      const divider = byId(id);
      divider.addEventListener("pointerdown", (event) => {
        if (divider.hidden) return;
        event.preventDefault();
        const startX = event.clientX;
        const startWidth = document.querySelector(paneSelector).getBoundingClientRect().width;
        divider.setPointerCapture(event.pointerId);
        document.body.classList.add("alerts-resizing");
        const move = (next) => resizeAlertPane(kind, startWidth + next.clientX - startX);
        const finish = () => {
          divider.removeEventListener("pointermove", move);
          divider.removeEventListener("pointerup", finish);
          divider.removeEventListener("pointercancel", finish);
          document.body.classList.remove("alerts-resizing");
        };
        divider.addEventListener("pointermove", move);
        divider.addEventListener("pointerup", finish);
        divider.addEventListener("pointercancel", finish);
      });
      divider.addEventListener("keydown", (event) => {
        if (divider.hidden || !["ArrowLeft", "ArrowRight"].includes(event.key)) return;
        event.preventDefault();
        const width = document.querySelector(paneSelector).getBoundingClientRect().width;
        resizeAlertPane(kind, width + (event.key === "ArrowRight" ? 24 : -24));
      });
    });
  window.addEventListener("resize", updateAlertViewportHeight);
}

/** Refresh the host list while retaining an open investigation. */
async function loadAlerts() {
  const payload = await api("alerts", listPath("alerts"));
  if (!payload) return;
  applyPage("alerts", payload);
  byId("alerts-count").textContent = compact(payload.total);
  renderAlertSeverityFilters();
  renderAlertHostList();
  pager("alerts", "alerts-pager", loadAlerts);
  const workspace = state.alertsWorkspace;
  if (workspace.host) {
    const current = payload.items.find((item) => item.ip_alerted === workspace.host.ip_alerted);
    if (current) {
      workspace.host = current;
      renderAlertSelectedHost();
    }
    const signature = `${rangeQuery("alerts")}&${state.hideExcluded}`;
    if (workspace.listSignature !== signature || Date.now() - workspace.listLoadedAt > 15000) {
      loadAlertHostAlerts(true, true).catch(() => {});
    }
  }
}

/** Fit the Evidence workspace below the shared navigation. */
function updateEvidenceViewportHeight() {
  const bottom = document.querySelector(".tabs").getBoundingClientRect().bottom;
  byId("evidence").style.setProperty("--evidence-panel-height", `${Math.max(380, window.innerHeight - bottom)}px`);
}

/** Clear a selected group when the filtering context changes. */
function clearEvidenceSelection() {
  const workspace = state.evidenceWorkspace;
  workspace.group = null;
  workspace.record = null;
  workspace.records = [];
  workspace.next = null;
  workspace.generation += 1;
  highlightEvidenceSelection();
  renderEvidenceEmptyState();
}

/** Highlight the table row represented by the current group or record. */
function highlightEvidenceSelection() {
  const mode = byId("evidence-view").value;
  document.querySelectorAll("#evidence-table tbody tr").forEach((row, index) => {
    const item = state.pages.evidence.items[index];
    row.classList.toggle("selected", Boolean(item && (mode === "individual"
      ? item.id === state.evidenceWorkspace.record?.id
      : item.id === state.evidenceWorkspace.group?.id)));
  });
}

/** Render compact severity filters using counts from an unfiltered page. */
function renderEvidenceThreatChips() {
  const selected = byId("evidence-threat").value;
  const counts = state.evidenceWorkspace.threatCounts || new Map();
  const container = byId("evidence-threat-chips");
  container.replaceChildren();
  [["", "All"], ...["critical", "high", "medium", "low", "info"]
    .filter((level) => counts.get(level) || selected === level)
    .map((level) => [level, level[0].toUpperCase() + level.slice(1)])]
    .forEach(([level, label]) => {
      const button = text("button", `${label} ${compact(counts.get(level) || 0)}`, "evidence-chip");
      button.type = "button";
      button.dataset.level = level;
      button.classList.toggle("active", level === selected);
      button.setAttribute("aria-pressed", String(level === selected));
      button.addEventListener("click", () => {
        if (selected === level) return;
        byId("evidence-threat").value = level;
        clearEvidenceSelection();
        renderEvidenceThreatChips();
        byId("evidence-threat").dispatchEvent(new Event("change"));
      });
      container.append(button);
    });
}

/** Render grouping controls for the four Evidence table modes. */
function renderEvidenceGroupControls() {
  const mode = byId("evidence-view").value;
  const container = byId("evidence-group-controls");
  container.replaceChildren();
  [["grouped", "Host + type"], ["type", "Type"], ["host", "Host"], ["individual", "None"]]
    .forEach(([value, label]) => {
      const button = text("button", label, "evidence-group-button");
      button.type = "button";
      button.classList.toggle("active", value === mode);
      button.setAttribute("aria-pressed", String(value === mode));
      button.addEventListener("click", () => {
        if (mode === value) return;
        byId("evidence-view").value = value;
        byId("evidence-threat").value = "";
        state.evidenceWorkspace.threatCounts = null;
        clearEvidenceSelection();
        renderEvidenceGroupControls();
        byId("evidence-view").dispatchEvent(new Event("change"));
      });
      container.append(button);
    });
}

/** Show the selected Evidence page as a compact, keyboard-accessible table.
 * @param {object} payload Bounded API page with grouped or individual records.
 */
function renderEvidenceTable(payload) {
  const mode = byId("evidence-view").value;
  configureTable("evidence", mode, [
    ["Latest", "time"], ["Host", "host"], ["Type · module", "type"],
    ["Threat", "threat"], ["Score", "score"],
    [mode === "individual" ? "Flows" : "Records", mode === "individual" ? "flows" : "evidence"],
    ["Alerts", "alert"],
  ], loadEvidence);
  renderTable("evidence-table", payload.items, [
    (row) => evidenceClock(row.timestamp),
    (row) => row.profile_ip ? hostIdentity(row.profile_ip) : "All hosts",
    (row) => {
      const cell = document.createElement("span");
      cell.append(text("code", row.evidence_type || "All types"));
      if (row.module) cell.append(text("small", ` ${row.module}`, "muted"));
      return cell;
    },
    (row) => threat(row.threat_level),
    (row) => slipsScore(row),
    (row) => compact(mode === "individual" ? row.flow_count : row.evidence_count),
    (row) => compact(mode === "individual" ? row.alert_ids?.length : row.alert_count),
  ], (row) => {
    if (mode === "individual") selectEvidenceRecord(row);
    else selectEvidenceGroup(row);
  });
  document.querySelectorAll("#evidence-table tbody tr").forEach((row, index) => {
    const record = payload.items[index];
    if (!record) return;
    row.addEventListener("keydown", (event) => {
      if (!["ArrowDown", "ArrowUp"].includes(event.key)) return;
      event.preventDefault();
      const rows = [...row.parentElement.querySelectorAll('tr[data-clickable="true"]')];
      rows[Math.max(0, Math.min(rows.length - 1,
        index + (event.key === "ArrowDown" ? 1 : -1)))]?.focus();
    });
  });
  highlightEvidenceSelection();
}

/** Format a persisted Evidence timestamp as a compact local clock time.
 * @param {number} timestamp Seconds from the run clock.
 * @returns {string} Local clock time or a relative capture timestamp.
 */
function evidenceClock(timestamp) {
  const value = numeric(timestamp);
  return value >= 946684800 ? new Date(value * 1000).toLocaleTimeString() : formatTime(value);
}

/** Draw the overview shown before an Evidence group is selected. */
function renderEvidenceEmptyState() {
  const right = byId("evidence-right");
  right.replaceChildren();
  const payload = state.pages.evidence;
  const mode = byId("evidence-view").value;
  const prompt = document.createElement("div");
  prompt.className = "evidence-right-panel";
  prompt.append(text("h3", mode === "individual" ? "Select a record to inspect it" : "Select a group to see its records"),
    text("p", "Use ↑↓ and Enter in the table. The summary below covers the groups loaded on this page."));
  right.append(prompt);
  if (mode === "individual" || !payload.items.length) return;
  const typeCounts = new Map();
  const hostScores = new Map();
  payload.items.forEach((item) => {
    if (item.evidence_type) typeCounts.set(item.evidence_type,
      (typeCounts.get(item.evidence_type) || 0) + numeric(item.evidence_count));
    if (item.profile_ip && !item.whitelisted) {
      const previous = hostScores.get(item.profile_ip);
      if (!previous || numeric(item.alert_score) > numeric(previous.alert_score)) {
        hostScores.set(item.profile_ip, item);
      }
    }
  });
  if (typeCounts.size) {
    const panel = document.createElement("div");
    panel.className = "evidence-right-panel";
    panel.append(text("h3", "By type"));
    const bars = document.createElement("div");
    bars.className = "evidence-bars";
    const allTypes = [...typeCounts].sort((a, b) => b[1] - a[1]);
    const sorted = allTypes.slice(0, 7);
    if (allTypes.length > 7) {
      sorted.push([`Other (${allTypes.length - 7} types)`,
        allTypes.slice(7).reduce((sum, [, count]) => sum + count, 0)]);
    }
    const max = sorted[0]?.[1] || 1;
    sorted.forEach(([type, count]) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "evidence-bar-row";
      const track = text("span", "", "evidence-bar-track");
      const fill = document.createElement("span");
      fill.style.width = `${Math.max(1, 100 * count / max)}%`;
      track.append(fill);
      row.append(text("span", type, "evidence-bar-label"), track,
        text("span", compact(count), "evidence-bar-count"));
      if (typeCounts.has(type)) row.addEventListener("click", () => {
        state.evidenceWorkspace.typeFilter = type;
        clearEvidenceSelection();
        resetPage("evidence");
        loadEvidence().catch(() => {});
      });
      bars.append(row);
    });
    panel.append(bars);
    right.append(panel);
  }
  if (hostScores.size) {
    const panel = document.createElement("div");
    panel.className = "evidence-right-panel";
    panel.append(text("h3", "Hosts closest to the alert threshold"));
    const bars = document.createElement("div");
    bars.className = "evidence-bars";
    [...hostScores.values()].sort((a, b) => numeric(b.alert_score) - numeric(a.alert_score))
      .slice(0, 5).forEach((host) => {
        const row = document.createElement("button");
        row.type = "button";
        row.className = "evidence-bar-row";
        const track = text("span", "", "evidence-bar-track evidence-score-track");
        const fill = document.createElement("span");
        fill.style.width = `${Math.min(100, numeric(host.alert_score) * 10)}%`;
        fill.style.background = numeric(host.alert_score) >= 5 ? "#f36575" : "#e6b543";
        track.append(fill);
        row.append(text("span", host.profile_ip, "evidence-bar-label"), track,
          text("span", numeric(host.alert_score).toFixed(2), "evidence-bar-count"));
        row.addEventListener("click", () => {
          byId("evidence-search").value = host.profile_ip;
          clearEvidenceSelection();
          resetPage("evidence");
          loadEvidence().catch(() => {});
        });
        bars.append(row);
      });
    panel.append(bars, text("p", "The marker is the alert threshold: 5.0 on a scale to 10."));
    right.append(panel);
  }
}

/** Select a group and load its newest bounded record page.
 * @param {object} group Grouped evidence API row.
 */
function selectEvidenceGroup(group) {
  const workspace = state.evidenceWorkspace;
  if (workspace.group?.id === group.id) return;
  workspace.group = group;
  workspace.record = null;
  workspace.records = [];
  workspace.next = null;
  workspace.total = 0;
  byId("evidence-right").replaceChildren();
  highlightEvidenceSelection();
  renderEvidenceGroup();
  loadEvidenceGroupRecords(true).catch(() => {});
}

/** Return query parameters for the selected group's individual records.
 * @returns {URLSearchParams} Active range, group, and visibility filters.
 */
function evidenceGroupQuery() {
  const workspace = state.evidenceWorkspace;
  const params = rangeQuery("evidence");
  if (workspace.group?.profile_ip) params.set("profile", workspace.group.profile_ip);
  if (workspace.group?.evidence_type || workspace.typeFilter) {
    params.set("type", workspace.group?.evidence_type || workspace.typeFilter);
  }
  params.set("limit", "50");
  params.set("sort", "time");
  params.set("order", "desc");
  const level = byId("evidence-threat").value;
  const association = byId("evidence-link").value;
  const search = byId("evidence-search").value.trim();
  if (level) params.set("threat", level);
  if (association) params.set("association", association);
  if (search) params.set("search", search);
  if (state.hideExcluded) params.set("hide_excluded", "1");
  if (byId("evidence-scored-only").checked) params.set("scored_only", "1");
  return params;
}

/** Load one page of individual evidence inside a selected group.
 * @param {boolean} reset Whether to replace the currently loaded records.
 * @returns {Promise<void>} Completes when the bounded page has rendered.
 */
async function loadEvidenceGroupRecords(reset = true) {
  const workspace = state.evidenceWorkspace;
  if (!workspace.group) return;
  const groupId = workspace.group.id;
  const generation = ++workspace.generation;
  const params = evidenceGroupQuery();
  if (!reset && workspace.next) params.set("cursor", workspace.next);
  const payload = await api("evidenceGroupPane", `/api/evidence?${params}`);
  if (!payload || generation !== workspace.generation || workspace.group?.id !== groupId) return;
  workspace.records = reset ? payload.items : [...workspace.records, ...payload.items];
  workspace.next = payload.next_cursor;
  workspace.total = payload.total;
  workspace.listLoadedAt = Date.now();
  workspace.listSignature = evidenceGroupQuery().toString();
  if (workspace.record) {
    workspace.record = workspace.records.find((item) => item.id === workspace.record.id) || null;
  }
  if (!document.activeElement?.closest("#evidence-right .whitelist-editor")) {
    renderEvidenceGroup();
  }
}

/** Name a reporting peer in retained P2P report text.
 * @param {object} record Individual P2P evidence record.
 * @returns {string} Recorded peer address and ID, when available.
 */
function evidenceReporter(record) {
  const description = String(record.description || "");
  const received = description.match(/Received from P2P peer (.+?): reputation report/i);
  if (received) return received[1];
  const legacy = description.match(/attacking another peer:\s*(.+?)\. confidence:/i);
  return legacy ? legacy[1] : "Peer not recorded";
}

/** Render the selected group's summary, record list, and record details. */
function renderEvidenceGroup() {
  const workspace = state.evidenceWorkspace;
  const group = workspace.group;
  if (!group) return renderEvidenceEmptyState();
  const right = byId("evidence-right");
  const listScroll = right.querySelector(".evidence-record-list")?.scrollTop || 0;
  const openPeers = new Map([...right.querySelectorAll(".evidence-peer-group")]
    .map((details) => [details.dataset.peer, details.open]));
  right.replaceChildren();
  const summary = document.createElement("div");
  summary.className = "evidence-right-panel evidence-group-summary";
  const head = document.createElement("div");
  head.className = "evidence-right-head";
  const label = document.createElement("div");
  label.append(text("span", group.evidence_type || "All types", "type-chip"),
    text("small", `${group.module || "Module unknown"} · ${compact(group.evidence_count)} records · ${formatTime(group.timestamp)}`, "muted"));
  const close = text("button", "×");
  close.type = "button";
  close.title = "Close evidence group";
  close.setAttribute("aria-label", "Close evidence group");
  close.addEventListener("click", clearEvidenceSelection);
  head.append(label, close);
  summary.append(head);
  const p2pReports = group.evidence_type === "P2P_REPORT";
  const peerCount = new Set(workspace.records.map(evidenceReporter)).size;
  const title = p2pReports && group.profile_ip && workspace.records.length
      && workspace.total <= workspace.records.length
    ? `${peerCount} peer${peerCount === 1 ? "" : "s"} reported ${group.profile_ip} as malicious`
    : group.profile_ip && group.evidence_type
      ? `${group.evidence_type} · ${group.profile_ip}`
      : group.profile_ip || group.evidence_type || "Evidence group";
  summary.append(text("h3", title));
  if (p2pReports) summary.append(text("p", `Reputation reports received from Slips P2P peers. A report identifies its sender and subject; it does not by itself describe an attack or prove a local connection to that peer.${numeric(group.alert_score) === 0 ? " These reports have not increased the local score." : ""}`));
  else if (workspace.records[0]?.description) summary.append(hostDescription(workspace.records[0], "evidence-group-description"));
  summary.append(investigationStats([
    ["Host", group.profile_ip ? hostIdentity(group.profile_ip) : "All hosts"],
    ["Threat", threat(group.threat_level)],
    ["Local score", slipsScore(group)],
    ["Network", group.profile_ip ? networkContext(group) : "Multiple networks"],
  ]));
  right.append(summary);
  const list = document.createElement("div");
  list.className = "evidence-right-panel evidence-record-list";
  const listHead = document.createElement("div");
  listHead.className = "evidence-right-head";
  listHead.append(text("h3", `Records · ${compact(workspace.total || group.evidence_count)}`),
    text("small", p2pReports ? "Grouped by reporting peer" : "Newest first", "muted"));
  list.append(listHead);
  if (!workspace.records.length) list.append(text("p", "Loading records…"));
  const appendRecord = (container, record) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "evidence-record-row";
    button.classList.toggle("selected", record.id === workspace.record?.id);
    button.append(text("span", evidenceClock(record.timestamp)),
      text("span", p2pReports ? `maliciousness · confidence ${numeric(record.confidence).toFixed(2)}` : record.description || record.evidence_type),
      text("span", record.twid || "—"),
      text("span", `${compact(record.flow_count)} flow${numeric(record.flow_count) === 1 ? "" : "s"}`));
    button.addEventListener("click", () => selectEvidenceRecord(record));
    container.append(button);
  };
  if (p2pReports) {
    const peers = new Map();
    workspace.records.forEach((record) => {
      const peer = evidenceReporter(record);
      if (!peers.has(peer)) peers.set(peer, []);
      peers.get(peer).push(record);
    });
    peers.forEach((records, peer) => {
      const details = document.createElement("details");
      details.className = "evidence-peer-group";
      details.dataset.peer = peer;
      details.open = openPeers.get(peer) ?? true;
      details.append(text("summary", `${peer} · ${compact(records.length)} report${records.length === 1 ? "" : "s"}`));
      records.forEach((record) => appendRecord(details, record));
      list.append(details);
    });
  } else workspace.records.forEach((record) => appendRecord(list, record));
  if (workspace.next) {
    const actions = document.createElement("div");
    actions.className = "evidence-record-actions";
    const more = text("button", `Load more · ${compact(workspace.records.length)} of ${compact(workspace.total)}`, "secondary");
    more.type = "button";
    more.addEventListener("click", () => loadEvidenceGroupRecords(false).catch(() => {}));
    actions.append(more);
    list.append(actions);
  }
  right.append(list);
  list.scrollTop = listScroll;
  if (workspace.record) renderEvidenceRecordDetail(workspace.record);
}

/** Select one evidence record for inline investigation.
 * @param {object} record Individual durable evidence record.
 */
function selectEvidenceRecord(record) {
  state.evidenceWorkspace.record = record;
  highlightEvidenceSelection();
  if (byId("evidence-view").value === "individual") {
    renderEvidenceRecordDetail(record, true);
  } else renderEvidenceGroup();
}

/** Copy an evidence identifier in secure and local HTTP browser contexts.
 * @param {string} identifier Durable evidence UUID.
 * @returns {Promise<void>} Completes after the copy result is reported.
 */
async function copyEvidenceId(identifier) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(identifier);
  } else {
    const input = document.createElement("textarea");
    input.value = identifier;
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.append(input);
    input.select();
    const copied = document.execCommand("copy");
    input.remove();
    if (!copied) throw new Error("Browser denied clipboard access");
  }
  toast("Evidence ID copied.");
}

/** Show a record's identity, linked flows, whitelist editor, and raw JSON.
 * @param {object} record Individual durable evidence record.
 * @param {boolean} replace Whether to replace the right-pane contents.
 */
function renderEvidenceRecordDetail(record, replace = false) {
  const right = byId("evidence-right");
  if (replace) right.replaceChildren();
  const panel = document.createElement("div");
  panel.className = "evidence-right-panel evidence-record-detail";
  const head = document.createElement("div");
  head.className = "evidence-right-head";
  head.append(text("h3", `Record · ${formatTime(record.timestamp)}`));
  const actions = document.createElement("div");
  const close = text("button", "×");
  close.type = "button";
  close.title = "Close evidence record";
  close.setAttribute("aria-label", "Close evidence record");
  close.addEventListener("click", () => {
    state.evidenceWorkspace.record = null;
    highlightEvidenceSelection();
    if (state.evidenceWorkspace.group) renderEvidenceGroup();
    else renderEvidenceEmptyState();
  });
  const copy = text("button", "Copy ID");
  copy.type = "button";
  copy.addEventListener("click", () => copyEvidenceId(record.id)
    .catch(() => toast("Could not copy the evidence ID.")));
  const json = text("button", "JSON");
  json.type = "button";
  json.addEventListener("click", () => panel.querySelector(".json-details")?.setAttribute("open", ""));
  actions.append(copy, json, close);
  head.append(actions);
  panel.append(head, hostDescription(record, "evidence-record-description"));
  const fields = document.createElement("dl");
  [["Host", record.profile_ip], ["From peer", record.evidence_type === "P2P_REPORT" ? evidenceReporter(record) : ""],
    ["Threat", record.threat_level], ["Confidence", `${Math.round(numeric(record.confidence) * 100)}%`],
    ["Time window", record.twid || "—"], ["Triggering flows", `${compact(record.flow_count)} stored`],
    ["Alert links", compact(record.alert_ids?.length)], ["Evidence ID", record.id]]
    .filter(([, value]) => value !== "").forEach(([label, value]) => {
      fields.append(text("dt", label), text("dd", value));
    });
  panel.append(fields);
  const flowButton = text("button", "Inspect triggering flows", "secondary");
  flowButton.type = "button";
  flowButton.addEventListener("click", () => openEvidence(record).catch(() => {}));
  panel.append(flowButton, whitelistEditor("evidence-pane", record), rawBlock(record, "evidence"));
  right.append(panel);
}

/** Refresh the Evidence table while retaining a valid open investigation. */
async function loadEvidence() {
  renderEvidenceGroupControls();
  const payload = await api("evidence", listPath("evidence"));
  if (!payload) return;
  applyPage("evidence", payload);
  const mode = byId("evidence-view").value;
  if (!byId("evidence-threat").value && !state.evidenceWorkspace.typeFilter) {
    const counts = new Map([["", payload.total]]);
    payload.items.forEach((item) => {
      const level = String(item.threat_level || "info").toLowerCase();
      counts.set(level, (counts.get(level) || 0) + 1);
    });
    state.evidenceWorkspace.threatCounts = counts;
  }
  renderEvidenceThreatChips();
  renderEvidenceTable(payload);
  const loadedRecords = mode === "individual"
    ? payload.items.length
    : payload.items.reduce((sum, item) => sum + numeric(item.evidence_count), 0);
  const recordsLabel = payload.page_size === payload.total
    ? `${compact(loadedRecords)} records`
    : `${compact(loadedRecords)} records on this page`;
  const activeType = byId("evidence-active-type");
  activeType.hidden = !state.evidenceWorkspace.typeFilter;
  activeType.textContent = state.evidenceWorkspace.typeFilter
    ? `${state.evidenceWorkspace.typeFilter} ×` : "";
  byId("evidence-count").textContent = mode === "individual"
    ? `${compact(payload.total)} records`
    : `${compact(payload.total)} groups · ${recordsLabel}`;
  const selectedRange = byId("evidence-range");
  byId("evidence-range-badge").textContent = selectedRange.selectedOptions[0]?.textContent || "Full run";
  byId("evidence-summary").textContent = `${payload.page_size} of ${compact(payload.total)} ${mode === "individual" ? "records" : "groups"}${state.evidenceWorkspace.typeFilter ? ` · ${state.evidenceWorkspace.typeFilter}` : ""}`;
  pager("evidence", "evidence-pager", loadEvidence);
  const workspace = state.evidenceWorkspace;
  if (workspace.group) {
    workspace.group = payload.items.find((item) => item.id === workspace.group.id) || workspace.group;
    const signature = evidenceGroupQuery().toString();
    if (workspace.listSignature !== signature || Date.now() - workspace.listLoadedAt > 15000) {
      loadEvidenceGroupRecords(true).catch(() => {});
    }
  } else if (workspace.record && mode === "individual") {
    renderEvidenceRecordDetail(workspace.record, true);
  } else renderEvidenceEmptyState();
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

/** Save a whitelist change through the run-scoped local API.
 * @param {object} change - Rule value, direction, suppression, and action.
 * @returns {Promise<object>} The saved rule returned by the server.
 */
async function saveWhitelistRule(change) {
  const response = await fetch("/api/whitelists", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(change),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
  await loadWhitelists();
  return payload;
}

/** Offer IP and port values present in an evidence and its linked flows.
 * @param {object|null} record - Individual evidence, if available.
 * @param {object[]} groups - Triggering flow groups.
 * @returns {Map<string, object>} Suggested values and their directions.
 */
function whitelistSuggestions(record, groups = []) {
  const choices = new Map();
  /** Add one suggested value, merging directions when it appears on both sides.
   * @param {string} value - Rule value.
   * @param {string} direction - Traffic side.
   * @param {string} label - Browser suggestion label.
   */
  const add = (value, direction, label) => {
    if (value === null || value === undefined || value === "" || choices.size >= 200) return;
    const key = String(value);
    const existing = choices.get(key);
    if (existing?.label === "Profile host IP" && direction !== "both") {
      choices.set(key, { direction, label });
      return;
    }
    choices.set(key, {
      direction: existing && existing.direction !== direction ? "both" : direction,
      label: existing?.label || label,
    });
  };
  /** Suggest an IP, its exact port, and the corresponding port-only rule.
   * @param {string|null} ip - Address on this side, if known.
   * @param {number|string|null} port - Port on this side, if known.
   * @param {string} direction - Traffic side.
   * @param {string} label - Browser suggestion label.
   */
  const addSide = (ip, port, direction, label) => {
    if (ip) add(ip, direction, `${label} IP`);
    if (port !== null && port !== undefined && /^\d+$/.test(String(port))
        && Number(port) > 0 && Number(port) <= 65535) {
      if (ip) add(`${String(ip).includes(":") ? `[${ip}]` : ip}:${port}`,
        direction, `${label} IP and port`);
      add(`*:${port}`, direction, `${label} port on any IP`);
    }
  };
  if (record?.profile_ip) add(record.profile_ip, "both", "Profile host IP");
  addSide(null, record?.src_port, "src", "Evidence source");
  addSide(null, record?.dst_port, "dst", "Evidence destination");
  for (const role of ["attacker", "victim"]) {
    const entity = record?.[role];
    if (String(entity?.ioc_type || "").toUpperCase() !== "IP") continue;
    const direction = String(entity.direction || "").toLowerCase().includes("src")
      ? "src" : String(entity.direction || "").toLowerCase().includes("dst") ? "dst" : "both";
    const port = direction === "src" ? record.src_port
      : direction === "dst" ? record.dst_port : null;
    addSide(entity.value, port, direction, role);
  }
  groups.forEach((group) => {
    [group.network_flow, ...(group.protocol_flows || [])].filter(Boolean).forEach((row) => {
      const flow = row.flow && typeof row.flow === "object" ? row.flow : row;
      addSide(flowValue(flow, "saddr", "src_ip", "id.orig_h"),
        flowValue(flow, "sport", "src_port", "id.orig_p"), "src", "Flow source");
      addSide(flowValue(flow, "daddr", "dst_ip", "id.resp_h"),
        flowValue(flow, "dport", "dst_port", "id.resp_p"), "dst", "Flow destination");
    });
  });
  return choices;
}

/** Fill one whitelist editor with values from an evidence or linked flows.
 * @param {Element} editor - Editor containing the suggestion list.
 * @param {object|null} record - Individual evidence, if available.
 * @param {object[]} groups - Triggering flow groups.
 */
function updateWhitelistSuggestions(editor, record, groups = []) {
  const list = editor.querySelector("datalist");
  if (!list) return;
  list.replaceChildren();
  whitelistSuggestions(record, groups).forEach((choice, value) => {
    const option = document.createElement("option");
    option.value = value;
    option.label = `${choice.label} · ${choice.direction}`;
    option.dataset.direction = choice.direction;
    list.append(option);
  });
}

/** Build an IP whitelist editor for the tab or an individual evidence.
 * @param {string} kind - Unique list prefix for tab or evidence.
 * @param {object|null} record - Individual evidence, if available.
 * @returns {Element} Editor with its own submit handler.
 */
function whitelistEditor(kind, record = null) {
  const section = document.createElement("section");
  section.className = "surface whitelist-editor";
  section.append(
    text("h3", record ? "Whitelist future matches from this evidence" : "Add an IP or port rule"),
    text("p", "Choose an IP, IP:port, [IPv6]:port, or *:port. Port-only rules affect that port on any IP. Existing evidence stays in the record.", "muted"),
  );
  const form = document.createElement("form");
  form.className = "whitelist-form";
  const valueLabel = document.createElement("label");
  valueLabel.append(text("span", "IP or port"));
  const value = document.createElement("input");
  value.type = "text";
  value.required = true;
  value.maxLength = 128;
  value.placeholder = "192.168.1.10:443 or *:443";
  value.setAttribute("list", `${kind}-whitelist-values`);
  valueLabel.append(value);
  const list = document.createElement("datalist");
  list.id = `${kind}-whitelist-values`;
  const directionLabel = document.createElement("label");
  directionLabel.append(text("span", "Applies on"));
  const direction = document.createElement("select");
  [["dst", "Destination"], ["src", "Source"], ["both", "Both sides"]].forEach(([key, label]) => {
    const option = text("option", label);
    option.value = key;
    direction.append(option);
  });
  directionLabel.append(direction);
  value.addEventListener("input", () => {
    const selected = Array.from(list.options).find((option) => option.value === value.value);
    if (selected) direction.value = selected.dataset.direction;
  });
  const ignoreLabel = document.createElement("label");
  ignoreLabel.append(text("span", "Suppress"));
  const ignored = document.createElement("select");
  [["alerts", "Future evidence and alerts"], ["flows", "Flows"],
    ["both", "Flows, evidence and alerts"]].forEach(([key, label]) => {
    const option = text("option", label);
    option.value = key;
    ignored.append(option);
  });
  ignoreLabel.append(ignored);
  const typeLabel = document.createElement("label");
  typeLabel.append(text("span", "Evidence type"));
  const evidenceType = document.createElement("select");
  evidenceType.className = "whitelist-evidence-type";
  const allTypes = text("option", "All evidence types");
  allTypes.value = "";
  evidenceType.append(allTypes);
  const typeNames = new Set(state.whitelists?.evidence_types || []);
  if (record?.evidence_type) typeNames.add(record.evidence_type);
  typeNames.forEach((name) => {
    const option = text("option", name);
    option.value = name;
    evidenceType.append(option);
  });
  if (record?.evidence_type) evidenceType.value = record.evidence_type;
  evidenceType.addEventListener("change", () => {
    if (evidenceType.value) ignored.value = "alerts";
    ignored.disabled = Boolean(evidenceType.value);
  });
  ignored.disabled = Boolean(evidenceType.value);
  typeLabel.append(evidenceType);
  const save = text("button", "Add rule", "secondary");
  save.type = "submit";
  const feedback = text("p", "Rules take effect for future traffic and detections while Slips is running.", "muted whitelist-feedback");
  form.append(valueLabel, list, directionLabel, ignoreLabel, typeLabel, save);
  section.append(form, feedback);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    feedback.textContent = "Saving rule…";
    try {
      const result = await saveWhitelistRule({
        action: "add", value: value.value, direction: direction.value,
        ignore: ignored.value, evidence_type: evidenceType.value,
      });
      feedback.textContent = `${result.value} was added. New matching activity will be suppressed within a few seconds.`;
      value.value = "";
      toast("Whitelist rule added");
    } catch (error) {
      feedback.textContent = `Could not add rule: ${error.message}`;
    } finally {
      save.disabled = false;
    }
  });
  updateWhitelistSuggestions(section, record);
  return section;
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
    (row) => row.evidence_type || "All",
    (row) => row.effect,
    (row) => row.source,
    (row) => {
      if (!row.managed) return "—";
      const remove = text("button", "Remove", "secondary");
      remove.type = "button";
      remove.addEventListener("click", async () => {
        if (!window.confirm(`Remove whitelist rule ${row.value}?`)) return;
        remove.disabled = true;
        try {
          await saveWhitelistRule({
            action: "remove", value: row.value, direction: row.direction,
            ignore: row.ignore, evidence_type: row.evidence_type,
          });
          toast("Whitelist rule removed");
        } catch (error) {
          remove.disabled = false;
          toast(`Could not remove rule: ${error.message}`);
        }
      });
      return remove;
    },
  ]);
}

async function loadWhitelists() {
  const payload = await api("whitelists", "/api/whitelists");
  if (!payload) return;
  state.whitelists = payload;
  document.querySelectorAll(".whitelist-evidence-type").forEach((select) => {
    const selected = select.value;
    select.replaceChildren();
    const all = text("option", "All evidence types");
    all.value = "";
    select.append(all);
    (payload.evidence_types || []).forEach((name) => {
      const option = text("option", name);
      option.value = name;
      select.append(option);
    });
    select.value = selected;
  });
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
  byId("firewall-disabled").hidden = payload.enabled;
  byId("firewall-stats").hidden = !payload.enabled;
  if (!payload.enabled) return;
  byId("firewall-count").textContent = `${payload.page_size} active enforcement record${payload.page_size === 1 ? "" : "s"}`;
  const impact = payload.impact || {};
  setSummaryCards([
    ["Packets stopped (estimated)", compact(impact.packets)],
    ["Flows stopped (estimated)", compact(impact.flows)],
    ["Evidence while blocked", compact(impact.evidence)],
  ], "firewall-impact-summary");
  renderTable("firewall-table", payload.items, [
    (row) => hostIdentity(row.ip),
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
    (row) => hostIdentity(row.ip),
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
      (row) => hostIdentity(row.ip),
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
      (row) => hostIdentity(row.ip),
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
      (row) => hostIdentity(row.profile_ip),
      (row) => threat(row.threat_level),
      (row) => text("code", row.evidence_type),
      (row) => `${Math.round(numeric(row.confidence) * 100)}%`,
      (row) => compact(row.flow_count),
      (row) => compact(row.alert_count),
      (row) => hostDescription(row),
    ], (row) => openHost(row.profile_ip));
}

/** Load the bounded, run-scoped ARP poisoner and detector view. */
async function loadArpPoisoning() {
  const path = state.hideExcluded
    ? "/api/arp-poisoning?hide_excluded=1" : "/api/arp-poisoning";
  const payload = await api("arpPoisoning", path);
  if (!payload) return;
  state.arpPoisoning = payload;
  const counts = payload.counts || {};
  const module = payload.module || {};
  byId("arp-poisoning-badge").textContent = compact(counts.active);
  byId("arp-poisoning-disabled").hidden = module.enabled;
  byId("arp-poisoning-stats").hidden = !module.enabled;
  if (!module.enabled) {
    byId("arp-poisoning-status").textContent = "ARP poisoning not enabled in this run.";
    return;
  }
  byId("arp-poisoning-status").textContent = `arp_poisoner is ${module.state}${module.pid ? ` · PID ${module.pid}` : ""}.`;
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
    const item = document.createElement("span");
    item.className = "p2p-trust-legend-item";
    const marker = document.createElement("i");
    marker.className = `peer-trust-key peer-trust-line-${index % 8}`;
    item.append(marker, peerIps.get(peerId)
      ? hostIdentity(peerIps.get(peerId)) : text("code", peerId));
    item.title = peerId;
    legend.append(item);
  });
}

/** Combine retained message telemetry with reports still present in the trust DB. */
function p2pMessageRows(payload) {
  const activity = (payload.activity || []).filter((record) => record && typeof record === "object")
    .map((record) => {
      const content = record.message && typeof record.message === "object" ? record.message : null;
      const evaluation = content?.evaluation && typeof content.evaluation === "object"
        ? content.evaluation : {};
      return {
        ...record,
        message_type: String(record.message_type || "unknown"),
        direction: String(record.direction || "unknown"),
        peer: String(record.peer || record.peer_id || ""),
        target: String(record.target || content?.key || ""),
        score: evaluation.score !== null && evaluation.score !== undefined
          && Number.isFinite(Number(evaluation.score)) ? Number(evaluation.score) : null,
        confidence: evaluation.confidence !== null && evaluation.confidence !== undefined
          && Number.isFinite(Number(evaluation.confidence)) ? Number(evaluation.confidence) : null,
      };
    });
  const reportKey = (peer, target, timestamp) =>
    `${peer}\u0000${target}\u0000${Number(timestamp).toFixed(3)}`;
  const retained = new Set(activity
    .filter((row) => row.direction === "received" && ["report", "blame"].includes(row.message_type))
    .map((row) => reportKey(row.peer, row.target, row.report_time || row.timestamp)));
  for (const report of payload.reports || []) {
    const key = reportKey(report.peer_id, report.target, report.timestamp);
    if (retained.has(key)) continue;
    retained.add(key);
    activity.push({
      timestamp: report.timestamp,
      direction: "received",
      message_type: "report",
      peer: report.peer_id,
      target: report.target,
      score: report.score,
      confidence: report.confidence,
      archived_report: true,
    });
  }
  return activity;
}

/** Apply the selected report/message filter and render the sortable table. */
function renderP2PMessages() {
  const payload = state.p2p || {};
  const filter = byId("p2p-message-filter").value;
  const rows = p2pMessageRows(payload);
  const visible = rows.filter((row) => {
    if (filter === "all") return true;
    if (filter === "received-report") return row.direction === "received"
      && row.message_type === "report";
    if (filter === "sent-report") return row.direction === "sent"
      && row.message_type === "report";
    return row.message_type === filter;
  });
  byId("p2p-message-count").textContent = `${visible.length} shown · ${rows.length} retained`;
  renderTable("p2p-activity-table", sortLocalRows("p2p-activity-table", visible), [
    (row) => formatTime(row.timestamp),
    (row) => row.direction,
    (row) => row.message_type,
    (row) => hostOrText(row.peer),
    (row) => hostOrText(row.target),
    (row) => row.score === null || row.score === undefined ? "—" : numeric(row.score).toFixed(3),
    (row) => row.confidence === null || row.confidence === undefined
      ? "—" : numeric(row.confidence).toFixed(3),
  ], openP2PMessage);
}

/** Open the complete retained content for a P2P message or report. */
function openP2PMessage(record) {
  openDrawer("P2P MESSAGE", `${record.message_type} · ${record.direction}`);
  const body = byId("drawer-body");
  const facts = [
    ["Time", formatTime(record.timestamp)],
    ["Direction", record.direction],
    ["Type", record.message_type],
    ["Peer", record.peer || "—"],
    ["Target", record.target || "—"],
    ["Score", record.score === null || record.score === undefined ? "—" : numeric(record.score).toFixed(3)],
    ["Confidence", record.confidence === null || record.confidence === undefined
      ? "—" : numeric(record.confidence).toFixed(3)],
  ];
  if (record.report_time) facts.splice(1, 0, ["Peer report time", formatTime(record.report_time)]);
  body.append(investigationStats(facts));
  const content = record.message && typeof record.message === "object"
    ? record.message : record.archived_report
      ? { key: record.target, evaluation: { score: record.score, confidence: record.confidence } }
      : record;
  body.append(text("h3", record.archived_report ? "Stored report fields" : "Message content"));
  if (record.archived_report) body.append(text("p", "The original message is no longer retained; these report fields remain in the trust database.", "muted"));
  body.append(text("pre", JSON.stringify(content, null, 2), "p2p-message-content"));
}

async function loadP2P() {
  const range = byId("p2p-range").value;
  const payload = await api("p2p", `/api/p2p?range=${encodeURIComponent(range)}`);
  if (!payload) return;
  state.p2p = payload;
  const counts = payload.counts || {};
  byId("p2p-badge").textContent = compact(counts.connected);
  byId("p2p-disabled").hidden = payload.enabled;
  byId("p2p-stats").hidden = !payload.enabled;
  if (!payload.enabled) {
    byId("p2p-status").textContent = "P2P not enabled in this run.";
    return;
  }
  byId("p2p-status").textContent = counts.connected
    ? `${counts.connected} peer${counts.connected === 1 ? "" : "s"} connected now.`
    : "P2P is running and listening; no peers are connected now.";
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
    (row) => hostIdentity(row.ip),
    (row) => text("span", row.connected ? "connected" : "offline", `status ${row.connected ? "ok" : "warn"}`),
    (row) => row.trust === null ? "—" : numeric(row.trust).toFixed(3),
    (row) => row.reliability === null ? "—" : numeric(row.reliability).toFixed(3),
    (row) => compact(row.reports_received),
    (row) => formatTime(row.last_seen),
  ]);
  renderP2PMessages();
}

async function loadHosts() {
  const payload = await api("hosts", listPath("hosts"));
  if (!payload) return;
  payload.items.forEach(rememberHostRecord);
  refreshHostLabels();
  const page = state.pages.hosts;
  const retained = page.items.slice(100);
  const retainedNext = page.next;
  applyPage("hosts", payload);
  if (retained.length) {
    const known = new Set(page.items.map((row) => row.ip));
    retained.forEach((row) => {
      if (!known.has(row.ip)) page.items.push(row);
    });
    page.next = retainedNext;
  }
  renderHostFilterChips(payload);
  renderHostsPage();
}

/** Append the next server page when the visible inventory reaches its end. */
async function loadMoreHosts() {
  const page = state.pages.hosts;
  if (page.visible < page.items.length) {
    page.visible += 14;
    renderHostsPage();
    return;
  }
  if (!page.next) return;
  const params = new URLSearchParams(listPath("hosts").split("?", 2)[1]);
  params.set("cursor", page.next);
  const payload = await api("hostsMore", `/api/hosts?${params}`);
  if (!payload) return;
  payload.items.forEach(rememberHostRecord);
  page.items.push(...payload.items);
  page.next = payload.next_cursor;
  page.total = payload.total;
  page.visible = Math.min(page.items.length, page.visible + 14);
  renderHostsPage();
}

/** Show the bounded inventory page with compact score and identity columns. */
function renderHostsPage() {
  const page = state.pages.hosts;
  const rows = page.items.slice(0, page.visible);
  renderTable("hosts-table", rows, [
    (row) => hostIdentity(row.ip),
    (row) => {
      const value = document.createElement("span");
      value.className = "hosts-mac-vendor";
      value.append(text("code", row.mac || "—"), text("small", row.mac_vendor || ""));
      return value;
    },
    (row) => text("span", row.scope || "—", `hosts-scope-${row.scope || "unknown"}`),
    (row) => hostPeakScoreCell(row),
    (row) => compact(row.load?.flows),
    (row) => formatBytes(row.load?.bytes),
    (row) => compact(row.evidence_count),
    (row) => compact(row.alert_count),
    (row) => formatShortTime(row.load?.last_seen || row.observed_at),
    (row) => row.hostname || "—",
    (row) => tiFeeds(row),
    (row) => slipsScore(row),
  ], (row) => openHost(row.ip, row));
  document.querySelectorAll("#hosts-table tbody tr").forEach((row) => {
    ["hostname", "ti", "score"].forEach((key, index) => {
      const td = row.cells[9 + index];
      if (td) td.hidden = !document.querySelector(`[data-host-column="${key}"]`).checked;
    });
  });
  const shown = Math.min(page.visible, page.items.length);
  byId("hosts-count").textContent = `${compact(page.total)} hosts · sorted by ${page.sort.replaceAll("_", " ")}`;
  byId("hosts-list-status").textContent = `${shown} of ${compact(page.total)} hosts · threshold line at ${numeric(page.items[0]?.alert_threshold).toFixed(1)} · current score on hover`;
  byId("hosts-more").hidden = shown >= page.items.length && !page.next;
  applySortIndicators("hosts");
}

/** Format inventory timestamps without repeating the date in every row. */
function formatShortTime(value) {
  if (!numeric(value)) return "—";
  return new Date(numeric(value) * 1000).toLocaleTimeString();
}

/** Draw the peak score and threshold in a single compact table cell. */
function hostPeakScoreCell(row) {
  const wrapper = document.createElement("span");
  wrapper.className = "hosts-peak-cell";
  const level = String(row.max_threat_level || "info").toLowerCase();
  const peak = row.peak_alert_score === null || row.peak_alert_score === undefined
    ? null : Number(row.peak_alert_score);
  const threshold = numeric(row.alert_threshold) || 5;
  const label = text("span", level, `hosts-threat-level threat-${level}`);
  const value = text("strong", peak === null ? "—" : peak.toFixed(2));
  const track = text("span", "", "hosts-score-track");
  const fill = text("span", "", `hosts-score-fill threat-${level}`);
  fill.style.width = `${Math.min(100, Math.max(0, numeric(peak) / Math.max(threshold * 2, 1) * 100))}%`;
  track.append(fill);
  wrapper.title = `Current score: ${row.alert_score ?? "unavailable"} · peak: ${peak ?? "unavailable"} · alert threshold: ${threshold}`;
  wrapper.append(label, value, track);
  return wrapper;
}

/** Keep threat and scope chips synchronized with the server filters. */
function renderHostFilterChips(payload) {
  const groups = [
    ["hosts-threat-chips", "hosts-threat", [["", "All"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["info", "Info"]], "max_threat_level"],
    ["hosts-scope-chips", "hosts-scope", [["", "All scopes"], ["local", "Local"], ["public", "Public"]], "scope"],
  ];
  groups.forEach(([targetId, selectId, options, field]) => {
    const target = byId(targetId);
    const select = byId(selectId);
    target.replaceChildren();
    options.forEach(([value, label]) => {
      const completePage = payload.items.length === payload.total;
      const count = !value || select.value === value ? payload.total
        : payload.items.filter((row) => String(row[field] || "").toLowerCase() === value).length;
      const showCount = !value || select.value === value
        || (completePage && !byId("hosts-threat").value && !byId("hosts-scope").value);
      const button = text("button", `${label}${showCount ? ` ${compact(count)}` : ""}`, `hosts-filter-chip ${select.value === value ? "active" : ""}`);
      button.type = "button";
      button.addEventListener("click", () => {
        select.value = value;
        state.pages.hosts.visible = 14;
        resetPage("hosts");
        loadHosts().catch(() => {});
      });
      target.append(button);
    });
  });
}

/** Render cached rDNS or the most recently associated DNS domain. */
function contextName(record) {
  const value = record.dns_name || "—";
  const source = record.dns_name_source || "No cached DNS context";
  const element = text("code", value);
  element.title = source;
  return element;
}

/** Show the saved network where a detection occurred. */
function networkContext(record) {
  const label = record.network_label || "Unknown network (not recorded)";
  const element = text("span", label);
  if (record.network_id) element.title = record.network_id;
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
  const button = document.createElement("button");
  button.className = "ip-link";
  button.type = "button";
  button.append(hostIdentity(ip));
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
  button.append(heading, hostDescription(record, "investigation-description"));
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
  const timestamp = flowValue(flow, "starttime", "ts") ?? record?.event_time;
  context.append(
    text("span", "Alternative protocol flow: " + displayType),
    text("span", "UID: " + (record.uid || flow.uid || "Unknown")),
  );
  if (timestamp !== null && timestamp !== undefined && timestamp !== "") {
    const observed = Number.isFinite(Number(timestamp))
      ? formatTime(timestamp) : String(timestamp);
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
  const timestamp = flowValue(flow, "starttime", "ts") ?? record?.event_time;
  const observed = timestamp === null || timestamp === undefined || timestamp === ""
    ? "—" : Number.isFinite(Number(timestamp)) ? formatTime(timestamp) : String(timestamp);
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
      ["Observed", observed],
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
      ["Network", networkContext(record)],
      ["Threat", threat(record.threat_level)],
      ["Slips score", slipsScore(record), "accent"],
      ["Confidence", `${Math.round(numeric(record.confidence) * 100)}%`, "accent"],
    ]),
    investigationHeading("Detection summary", record.module ? `Generated by ${record.module}` : ""),
    hostDescription(record, "description-box"),
  );
  if (record.evidence_type === "MALICIOUS_IP_FROM_P2P_NETWORK") {
    body.append(detailRow("Reporting peers", reportingPeers(record)));
  }
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
  const whitelistSection = whitelistEditor("evidence", record);
  body.append(whitelistSection);
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
    updateWhitelistSuggestions(whitelistSection, record, payload.items);
    if (numeric(payload.recovered_flow_count) > 0) {
      body.append(text("p", `${compact(payload.recovered_flow_count)} linked flow(s) recovered from current Zeek logs after their SQLite rows were pruned.`, "muted"));
    }
    if (!payload.items.length) {
      body.append(text("p", numeric(payload.unavailable_flow_count) > 0
        ? "The evidence still has linked flow IDs, but their raw records are unavailable. They may have expired under retention or were never stored."
        : "No triggering flow records are available."));
    } else if (numeric(payload.unavailable_flow_count) > 0) {
      body.append(text("p", `${compact(payload.unavailable_flow_count)} linked flow record(s) are unavailable; they may have expired under retention.`, "muted"));
    }
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
  const generation = openDrawer("ALERT", "Alert details");
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
      ["Network", networkContext(record)],
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

function hostRangeParams() {
  const params = rangeQuery("host");
  return params;
}

/**
 * Show host clues saved across runs, separated by local network.
 * @param {Object[]} profiles Permanent host records for this IP.
 * @param {HTMLElement|null} currentEditorTarget Editor location in the identity card.
 */
function renderPermanentProfiles(profiles, currentEditorTarget = null) {
  const container = byId("host-permanent-profiles");
  const profileIp = profiles?.[0]?.ip || "";
  if (container.dataset.profileIp === profileIp
      && document.activeElement?.closest(".profile-network-name-form, .host-annotation-form")
      && (container.contains(document.activeElement)
        || currentEditorTarget?.contains(document.activeElement))) return;
  const openSections = new Map();
  if (container.dataset.profileIp === profileIp) {
    container.querySelectorAll("details.host-profile-facts").forEach((details) => {
      openSections.set(details.dataset.key, details.open);
    });
  }
  container.replaceChildren();
  container.dataset.profileIp = profileIp;
  if (!profiles?.length) {
    container.append(text("p", "No permanent identity clues recorded yet.", "muted"));
    return;
  }
  const labels = {
    hostname: "Names", reverse_dns: "Reverse DNS", dns_name: "DNS names",
    mdns_name: "Multicast DNS names", sni: "HTTPS SNI",
    http_host: "HTTP hosts", url: "Requested URLs", mac: "MAC addresses",
    asn: "ASN", country: "Country",
    threat_feed: "Threat feed appearances",
  };
  profiles.forEach((profile, index) => {
    const group = document.createElement("section");
    group.className = "permanent-host-profile";
    const title = text("strong", `Network: ${profile.network_label || profile.network_id}`);
    group.append(title);
    group.append(text("small", `First seen ${formatTime(profile.first_seen)} · Last seen ${formatTime(profile.last_seen)}`, "muted"));
    const annotationKey = JSON.stringify([profile.network_id, profile.ip]);
    const annotation = document.createElement("form");
    annotation.className = "host-annotation-form";
    annotation.hidden = !state.hostAnnotationEditorOpen.has(annotationKey);
    const nameLabel = text("label", "Custom name");
    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.maxLength = 80;
    nameInput.placeholder = "e.g. Sebastian's iPad";
    nameInput.value = state.hostAnnotationDrafts.get(annotationKey)?.name ?? profile.user_name ?? "";
    const noteLabel = text("label", "Note");
    const noteInput = document.createElement("textarea");
    noteInput.maxLength = 1000;
    noteInput.rows = 3;
    noteInput.placeholder = "How you recognize this host";
    noteInput.value = state.hostAnnotationDrafts.get(annotationKey)?.note ?? profile.user_note ?? "";
    const rememberDraft = () => state.hostAnnotationDrafts.set(annotationKey, {
      name: nameInput.value, note: noteInput.value,
    });
    nameInput.addEventListener("input", rememberDraft);
    noteInput.addEventListener("input", rememberDraft);
    nameLabel.append(nameInput);
    noteLabel.append(noteInput);
    const annotationSave = text("button", "Save identification", "secondary");
    annotationSave.type = "submit";
    const annotationFeedback = text("small", "", "network-name-feedback");
    annotation.append(nameLabel, noteLabel, annotationSave, annotationFeedback);
    const annotationEdit = text("button", profile.user_name || profile.user_note
      ? "Edit name and note" : "Name this host", "secondary profile-network-name-action");
    annotationEdit.type = "button";
    annotationEdit.addEventListener("click", () => {
      annotation.hidden = !annotation.hidden;
      if (annotation.hidden) state.hostAnnotationEditorOpen.delete(annotationKey);
      else {
        state.hostAnnotationEditorOpen.add(annotationKey);
        nameInput.focus();
      }
    });
    annotation.addEventListener("submit", async (event) => {
      event.preventDefault();
      annotationSave.disabled = true;
      annotationFeedback.textContent = "Saving…";
      try {
        const response = await fetch("/api/host-annotation", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ip: profile.ip, network_id: profile.network_id,
            name: nameInput.value, note: noteInput.value,
          }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
        profile.user_name = payload.name;
        profile.user_note = payload.note;
        state.hostAnnotationDrafts.delete(annotationKey);
        state.hostAnnotationEditorOpen.delete(annotationKey);
        if (!state.host || state.host.ip !== profile.ip) return;
        const currentProfile = state.host.permanent_profiles?.find(
          (item) => item.network_id === profile.network_id,
        );
        if (currentProfile) {
          currentProfile.user_name = payload.name;
          currentProfile.user_note = payload.note;
        }
        if (state.host?.permanent_profiles?.[0]?.network_id === profile.network_id) {
          state.host.user_name = payload.name;
          state.host.user_note = payload.note;
          state.hostNames.delete(profile.ip);
          rememberHostRecord(state.host);
          if (!payload.name) {
            state.pendingHostNames.add(profile.ip);
            loadHostNames();
          }
          refreshHostLabels();
        }
        annotation.hidden = true;
        annotationFeedback.textContent = "";
        document.activeElement?.blur();
        renderHostCards(state.host);
        toast(payload.name || payload.note ? "Host identification saved." : "Host identification removed.");
      } catch (error) {
        annotationFeedback.textContent = error.message;
        annotationSave.disabled = false;
      }
    });
    if (profile.user_name) group.append(text("p", `Custom name: ${profile.user_name}`, "host-user-name"));
    if (profile.user_note) group.append(text("p", profile.user_note, "host-user-note"));
    if (index === 0 && currentEditorTarget) {
      currentEditorTarget.append(annotationEdit, annotation);
    } else {
      group.append(annotationEdit, annotation);
    }
    const form = document.createElement("form");
    form.className = "network-name-form profile-network-name-form";
    form.hidden = !state.networkNameEditorOpen.has(profile.network_id);
    const label = text("label", "Network name");
    const input = document.createElement("input");
    input.type = "text";
    input.maxLength = 80;
    input.placeholder = "Name this network";
    input.autocomplete = "off";
    input.value = state.networkNameDrafts.get(profile.network_id)
      ?? profile.network_name ?? "";
    input.disabled = profile.network_name === undefined;
    input.addEventListener("input", () => {
      state.networkNameDrafts.set(profile.network_id, input.value);
    });
    label.append(input);
    const save = text("button", "Save name", "secondary");
    save.type = "submit";
    save.disabled = input.disabled;
    form.append(label, save);
    const feedback = text("small", "", "network-name-feedback");
    form.append(feedback);
    const edit = text("button", profile.network_name ? "Edit name" : "Name network", "secondary profile-network-name-action");
    edit.type = "button";
    edit.disabled = input.disabled;
    edit.addEventListener("click", () => {
      form.hidden = !form.hidden;
      if (form.hidden) state.networkNameEditorOpen.delete(profile.network_id);
      else {
        state.networkNameEditorOpen.add(profile.network_id);
        input.focus();
      }
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      save.disabled = true;
      feedback.textContent = "Saving…";
      try {
        const response = await fetch("/api/network-name", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ip: profile.ip,
            network_id: profile.network_id,
            name: input.value,
          }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
        profile.network_name = payload.name;
        profile.network_label = payload.name || profile.default_network_label;
        title.textContent = profile.network_label;
        renderHostNetworkClues(state.host?.permanent_profiles || []);
        feedback.textContent = "";
        state.networkNameDrafts.delete(profile.network_id);
        state.networkNameEditorOpen.delete(profile.network_id);
        form.hidden = true;
        edit.textContent = payload.name ? "Edit name" : "Name network";
        document.activeElement?.blur();
        toast(payload.name ? "Network name saved." : "Network name removed.");
      } catch (error) {
        feedback.textContent = error.message;
        save.disabled = false;
      }
    });
    group.append(edit, form);
    const byKind = new Map();
    (profile.facts || []).forEach((fact) => {
      if (fact.kind === "country" && ["private", "unknown"].includes(String(fact.value).trim().toLowerCase())) return;
      if (!byKind.has(fact.kind)) byKind.set(fact.kind, []);
      byKind.get(fact.kind).push(fact);
    });
    Object.entries(labels).forEach(([kind, label]) => {
      const values = byKind.get(kind) || [];
      if (!values.length) return;
      const details = document.createElement("details");
      details.className = "host-profile-facts";
      details.dataset.key = JSON.stringify([profile.network_id, kind]);
      details.open = openSections.has(details.dataset.key)
        ? openSections.get(details.dataset.key)
        : ["hostname", "mdns_name", "dns_name"].includes(kind);
      const summary = document.createElement("summary");
      summary.append(text("span", label), text("span", compact(values.length), "count-chip"));
      details.append(summary);
      const list = document.createElement("ul");
      values.forEach((fact) => {
        const item = document.createElement("li");
        item.append(text("span", fact.value, "host-profile-value"));
        item.append(text("small", `Seen ${compact(fact.observations)}× · ${formatTime(fact.first_seen)} to ${formatTime(fact.last_seen)}`, "muted"));
        list.append(item);
      });
      details.append(list);
      group.append(details);
    });
    container.append(group);
  });
}

/** Summarize saved mDNS names and networks beside the selected host's traffic. */
function renderHostNetworkClues(profiles) {
  const mdns = byId("host-mdns-names");
  const networks = byId("host-networks-seen");
  mdns.replaceChildren();
  networks.replaceChildren();
  const names = new Map();
  profiles.forEach((profile) => (profile.facts || []).forEach((fact) => {
    if (fact.kind !== "mdns_name" || !fact.value) return;
    const previous = names.get(fact.value) || { observations: 0, last_seen: 0 };
    names.set(fact.value, {
      observations: previous.observations + numeric(fact.observations),
      last_seen: Math.max(previous.last_seen, numeric(fact.last_seen)),
    });
  }));
  const sortedNames = [...names].sort((left, right) => right[1].last_seen - left[1].last_seen);
  sortedNames.slice(0, 4).forEach(([name, details]) => {
    const row = document.createElement("div");
    row.className = "host-clue-row";
    row.append(text("code", name), text("small", `${compact(details.observations)}× · ${formatShortTime(details.last_seen)}`));
    mdns.append(row);
  });
  if (!sortedNames.length) mdns.append(text("p", "No mDNS names recorded.", "muted"));
  if (sortedNames.length > 4) mdns.append(text("small", `+ ${sortedNames.length - 4} more saved names`, "muted"));
  profiles.slice(0, 4).forEach((profile) => {
    const row = document.createElement("div");
    row.className = "host-clue-row";
    row.append(text("strong", profile.network_label || profile.network_id || "Unidentified network"),
      text("small", `${new Date(numeric(profile.first_seen) * 1000).toLocaleDateString()} – ${new Date(numeric(profile.last_seen) * 1000).toLocaleDateString()}`));
    networks.append(row);
  });
  if (!profiles.length) networks.append(text("p", "No permanent network history recorded.", "muted"));
  if (profiles.length > 4) networks.append(text("small", `+ ${profiles.length - 4} more networks`, "muted"));
}

function renderHostCards(host) {
  const exactAggregates = host.exact_aggregates !== false;
  setSummaryCards([
    ["Alerts", exactAggregates ? compact(host.alert_count) : "—"],
    ["Evidence", exactAggregates ? compact(host.evidence_count) : "—"],
    ["Flows in / out", exactAggregates ? compact(host.load?.flows) : "—"],
    ["Traffic in / out", exactAggregates ? formatBytes(host.load?.bytes) : "—"],
    ["Packets", exactAggregates ? compact(host.load?.packets) : "—"],
    ["Seen on", `${compact(host.permanent_profiles?.length || 0)} networks`],
  ], "host-summary");
  const summaryCards = byId("host-summary").children;
  summaryCards[2].append(text("small", `${compact(host.load?.inbound_flows)} in / ${compact(host.load?.outbound_flows)} out`));
  summaryCards[3].append(text("small", `${formatBytes(host.load?.inbound_bytes)} in / ${formatBytes(host.load?.outbound_bytes)} out`));
  byId("host-flows-tab-count").textContent = compact(host.load?.flows);
  byId("host-alerts-tab-count").textContent = compact(host.alert_count);
  byId("host-evidence-tab-count").textContent = compact(host.evidence_count);
  const scorePill = byId("host-score-pill");
  scorePill.replaceChildren(text("span", "Score "), slipsScore(host));
  const identity = byId("host-identity");
  const editingCurrentHost = identity.dataset.profileIp === host.ip
    && identity.contains(document.activeElement)
    && document.activeElement.closest(".host-annotation-form");
  if (!editingCurrentHost) {
    const annotationEntry = document.createElement("div");
    annotationEntry.id = "host-annotation-entry";
    const displayedName = text("span", "—");
    displayedName.id = "host-displayed-name";
    identity.replaceChildren(
      detailRow("Name", host.user_name || displayedName),
      detailRow("Note", host.user_note || "—"),
      ...(host.permanent_profiles?.length
        ? [detailRow("Edit identification", annotationEntry)] : []),
      detailRow("Hostname", host.hostname || "Unknown"),
      detailRow("MAC", host.mac || "Unknown"),
      detailRow("Vendor", host.mac_vendor || "Unknown"),
      detailRow("DNS", host.dns?.domains?.[0] || "No A/AAAA record"),
    );
    identity.dataset.profileIp = host.ip;
    refreshHostLabels();
  }
  renderPermanentProfiles(host.permanent_profiles || [], byId("host-annotation-entry"));
  renderHostNetworkClues(host.permanent_profiles || []);
  byId("host-dns-details").replaceChildren(renderDnsDetails(host.dns));
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

/** Switch the host activity table without reloading its data. */
function showHostActivity(name) {
  ["flows", "alerts", "evidence"].forEach((item) => {
    byId(`host-${item}-panel`).hidden = item !== name;
    document.querySelector(`[data-host-activity="${item}"]`).classList.toggle("active", item === name);
  });
  byId("host-evidence-search").hidden = name !== "evidence";
  byId("host-flow-search").hidden = name !== "flows";
}

/** Filter the currently loaded flow rows without requesting a new server page. */
function filterVisibleHostFlows() {
  const query = byId("host-flow-search").value.trim().toLowerCase();
  document.querySelectorAll("#host-flows-table tbody tr").forEach((row) => {
    row.hidden = Boolean(query) && !row.textContent.toLowerCase().includes(query);
  });
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
  if (state.hideExcluded) params.set("hide_excluded", "1");
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
    (row) => reportingPeers(row),
    (row) => text("code", row.module || "—"),
    (row) => whitelistHandling(row),
    (row) => Math.round(numeric(row.confidence) * 100) + "%",
    (row) => compact(row.flow_count),
    (row) => row.alert_ids?.length ? compact(row.alert_ids.length) : "none",
    (row) => {
      const description = hostDescription(row, "host-evidence-description");
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
  if (state.hideExcluded) params.set("hide_excluded", "1");
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
    (row) => hostIdentity(row.peer),
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
      detailRow("Peer", hostIdentity(row.peer)),
      detailRow("Source", hostLink(row.src_ip)),
      detailRow("Destination", hostLink(row.dst_ip)),
      detailRow("Ports", `${row.src_port ?? "—"} → ${row.dst_port ?? "—"}`),
      rawBlock(row.raw, "flow"),
    );
  });
  filterVisibleHostFlows();
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
    if (state.hideExcluded) query.set("hide_excluded", "1");
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
        ? "score decreased (possible reset)"
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

/** Explain why an address seen in evidence has no Slips host profile.
 * @param {string} ip - Address selected from evidence or traffic.
 */
async function showUnprofiledHost(ip) {
  let direction = "";
  try {
    let config = state.configuration;
    if (!config) {
      const response = await fetch("/api/configuration", { cache: "no-store" });
      if (response.ok) {
        config = await response.json();
        applyRunIdentity(config.run_identity);
        state.configuration = config;
      }
    }
    direction = config?.sections?.find((section) => section.key === "parameters")
      ?.settings?.find((setting) => setting.key === "analysis_direction")?.value || "";
  } catch (error) {
    // The profile explanation still works if the captured config is unavailable.
  }
  const explanation = direction === "out"
    ? "This run analyzes outgoing traffic only (analysis_direction: out). Slips profiles the source IP; a destination can appear in evidence or a flow without getting its own Host profile."
    : "This IP appears in evidence or traffic, but Slips did not create a Host profile for it in this run. Host workspaces show only profiled IPs.";
  state.host = null;
  byId("hosts-list-view").hidden = true;
  byId("host-detail-view").hidden = false;
  byId("host-detail-view").classList.add("unprofiled");
  byId("host-title").replaceChildren(hostIdentity(ip));
  byId("host-subtitle").textContent = "No Slips profile in this run";
  byId("host-unprofiled-reason").textContent = explanation;
  byId("host-unprofiled").hidden = false;
  clearError();
}

async function openHost(ip, summary = null) {
  const detail = await api("host", `/api/hosts/${escapePath(ip)}`, true, true);
  if (!detail) return;
  if (detail.not_found) {
    await showUnprofiledHost(ip);
    return;
  }
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
  rememberHostRecord(host);
  refreshHostLabels();
  resetPage("hostFlows");
  resetPage("host-evidence");
  byId("hosts-list-view").hidden = true;
  byId("host-detail-view").hidden = false;
  byId("host-detail-view").classList.remove("unprofiled");
  byId("host-unprofiled").hidden = true;
  byId("host-title").replaceChildren(hostIdentity(host.ip));
  byId("host-subtitle").textContent =
    `${host.scope || "unknown scope"} · ${host.permanent_profiles?.[0]?.network_label || "network not recorded"} · ${host.mac || "MAC unknown"} · ${host.mac_vendor || "vendor unknown"} · ${host.live ? "current" : "last-known metadata"}`;
  showHostActivity("flows");
  renderHostCards(host);
  await Promise.all([
    loadHostFlows(), loadHostSummary(), loadHostScoreHistory(), loadHostEvidence(),
  ]);
}

async function refreshHostWorkspace() {
  if (!state.host) return;
  const ip = state.host.ip;
  const detail = await api("host", `/api/hosts/${escapePath(ip)}`);
  if (!detail || !state.host || state.host.ip !== ip) return;
  const staleAliases = Array.isArray(detail.all_ips)
    ? detail.all_ips.filter((address) => address !== ip)
    : [];
  const host = {
    ...state.host,
    ...detail,
    permanent_profiles: detail.permanent_profiles?.length
      ? detail.permanent_profiles
      : state.host.permanent_profiles || [],
    all_ips: [ip],
    exact_aggregates: staleAliases.length === 0,
    ignored_aliases: staleAliases,
  };
  state.host = host;
  rememberHostRecord(host);
  refreshHostLabels();
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
  byId("host-detail-view").classList.remove("unprofiled");
  byId("host-unprofiled").hidden = true;
  byId("hosts-list-view").hidden = false;
  updateHostViewportHeight();
}

/** Match the Hosts workspace to the visible space below the shared navigation. */
function updateHostViewportHeight() {
  const bottom = byId("hosts").getBoundingClientRect().top;
  byId("hosts").style.setProperty("--hosts-panel-height", `${Math.max(380, window.innerHeight - bottom)}px`);
}

/** Keep Metadata's cards and module table within the visible browser height. */
function updateMetadataViewportHeight() {
  const bottom = byId("metadata").getBoundingClientRect().top;
  byId("metadata").style.setProperty("--metadata-panel-height", `${Math.max(380, window.innerHeight - bottom)}px`);
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
  if (["configuration", "whitelists"].includes(state.activeTab)) return false;
  if (state.activeTab === "metadata") return true;
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

/** Poll backend liveness independently from the active tab's data range. */
async function pollBackendStatus() {
  if (document.hidden) return;
  try {
    await api("backendStatus", "/api/identity", false);
    await loadLiveTitleCounts();
  } catch (_) {
    // renderConnectionState() already exposes the failure persistently.
  } finally {
    scheduleBackendStatusPoll();
  }
}

/** Schedule the next lightweight backend heartbeat check. */
function scheduleBackendStatusPoll() {
  window.clearTimeout(state.statusTimer);
  if (document.hidden) return;
  state.statusTimer = window.setTimeout(pollBackendStatus, 5000);
}

function switchTab(name) {
  state.activeTab = name;
  document.body.classList.toggle("overview-active", name === "overview");
  document.body.classList.toggle("alerts-active", name === "alerts");
  document.body.classList.toggle("evidence-active", name === "evidence");
  document.body.classList.toggle("hosts-active", name === "hosts");
  document.body.classList.toggle("metadata-active", name === "metadata");
  document.querySelectorAll(".tab").forEach((tab) =>
    tab.classList.toggle("active", tab.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((panel) =>
    panel.classList.toggle("active", panel.id === name));
  if (name === "alerts") updateAlertViewportHeight();
  if (name === "evidence") updateEvidenceViewportHeight();
  if (name === "hosts") updateHostViewportHeight();
  if (name === "metadata") updateMetadataViewportHeight();
  currentLoader()().catch(() => {}).finally(schedulePoll);
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
        loader().catch(() => {}).finally(schedulePoll);
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
    loader().catch(() => {}).finally(schedulePoll);
  });
}

function bindRange(prefix, pageName, loader) {
  const select = byId(`${prefix}-range`);
  const update = () => {
    const custom = select.value === "custom";
    byId(`${prefix}-from`).hidden = !custom;
    byId(`${prefix}-to`).hidden = !custom;
    resetPage(pageName);
    loader().catch(() => {}).finally(schedulePoll);
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
byId("overview-alerts-link").addEventListener("click", () => switchTab("alerts"));
byId("toggle-overview-details").addEventListener("click", () => {
  const details = byId("overview-details");
  details.hidden = !details.hidden;
  byId("toggle-overview-details").setAttribute("aria-expanded", String(!details.hidden));
  byId("toggle-overview-details").textContent = details.hidden ? "More run details" : "Hide run details";
  if (!details.hidden) loadMetrics().catch(() => {});
});
byId("load-module-evidence").addEventListener("click", () =>
  loadOverviewEvidenceCounts().catch(() => {}));
byId("metrics-range").addEventListener("change", () => loadMetrics().catch(() => {}));
byId("p2p-range").addEventListener("change", () => loadP2P().catch(() => {}));
byId("p2p-message-filter").addEventListener("change", renderP2PMessages);
bindLocalTableSort("p2p-activity-table", renderP2PMessages);
byId("module-search").addEventListener("input", () =>
  state.overview && renderModules(state.overview.modules));
byId("drawer-close").addEventListener("click", closeDrawer);
byId("drawer-back").addEventListener("click", backDrawer);
byId("drawer-backdrop").addEventListener("click", closeDrawer);
byId("host-back").addEventListener("click", closeHost);
document.querySelectorAll("[data-host-activity]").forEach((button) =>
  button.addEventListener("click", () => showHostActivity(button.dataset.hostActivity)));
byId("host-flow-search").addEventListener("input", filterVisibleHostFlows);
byId("host-whitelist-action").addEventListener("click", () => {
  const ip = state.host?.ip;
  switchTab("whitelists");
  const input = byId("whitelists-editor").querySelector(".whitelist-form input");
  if (input && ip) {
    input.value = ip;
    input.focus();
    input.scrollIntoView({ block: "center" });
  }
});
byId("hosts-alerts-only").addEventListener("change", () => {
  state.pages.hosts.visible = 14;
  resetPage("hosts");
  loadHosts().catch(() => {});
});
document.querySelectorAll(".hosts-columns input").forEach((input) =>
  input.addEventListener("change", () => {
    document.querySelectorAll(`#hosts-table [data-host-column="${input.dataset.hostColumn}"]`)
      .forEach((element) => { element.hidden = !input.checked; });
    renderHostsPage();
  }));
byId("hosts-more").addEventListener("click", () => loadMoreHosts().catch(() => {}));
byId("hosts-export").addEventListener("click", () => {
  const rows = state.pages.hosts.items;
  const fields = ["ip", "user_name", "hostname", "mac", "mac_vendor", "scope", "max_threat_level", "peak_alert_score", "alert_score", "flows", "bytes", "evidence_count", "alert_count", "last_seen"];
  const escapeCsv = (value) => {
    const plain = String(value ?? "");
    const safe = /^[=+\-@\t\r]/.test(plain) ? `'${plain}` : plain;
    return `"${safe.replaceAll('"', '""')}"`;
  };
  const csv = [fields.join(","), ...rows.map((row) => fields.map((key) =>
    escapeCsv(["flows", "bytes", "last_seen"].includes(key)
      ? row.load?.[key] : row[key])).join(","))].join("\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  link.download = "slips-hosts-page.csv";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});
byId("host-flow-limit").addEventListener("change", () => {
  resetPage("hostFlows");
  loadHostFlows().catch(() => {});
});
document.querySelectorAll(".excluded-visibility-select").forEach((select) => {
  select.value = state.hideExcluded ? "hide" : "show";
  select.addEventListener("change", () => {
    state.hideExcluded = select.value === "hide";
    document.querySelectorAll(".excluded-visibility-select").forEach((other) => {
      other.value = select.value;
    });
    ["alerts", "evidence", "host-evidence", "hostFlows"].forEach(resetPage);
    if (state.activeTab === "hosts" && state.host) {
      Promise.all([loadHostEvidence(), loadHostFlows()]).catch(() => {});
    } else if (state.activeTab === "alerts" || state.activeTab === "evidence") {
      currentLoader()().catch(() => {});
    } else if (state.activeTab === "arp-poisoning") {
      loadArpPoisoning().catch(() => {});
    }
    schedulePoll();
  });
});

bindFilters("firewall", ["firewall-search"], loadFirewall);
bindFilters("host-evidence", ["host-evidence-search"], loadHostEvidence);
byId("arp-poisoning-search").addEventListener("input", renderArpPoisoning);
["arp-poisoning-hosts-table", "arp-poisoning-events-table",
  "arp-poisoning-evidence-table"].forEach((id) =>
  bindLocalTableSort(id, renderArpPoisoning));
bindFilters("alerts", ["alerts-search"], loadAlerts);
bindFilters("evidence", ["evidence-search", "evidence-threat", "evidence-link"], loadEvidence);
byId("evidence-scored-only").addEventListener("change", () => {
  clearEvidenceSelection();
  resetPage("evidence");
  loadEvidence().catch(() => {});
});
byId("evidence-active-type").addEventListener("click", () => {
  state.evidenceWorkspace.typeFilter = "";
  clearEvidenceSelection();
  resetPage("evidence");
  loadEvidence().catch(() => {});
});
byId("evidence-search").addEventListener("input", clearEvidenceSelection);
byId("evidence-link").addEventListener("change", clearEvidenceSelection);
bindFilters("hosts", ["hosts-search", "hosts-scope", "hosts-threat"], loadHosts);
byId("configuration-search").addEventListener("input", renderConfiguration);
byId("whitelists-search").addEventListener("input", renderWhitelists);
byId("whitelists-type").addEventListener("change", renderWhitelists);
byId("whitelists-editor").append(whitelistEditor("tab"));
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
    window.clearTimeout(state.statusTimer);
    state.requests.forEach((controller) => controller.abort());
  } else {
    refreshActive();
    pollBackendStatus();
  }
});
window.addEventListener("beforeunload", () => {
  window.clearTimeout(state.statusTimer);
  state.requests.forEach((controller) => controller.abort());
});

initDrawerResize();
initAlertPaneResize();
window.addEventListener("resize", updateEvidenceViewportHeight);
window.addEventListener("resize", updateHostViewportHeight);
window.addEventListener("resize", updateMetadataViewportHeight);
window.setInterval(renderHeaderUptime, 1000);
loadOverview().catch(() => {}).finally(() => {
  if (state.activeTab === "overview") schedulePoll();
});
loadWhitelists().catch(() => {});
loadLiveTitleCounts().catch(() => {});
scheduleBackendStatusPoll();
