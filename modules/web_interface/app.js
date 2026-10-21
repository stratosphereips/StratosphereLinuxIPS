"use strict";

const state = {
  activeTab: "overview",
  hideExcluded: true,
  overview: null,
  overviewEvidence: null,
  overviewEvidenceLoading: false,
  overviewAlertGroups: null,
  overviewAlertQuery: "",
  filteredBadgeCounts: { alerts: null, evidence: null, hosts: null },
  metadata: null,
  metrics: [],
  configuration: null,
  archiveSource: "",
  archivesCheckedAt: 0,
  configurationSection: "detection",
  configurationFilter: "all",
  whitelists: null,
  arpPoisoning: null,
  p2p: null,
  p2pSelectedPeer: null,
  p2pSelectedMessage: null,
  p2pVisibleMessages: 12,
  logs: null,
  firewall: null,
  configurationSort: { key: null, order: "asc" },
  host: null,
  hostActivity: "alerts",
  hostActivityPreferred: false,
  hostActivityGroups: { alerts: "", evidence: "", flows: "" },
  hostActivityThreats: { alerts: "", evidence: "", flows: "" },
  alertsWorkspace: {
    severity: "", grouping: "host", host: null, alert: null, items: [], next: null,
    total: 0, listGeneration: 0, detailGeneration: 0,
    listLoadedAt: 0, listSignature: "", fullTotal: 0,
    rangeTouched: false, autoRange: "",
    itemSort: "time", itemOrder: "desc",
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
  titleTimer: null,
  requests: new Map(),
  drawerHistory: [],
  drawerGeneration: 0,
  evidenceDetail: { record: null, records: [], generation: 0, history: [], inAlertPane: false },
  runIdentity: null,
  reviewAvailable: false,
  networkOnly: false,
  deviceView: false,
  deviceViewSupported: false,
  networkFilterSupported: false,
  currentNetworkStart: null,
  headerNetwork: null,
  rangesInitialized: false,
  localSorts: {
    "arp-poisoning-hosts-table": { key: "ip", order: "asc" },
    "arp-poisoning-events-table": { key: "timestamp", order: "desc" },
    "arp-poisoning-evidence-table": { key: "timestamp", order: "desc" },
    "p2p-activity-table": { key: "timestamp", order: "desc" },
    "p2p-peers-table": { key: "connected", order: "desc" },
    "logs-table": { key: "event_time", order: "desc" },
    "firewall-table": { key: null, order: "asc" },
    "firewall-history-table": { key: "timestamp", order: "desc" },
    "whitelists-table": { key: null, order: "asc" },
    "host-flows-table": { key: "event_time", order: "desc" },
  },
  pages: {
    alerts: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
    evidence: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
    hosts: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "peak_score", order: "desc", revision: 0, loadingMore: false },
    modules: { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "cpu_percent", order: "desc" },
    firewall: { items: [], total: 0, next: null, cursors: [null], index: 0 },
    hostAlerts: { items: [], total: 0, next: null, cursors: [null], index: 0 },
    hostFlows: { items: [], total: 0, next: null, cursors: [null], index: 0 },
    "host-evidence": { items: [], total: 0, next: null, cursors: [null], index: 0, sort: "time", order: "desc" },
  },
};

const byId = (id) => document.getElementById(id);
const VIEW_PREFERENCES_KEY = "slips-view-preferences-v1";
const VIEW_CONTROL_IDS = [
  "metrics-range", "module-search", "alerts-group", "alerts-search", "alerts-review",
  "alerts-range", "alerts-from", "alerts-to", "alerts-host-sort", "alerts-item-sort",
  "evidence-search", "evidence-review", "evidence-threat", "evidence-view",
  "evidence-scored-only", "evidence-link", "evidence-range", "evidence-from",
  "evidence-to", "hosts-search", "hosts-threat", "hosts-scope", "hosts-review",
  "hosts-alerts-only", "hosts-range", "hosts-from", "hosts-to",
  "host-range", "host-from", "host-to", "host-alert-search",
  "host-evidence-search", "host-flow-search", "host-flow-limit",
  "p2p-range", "p2p-message-filter", "configuration-search",
  "whitelists-search", "whitelists-type", "firewall-search", "arp-poisoning-search",
  "device-view",
];

/** Save browser-only filters, sorts, visible columns, and pane widths. */
function saveViewPreferences() {
  const controls = {};
  VIEW_CONTROL_IDS.forEach((id) => {
    const element = byId(id);
    if (element) controls[id] = element.type === "checkbox" ? element.checked : element.value;
  });
  const columns = {};
  document.querySelectorAll(".hosts-columns input[data-host-column]").forEach((input) => {
    columns[input.dataset.hostColumn] = input.checked;
  });
  const paneWidths = {};
  [["alerts-workspace", ["--alerts-host-width", "--alerts-list-width", "--alerts-detail-width"]],
    ["evidence-workspace", ["--evidence-left-width", "--evidence-detail-group-width", "--evidence-detail-record-width"]]]
    .forEach(([id, names]) => {
      const element = byId(id);
      paneWidths[id] = Object.fromEntries(names.map((name) => [name, element.style.getPropertyValue(name)]));
    });
  const preferences = {
    controls, columns, paneWidths,
    hideExcluded: state.hideExcluded,
    alertSeverity: state.alertsWorkspace.severity,
    alertItemSort: state.alertsWorkspace.itemSort,
    alertItemOrder: state.alertsWorkspace.itemOrder,
    evidenceType: state.evidenceWorkspace.typeFilter,
    hostActivity: state.hostActivity,
    hostActivityPreferred: state.hostActivityPreferred,
    hostActivityGroups: state.hostActivityGroups,
    hostActivityThreats: state.hostActivityThreats,
    p2pSelectedPeer: state.p2pSelectedPeer,
    configurationSection: state.configurationSection,
    configurationFilter: state.configurationFilter,
    configurationSort: state.configurationSort,
    pageSorts: Object.fromEntries(Object.entries(state.pages)
      .filter(([, page]) => page.sort).map(([name, page]) => [name, { sort: page.sort, order: page.order }])),
    localSorts: state.localSorts,
  };
  try {
    window.localStorage.setItem(VIEW_PREFERENCES_KEY, JSON.stringify(preferences));
  } catch (_) {
    // Filtering still works when browser storage is unavailable.
  }
}

/** Restore browser-only view choices before the first API requests. */
function restoreViewPreferences() {
  let saved;
  try {
    saved = JSON.parse(window.localStorage.getItem(VIEW_PREFERENCES_KEY) || "null");
  } catch (_) {
    return;
  }
  if (!saved || typeof saved !== "object") return;
  Object.entries(saved.controls || {}).forEach(([id, value]) => {
    if (!VIEW_CONTROL_IDS.includes(id)) return;
    const element = byId(id);
    if (!element) return;
    if (element.type === "checkbox") element.checked = value === true;
    else if (element.tagName !== "SELECT" || [...element.options].some((option) => option.value === value)) {
      element.value = String(value);
    }
  });
  document.querySelectorAll(".hosts-columns input[data-host-column]").forEach((input) => {
    if (typeof saved.columns?.[input.dataset.hostColumn] === "boolean") {
      input.checked = saved.columns[input.dataset.hostColumn];
    }
  });
  Object.entries(saved.paneWidths || {}).forEach(([id, widths]) => {
    if (!["alerts-workspace", "evidence-workspace"].includes(id) || !byId(id)) return;
    Object.entries(widths || {}).forEach(([name, width]) => {
      if (/^--(?:alerts|evidence)-[a-z-]+-width$/.test(name) && /^\d+(?:\.\d+)?(?:px|%)$/.test(width)) {
        if (id === "evidence-workspace" && name === "--evidence-left-width"
            && width.endsWith("%") && Number.parseFloat(width) < 20) return;
        byId(id).style.setProperty(name, width);
      }
    });
  });
  state.hideExcluded = saved.hideExcluded !== false;
  state.deviceView = byId("device-view").checked;
  state.alertsWorkspace.severity = String(saved.alertSeverity || "");
  state.alertsWorkspace.grouping = byId("alerts-group").value;
  state.alertsWorkspace.itemSort = String(saved.alertItemSort || "time");
  state.alertsWorkspace.itemOrder = saved.alertItemOrder === "asc" ? "asc" : "desc";
  state.evidenceWorkspace.typeFilter = String(saved.evidenceType || "");
  state.hostActivityGroups = { ...state.hostActivityGroups, ...saved.hostActivityGroups };
  state.hostActivityThreats = { ...state.hostActivityThreats, ...saved.hostActivityThreats };
  if (["alerts", "evidence", "flows"].includes(saved.hostActivity)) state.hostActivity = saved.hostActivity;
  state.hostActivityPreferred = saved.hostActivityPreferred === true;
  state.configurationSection = String(saved.configurationSection || "detection");
  state.configurationFilter = String(saved.configurationFilter || "all");
  if (typeof saved.p2pSelectedPeer === "string") state.p2pSelectedPeer = saved.p2pSelectedPeer;
  if (saved.configurationSort && typeof saved.configurationSort.key === "string") {
    state.configurationSort = {
      key: saved.configurationSort.key,
      order: saved.configurationSort.order === "desc" ? "desc" : "asc",
    };
  }
  Object.entries(saved.pageSorts || {}).forEach(([name, sort]) => {
    if (state.pages[name] && sort && typeof sort.sort === "string") {
      state.pages[name].sort = sort.sort;
      state.pages[name].order = sort.order === "asc" ? "asc" : "desc";
    }
  });
  Object.entries(saved.localSorts || {}).forEach(([name, sort]) => {
    if (state.localSorts[name] && sort && typeof sort.key === "string") {
      state.localSorts[name] = { key: sort.key, order: sort.order === "asc" ? "asc" : "desc" };
    }
  });
  if (saved.controls?.["alerts-range"] || saved.controls?.["evidence-range"] || saved.controls?.["hosts-range"]) {
    state.rangesInitialized = true;
    state.alertsWorkspace.rangeTouched = true;
  }
  byId("alerts-host-order").textContent = state.pages.alerts.order === "asc" ? "↑" : "↓";
  byId("alerts-item-order").textContent = state.alertsWorkspace.itemOrder === "asc" ? "↑" : "↓";
  document.querySelectorAll("[data-alert-group]").forEach((button) => {
    const active = button.dataset.alertGroup === state.alertsWorkspace.grouping;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  document.querySelectorAll("[data-config-filter]").forEach((button) => {
    const active = button.dataset.configFilter === state.configurationFilter;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  ["alerts", "evidence", "hosts", "host"].forEach((name) => {
    const custom = byId(`${name}-range`)?.value === "custom";
    if (byId(`${name}-from`)) byId(`${name}-from`).hidden = !custom;
    if (byId(`${name}-to`)) byId(`${name}-to`).hidden = !custom;
  });
}

restoreViewPreferences();
/**
 * Apply the selected interface theme and optionally remember it in this browser.
 * @param {string} theme The requested theme, light or dark.
 * @param {boolean} persist Whether to save the choice for later visits.
 */
function setTheme(theme, persist = false) {
  const selected = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = selected;
  const toggle = byId("theme-toggle");
  toggle.querySelector(".theme-icon").textContent = selected === "light" ? "☾" : "☀";
  toggle.querySelector(".theme-label").textContent = selected === "light" ? "Dark" : "Light";
  toggle.setAttribute("aria-label", `Switch to ${selected === "light" ? "dark" : "light"} theme`);
  if (persist) {
    try {
      window.localStorage.setItem("slips-theme", selected);
    } catch (_) {
      // The switch still works if browser storage is unavailable.
    }
  }
}
let storedTheme = "dark";
try {
  storedTheme = window.localStorage.getItem("slips-theme");
} catch (_) {
  // Private browsing may disable storage; the default remains dark.
}
setTheme(storedTheme);
try {
  state.networkOnly = window.localStorage.getItem("slips-network-only") === "1";
} catch (_) {
  state.networkOnly = false;
}
byId("network-filter").checked = state.networkOnly;
byId("theme-toggle").addEventListener("click", () => {
  setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light", true);
});
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
  return { "User name": 4, Hostname: 3, mDNS: 2, DNS: 2, rDNS: 2, "MAC vendor": 1 }[source] || 0;
}

/** Remember the best currently available identity from a Host record. */
function rememberHostRecord(record) {
  if (!record?.ip) return;
  if (Object.hasOwn(record, "user_name") && !record.user_name
      && state.hostNames.get(record.ip)?.source === "User name") state.hostNames.delete(record.ip);
  if (record.user_name) rememberHostName(record.ip, record.user_name, "User name");
  else if (record.hostname) rememberHostName(record.ip, record.hostname, record.hostname_source || "Hostname");
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
      const networkOnly = state.networkOnly && state.networkFilterSupported;
      const networkStart = state.currentNetworkStart;
      if (networkOnly) params.set("network", "current");
      ips.forEach((ip) => params.append("ip", ip));
      const response = await fetch(`/api/host-names?${params}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      if (networkOnly !== (state.networkOnly && state.networkFilterSupported)
          || networkStart !== state.currentNetworkStart) continue;
      applyRunIdentity(payload.run_identity);
      ips.forEach((ip) => {
        if (!Object.hasOwn(payload.names || {}, ip)) return;
        const fetched = payload.names[ip];
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

/** Show the representative host and the addresses merged into a device. */
function deviceIdentity(row, field = "ip") {
  const element = document.createElement("span");
  element.className = "device-identity";
  element.append(hostIdentity(row[field]));
  if (state.deviceView && Array.isArray(row.device_ips) && row.device_ips.length > 1) {
    element.append(text("small", `${row.device_ips.length} addresses · ${row.device_ips.join(" · ")}`, "device-addresses"));
  }
  return element;
}

/** Add host names and compact MAC markers to detection descriptions. */
function hostDescription(record, className = "") {
  const description = String(record.description || "—");
  const addresses = new Set(description.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []);
  const macs = new Set(description.match(/(?<![\w:])(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}(?![\w:])/gi) || []);
  [record.attacker, record.victim].forEach((entity) => {
    if (String(entity?.ioc_type || "").toUpperCase() === "IP"
        && description.includes(entity.value)) addresses.add(entity.value);
  });
  const element = document.createElement("span");
  if (className) element.className = className;
  if (!addresses.size && !macs.size) {
    element.textContent = description;
    return element;
  }
  const escaped = Array.from(new Set([...addresses, ...macs])).sort((left, right) => right.length - left.length)
    .map((ip) => ip.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const matcher = new RegExp(`(${escaped.join("|")})`, "g");
  description.split(matcher).forEach((part) => {
    if (macs.has(part)) element.append(macIdentity(part));
    else if (addresses.has(part)) element.append(hostIdentity(part));
    else element.append(part);
  });
  return element;
}

/** Show an indicator as a named host when it is an IP address. */
function hostOrText(value) {
  const candidate = String(value || "");
  if (normalizeMac(candidate)) return macIdentity(candidate);
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(candidate);
  const ipv6 = /^[0-9a-fA-F:.]+$/.test(candidate)
    && (candidate.includes("::") || candidate.split(":").length === 8);
  return ipv4 || ipv6 ? hostIdentity(candidate) : text("code", value || "—");
}
const threat = (value) => {
  const level = String(value || "info").toLowerCase();
  return text("span", level, `status threat-${level}`);
};

const MAC_ADDRESS_TYPES = {
  locally_administered: ["Locally administered", "U/L bit = 1. May be private/randomized, manually assigned, or virtual. Randomization cannot be determined from the MAC address alone."],
  universally_administered: ["Universally administered", "U/L bit = 0. Uses the IEEE universally administered address format; this does not prove that the address is unchanged or authentic."],
  multicast: ["Multicast", "I/G bit = 1. A group address, not an individual device identity."],
  broadcast: ["Broadcast", "All stations on the local link; not an individual device identity."],
  unspecified: ["Unspecified", "All-zero hardware address; no individual device MAC is specified."],
  invalid: ["Invalid MAC", "This value is not a valid 48-bit MAC address."],
  unknown: ["Unknown", "No MAC address is available."],
};

/** Normalize supported 48-bit MAC notation without changing stored identities.
 * @param {string|null} value Packet or operating-system MAC representation.
 * @returns {string} Colon-separated address, or empty for invalid input.
 */
function normalizeMac(value) {
  if (typeof value !== "string") return "";
  value = value.trim().toLowerCase();
  if (/^[0-9a-f]{12}$/.test(value)) return value.match(/../g).join(":");
  if (/^[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}$/.test(value)) return normalizeMac(value.replaceAll(".", ""));
  for (const separator of [":", "-"]) {
    const parts = value.split(separator);
    if (parts.length === 6 && parts.every((part) => /^[0-9a-f]{1,2}$/.test(part))) {
      return parts.map((part) => part.padStart(2, "0")).join(":");
    }
  }
  return "";
}

/** Read IEEE I/G and U/L bits; local administration does not prove randomness.
 * @param {string|null} value Candidate MAC address.
 * @returns {string} MAC address classification, matching the Slips API.
 */
function classifyMac(value) {
  if (value == null || value === "") return "unknown";
  const mac = normalizeMac(value);
  if (!mac) return "invalid";
  if (mac === "00:00:00:00:00:00") return "unspecified";
  if (mac === "ff:ff:ff:ff:ff:ff") return "broadcast";
  const octet = parseInt(mac.slice(0, 2), 16);
  if (octet & 0x01) return "multicast";
  return octet & 0x02 ? "locally_administered" : "universally_administered";
}

/** Display a MAC with a compact U/L marker and its full explanation on hover.
 * @param {string|null} value Candidate MAC address.
 * @returns {HTMLElement} Original address and administration/group badge.
 */
function macIdentity(value) {
  const kind = classifyMac(value);
  const [label, description] = MAC_ADDRESS_TYPES[kind];
  const marker = { locally_administered: "L", universally_administered: "U",
    multicast: "M", broadcast: "B", unspecified: "0", invalid: "?" }[kind];
  const explanation = `${label}. ${description}`;
  const node = text("span", "", "mac-identity");
  node.title = explanation;
  node.append(text("code", value || "—"));
  if (marker) {
    const badge = text("span", marker, `mac-badge mac-${kind}`);
    badge.title = explanation;
    badge.setAttribute("role", "img");
    badge.setAttribute("aria-label", explanation);
    node.append(badge);
  }
  return node;
}
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
    unavailable.title = "No persisted Slips score sample exists in the selected scope.";
    return unavailable;
  }
  return slipsScore({
    ...record,
    alert_score: record.peak_alert_score,
    alert_score_basis: "highest persisted score in the selected time and network scope",
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
  if (!peers.length) return "Unavailable";
  const label = text("code", peers.map(shortPeerId).join(", "));
  label.title = peers.join(", ");
  return label;
}
/** Keep peer IDs distinguishable while fitting them in tables and plots.
 * @param {string} value Full peer ID.
 * @returns {string} A short peer ID retaining both ends of the hash.
 */
function shortPeerId(value) {
  const id = String(value || "");
  if (/\s/.test(id)) return id;
  return id.length > 20 ? `${id.slice(0, 8)}…${id.slice(-6)}` : id || "—";
}

/** Shorten the peer hash inside a displayed P2P multiaddress.
 * @param {string} value Multiaddress or other identity text.
 * @returns {string} Text with the full hash kept available through title/copy.
 */
function shortP2PAddress(value) {
  return String(value || "").replace(/(\/p2p\/)([^\s/]+)/g,
    (_match, prefix, peerId) => `${prefix}${shortPeerId(peerId)}`);
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
    closeEvidenceDetail(false, true);
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
    state.overviewAlertGroups = null;
    state.overviewAlertQuery = "";
    state.filteredBadgeCounts.alerts = null;
    state.filteredBadgeCounts.evidence = null;
    state.filteredBadgeCounts.hosts = null;
    state.metadata = null;
    state.metrics = [];
    state.configuration = null;
    state.alertsWorkspace.rangeTouched = false;
    state.alertsWorkspace.autoRange = "";
    byId("alerts-range").value = "live";
    byId("alerts-range-note").hidden = true;
    state.rangesInitialized = false;
    state.hostNames.clear();
    state.pendingHostNames.clear();
    state.networkNameDrafts.clear();
    state.networkNameEditorOpen.clear();
    state.ownAddresses.clear();
    state.computerName = "";
    state.headerNetwork = null;
    toast("A new Slips run is now active. Investigation state was cleared.");
  }
  state.runIdentity = token;
}

async function api(key, path, trackFailures = true, allowNotFound = false) {
  state.requests.get(key)?.abort();
  const controller = new AbortController();
  state.requests.set(key, controller);
  try {
    if (state.archiveSource && /^\/api\/(?:alerts|evidence|hosts|flows)(?:[/?]|$)/.test(path)) {
      const url = new URL(path, window.location.origin);
      url.searchParams.set("archive", state.archiveSource);
      url.searchParams.delete("network");
      path = `${url.pathname}${url.search}`;
    }
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
  if (!sort || !sort.key) return [...rows];
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
  if (name === "hosts") {
    state.pages.hosts.revision += 1;
    state.pages.hosts.loadingMore = false;
    state.requests.get("hostsMore")?.abort();
  }
}

function rangeQuery(prefix) {
  const range = byId(`${prefix}-range`).value;
  const params = new URLSearchParams({ range });
  if (state.networkOnly && state.networkFilterSupported) params.set("network", "current");
  if (state.deviceView && state.deviceViewSupported) params.set("device", "1");
  if (prefix === "alerts" && ["5m", "15m"].includes(range)) {
    const seconds = range === "5m" ? 300 : 900;
    const now = Date.now() / 1000;
    params.set("range", "custom");
    params.set("from", String(now - seconds));
    params.set("to", String(now));
  }
  if (range === "custom") {
    const from = byId(`${prefix}-from`).value;
    const to = byId(`${prefix}-to`).value;
    if (from) params.set("from", String(new Date(from).getTime() / 1000));
    if (to) params.set("to", String(new Date(to).getTime() / 1000));
  }
  return params;
}

/** Keep rolling alert windows stable when deciding whether details need reload. */
function alertRangeSignature() {
  const range = byId("alerts-range").value;
  const custom = range === "custom"
    ? `${byId("alerts-from").value}|${byId("alerts-to").value}` : "";
  return `${range}|${custom}|${state.hideExcluded}|${state.alertsWorkspace.severity}|${state.networkOnly && state.networkFilterSupported}|${state.deviceView && state.deviceViewSupported}`;
}

function rangeIsLive(prefix) {
  return ["5m", "15m", "live", "1h", "24h", "7d", "all"]
    .includes(byId(`${prefix}-range`).value);
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

/** Show the nearest sample time and values while the plot is hovered.
 * @param {SVGElement} svg - Rendered chart.
 * @param {SVGElement} target - Hit area covering the plot.
 * @param {Array<object>} points - Chronologically sorted chart samples.
 * @param {Array<object>} series - Plotted series and display labels.
 * @param {Function} formatValue - Value formatter for this chart.
 * @param {number} maximum - Highest value on the chart.
 * @param {number} left - Plot's left coordinate.
 * @param {number} plotWidth - Plot's SVG width.
 * @param {number} minimumTime - Earliest chart timestamp.
 * @param {number} span - Chart time span in seconds.
 */
function bindChartHover(svg, target, points, series, formatValue, maximum, left, plotWidth, minimumTime, span) {
  const tooltip = chartTooltip(svg);
  target.addEventListener("pointermove", (event) => {
    const bounds = svg.getBoundingClientRect();
    if (!bounds.width) return;
    const x = (event.clientX - bounds.left) * svg.viewBox.baseVal.width / bounds.width;
    const timestamp = minimumTime + Math.max(0, Math.min(1, (x - left) / plotWidth)) * span;
    const point = nearestChartPoint(points, timestamp);
    const values = series.filter((item) => point[item.key] !== null
      && point[item.key] !== undefined && Number.isFinite(Number(point[item.key])))
      .map((item) => `${item.label || item.key.replaceAll("_", " ")}: ${formatValue(point[item.key], maximum)}`);
    tooltip.textContent = `${formatTime(point.ts)}\n${values.join("\n")}`;
    tooltip.hidden = false;
    const containerBounds = svg.parentElement.getBoundingClientRect();
    tooltip.style.left = `${Math.max(4, Math.min(event.clientX - containerBounds.left + 12,
      containerBounds.width - tooltip.offsetWidth - 4))}px`;
    tooltip.style.top = `${Math.max(4, Math.min(event.clientY - containerBounds.top + 12,
      containerBounds.height - tooltip.offsetHeight - 4))}px`;
  });
  target.addEventListener("pointerleave", () => { tooltip.hidden = true; });
}

/** Render a performance chart with numeric and time axes and an optional lower bound. */
function renderLineChart(id, points, series, formatValue = formatChartValue, minimumValue = 0) {
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
  const overviewChart = Boolean(svg.closest(".overview-performance"));
  const left = overviewChart ? 145 : 42;
  const right = 10;
  const top = overviewChart ? 28 : 12;
  const bottom = overviewChart ? 20 : 30;
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
  const valueSpan = Math.max(maximum - minimumValue, 0.001);
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
    label.setAttribute("class", "chart-label chart-y-label");
    label.textContent = formatValue(minimumValue + valueSpan * ratio, maximum);
    svg.append(label);
  });
  [0, 0.5, 1].forEach((ratio) => {
    const x = left + ratio * plotWidth;
    const timestamp = minimumTime + ratio * span;
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", String(x));
    label.setAttribute("y", String(height - 8));
    label.setAttribute("text-anchor", ratio === 0 ? "start" : ratio === 1 ? "end" : "middle");
    label.setAttribute("class", "chart-label chart-time-label");
    label.textContent = formatChartTime(timestamp, span);
    svg.append(label);
  });
  for (const item of series) {
    const seriesPoints = points.filter((point) => hasValue(point, item.key));
    if (!seriesPoints.length) continue;
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    const d = seriesPoints.map((point, index) => {
      const x = left + ((numeric(point.ts) - minimumTime) / span) * plotWidth;
      const y = height - bottom - ((numeric(point[item.key]) - minimumValue) / valueSpan) * plotHeight;
      return `${index ? "L" : "M"}${x.toFixed(2)} ${y.toFixed(2)}`;
    }).join(" ");
    path.setAttribute("d", d);
    path.setAttribute("class", `chart-line ${item.className || ""}`);
    svg.append(path);
    if (seriesPoints.length === 1) {
      const point = seriesPoints[0];
      const marker = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      marker.setAttribute("cx", String(left + ((numeric(point.ts) - minimumTime) / span) * plotWidth));
      marker.setAttribute("cy", String(height - bottom - ((numeric(point[item.key]) - minimumValue) / valueSpan) * plotHeight));
      marker.setAttribute("r", "3");
      marker.setAttribute("class", `chart-point ${item.className || ""}`);
      svg.append(marker);
    }
  }
  const hitArea = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  hitArea.setAttribute("x", String(left));
  hitArea.setAttribute("y", String(top));
  hitArea.setAttribute("width", String(plotWidth));
  hitArea.setAttribute("height", String(plotHeight));
  hitArea.setAttribute("class", "chart-hit-area");
  svg.append(hitArea);
  bindChartHover(svg, hitArea, points, series, formatValue, maximum,
    left, plotWidth, minimumTime, span);
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
  document.title = `Slips ${compact(counts.alerts)} alerts · ${compact(counts.hosts)} ${state.deviceView && state.deviceViewSupported ? "devices" : "hosts"}`;
}

/** Refresh live title totals independently of the selected tab and filters. */
async function loadLiveTitleCounts() {
  const params = new URLSearchParams();
  if (state.networkOnly && state.networkFilterSupported) params.set("network", "current");
  if (state.deviceView && state.deviceViewSupported) params.set("device", "1");
  const payload = await api("liveTitleCounts", `/api/live-counts${params.size ? `?${params}` : ""}`, false, true);
  if (payload && !payload.not_found) updatePageTitle(payload);
}

/** Keep the browser title current even when the dashboard tab is hidden. */
function startLiveTitlePolling() {
  window.clearInterval(state.titleTimer);
  loadLiveTitleCounts().catch(() => {});
  state.titleTimer = window.setInterval(() => {
    loadLiveTitleCounts().catch(() => {});
  }, 5000);
}

/** Update the network name in the shared header from the latest heartbeat.
 * @param {Object} data Current overview payload for run metadata.
 */
function renderHeaderNetwork(data) {
  const run = data.run;
  const metadata = data.run_metadata || {};
  const overviewNetwork = (data.network_states || []).find((network) =>
    network.connected && network.interface === run.interface)
    || (data.network_states || []).find((network) => network.connected);
  const liveNetwork = String(run.interface || "").split(/[,\s]+/).includes(state.headerNetwork?.interface)
    ? state.headerNetwork : null;
  const network = liveNetwork || overviewNetwork;
  const detailsLink = text("button", "run details", "overview-link");
  detailsLink.type = "button";
  detailsLink.addEventListener("click", () => switchTab("metadata"));
  byId("run-meta").replaceChildren(
    text("span", [
      run.interface || metadata.File || run.input_type || "input",
      network?.connected ? network.name || "" : "",
      metadata["Slips version"] ? `Slips ${metadata["Slips version"]}` : "",
    ].filter(Boolean).join(" · ")),
    text("span", " · "), detailsLink,
  );
  renderHeaderAddresses(data, liveNetwork);
}

/** Show every current monitored address and refresh this-device labels.
 * @param {Object} data Overview identity and address fallback for older servers.
 * @param {Object|null} network Latest lightweight network heartbeat.
 */
function renderHeaderAddresses(data, network) {
  const addresses = network?.host_addresses || (network?.connected === false
    ? {} : data.host_addresses || {});
  const ipv4 = [...new Set(addresses.ipv4 || [])];
  const ipv6 = [...new Set(addresses.ipv6 || [])];
  if (!network?.host_addresses && !ipv4.length && !ipv6.length && network?.host_ip) {
    (network.host_ip.includes(":") ? ipv6 : ipv4).push(network.host_ip);
  }
  const previous = data.host_addresses || {};
  const previousMonitored = new Set([...(previous.ipv4 || []), ...(previous.ipv6 || [])]);
  const computer = data.computer_addresses || {};
  const ownAddresses = new Set([
    ...(computer.ipv4 || []), ...(computer.ipv6 || []),
  ].filter((ip) => !previousMonitored.has(ip)));
  [...ipv4, ...ipv6, "127.0.0.1", "::1"].forEach((ip) => ownAddresses.add(ip));
  const changed = ownAddresses.size !== state.ownAddresses.size
    || [...ownAddresses].some((ip) => !state.ownAddresses.has(ip));
  state.ownAddresses = ownAddresses;
  const addressLine = byId("run-addresses");
  const key = JSON.stringify([ipv4, ipv6, state.computerName]);
  if (addressLine.dataset.addresses === key) {
    if (changed) refreshHostLabels();
    return;
  }
  addressLine.dataset.addresses = key;
  addressLine.replaceChildren();
  [["IPv4", ipv4], ["IPv6", ipv6]].forEach(([kind, ips]) => {
    if (!ips.length) return;
    const group = text("span", "", "run-address-family");
    group.append(text("span", `${kind}: `, "run-address-kind"));
    ips.forEach((ip, index) => {
      if (index) group.append(", ");
      group.append(hostIdentity(ip));
    });
    addressLine.append(group);
  });
  addressLine.hidden = !addressLine.childNodes.length;
  refreshHostLabels();
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
  const addresses = data.host_addresses || {};
  state.computerName = data.computer_name || "";
  byId("run-device").textContent = state.computerName
    || addresses.ipv4?.[0] || addresses.ipv6?.[0] || "Name unavailable";
  renderHeaderNetwork(data);
  renderConnectionState(backendConnected);
  byId("alerts-badge").textContent = compact(state.filteredBadgeCounts.alerts ?? data.counts.alerts);
  byId("evidence-badge").textContent = compact(state.filteredBadgeCounts.evidence ?? data.counts.evidence);
  byId("hosts-badge").textContent = compact(state.filteredBadgeCounts.hosts ?? data.counts.hosts);
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
  const selectedAlerts = state.overviewAlertGroups?.matching_total;
  setSummaryCards([
    ["Alerts", selectedAlerts === undefined ? "…" : compact(selectedAlerts)],
    ["Evidence", compact(data.counts.evidence)],
    ["Hosts seen", compact(data.counts.hosts)],
    ["Flows processed", compact(data.counts.processed_flows)],
    ["Firewall blocks", firewall.current ? compact(firewall.current)
      : (data.modules || []).some((module) => module.name === "blocking") ? "0" : "off"],
  ]);
  byId("summary-cards").classList.toggle("has-alerts", numeric(selectedAlerts) > 0);
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

/** Show alerts grouped by host using the current Alerts pane selection. */
function renderOverviewStatus(data) {
  const summary = state.overviewAlertGroups;
  const hasAlerts = numeric(summary?.matching_total) > 0;
  const panel = byId("overview-status");
  panel.classList.toggle("has-alerts", hasAlerts);
  byId("overview-alerts-link").hidden = !numeric(summary?.full_total) && !numeric(data.counts.alerts);
  byId("overview-status-description").hidden = false;
  const list = byId("overview-alert-hosts");
  list.replaceChildren();
  if (!summary) {
    byId("overview-status-title").textContent = "Alerts grouped by host";
    byId("overview-status-description").textContent = "Loading the Alerts selection…";
    return;
  }
  if (summary.error) {
    byId("overview-status-title").textContent = "Alerts grouped by host";
    byId("overview-status-description").textContent = "Could not load the selected alerts. Open Alerts to retry.";
    return;
  }
  const selectedFilters = [
    state.networkOnly && state.networkFilterSupported ? "Current network" : null,
    byId("alerts-review").selectedOptions[0]?.textContent,
    byId("alerts-range").selectedOptions[0]?.textContent,
    state.alertsWorkspace.severity
      ? state.alertsWorkspace.severity.replace("_or_more", "+") : null,
    byId("alerts-search").value.trim()
      ? `Search: ${byId("alerts-search").value.trim()}` : null,
  ].filter(Boolean).join(" · ");
  if (!hasAlerts) {
    byId("overview-status-title").textContent = numeric(summary.full_total)
      ? "No alerts match the selected filters" : "No alerts in this run";
    const top = data.highest_score;
    const threshold = numeric(data.alert_threshold) || 5;
    byId("overview-status-description").textContent =
      numeric(summary.full_total) ? selectedFilters
        : `${compact(data.counts.evidence)} evidence records from ${compact(data.counts.hosts)} hosts. `
          + `No host crossed the alert threshold (${threshold}).`
          + (top?.ip && top.score !== null ? ` Highest current score: ${numeric(top.score).toFixed(2)} on ${top.ip}.` : "");
    return;
  }
  byId("overview-status-title").textContent = "Alerts grouped by host";
  byId("overview-status-description").textContent =
    `${compact(summary.matching_total)} alerts across ${compact(summary.total)} `
    + `${numeric(summary.total) === 1 ? "host" : "hosts"} · ${selectedFilters}`;
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
        if (state.headerNetwork?.network_id === network.network_id) {
          state.headerNetwork.name = payload.name;
        }
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
    mac.append(text("span", "Router MAC"), macIdentity(network.gateway_mac));
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
  const tokenPattern = /((?<![\w:])(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}(?![\w:])|\b(?:critical|fatal|panic|traceback|exception|error|failed|failure|warning|warn)\b|(?:\/[\w.@-]+)+(?:\.py)?(?::\d+)?|\b(?:\d{1,3}\.){3}\d{1,3}\b)/gi;
  let offset = 0;
  for (const match of content.matchAll(tokenPattern)) {
    if (match.index > offset) {
      container.append(document.createTextNode(content.slice(offset, match.index)));
    }
    const token = match[0];
    const className = token.startsWith("/") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(token)
      ? "log-token-reference" : "log-token-alert";
    container.append(normalizeMac(token) ? macIdentity(token) : text("span", token, className));
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
  const errors = sortLocalRows("logs-table", (payload.items || []).map((row) => ({
    ...row, level: logSeverity(row),
  })));
  byId("logs-badge").textContent = compact(payload.total);
  byId("logs-count").textContent = `${errors.length} shown · ${compact(payload.total)} total`;
  renderTable("logs-table", errors, [
    (row) => formatTime(row.event_time),
    (row) => text("span", logSeverity(row), `log-level ${logSeverity(row)}`),
    (row) => text("code", row.module, "log-module"),
    (row) => {
      const message = text("span", "", `log-message ${logSeverity(row)}`);
      appendHighlightedLogText(message, row.message);
      return message;
    },
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
  const preserveAlerts = state.alertsWorkspace.rangeTouched
    || Boolean(state.alertsWorkspace.autoRange);
  const activeRange = ["alerts", "evidence", "hosts"].includes(state.activeTab)
    ? byId(`${state.activeTab}-range`) : null;
  const refreshActiveRange = activeRange && activeRange.value !== range
    && !(state.activeTab === "alerts" && preserveAlerts);
  ["alerts", "evidence", "hosts", "host"].forEach((name) => {
    if (name === "alerts" && preserveAlerts) return;
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
  const scope = state.networkOnly && state.networkFilterSupported ? "?network=current" : "";
  const payload = await api("overview", `/api/overview${scope}`);
  if (!payload) return;
  applyOverviewEvidence(payload);
  state.overview = payload;
  initializeRanges(payload.run);
  const alertPath = overviewAlertGroupsPath();
  if (state.overviewAlertQuery !== alertPath) {
    state.overviewAlertQuery = alertPath;
    state.overviewAlertGroups = null;
  }
  renderOverview();
  await Promise.allSettled([loadMetrics(), loadOverviewAlertGroups(alertPath)]);
}

/** Build a bounded host grouping with the Alerts pane's current filters. */
function overviewAlertGroupsPath() {
  const params = new URLSearchParams(listPath("alerts").split("?", 2)[1]);
  params.set("group", "host");
  params.set("limit", "4");
  params.delete("cursor");
  params.delete("summary");
  return `/api/alerts?${params}`;
}

/** Refresh Overview's alert groups without changing the Alerts pane. */
async function loadOverviewAlertGroups(path) {
  try {
    const payload = await api("overviewAlertGroups", path);
    if (state.overviewAlertQuery !== path) return;
    state.overviewAlertGroups = payload || { error: true };
  } catch (_) {
    if (state.overviewAlertQuery !== path) return;
    state.overviewAlertGroups = { error: true };
  }
  if (state.overview) renderOverview();
}

/** Load exact retained evidence attribution only after a user asks for it. */
async function loadOverviewEvidenceCounts() {
  if (state.overviewEvidenceLoading) return;
  state.overviewEvidenceLoading = true;
  renderOverview();
  try {
    const scope = state.networkOnly && state.networkFilterSupported ? "?network=current" : "";
    const payload = await api(
      "overviewEvidence", `/api/overview/evidence-counts${scope}`,
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
    api("metadataOverview", `/api/overview${state.networkOnly && state.networkFilterSupported ? "?network=current" : ""}`),
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
  const sort = state.localSorts["logs-table"];
  const params = new URLSearchParams({ sort: sort.key, order: sort.order });
  const payload = await api("logs", `/api/logs?${params}`);
  if (!payload) return;
  state.logs = payload;
  renderLogs(payload);
}

function listPath(name) {
  const page = state.pages[name];
  const params = rangeQuery(name);
  params.set("limit", "100");
  params.set("sort", page.sort);
  params.set("order", page.order);
  if (state.hideExcluded && ["alerts", "evidence", "hosts"].includes(name)) {
    params.set("hide_excluded", "1");
  }
  if (page.cursors[page.index]) params.set("cursor", page.cursors[page.index]);
  const search = byId(`${name}-search`).value.trim();
  if (search) params.set("search", search);
  if (name === "alerts") {
    if (state.alertsWorkspace.grouping === "host") params.set("group", "host");
    else params.set("summary", "1");
    params.set("details", "false");
    params.set("review", byId("alerts-review").value);
    if (state.alertsWorkspace.severity && state.alertsWorkspace.severity !== "info_or_more") {
      params.set("threat", state.alertsWorkspace.severity);
    }
  } else if (name === "evidence") {
    params.set("review", byId("evidence-review").value);
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
    if (byId("hosts-review").value) params.set("review", byId("hosts-review").value);
  }
  return `/api/${name}?${params}`;
}

function applyPage(name, payload) {
  const page = state.pages[name];
  page.items = payload.items;
  page.total = payload.total;
  page.next = payload.next_cursor;
  if (name === "hosts") {
    state.filteredBadgeCounts.hosts = payload.total;
    byId("hosts-badge").textContent = compact(payload.total);
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

/** Reveal the alert panes reached by the current selection. */
function setAlertPaneCount(count) {
  const workspace = byId("alerts-workspace");
  const individual = state.alertsWorkspace.grouping === "individual";
  workspace.classList.toggle("individual", individual);
  workspace.dataset.panes = String(count);
  byId("alerts-host-divider").hidden = false;
  byId("alerts-empty-pane").hidden = count !== 1;
  byId("alerts-list-pane").hidden = individual || count < 2;
  byId("alerts-detail-divider").hidden = individual || count < 3;
  byId("alerts-detail-pane").hidden = individual ? count < 2 : count < 3;
  const evidenceVisible = individual ? count >= 3 : count >= 4;
  byId("alerts-evidence-divider").hidden = !evidenceVisible;
  byId("alerts-evidence-pane").hidden = !evidenceVisible;
  if (!individual && count === 4) {
    const total = workspace.getBoundingClientRect().width;
    /** Convert a saved pane width to pixels, falling back to its default. */
    const savedWidth = (name, fallback) => {
      const value = workspace.style.getPropertyValue(name);
      return value.endsWith("%") ? total * parseFloat(value) / 100
        : parseFloat(value) || fallback;
    };
    const host = Math.max(44, Math.min(savedWidth("--alerts-host-width", total * .18), total - 540));
    const list = Math.max(44, Math.min(savedWidth("--alerts-list-width", total * .18), total - host - 488));
    const detail = Math.max(44, Math.min(savedWidth("--alerts-detail-width", total * .22), total - host - list - 444));
    workspace.style.setProperty("--alerts-host-width", `${Math.round(host)}px`);
    workspace.style.setProperty("--alerts-list-width", `${Math.round(list)}px`);
    workspace.style.setProperty("--alerts-detail-width", `${Math.round(detail)}px`);
  } else if (workspace.style.getPropertyValue("--alerts-host-width")) {
    resizeAlertPane("host", document.querySelector(".alerts-host-pane").getBoundingClientRect().width);
  }
}

/** Render exact and inclusive severity filters for alert hosts. */
function renderAlertSeverityFilters() {
  const page = state.pages.alerts;
  const selected = state.alertsWorkspace.severity;
  const container = byId("alerts-severity-filters");
  container.replaceChildren();
  [["", "All"], ...["critical", "high", "medium", "low", "info"]
    .map((level) => [level, level[0].toUpperCase() + level.slice(1)]),
    ...["critical", "high", "medium", "low", "info"]
      .map((level) => [`${level}_or_more`, `${level[0].toUpperCase() + level.slice(1)}+`])]
    .forEach(([level, label]) => {
      const button = text("button", `${label}${selected === level ? ` ${compact(page.total)}` : ""}`, "alerts-filter");
      button.type = "button";
      button.dataset.level = level;
      button.classList.toggle("active", selected === level);
      button.setAttribute("aria-pressed", String(selected === level));
      button.addEventListener("click", () => {
        if (selected === level) return;
        state.alertsWorkspace.severity = level;
        if (state.alertsWorkspace.host) closeAlertHostPane();
        resetPage("alerts");
        byId("alerts-host-list").replaceChildren(text("p", "Loading alert hosts…", "empty-state"));
        renderAlertSeverityFilters();
        loadAlerts().catch(() => {});
      });
      container.append(button);
    });
}

/** Count the detection types linked to an alert without choosing one as its summary. */
function alertEvidenceTypes(record) {
  if (Array.isArray(record.evidence_types)) return record.evidence_types;
  const counts = new Map();
  (record.evidence || []).forEach((item) => {
    const type = item.evidence_type || "UNKNOWN";
    counts.set(type, (counts.get(type) || 0) + 1);
  });
  return [...counts].map(([type, count]) => ({ type, count }))
    .sort((left, right) => right.count - left.count || left.type.localeCompare(right.type));
}

/** Give a detector type a readable name in alert summaries. */
function alertTypeName(type) {
  const names = {
    CONNECTION_TO_PRIVATE_IP: "Private IP connection",
    UNKNOWN_PORT: "Unknown port",
    VERTICAL_PORT_SCAN: "Vertical port scan",
    HORIZONTAL_PORT_SCAN: "Horizontal port scan",
    HTTP_TRAFFIC: "HTTP traffic",
    ARP_SCAN: "ARP scan",
    P2P_REPORT: "P2P report",
  };
  return names[type] || String(type || "Unknown detection").replaceAll("_", " ").toLowerCase()
    .replace(/^./, (first) => first.toUpperCase());
}

/** Summarize every linked detection type in one alert-list row. */
function alertComposition(record) {
  const types = alertEvidenceTypes(record);
  if (!types.length) return record.summary || record.evidence_type || record.label || "Alert";
  const leading = types.slice(0, 3).map(({ type, count }) =>
    `${alertTypeName(type)} (${compact(count)})`).join(" · ");
  return types.length > 3 ? `${leading} · +${types.length - 3} more types` : leading;
}

/** Render the grouped host list without opening another overlay. */
function renderAlertHostList() {
  const container = byId("alerts-host-list");
  const scrollTop = container.scrollTop;
  const selected = state.alertsWorkspace.host?.ip_alerted;
  const level = state.alertsWorkspace.severity;
  const rows = state.pages.alerts.items || [];
  container.replaceChildren();
  if (!rows.length) {
    const label = byId("alerts-range").selectedOptions[0]?.textContent || "this range";
    const searched = byId("alerts-search").value.trim();
    const noun = state.alertsWorkspace.grouping === "host" ? "host groups" : "alerts";
    container.append(text("p", searched || level
      ? `No ${noun} match these filters.`
      : `No alerts in ${label}.`, "empty-state"));
    if (state.alertsWorkspace.fullTotal && byId("alerts-range").value !== "all") {
      const showHistory = text("button", "Show full run alerts", "secondary alerts-show-history");
      showHistory.type = "button";
      showHistory.addEventListener("click", () => {
        byId("alerts-range").value = "all";
        byId("alerts-range").dispatchEvent(new Event("change"));
      });
      container.append(showHistory);
    }
    return;
  }
  if (state.alertsWorkspace.grouping === "individual") {
    rows.forEach((record) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "alerts-alert-row";
      row.dataset.alertId = record.alert_id;
      row.classList.toggle("selected", record.alert_id === state.alertsWorkspace.alert?.alert_id);
      const top = document.createElement("div");
      top.className = "alerts-alert-row-top";
      top.append(text("span", formatTime(record.alert_time)),
        text("span", numeric(record.alert_score).toFixed(2), `threat-${record.threat_level}`));
      const summary = alertComposition(record);
      row.title = summary;
      row.append(top, deviceIdentity(record, "ip_alerted"),
        text("span", summary, "alerts-alert-row-title"),
        text("span", `${compact(record.evidence_count)} evidence · ${(record.review_status || "active").replaceAll("_", " ")}`, "alerts-alert-row-meta"));
      row.addEventListener("click", () => selectAlertDetailPane(record).catch(() => {}));
      container.append(row);
    });
    container.scrollTop = scrollTop;
    return;
  }
  rows.forEach((host) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "alerts-host-row";
    row.classList.toggle("selected", (host.device_id || host.ip_alerted)
      === (state.alertsWorkspace.host?.device_id || selected));
    row.append(
      deviceIdentity(host, "ip_alerted"),
      text("span", host.alert_score == null ? "—" : numeric(host.alert_score).toFixed(2),
        `alerts-host-score threat-${host.threat_level || "info"}`),
      text("span", `${compact(host.alert_count)} · ${formatAge(host.alert_time)}`, "alerts-host-meta"),
    );
    row.title = `${host.alert_count} alerts · ${host.evidence_count} evidence links`;
    row.addEventListener("click", () => selectAlertHostPane(host));
    container.append(row);
  });
  container.scrollTop = scrollTop;
}

/** Show one host in the middle pane and load its individual alerts. */
function selectAlertHostPane(host) {
  const workspace = state.alertsWorkspace;
  const changed = (workspace.host?.device_id || workspace.host?.ip_alerted)
    !== (host.device_id || host.ip_alerted);
  if (changed && state.evidenceDetail.inAlertPane) closeEvidenceDetail(false, true);
  workspace.host = host;
  if (changed) {
    workspace.alert = null;
    workspace.items = [];
    workspace.next = null;
    workspace.detailGeneration += 1;
    byId("alerts-detail").replaceChildren();
    byId("alerts-list").scrollTop = 0;
  }
  setAlertPaneCount(workspace.alert ? state.evidenceDetail.inAlertPane ? 4 : 3 : 2);
  renderAlertHostList();
  renderAlertSelectedHost();
  if (changed || !workspace.items.length) loadAlertHostAlerts(true).catch(() => {});
}

/** Close the selected host and return to the first pane. */
function closeAlertHostPane() {
  const workspace = state.alertsWorkspace;
  if (state.evidenceDetail.inAlertPane) closeEvidenceDetail(false, true);
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
  container.append(close, text("h3", host.device_id ? "Alerts for this device" : "Alerts for this host", "alerts-selected-title"),
    text("strong", host.ip_alerted));
  container.append(deviceIdentity(host, "ip_alerted"));
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
  if (state.deviceView && workspace.host?.device_id) params.set("device_id", workspace.host.device_id);
  else params.set("profile", host);
  params.set("limit", "50");
  params.set("sort", workspace.itemSort);
  params.set("order", workspace.itemOrder);
  params.set("details", "false");
  params.set("summary", "1");
  params.set("review", byId("alerts-review").value);
  if (workspace.severity && workspace.severity !== "info_or_more") {
    params.set("threat", workspace.severity);
  }
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
  workspace.listSignature = alertRangeSignature();
  renderAlertTimeline();
}

/** Render the middle-pane timeline and its bounded next-page control. */
function renderAlertTimeline() {
  const workspace = state.alertsWorkspace;
  const container = byId("alerts-list");
  const scrollTop = container.scrollTop;
  container.replaceChildren();
  if (!workspace.items.length) {
    container.append(text("p", "No alerts in this range for this host.", "empty-state"));
  }
  workspace.items.forEach((record) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "alerts-alert-row";
    row.dataset.alertId = record.alert_id;
    row.classList.toggle("selected", record.alert_id === workspace.alert?.alert_id);
    const top = document.createElement("div");
    top.className = "alerts-alert-row-top";
    top.append(text("span", formatTime(record.alert_time)),
      text("span", numeric(record.alert_score).toFixed(2), `threat-${record.threat_level}`));
    const title = alertComposition(record);
    row.title = title;
    row.append(top, text("span", title, "alerts-alert-row-title"),
      text("span", `${compact(record.evidence_count)} evidence · ${(record.review_status || "active").replaceAll("_", " ")}`, "alerts-alert-row-meta"));
    row.addEventListener("click", () => selectAlertDetailPane(record).catch(() => {}));
    container.append(row);
  });
  container.scrollTop = scrollTop;
  const more = byId("alerts-list-more");
  more.replaceChildren();
  if (workspace.next) {
    const button = text("button", `Load more · ${compact(workspace.items.length)} of ${compact(workspace.total)}`, "secondary");
    button.type = "button";
    button.addEventListener("click", () => loadAlertHostAlerts(false).catch(() => {}));
    more.append(button);
  }
}

/** Return from the selected alert to its host's list without losing position. */
function closeAlertDetailPane() {
  const workspace = state.alertsWorkspace;
  if (state.evidenceDetail.inAlertPane) closeEvidenceDetail(false, true);
  const alertId = workspace.alert?.alert_id;
  workspace.alert = null;
  workspace.detailGeneration += 1;
  setAlertPaneCount(workspace.grouping === "individual" ? 1 : workspace.host ? 2 : 1);
  byId("alerts-detail").replaceChildren();
  let selectedRow = null;
  document.querySelectorAll("#alerts-list .alerts-alert-row, #alerts-host-list .alerts-alert-row").forEach((row) => {
    if (row.dataset.alertId === alertId) selectedRow = row;
    row.classList.remove("selected");
  });
  selectedRow?.focus({ preventScroll: true });
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
  const back = text("button", "← Back to alerts", "secondary");
  back.type = "button";
  back.addEventListener("click", closeAlertDetailPane);
  const whitelist = text("button", "Whitelist", "secondary");
  whitelist.type = "button";
  const close = text("button", "×", "secondary");
  close.type = "button";
  close.title = "Close alert details";
  close.setAttribute("aria-label", "Close alert details pane");
  close.addEventListener("click", closeAlertDetailPane);
  actions.append(back, whitelist, close);
  header.append(context, actions);
  const types = alertEvidenceTypes(record);
  const count = numeric(record.evidence_count || record.evidence?.length);
  const title = types.length > 1
    ? `${compact(count)} evidence records across ${types.length} detection types`
    : types.length === 1
      ? `${alertTypeName(types[0].type)} · ${compact(count)} evidence record${count === 1 ? "" : "s"}`
      : "Alert details";
  container.append(header, text("h3", title));
  if (types.length) {
    const composition = document.createElement("div");
    composition.className = "alerts-type-summary";
    types.forEach(({ type, count: typeCount }) => composition.append(
      text("span", `${alertTypeName(type)} · ${compact(typeCount)}`)));
    container.append(composition);
  }
  if (types.length <= 1 && firstEvidence.description) {
    container.append(text("p", firstEvidence.description, "alerts-detail-summary"));
  }
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
  container.append(reviewEditor("alert", record));
  const evidence = document.createElement("div");
  evidence.className = "investigation-list";
  (record.evidence || []).forEach((item) => evidence.append(evidenceCard(item, record.evidence, true)));
  if (!record.evidence?.length) evidence.append(text("p", "No related evidence is available.", "muted"));
  container.append(evidence, investigationHeading("Identifiers"),
    text("p", record.alert_id, "mono"), rawBlock(record, "alert"));
}

/** Open one alert in the right pane and load its linked evidence. */
async function selectAlertDetailPane(record) {
  const workspace = state.alertsWorkspace;
  if (workspace.alert?.alert_id !== record.alert_id && state.evidenceDetail.inAlertPane) {
    closeEvidenceDetail(false, true);
  }
  workspace.alert = record;
  const generation = ++workspace.detailGeneration;
  setAlertPaneCount(workspace.grouping === "individual"
    ? state.evidenceDetail.inAlertPane ? 3 : 2
    : state.evidenceDetail.inAlertPane ? 4 : 3);
  document.querySelectorAll("#alerts-list .alerts-alert-row, #alerts-host-list .alerts-alert-row").forEach((row) => {
    row.classList.toggle("selected", row.dataset.alertId === record.alert_id);
  });
  const back = text("button", "← Back to alerts", "secondary");
  back.type = "button";
  back.addEventListener("click", closeAlertDetailPane);
  byId("alerts-detail").replaceChildren(back,
    text("p", "Loading alert evidence…", "empty-state"));
  const params = new URLSearchParams({ range: "all", review: "all", limit: "1", search: record.alert_id });
  const payload = await api("alertPaneDetail", `/api/alerts?${params}`);
  if (!payload || generation !== workspace.detailGeneration
      || workspace.alert?.alert_id !== record.alert_id) return;
  const detailed = payload.items.find((item) => item.alert_id === record.alert_id);
  if (!detailed) {
    byId("alerts-detail").replaceChildren(back,
      text("p", "This alert is no longer available.", "empty-state"));
    return;
  }
  workspace.alert = { ...detailed, summary: record.summary,
    evidence_types: record.evidence_types };
  renderAlertDetailPane(workspace.alert);
}

/** Resize the pane immediately before a draggable Alerts divider. */
function resizeAlertPane(kind, desiredWidth, initialWidths = null) {
  const workspace = byId("alerts-workspace");
  const total = workspace.getBoundingClientRect().width;
  const host = document.querySelector(".alerts-host-pane").getBoundingClientRect().width;
  const middle = byId("alerts-list-pane").getBoundingClientRect().width;
  const detail = byId("alerts-detail-pane").getBoundingClientRect().width;
  const panes = Number(workspace.dataset.panes);
  const individual = workspace.classList.contains("individual");
  if (kind === "host") {
    const remaining = individual
      ? panes === 3 ? detail + 420 + 16 : 320 + 8
      : panes === 4 ? middle + detail + 420 + 24
        : panes === 3 ? middle + 320 + 16 : 240 + 8;
    const width = Math.max(panes === 4 ? 210 : 240,
      Math.min(desiredWidth, total - remaining));
    workspace.style.setProperty("--alerts-host-width", `${Math.round(width)}px`);
  } else if (kind === "detail" && !individual && panes >= 3) {
    const remaining = panes === 4 ? detail + 420 + 24 : 320 + 16;
    const width = Math.max(panes === 4 ? 210 : 240,
      Math.min(desiredWidth, total - host - remaining));
    workspace.style.setProperty("--alerts-list-width", `${Math.round(width)}px`);
  } else if (kind === "evidence" && (panes === 4 || individual && panes === 3)) {
    const initial = initialWidths || { host, middle, detail };
    const widths = individual
      ? [initial.host, initial.detail]
      : [initial.host, initial.middle, initial.detail];
    const beforeEvidence = widths.reduce((sum, width) => sum + width, 0);
    const target = Math.max(widths.length * 44,
      Math.min(beforeEvidence - initial.detail + desiredWidth,
        total - 420 - (widths.length + 1) * 8));
    let reduction = beforeEvidence - target;
    if (reduction > 0) {
      for (let index = widths.length - 1; index >= 0; index -= 1) {
        const amount = Math.min(Math.max(widths[index] - 44, 0), reduction);
        widths[index] -= amount;
        reduction -= amount;
      }
    } else {
      widths[widths.length - 1] -= reduction;
    }
    workspace.style.setProperty("--alerts-host-width", `${Math.round(widths[0])}px`);
    if (!individual) workspace.style.setProperty("--alerts-list-width", `${Math.round(widths[1])}px`);
    workspace.style.setProperty("--alerts-detail-width", `${Math.round(widths.at(-1))}px`);
  }
}

/** Enable pointer and keyboard resizing between visible Alerts panes. */
function initAlertPaneResize() {
  [["alerts-host-divider", "host", ".alerts-host-pane"],
    ["alerts-detail-divider", "detail", "#alerts-list-pane"],
    ["alerts-evidence-divider", "evidence", "#alerts-detail-pane"]]
    .forEach(([id, kind, paneSelector]) => {
      const divider = byId(id);
      divider.addEventListener("pointerdown", (event) => {
        if (divider.hidden) return;
        event.preventDefault();
        const startX = event.clientX;
        const startWidth = document.querySelector(paneSelector).getBoundingClientRect().width;
        const initialWidths = kind === "evidence" ? {
          host: document.querySelector(".alerts-host-pane").getBoundingClientRect().width,
          middle: byId("alerts-list-pane").getBoundingClientRect().width,
          detail: byId("alerts-detail-pane").getBoundingClientRect().width,
        } : null;
        divider.setPointerCapture(event.pointerId);
        document.body.classList.add("alerts-resizing");
        const move = (next) => resizeAlertPane(kind, startWidth + next.clientX - startX, initialWidths);
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
  const workspace = state.alertsWorkspace;
  workspace.fullTotal = byId("alerts-review").value === "open"
    ? payload.open_total || 0 : payload.full_total || 0;
  applyPage("alerts", payload);
  state.filteredBadgeCounts.alerts = payload.matching_total ?? payload.total;
  byId("alerts-badge").textContent = compact(state.filteredBadgeCounts.alerts);
  byId("alerts-count").textContent = compact(payload.total);
  renderAlertSeverityFilters();
  renderAlertHostList();
  pager("alerts", "alerts-pager", loadAlerts);
  if (workspace.host && workspace.grouping === "host") {
    const current = payload.items.find((item) =>
      (item.device_id || item.ip_alerted) === (workspace.host.device_id || workspace.host.ip_alerted));
    if (current) {
      workspace.host = current;
      renderAlertSelectedHost();
    }
    const signature = alertRangeSignature();
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

/** Resize the evidence table or records pane while keeping the inspector usable.
 * @param {string} kind Pane before the dragged divider.
 * @param {number} desiredWidth Requested pane width in pixels.
 */
function resizeEvidencePane(kind, desiredWidth) {
  const workspace = byId("evidence-workspace");
  const width = workspace.getBoundingClientRect().width;
  const hasDetail = workspace.classList.contains("has-detail");
  const left = workspace.querySelector(".evidence-left").getBoundingClientRect().width;
  if (kind === "group") {
    const records = byId("evidence-right").getBoundingClientRect().width;
    const remaining = hasDetail ? records + 320 + 16 : 240 + 8;
    workspace.style.setProperty(hasDetail ? "--evidence-detail-group-width" : "--evidence-left-width", `${Math.round(Math.max(240, Math.min(desiredWidth, width - remaining)))}px`);
  } else if (hasDetail) {
    workspace.style.setProperty("--evidence-detail-record-width", `${Math.round(Math.max(280, Math.min(desiredWidth, width - left - 320 - 16)))}px`);
  }
}

/** Enable pointer and keyboard resizing for Evidence's three panes. */
function initEvidencePaneResize() {
  [["evidence-group-divider", "group", ".evidence-left"],
    ["evidence-detail-divider", "records", "#evidence-right"]]
    .forEach(([id, kind, selector]) => {
      const divider = byId(id);
      divider.addEventListener("pointerdown", (event) => {
        if (divider.hidden) return;
        event.preventDefault();
        const startX = event.clientX;
        const startWidth = document.querySelector(selector).getBoundingClientRect().width;
        divider.setPointerCapture(event.pointerId);
        const move = (next) => resizeEvidencePane(kind, startWidth + next.clientX - startX);
        const finish = () => {
          divider.removeEventListener("pointermove", move);
          divider.removeEventListener("pointerup", finish);
          divider.removeEventListener("pointercancel", finish);
        };
        divider.addEventListener("pointermove", move);
        divider.addEventListener("pointerup", finish);
        divider.addEventListener("pointercancel", finish);
      });
      divider.addEventListener("keydown", (event) => {
        if (divider.hidden || !["ArrowLeft", "ArrowRight"].includes(event.key)) return;
        event.preventDefault();
        const current = document.querySelector(selector).getBoundingClientRect().width;
        resizeEvidencePane(kind, current + (event.key === "ArrowRight" ? 24 : -24));
      });
    });
}

/** Clear a selected group when the filtering context changes. */
function clearEvidenceSelection() {
  if (state.evidenceDetail.record && state.evidenceDetail.inPane) closeEvidenceDetail(false, true);
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
    .map((level) => [level, level[0].toUpperCase() + level.slice(1)]),
    ...[["critical_or_more", "Critical+"], ["high_or_more", "High+"],
      ["medium_or_more", "Medium+"], ["low_or_more", "Low+"], ["info_or_more", "Info+"]]]
    .forEach(([level, label]) => {
      const button = text("button", level.endsWith("_or_more")
        ? label : `${label} ${compact(counts.get(level) || 0)}`, "evidence-chip");
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
  [["grouped", state.deviceView ? "Device + type" : "Host + type"],
    ["type", "Type"], ["host", state.deviceView ? "Device" : "Host"],
    ["individual", "None"]]
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
    (row) => row.profile_ip ? deviceIdentity(row, "profile_ip") : "All hosts",
    (row) => {
      const cell = document.createElement("span");
      cell.append(text("code", row.evidence_type || "All types"));
      if (row.module) cell.append(text("small", ` ${row.module}`, "muted"));
      if (mode === "individual" && row.review_status && row.review_status !== "unreviewed") {
        cell.append(text("small", ` · ${row.review_status.replaceAll("_", " ")}`, "review-state"));
      }
      return cell;
    },
    (row) => threat(row.threat_level),
    (row) => slipsScore(row),
    (row) => compact(mode === "individual" ? row.flow_count : row.evidence_count),
    (row) => compact(mode === "individual" ? row.alert_ids?.length : row.alert_count),
  ], (row) => {
    if (mode === "individual") selectEvidenceRecord(row).catch(() => {});
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
    text("p", "Use ↑↓ and Enter in the table. Selecting a record opens its full details and triggering flows. The summary below covers the groups loaded on this page."));
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
  if (state.evidenceDetail.record && state.evidenceDetail.inPane) closeEvidenceDetail(false, true);
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
  if (state.deviceView && workspace.group?.device_id) params.set("device_id", workspace.group.device_id);
  else if (workspace.group?.profile_ip) params.set("profile", workspace.group.profile_ip);
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
  params.set("review", byId("evidence-review").value);
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
  renderEvidenceGroup();
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
    [state.deviceView ? "Device" : "Host", group.profile_ip ? deviceIdentity(group, "profile_ip") : "All hosts"],
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
    button.dataset.evidenceId = record.id;
    button.classList.toggle("selected", record.id === workspace.record?.id);
    button.append(text("span", evidenceClock(record.timestamp)),
      text("span", p2pReports ? `maliciousness · confidence ${numeric(record.confidence).toFixed(2)}` : record.description || record.evidence_type),
      text("span", `${record.twid || "—"}${record.review_status && record.review_status !== "unreviewed" ? ` · ${record.review_status.replaceAll("_", " ")}` : ""}`),
      text("span", `${compact(record.flow_count)} flow${numeric(record.flow_count) === 1 ? "" : "s"}`));
    button.addEventListener("click", () => selectEvidenceRecord(record).catch(() => {}));
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
      const label = text("summary", `${peer.replace(/[A-Za-z0-9]{25,}/g, shortPeerId)} · ${compact(records.length)} report${records.length === 1 ? "" : "s"}`);
      label.title = peer;
      details.append(label);
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
}

/** Open one evidence record in the full-width investigation page.
 * @param {object} record Individual durable evidence record.
 * @returns {Promise<void>} Completes after the triggering flows load.
 */
async function selectEvidenceRecord(record) {
  state.evidenceWorkspace.record = record;
  await openEvidence(record);
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

/** Refresh the Evidence table while retaining a valid open investigation. */
async function loadEvidence() {
  renderEvidenceGroupControls();
  const payload = await api("evidence", listPath("evidence"));
  if (!payload) return;
  applyPage("evidence", payload);
  state.filteredBadgeCounts.evidence = payload.matching_total ?? payload.total;
  byId("evidence-badge").textContent = compact(state.filteredBadgeCounts.evidence);
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
  } else renderEvidenceEmptyState();
}

/** Format a captured configuration value without interpreting it as a timestamp. */
function configValue(value, sensitive = false) {
  if (sensitive) return "Configured — hidden";
  if (value === true) return "on";
  if (value === false) return "off";
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) return value.join(", ") || "none";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** Fill the six quick facts from settings captured at the start of this run. */
function renderConfigurationSummary(sections) {
  const setting = (path) => {
    const [sectionKey, ...keys] = path.split(".");
    return sections.find((section) => section.key === sectionKey)
      ?.settings?.find((item) => item.key === keys.join("."))?.value;
  };
  const windowSeconds = Number(setting("parameters.time_window_width"));
  const disabled = setting("modules.disable");
  const disabledNames = Array.isArray(disabled)
    ? disabled.filter((name) => name !== "template") : [];
  const tiPeriod = Number(setting("threatintelligence.TI_files_update_period"));
  const facts = [
    ["Alert threshold", configValue(setting("detection.risk_accumulated_threat_level")), "score to raise an alert"],
    ["Time window", Number.isFinite(windowSeconds) && windowSeconds > 0
      ? windowSeconds % 3600 === 0 ? `${windowSeconds / 3600} h` : `${windowSeconds} s`
      : configValue(setting("parameters.time_window_width")), `${windowSeconds || 0} s`],
    ["Direction", configValue(setting("parameters.analysis_direction")),
      setting("parameters.analysis_direction") === "out" ? "outbound only" : "traffic analyzed"],
    ["Modules", `${disabledNames.length} off`, disabledNames.join(", ") || "all detection modules available"],
    ["Threat-intel feeds", setting("threatintelligence.ti_files") ? "configured" : "none",
      Number.isFinite(tiPeriod) && tiPeriod > 0 ? `updated every ${Math.round(tiPeriod / 3600)} h` : "update period unknown"],
    ["P2P", setting("local_p2p.use_p2p") ? "on" : "off", "local peer network"],
  ];
  byId("configuration-summary").replaceChildren(...facts.map(([label, value, hint]) => {
    const card = document.createElement("article");
    card.className = "surface config-fact";
    card.append(text("span", label), text("strong", value), text("small", hint));
    return card;
  }));
}

/** Render the selected section as compact, explained settings with defaults. */
function renderConfiguration() {
  const payload = state.configuration;
  if (!payload) return;
  const query = byId("configuration-search").value.trim().toLowerCase();
  const container = byId("configuration-sections");
  container.replaceChildren();
  const preferred = ["detection", "parameters", "modules", "update", "output", "Debug",
    "threatintelligence", "global_p2p", "local_p2p", "alert_summary", "llm_proxy",
    "exporting_alerts", "ml_linear_model", "virustotal", "web_interface", "whitelists"];
  const sections = [...(payload.sections || [])].sort((left, right) => {
    const leftOrder = preferred.indexOf(left.key);
    const rightOrder = preferred.indexOf(right.key);
    return (leftOrder < 0 ? 100 : leftOrder) - (rightOrder < 0 ? 100 : rightOrder);
  });
  const matches = (section) => (section.settings || []).filter((setting) => {
    if (state.configurationFilter === "changed" && !setting.changed) return false;
    if (state.configurationFilter === "secrets" && !setting.sensitive) return false;
    return !query || [section.title, section.description, setting.key, setting.label,
      setting.explanation, configValue(setting.value, setting.sensitive)].join(" ").toLowerCase().includes(query);
  });
  const visible = sections.filter((section) => matches(section).length);
  if (!visible.some((section) => section.key === state.configurationSection)) {
    state.configurationSection = visible[0]?.key || "";
  }
  const navigation = byId("configuration-navigation");
  navigation.replaceChildren(text("strong", `SECTIONS · ${sections.length}`, "config-nav-title"));
  sections.forEach((section) => {
    const count = matches(section).length;
    const button = document.createElement("button");
    button.type = "button";
    button.className = `config-nav-item${section.key === state.configurationSection ? " active" : ""}`;
    button.disabled = !count;
    button.setAttribute("aria-current", section.key === state.configurationSection ? "true" : "false");
    const label = section.key === "threatintelligence" ? "Threat intelligence"
      : section.key === "global_p2p" ? "Global P2P"
        : section.key === "local_p2p" ? "Local P2P" : section.title;
    button.append(text("span", label), text("small", String(count), section.changed_count ? "changed" : ""));
    button.addEventListener("click", () => {
      state.configurationSection = section.key;
      renderConfiguration();
    });
    navigation.append(button);
  });
  const selected = visible.find((section) => section.key === state.configurationSection);
  if (!selected) {
    container.append(text("p", "No settings match this search or filter.", "surface empty-state"));
    byId("configuration-count").textContent = "Secrets are hidden; settings absent from the snapshot may use built-in defaults.";
    return;
  }
  const settings = matches(selected);
  if (selected.key === "detection") {
    const order = ["risk_accumulated_threat_level", "evidence_detection_threshold",
      "popup_alerts", "low_risk_weight", "medium_risk_weight", "high_risk_weight"];
    settings.sort((left, right) => order.indexOf(left.key) - order.indexOf(right.key));
  }
  if (state.configurationSort.key) {
    const key = state.configurationSort.key;
    const direction = state.configurationSort.order === "asc" ? 1 : -1;
    const valueFor = (item) => key === "label" ? item.label
      : key === "value" ? configValue(item.value, item.sensitive)
        : key === "explanation" ? item.explanation
          : item.changed ? `was ${configValue(item.default, item.sensitive)}`
            : item.has_default ? "default" : "—";
    settings.sort((left, right) => String(valueFor(left) ?? "").localeCompare(
      String(valueFor(right) ?? ""), undefined, { numeric: true, sensitivity: "base" },
    ) * direction);
  }
  const panel = document.createElement("article");
  panel.className = "surface config-table-panel";
  const heading = document.createElement("div");
  heading.className = "config-table-heading";
  const label = text("h3", selected.key === "threatintelligence" ? "Threat intelligence" : selected.title);
  const title = document.createElement("div");
  title.append(label, text("span", selected.description));
  heading.append(title, text("small", `${settings.length} settings · ${settings.filter((item) => item.changed).length} changed`));
  const wrap = document.createElement("div");
  wrap.className = "config-table-wrap";
  const table = document.createElement("table");
  table.className = "config-table";
  const headers = document.createElement("tr");
  [["Setting", "label"], ["Value", "value"], ["What it does", "explanation"],
    ["Default", "default"]].forEach(([label, key]) => {
    const header = text("th", label);
    header.dataset.sort = key;
    header.tabIndex = 0;
    const active = state.configurationSort.key === key;
    header.classList.toggle("sorted", active);
    header.dataset.order = active ? state.configurationSort.order : "";
    header.setAttribute("aria-sort", active
      ? state.configurationSort.order === "asc" ? "ascending" : "descending" : "none");
    const changeSort = () => {
      state.configurationSort.order = active && state.configurationSort.order === "asc" ? "desc" : "asc";
      state.configurationSort.key = key;
      renderConfiguration();
    };
    header.addEventListener("click", changeSort);
    header.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        changeSort();
      }
    });
    headers.append(header);
  });
  const head = document.createElement("thead");
  head.append(headers);
  table.append(head);
  const body = document.createElement("tbody");
  settings.forEach((setting) => {
    const row = document.createElement("tr");
    if (setting.changed) row.className = "changed";
    const name = document.createElement("td");
    name.append(text("strong", setting.label), text("small", `${selected.key}.${setting.key}`));
    const value = document.createElement("td");
    value.append(text("code", configValue(setting.value, setting.sensitive),
      setting.sensitive ? "config-secret" : "config-current"));
    const explanation = text("td", setting.explanation);
    const defaultCell = document.createElement("td");
    defaultCell.append(text("span", setting.changed
      ? `was ${configValue(setting.default, setting.sensitive)}`
      : setting.has_default ? "default" : "—",
    setting.changed ? "config-was" : "config-default"));
    row.append(name, value, explanation, defaultCell);
    body.append(row);
  });
  table.append(body);
  wrap.append(table);
  panel.append(heading, wrap);
  container.append(panel);
  byId("configuration-count").textContent =
    `Showing ${settings.length} of ${payload.total} captured settings · Secrets show as “configured” and are never displayed. Settings absent from the snapshot may use built-in defaults.`;
}

async function loadConfiguration() {
  const payload = await api("configuration", "/api/configuration");
  if (!payload) return;
  state.configuration = payload;
  byId("configuration-status").textContent = payload.captured
    ? `${payload.source || "run.yaml"} · read-only snapshot taken at start · ${payload.total} settings`
    : "No configuration snapshot was captured for this run.";
  byId("configuration-source").textContent = payload.source || "Run YAML snapshot";
  byId("configuration-yaml-content").textContent = payload.redacted_yaml || "No YAML snapshot is available.";
  byId("configuration-all-count").textContent = payload.total;
  byId("configuration-changed-count").textContent = payload.changed_total || 0;
  byId("configuration-secret-count").textContent = payload.secret_total || 0;
  renderConfigurationSummary(payload.sections || []);
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

/** Save an analyst decision or a confirmed cleanup action.
 * @param {string} entity Alert or evidence.
 * @param {object} change Review action, record ID, note, and status or depth.
 * @returns {Promise<object>} Saved decision or cleanup counts.
 */
async function saveReviewChange(entity, change) {
  if (!state.reviewAvailable) {
    throw new Error(state.archiveSource ? "Detection archives are read-only."
      : "Restart Slips manually to enable the new review controls.");
  }
  const response = await fetch(`/api/${entity}-review`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(change),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
  return payload;
}

/** Refresh the visible investigation after an alert or evidence decision.
 * @param {string} entity Alert or evidence that changed.
 * @returns {Promise<void>} Resolves after the current page refreshes.
 */
async function refreshAfterReview(entity) {
  closeDrawer();
  closeEvidenceDetail(false, true);
  if (state.activeTab === "hosts" && state.host) {
    resetPage("hostAlerts");
    resetPage("host-evidence");
    await refreshHostWorkspace();
    return;
  }
  if (state.activeTab === "alerts") {
    state.alertsWorkspace.alert = null;
    setAlertPaneCount(state.alertsWorkspace.host ? 2 : 1);
    resetPage("alerts");
    await loadAlerts();
    if (state.alertsWorkspace.host) {
      await loadAlertHostAlerts(true);
      if (!state.alertsWorkspace.items.length) closeAlertHostPane();
    }
    return;
  }
  if (state.activeTab === "evidence") {
    clearEvidenceSelection();
    resetPage("evidence");
    await loadEvidence();
    return;
  }
  await currentLoader()();
}

/** Build a durable review and cleanup form for one alert or evidence record.
 * @param {string} entity Alert or evidence.
 * @param {object} record Current durable record.
 * @returns {HTMLElement} Form with review states, note, and deletion depths.
 */
function reviewEditor(entity, record) {
  const identifier = entity === "alert" ? record.alert_id : record.id;
  const panel = document.createElement("section");
  panel.className = "surface review-editor";
  panel.append(text("h3", entity === "alert" ? "Review this alert" : "Review this evidence"));
  const availability = text("p", state.archiveSource ? "Detection archives are read-only."
    : "Restart Slips manually to enable review actions in the running web server.", "muted review-availability");
  availability.hidden = state.reviewAvailable;
  panel.append(availability);
  const current = record.review_status || (entity === "alert" ? "active" : "unreviewed");
  panel.append(text("p", `Current: ${current.replaceAll("_", " ")}${record.review_updated_at ? ` · ${formatTime(record.review_updated_at)}` : ""}`, "muted"));
  const status = document.createElement("select");
  const states = entity === "alert"
    ? [["active", "Active"], ["in_review", "In review"], ["resolved", "Resolved"]]
    : [["unreviewed", "Unreviewed"], ["in_review", "In review"],
      ["true_positive", "True positive"], ["false_positive", "False positive"],
      ["expected_behavior", "Expected behavior"], ["inconclusive", "Inconclusive"]];
  states.forEach(([value, label]) => {
    const option = new Option(label, value);
    status.append(option);
  });
  status.value = current;
  const note = document.createElement("textarea");
  note.rows = 3;
  note.maxLength = 2000;
  note.placeholder = "What did you check? Add context for future review.";
  note.value = record.review_note || "";
  const decisionLabel = text("label", "Decision");
  decisionLabel.append(status);
  const verdict = document.createElement("select");
  if (entity === "alert") {
    [["", "No verdict"], ["true_positive", "True positive"],
      ["false_positive", "False positive"], ["expected_behavior", "Expected behavior"],
      ["inconclusive", "Inconclusive"]]
      .forEach(([value, label]) => verdict.append(new Option(label, value)));
    verdict.value = record.review_verdict || "";
  }
  const noteLabel = text("label", "Analyst note");
  noteLabel.append(note);
  panel.append(decisionLabel);
  if (entity === "alert") {
    const verdictLabel = text("label", "Human verdict for linked flows");
    verdictLabel.append(verdict);
    panel.append(verdictLabel);
  }
  panel.append(noteLabel);
  panel.append(text("p", "TP, FP and expected-behavior verdicts inform P2P report accuracy. In review, resolved without a verdict, and inconclusive do not confirm a detection. Conflicting verdicts suspend learning. For an alert with several evidence types, review each evidence before confirming its detector.", "muted"));
  const feedback = text("p", "", "review-feedback");
  feedback.setAttribute("role", "alert");
  feedback.hidden = true;
  panel.append(feedback);
  status.addEventListener("change", () => {
    const required = entity === "alert" && status.value === "resolved";
    note.required = required;
    noteLabel.firstChild.textContent = required ? "Analyst note (required to resolve)" : "Analyst note";
    feedback.hidden = true;
  });
  status.dispatchEvent(new Event("change"));
  const actions = document.createElement("div");
  actions.className = "review-actions";
  const save = text("button", "Save review", "secondary");
  save.type = "button";
  save.disabled = !state.reviewAvailable;
  save.addEventListener("click", async () => {
    if (entity === "alert" && status.value === "resolved" && !note.value.trim()) {
      feedback.textContent = "Add an analyst note before resolving this alert.";
      feedback.hidden = false;
      note.focus();
      return;
    }
    save.disabled = true;
    try {
      const result = await saveReviewChange(entity, { action: "review", id: identifier,
        status: status.value, verdict: entity === "alert" ? verdict.value : "",
        note: note.value });
      feedback.hidden = true;
      toast(result.p2p_feedback_note || (result.p2p_feedback === "pending"
        ? "Review saved. P2P feedback is queued for retry."
        : status.value === "resolved"
        ? "Review saved. The alert is now in Resolved; use the Review filter to see it."
        : "Review saved."));
      await refreshAfterReview(entity);
    } catch (error) {
      feedback.textContent = error.message;
      feedback.hidden = false;
    }
    finally { save.disabled = false; }
  });
  const depth = document.createElement("select");
  const depths = entity === "alert"
    ? [["alert", "Alert only"], ["evidence", "Alert + unshared evidence"],
      ["flows", "Alert + unshared evidence + flows"]]
    : [["evidence", "Evidence only"], ["flows", "Evidence + unshared flows"]];
  depths.forEach(([value, label]) => depth.append(new Option(label, value)));
  const remove = text("button", "Delete…", "secondary review-delete");
  remove.type = "button";
  remove.disabled = !state.reviewAvailable;
  remove.addEventListener("click", async () => {
    if (!note.value.trim()) { toast("Add a deletion reason first."); return; }
    const label = depth.selectedOptions[0].textContent;
    if (!window.confirm(`Permanently delete ${label.toLowerCase()}? Shared records will be kept.`)) return;
    remove.disabled = true;
    try {
      const result = await saveReviewChange(entity, { action: "delete", id: identifier,
        depth: depth.value, note: note.value });
      toast(`Deleted. ${result.evidence_removed} evidence and ${result.flows_removed} flow rows removed; ${result.shared_preserved} shared evidence kept.`);
      await refreshAfterReview(entity);
    } catch (error) { toast(error.message); }
    finally { remove.disabled = false; }
  });
  actions.append(save, depth, remove);
  panel.append(actions);
  return panel;
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
  const add = (value, direction, label, ruleType = "ip") => {
    if (value === null || value === undefined || value === "" || choices.size >= 200) return;
    const key = String(value);
    const existing = choices.get(key);
    if (existing?.label === "Profile host IP" && direction !== "both") {
      choices.set(key, { direction, label, ruleType });
      return;
    }
    choices.set(key, {
      direction: existing && existing.direction !== direction ? "both" : direction,
      label: existing?.label || label,
      ruleType,
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
      if (flow.uri && String(flow.uri).startsWith("/")) {
        add(String(flow.uri), "both", "Request URI", "uri");
      }
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
  const choices = whitelistSuggestions(record, groups);
  choices.forEach((choice, value) => {
    const option = document.createElement("option");
    option.value = value;
    option.label = `${choice.label} · ${choice.direction}`;
    option.dataset.direction = choice.direction;
    option.dataset.ruleType = choice.ruleType;
    list.append(option);
  });
  const quick = editor.querySelector(".whitelist-quick-values");
  if (!quick) return;
  quick.replaceChildren();
  const ranked = [...choices.entries()].sort(([leftValue, left], [rightValue, right]) => {
    const rank = (value, choice) => choice.label.includes("Flow destination IP and port") ? 0
      : choice.ruleType === "uri" ? 1 : value.startsWith("*:") ? 2
        : choice.label.includes("IP and port") ? 3
          : choice.label.includes("Flow source IP") ? 4 : 5;
    return rank(leftValue, left) - rank(rightValue, right);
  });
  ranked.slice(0, 5).forEach(([suggestion]) => {
    const chip = text("button", suggestion, "whitelist-quick-value");
    chip.type = "button";
    chip.title = choices.get(suggestion).label;
    chip.addEventListener("click", () => {
      const input = editor.querySelector(".whitelist-form input[list]");
      input.value = suggestion;
      input.dispatchEvent(new Event("input"));
      input.focus();
    });
    quick.append(chip);
  });
}

/** Build an IP or request URI whitelist editor for the tab or evidence.
 * @param {string} kind - Unique list prefix for tab or evidence.
 * @param {object|null} record - Individual evidence, if available.
 * @returns {Element} Editor with its own submit handler.
 */
function whitelistEditor(kind, record = null, host = null) {
  const section = document.createElement("section");
  section.className = "surface whitelist-editor";
  section.append(
    text("h3", host ? "Whitelist this host" : record ? "Whitelist future matches from this evidence" : "Add a whitelist rule"),
    text("p", "Choose an IP, port, or request URI. URI rules suppress matching future flows and their detections regardless of IP or port. Existing evidence stays in the record.", "muted"),
  );
  const form = document.createElement("form");
  form.className = "whitelist-form";
  if (record) section.append(text("div", "", "whitelist-quick-values"));
  const ruleTypeLabel = document.createElement("label");
  ruleTypeLabel.append(text("span", "Rule type"));
  const ruleType = document.createElement("select");
  [["ip", "IP or port"], ["uri", "Request URI"]].forEach(([key, label]) => {
    const option = text("option", label);
    option.value = key;
    ruleType.append(option);
  });
  ruleTypeLabel.append(ruleType);
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
  if (host) {
    value.value = host.ip;
    direction.value = "both";
  }
  value.addEventListener("input", () => {
    const selected = Array.from(list.options).find((option) => option.value === value.value);
    if (selected) {
      ruleType.value = selected.dataset.ruleType || "ip";
      ruleType.dispatchEvent(new Event("change"));
      direction.value = selected.dataset.direction;
    }
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
  ruleType.addEventListener("change", () => {
    const uri = ruleType.value === "uri";
    allAddresses.disabled = uri;
    if (uri) allAddresses.checked = false;
    valueLabel.querySelector("span").textContent = uri ? "Request URI" : "IP or port";
    value.maxLength = uri ? 256 : 128;
    value.placeholder = uri ? "/info?txtAirPlay&txtRAOP RTSP/1." : "192.168.1.10:443 or *:443";
    directionLabel.hidden = uri;
    ignoreLabel.hidden = uri;
    typeLabel.hidden = uri;
    if (uri) {
      direction.value = "both";
      ignored.value = "flows";
      evidenceType.value = "";
      ignored.disabled = false;
    }
  });
  const save = text("button", "Add rule", "secondary");
  save.type = "submit";
  const feedback = text("p", "Rules take effect for future traffic and detections while Slips is running.", "muted whitelist-feedback");
  const deviceAddresses = state.deviceView && host ? (host.device_ips || host.all_ips || [host.ip]) : [];
  const allAddresses = document.createElement("input");
  allAddresses.type = "checkbox";
  allAddresses.addEventListener("change", () => {
    value.disabled = allAddresses.checked;
    ruleType.disabled = allAddresses.checked;
  });
  if (deviceAddresses.length > 1) {
    const deviceLabel = text("label", "");
    deviceLabel.append(allAddresses, text("span", `Apply to all ${deviceAddresses.length} known device addresses`));
    form.append(deviceLabel);
    section.append(text("p", "This saves a separate rule for each listed address. New addresses require their own rule.", "muted"));
  }
  form.append(ruleTypeLabel, valueLabel, list, directionLabel, ignoreLabel, typeLabel, save);
  section.append(form, feedback);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    feedback.textContent = "Saving rule…";
    try {
      const values = allAddresses.checked ? deviceAddresses : [value.value];
      const saved = [];
      for (const address of values) {
        const result = await saveWhitelistRule({
          action: "add", rule_type: allAddresses.checked ? "ip" : ruleType.value,
          value: address, direction: direction.value,
          ignore: ignored.value, evidence_type: evidenceType.value,
        });
        saved.push(result.value);
        feedback.textContent = `${saved.join(", ")} saved to the configured whitelist file.`;
      }
      feedback.textContent += " New matching activity will be suppressed within a few seconds.";
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
  const rows = sortLocalRows("whitelists-table", (payload.rules || []).filter((rule) =>
    (!type || rule.type === type) && (!query || JSON.stringify(rule).toLowerCase().includes(query))));
  byId("whitelists-count").textContent = `${rows.length} shown · ${payload.total} parsed local rules`;
  renderTable("whitelists-table", rows, [
    (row) => text("span", row.type, "type-chip"),
    (row) => row.type === "MAC address" ? macIdentity(row.value) : text("code", row.value),
    (row) => row.type === "Request URI" ? "Request" : row.direction === "both" ? "Source or destination" : row.direction === "src" ? "Source" : "Destination",
    (row) => row.type === "Request URI" ? "Flow and detections" : row.ignore === "both" ? "Flows and alerts" : row.ignore === "alerts" ? "Evidence and alerts" : "Flows",
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
            action: "remove", rule_type: row.type === "Request URI" ? "uri" : "ip",
            value: row.value, direction: row.direction,
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
  if (state.localSorts["firewall-table"].key) {
    params.set("sort", state.localSorts["firewall-table"].key);
    params.set("order", state.localSorts["firewall-table"].order);
  }
  params.set("history_sort", state.localSorts["firewall-history-table"].key);
  params.set("history_order", state.localSorts["firewall-history-table"].order);
  const historyPage = state.pages.firewall;
  const historyCursor = historyPage.cursors[historyPage.index];
  if (historyCursor) params.set("history_offset", historyCursor);
  const payload = await api("firewall", `/api/firewall?${params}`);
  if (!payload) return;
  state.firewall = payload;
  renderFirewall(payload);
}

/** Render sorted active firewall rules and their paged transition history.
 * @param {object} payload Current firewall API response.
 */
function renderFirewall(payload) {
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
  const rules = sortLocalRows("firewall-table", payload.items.map((row) => ({
    ...row,
    origin: row.recovered
      ? `${row.recovery_status || "Recovered"}${row.origin_run ? ` · ${row.origin_run}` : ""}`
      : "Current run",
  })));
  renderTable("firewall-table", rules, [
    (row) => deviceIdentity(row),
    (row) => text("span", row.status, `status ${["blocked", "overdue", "stale"].includes(row.status) ? "bad" : "warn"}`),
    (row) => row.origin,
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
  const history = sortLocalRows("firewall-history-table", payload.history || []);
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
      (row) => macIdentity(row.mac),
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

/** Plot measured reliability, matching the peers table's Reliability column.
 * @param {Array<object>} history - Retained reliability samples per peer.
 * @param {Array<object>} peers - Peer identities shown in the table.
 */
function renderP2PReliabilityChart(history, peers) {
  const rows = history.filter((row) => row.timestamp !== null && row.timestamp !== undefined
    && row.reliability !== null && row.reliability !== undefined
    && Number.isFinite(Number(row.timestamp))
    && Number.isFinite(Number(row.reliability)));
  const peerIds = [...new Set(rows.map((row) => String(row.peer_id)))];
  const peerIndexes = new Map(peerIds.map((peerId, index) => [peerId, index]));
  const peerIps = new Map(peers.map((peer) => [String(peer.peer_id), peer.ip]));
  const points = rows.map((row) => ({
    ts: numeric(row.timestamp),
    [`peer_${peerIndexes.get(String(row.peer_id))}`]: numeric(row.reliability),
  })).sort((left, right) => left.ts - right.ts);
  if (state.p2p?.trust_range === "all" && points.length) {
    const firstDetected = Math.min(...peers.map((peer) => numeric(peer.first_seen))
      .filter((timestamp) => timestamp > 0));
    if (Number.isFinite(firstDetected) && firstDetected < points[0].ts) {
      points.unshift({ ts: firstDetected });
    }
  }
  const series = peerIds.map((peerId, index) => ({
    key: `peer_${index}`,
    className: `peer-trust-line-${index % 8}`,
    label: `${peerIps.get(peerId) || "Unknown IP"} · ${shortPeerId(peerId)}`,
  }));
  const minimumReliability = rows.length
    ? Math.max(0, Math.floor((Math.min(...rows.map((row) => Number(row.reliability))) - 0.01) * 10) / 10)
    : 0;
  renderLineChart(
    "p2p-trust-chart",
    points,
    series,
    (value) => numeric(value).toFixed(3),
    minimumReliability,
  );
  const legend = byId("p2p-trust-legend");
  legend.replaceChildren();
  peerIds.forEach((peerId, index) => {
    const item = document.createElement("span");
    item.className = "p2p-trust-legend-item";
    const marker = document.createElement("i");
    marker.className = `peer-trust-key peer-trust-line-${index % 8}`;
    if (peerIps.get(peerId)) item.append(marker, hostIdentity(peerIps.get(peerId)),
      text("code", shortPeerId(peerId)));
    else item.append(marker, text("code", shortPeerId(peerId)));
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

/** Keep today's P2P table timestamps compact while retaining older dates.
 * @param {number|string} value Unix timestamp to display.
 * @returns {string} Local time for today or full date and time for older events.
 */
function formatP2PTime(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 946684800) return formatTime(value);
  const date = new Date(amount * 1000);
  return date.toDateString() === new Date().toDateString()
    ? date.toLocaleTimeString() : formatTime(value);
}

/** Apply the selected report/message filter and render the sortable table. */
function renderP2PMessages() {
  const payload = state.p2p || {};
  const filter = byId("p2p-message-filter").value;
  const rows = p2pMessageRows(payload);
  const visible = rows.filter((row) => {
    if (state.p2pSelectedPeer && row.peer !== state.p2pSelectedPeer.peer_id
      && row.peer !== state.p2pSelectedPeer.ip) return false;
    if (filter === "all") return true;
    if (filter === "reports") return ["report", "blame"].includes(row.message_type);
    if (filter === "received-report") return row.direction === "received"
      && row.message_type === "report";
    if (filter === "sent-report") return row.direction === "sent"
      && row.message_type === "report";
    return row.message_type === filter;
  });
  const sorted = sortLocalRows("p2p-activity-table", visible);
  const shown = sorted.slice(0, state.p2pVisibleMessages);
  byId("p2p-message-count").textContent = `${shown.length} shown · ${visible.length} matching · ${rows.length} retained`;
  const peerFilter = byId("p2p-peer-filter");
  peerFilter.hidden = !state.p2pSelectedPeer;
  peerFilter.replaceChildren();
  if (state.p2pSelectedPeer) {
    peerFilter.append(text("span", `Peer: ${state.p2pSelectedPeer.ip || "Unknown IP"} · ${shortPeerId(state.p2pSelectedPeer.peer_id)}`));
    const clear = text("button", "×");
    clear.type = "button";
    clear.title = "Show messages from all peers";
    clear.addEventListener("click", () => {
      state.p2pSelectedPeer = null;
      state.p2pVisibleMessages = 12;
      renderP2PPeers();
      renderP2PMessages();
    });
    peerFilter.append(clear);
  }
  document.querySelectorAll("[data-p2p-filter]").forEach((button) => {
    const active = button.dataset.p2pFilter === filter;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  const more = byId("p2p-load-more");
  more.hidden = shown.length >= sorted.length;
  more.textContent = `Load more (${sorted.length - shown.length} remaining)`;
  renderTable("p2p-activity-table", shown, [
    (row) => formatP2PTime(row.timestamp),
    (row) => row.direction,
    (row) => row.message_type,
    (row) => p2pPeerIdentity(row.peer),
    (row) => hostOrText(row.target),
    (row) => row.score === null || row.score === undefined ? "—" : numeric(row.score).toFixed(3),
    (row) => row.confidence === null || row.confidence === undefined
      ? "—" : numeric(row.confidence).toFixed(3),
  ], openP2PMessage);
  document.querySelectorAll("#p2p-activity-table tbody tr[data-clickable]").forEach((row, index) => {
    row.dataset.messageKey = p2pMessageKey(shown[index]);
    row.classList.toggle("selected", row.dataset.messageKey === state.p2pSelectedMessage);
  });
  const selected = rows.find((row) => p2pMessageKey(row) === state.p2pSelectedMessage);
  renderP2PMessageDetail(selected || null);
}

/** Identify a message across refreshes without depending on its array position.
 * @param {object} record Retained message or stored report.
 * @returns {string} Stable selection key.
 */
function p2pMessageKey(record) {
  return JSON.stringify([record.timestamp, record.report_time, record.direction,
    record.message_type, record.peer, record.target]);
}

/** Return retained content or report fields that survived in the trust database.
 * @param {object} record Selected message or report.
 * @returns {object} Content available for display and copying.
 */
function p2pMessageContent(record) {
  return record.message && typeof record.message === "object"
    ? record.message : record.archived_report
      ? { key: record.target, evaluation: { score: record.score, confidence: record.confidence } }
      : record;
}

/** Show a message sender with its known peer address and host name.
 * @param {string} peerId Sender peer ID or broadcast marker.
 * @returns {HTMLElement} Sender label for the activity table.
 */
function p2pPeerIdentity(peerId) {
  const wrapper = document.createElement("span");
  wrapper.className = "p2p-activity-peer";
  if (peerId === "*") {
    wrapper.textContent = "* all peers";
    return wrapper;
  }
  const id = text("code", shortPeerId(peerId));
  id.title = peerId || "";
  wrapper.append(id);
  const match = state.p2p?.peers?.find((peer) => peer.peer_id === peerId);
  if (match?.ip) wrapper.append(hostIdentity(match.ip));
  return wrapper;
}

/** Display a selected message beside the activity table.
 * @param {object|null} record Selected message, if any.
 */
function renderP2PMessageDetail(record) {
  const panel = byId("p2p-message-detail");
  panel.replaceChildren();
  if (!record) {
    panel.append(text("p", "Select a message to inspect its content.", "muted"));
    return;
  }
  const heading = document.createElement("div");
  heading.className = "p2p-detail-heading";
  const title = document.createElement("div");
  title.append(text("h3", `Message · ${formatTime(record.timestamp)}`),
    text("strong", `${record.message_type} · ${record.direction}`));
  const copy = text("button", "Copy JSON", "secondary");
  copy.type = "button";
  copy.addEventListener("click", () => copyP2PText(JSON.stringify(p2pMessageContent(record), null, 2), "Message JSON"));
  heading.append(title, copy);
  panel.append(heading);
  const peerAddress = state.p2p?.peers?.find((peer) => peer.peer_id === record.peer)?.ip;
  const facts = [
    ["Time", formatTime(record.timestamp)],
    ["Direction", record.direction],
    ["Type", record.message_type],
    ["Peer", record.peer === "*" ? "* (broadcast to all peers)" :
      `${shortPeerId(record.peer)}${peerAddress ? ` · ${peerAddress}` : ""}`],
    ["Target", record.target || "—"],
    ["Maliciousness score (1 = fully malicious)", record.score === null || record.score === undefined ? "—" : numeric(record.score).toFixed(3)],
    ["Confidence", record.confidence === null || record.confidence === undefined
      ? "—" : numeric(record.confidence).toFixed(3)],
  ];
  if (record.report_time) facts.splice(1, 0, ["Peer report time", formatTime(record.report_time)]);
  const list = document.createElement("dl");
  list.className = "p2p-message-facts";
  facts.forEach(([label, value]) => list.append(text("dt", label), text("dd", value)));
  panel.append(list, text("h4", record.archived_report ? "Stored report fields" : "Payload"));
  if (record.archived_report) panel.append(text("p", "The original message is no longer retained; these report fields remain in the trust database.", "muted"));
  panel.append(text("pre", JSON.stringify(p2pMessageContent(record), null, 2), "p2p-message-content"));
}

/** Select a message for inline inspection.
 * @param {object} record Selected message.
 */
function openP2PMessage(record) {
  state.p2pSelectedMessage = p2pMessageKey(record);
  renderP2PMessageDetail(record);
  document.querySelectorAll("#p2p-activity-table tbody tr[data-clickable]").forEach((row) => {
    row.classList.toggle("selected", row.dataset.messageKey === state.p2pSelectedMessage);
  });
}

/** Copy a P2P identifier or payload to the clipboard.
 * @param {string} value Text to copy.
 * @param {string} label User-facing content label.
 * @returns {Promise<void>} Completes after reporting the copy result.
 */
async function copyP2PText(value, label) {
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value);
    else {
      const input = document.createElement("textarea");
      input.value = value;
      input.style.position = "fixed";
      input.style.opacity = "0";
      document.body.append(input);
      input.select();
      const copied = document.execCommand("copy");
      input.remove();
      if (!copied) throw new Error("Browser denied clipboard access");
    }
    toast(`${label} copied`);
  } catch {
    toast(`Could not copy ${label.toLowerCase()}`);
  }
}

/** Render peers with address, state, trust and reliability.
 * Selecting a row filters the message table to that peer.
 */
function renderP2PPeers() {
  const peers = sortLocalRows("p2p-peers-table", state.p2p?.peers || []);
  byId("p2p-peer-count").textContent = String(peers.length);
  renderTable("p2p-peers-table", peers, [
    (row) => row.ip ? hostIdentity(row.ip) : text("span", "Unknown IP", "muted"),
    (row) => { const id = text("code", shortPeerId(row.peer_id), "p2p-short-id"); id.title = row.peer_id || ""; return id; },
    (row) => text("span", row.connected ? "connected" : "offline", `status ${row.connected ? "ok" : "warn"}`),
    (row) => {
      if (row.trust === null || row.trust === undefined) return "—";
      const value = text("code", numeric(row.trust).toFixed(3));
      value.title = "Slips peer trust calculated from reliability and local reputation";
      return value;
    },
    (row) => {
      const value = document.createElement("div");
      value.className = "p2p-reliability";
      value.append(text("code", row.reliability === null || row.reliability === undefined
        ? "—" : numeric(row.reliability).toFixed(3)));
      const track = document.createElement("span");
      track.className = "p2p-reliability-track";
      const fill = document.createElement("span");
      fill.style.width = `${Math.max(0, Math.min(100, numeric(row.reliability) * 100))}%`;
      track.append(fill);
      value.append(track);
      return value;
    },
    (row) => compact(row.reports_received),
    (row) => {
      const items = row.report_accuracy || [];
      if (!items.length) return text("span", "Not validated", "muted");
      const value = text("span", `TP ${row.confirmed_reports || 0} · FP ${row.false_reports || 0}`);
      value.title = items.map((item) => `${item.evidence_type} · ${item.rule_version.slice(0, 8)}: ${item.confirmed} TP, ${item.false_positive} FP, trust adjustment ${item.adjustment.toFixed(3)}`).join("\n");
      return value;
    },
    (row) => formatP2PTime(row.last_seen),
  ], (row) => {
    state.p2pSelectedPeer = state.p2pSelectedPeer?.peer_id === row.peer_id ? null : row;
    state.p2pVisibleMessages = 12;
    renderP2PPeers();
    renderP2PMessages();
  });
  document.querySelectorAll("#p2p-peers-table tbody tr[data-clickable]").forEach((row, index) => {
    row.classList.toggle("selected", peers[index].peer_id === state.p2pSelectedPeer?.peer_id);
  });
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
    ? `Collaborative intelligence · ${counts.connected} of ${counts.known || 0} known peers connected`
    : "P2P is running and listening; no peers are connected now.";
  byId("p2p-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  const reliability = (payload.peers || []).filter((peer) => peer.reliability !== null
    && peer.reliability !== undefined).map((peer) => Number(peer.reliability))
    .filter((value) => Number.isFinite(value));
  const average = reliability.length
    ? (reliability.reduce((sum, value) => sum + value, 0) / reliability.length).toFixed(2) : "—";
  setSummaryCards([
    ["Connected peers", `${compact(counts.connected)} / ${compact(counts.known)}`],
    ["Reports sent", compact(counts.reports_sent)],
    ["Reports received", compact(counts.reports_received)],
    ["Requests sent / received", `${compact(counts.requests_sent)} / ${compact(counts.requests_received)}`],
    ["Average reliability", average],
  ], "p2p-summary");
  const identity = byId("p2p-identity");
  identity.replaceChildren();
  [["Local peer ID", payload.local_peer_id || "Waiting for Pigeon identity"],
    ["Listen address", payload.listener || "Waiting for listener announcement"]].forEach(([label, value]) => {
    const line = document.createElement("div");
    line.className = "p2p-identity-row";
    const code = text("code", label === "Local peer ID" ? shortPeerId(value) : shortP2PAddress(value));
    code.title = value;
    const copy = text("button", "Copy", "p2p-copy-link");
    copy.type = "button";
    copy.addEventListener("click", () => copyP2PText(value, label));
    line.append(text("span", label), code, copy);
    identity.append(line);
  });
  renderP2PReliabilityChart(payload.trust_history || [], payload.peers || []);
  renderP2PPeers();
  renderP2PMessages();
}

async function loadHosts() {
  const page = state.pages.hosts;
  const revision = page.revision;
  const generation = (page.refreshGeneration || 0) + 1;
  page.refreshGeneration = generation;
  page.refreshing = true;
  state.requests.get("hostsMore")?.abort();
  state.requests.get("hostsRefreshMore")?.abort();
  const path = listPath("hosts");
  const wanted = Math.max(100, page.items.length);
  const scroll = document.querySelector(".hosts-list-table").scrollTop;
  const valid = () => page.refreshGeneration === generation
    && page.revision === revision && listPath("hosts") === path;
  try {
    const payload = await api("hosts", path);
    if (!payload || !valid()) return;
    const rows = [...payload.items];
    const known = new Set(rows.map((row) => row.device_id || row.ip));
    let next = payload.next_cursor;
    /** Publish the first fresh page before waiting for previously loaded pages. */
    const publish = () => {
      payload.items = [...rows];
      payload.page_size = rows.length;
      payload.next_cursor = next;
      rows.forEach(rememberHostRecord);
      refreshHostLabels();
      applyPage("hosts", payload);
      renderHostFilterChips(payload);
      renderHostsPage();
      document.querySelector(".hosts-list-table").scrollTop = scroll;
    };
    // Preserve a scrolled inventory while its later pages are revalidated.
    const published = !scroll || page.items.length <= rows.length;
    if (published) publish();
    let extended = false;
    while (rows.length < wanted && next) {
      const params = new URLSearchParams(path.split("?", 2)[1]);
      params.set("cursor", next);
      const following = await api("hostsRefreshMore", `/api/hosts?${params}`);
      if (!following || !valid()) return;
      following.items.forEach((row) => {
        const key = row.device_id || row.ip;
        if (!known.has(key)) { known.add(key); rows.push(row); }
      });
      extended = true;
      if (following.next_cursor === next) break;
      next = following.next_cursor;
    }
    if (extended || !published) publish();
  } finally {
    if (page.refreshGeneration === generation) page.refreshing = false;
  }
}

/** Append the next server page while keeping the initial Hosts load bounded. */
async function loadMoreHosts() {
  const page = state.pages.hosts;
  if (!page.next || page.loadingMore || page.refreshing) return;
  page.loadingMore = true;
  const revision = page.revision;
  const params = new URLSearchParams(listPath("hosts").split("?", 2)[1]);
  params.set("cursor", page.next);
  try {
    const payload = await api("hostsMore", `/api/hosts?${params}`);
    if (!payload || page.revision !== revision) return;
    payload.items.forEach(rememberHostRecord);
    const known = new Set(page.items.map((row) => row.ip));
    page.items.push(...payload.items.filter((row) => !known.has(row.ip)));
    page.next = payload.next_cursor;
    page.total = payload.total;
    renderHostsPage();
  } finally {
    if (page.revision === revision) page.loadingMore = false;
  }
}

/** Fetch the next Hosts page when the table scrolls near its end. */
function maybeLoadMoreHosts() {
  if (state.activeTab !== "hosts" || state.host || byId("hosts-list-view").hidden) return;
  const table = document.querySelector(".hosts-list-table");
  if (table.scrollTop + table.clientHeight >= table.scrollHeight - 250) {
    loadMoreHosts().catch(() => {});
  }
}

/** Show every loaded host with compact score and identity columns. */
function renderHostsPage() {
  const page = state.pages.hosts;
  renderTable("hosts-table", page.items, [
    (row) => hostIdentity(row.ip),
    (row) => {
      const value = document.createElement("span");
      value.className = "hosts-mac-vendor";
      if (row.mac_vendor) {
        const vendor = text("strong", row.mac_vendor);
        vendor.title = row.mac_vendor;
        value.append(vendor);
      }
      value.append(macIdentity(row.mac));
      return value;
    },
    (row) => text("span", row.scope || "—", `hosts-scope-${row.scope || "unknown"}`),
    (row) => hostPeakScoreCell(row),
    (row) => compact(row.load?.flows),
    (row) => formatBytes(row.load?.bytes),
    (row) => compact(row.evidence_count),
    (row) => compact(row.alert_count),
    (row) => formatShortTime(row.last_seen || row.load?.last_seen || row.observed_at),
    (row) => row.hostname || "—",
    (row) => tiFeeds(row),
    (row) => slipsScore(row),
    (row) => HOST_REVIEW_LABELS[row.user_status] || "Unmarked",
    (row) => (row.user_labels || []).join(", ") || "—",
  ], (row) => openHost(row.ip, row));
  document.querySelectorAll("#hosts-table tbody tr").forEach((row) => {
    ["hostname", "ti", "score"].forEach((key, index) => {
      const td = row.cells[9 + index];
      if (td) td.hidden = !document.querySelector(`[data-host-column="${key}"]`).checked;
    });
  });
  const shown = page.items.length;
  const unit = state.deviceView ? "devices" : "hosts";
  byId("hosts-count").textContent = `${compact(page.total)} ${unit} · sorted by ${page.sort.replaceAll("_", " ")}`;
  byId("hosts-list-status").textContent = `${shown} of ${compact(page.total)} ${unit} loaded${page.next ? " · scroll for more" : ""} · threshold line at ${numeric(page.items[0]?.alert_threshold).toFixed(1)} · current score on hover`;
  byId("hosts-more").hidden = !page.next;
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
  const noFindings = row.has_findings === false || (row.has_findings === undefined
    && !numeric(row.evidence_count) && !numeric(row.alert_count) && !numeric(peak));
  const label = text("span", noFindings ? "No evidence" : level,
    `hosts-threat-level${noFindings ? " muted" : ` threat-${level}`}`);
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
  const ranks = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const groups = [
    ["hosts-threat-chips", "hosts-threat", [["", "All"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["info", "Info"], ["critical_or_more", "Critical+"], ["high_or_more", "High+"], ["medium_or_more", "Medium+"], ["low_or_more", "Low+"], ["info_or_more", "Info+"]], "max_threat_level"],
    ["hosts-scope-chips", "hosts-scope", [["", "All scopes"], ["local", "Local"], ["public", "Public"]], "scope"],
  ];
  groups.forEach(([targetId, selectId, options, field]) => {
    const target = byId(targetId);
    const select = byId(selectId);
    target.replaceChildren();
    options.forEach(([value, label]) => {
      const completePage = payload.items.length === payload.total;
      const minimum = value.replace("_or_more", "");
      const count = !value || select.value === value ? payload.total
        : payload.items.filter((row) => {
          if (field === "max_threat_level" && row.has_findings === false) return false;
          const rowValue = String(row[field] || "info").toLowerCase();
          return field === "max_threat_level" && value.endsWith("_or_more")
            ? (ranks[rowValue] ?? 0) >= ranks[minimum] : rowValue === value;
        }).length;
      const showCount = !value || select.value === value
        || (completePage && !byId("hosts-threat").value && !byId("hosts-scope").value);
      const button = text("button", `${label}${showCount ? ` ${compact(count)}` : ""}`, `hosts-filter-chip ${select.value === value ? "active" : ""}`);
      button.type = "button";
      button.addEventListener("click", () => {
        select.value = value;
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
  ["alertDetail", "alertGroup", "evidenceGroup", "hostFlowDetail"].forEach((key) =>
    state.requests.get(key)?.abort());
}

/** Show whether the current investigation has a previous drawer panel. */
function updateDrawerBackButton() {
  const returnToEvidence = byId("drawer").classList.contains("alert-over-evidence")
    && Boolean(state.evidenceDetail.record);
  const back = byId("drawer-back");
  back.hidden = state.drawerHistory.length === 0 && !returnToEvidence;
  back.textContent = state.drawerHistory.length ? "← Back" : "← Back to evidence";
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
  if (!previous) {
    if (byId("drawer").classList.contains("alert-over-evidence")) closeDrawer();
    return;
  }
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
  byId("drawer").classList.remove("alert-over-evidence");
  byId("drawer").setAttribute("aria-hidden", "true");
  byId("drawer-backdrop").classList.remove("open");
  byId("drawer-backdrop").classList.remove("alert-over-evidence");
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
  details.append(summary);
  details.addEventListener("toggle", () => {
    if (details.open && !details.querySelector("pre")) {
      details.append(text("pre", JSON.stringify(displayData(record), null, 2)));
    }
  });
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

/** Create one accessible card for an individual evidence record.
 * @param {object} record Durable evidence record.
 * @param {object[]|null} contextRecords Records for previous/next navigation.
 * @param {boolean} inAlertPane Whether selection opens beside its parent alert.
 * @returns {HTMLElement} Evidence card.
 */
function evidenceCard(record, contextRecords = null, inAlertPane = false) {
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
  button.addEventListener("click", () => openEvidence(record, contextRecords, inAlertPane).catch(() => {}));
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
    ["Destination IP", ["daddr", "dst_ip", "resp_h"]],
    ["Source IP", ["saddr", "src_ip", "orig_h"]],
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
    field.className = "protocol-field" + (/query|host|uri|server name|destination ip/i.test(label) ? " important" : "");
    const isAddress = type === "arp" && /^(?:Source|Destination) IP$/.test(label);
    field.append(text("small", label), isAddress ? hostLink(value)
      : /(?:MAC|hardware)$/.test(label) ? macIdentity(value) : text("strong", value));
    grid.append(field);
  });
  card.append(heading, context, grid, rawBlock(record, displayType + " protocol flow"));
  return card;
}

/** Show nonduplicate stored fields in a compact table, with empty fields on demand.
 * @param {object} flow Parsed Zeek flow fields.
 * @param {string[]} displayedFields Fields already shown in the flow summary.
 * @returns {HTMLElement} Additional field table and empty-field toggle.
 */
function flowFieldList(flow, displayedFields = []) {
  const container = document.createElement("div");
  container.className = "evidence-flow-fields";
  const omitted = new Set(displayedFields);
  const fields = Object.entries(flow || {}).filter(([key]) => !omitted.has(key));
  if (!fields.length) return container;
  const empty = ([, value]) => value === "" || value === null || value === undefined
    || (Array.isArray(value) && value.length === 0);
  const populated = fields.filter((item) => !empty(item));
  const emptyFields = fields.filter(empty);
  const heading = text("h5", "Additional fields", "evidence-flow-fields-title");
  const table = document.createElement("table");
  table.className = "evidence-flow-table";
  const tbody = document.createElement("tbody");
  const appendRows = (items, hidden) => {
    for (let index = 0; index < items.length; index += 2) {
      const row = document.createElement("tr");
      row.hidden = hidden;
      if (hidden) row.dataset.empty = "true";
      const pair = items.slice(index, index + 2);
      pair.forEach(([key, value]) => {
        const label = text("th", key.replaceAll("_", " "));
        label.scope = "row";
        const cell = text("td", "");
        cell.append(!hidden && /^(?:[sd]mac|(?:src|dst|sender|target)_hw|(?:src|dst|client|server|gateway)_mac|mac(?:_addr(?:ess)?)?)$/i.test(key)
          ? macIdentity(value) : document.createTextNode(hidden ? "—" : protocolValueText(key, value)));
        if (pair.length === 1) cell.colSpan = 3;
        row.append(label, cell);
      });
      tbody.append(row);
    }
  };
  appendRows(populated, false);
  appendRows(emptyFields, true);
  table.append(tbody);
  container.append(heading, table);
  const emptyCount = emptyFields.length;
  if (emptyCount) {
    const toggle = text("button", `Show ${emptyCount} empty fields`, "evidence-flow-empty-toggle");
    toggle.type = "button";
    let showing = false;
    toggle.addEventListener("click", () => {
      showing = !showing;
      tbody.querySelectorAll('[data-empty="true"]').forEach((row) => { row.hidden = !showing; });
      toggle.textContent = `${showing ? "Hide" : "Show"} ${emptyCount} empty fields`;
    });
    container.append(toggle);
  }
  return container;
}

/** Create one primary network-flow card with selectable protocol records.
 * @param {object} group Connection and related protocol records sharing a UID.
 * @param {number} position Position of this flow in the evidence.
 * @param {number} total Total triggering flows shown for the evidence.
 * @param {string|null} title Optional heading outside an evidence investigation.
 * @returns {HTMLElement} Complete flow inspector.
 */
function flowCard(group, position = 1, total = 1, title = null) {
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
  const uid = group.uid || record?.uid || flow.uid || "Unknown UID";
  heading.append(text("strong", title || `Triggering flow · ${position} of ${total}`));
  if (related.length) heading.append(text("span", `${related.length} related protocol ${related.length === 1 ? "flow" : "flows"}`, "flow-related-count"));
  const flowActions = document.createElement("div");
  flowActions.className = "evidence-flow-actions";
  flowActions.append(text("code", `UID ${uid}`));
  const copy = text("button", "Copy", "evidence-detail-link");
  copy.type = "button";
  copy.addEventListener("click", () => copyP2PText(uid, "Flow UID"));
  flowActions.append(copy);
  heading.append(flowActions);
  card.append(heading);
  let path = null;
  let metrics = null;
  if (record) {
    const srcIp = flowValue(flow, "saddr", "src_ip", "id.orig_h");
    const dstIp = flowValue(flow, "daddr", "dst_ip", "id.resp_h");
    const srcPort = flowValue(flow, "sport", "src_port", "id.orig_p");
    const dstPort = flowValue(flow, "dport", "dst_port", "id.resp_p");
    const packets = flowValue(flow, "pkts", "packets")
      ?? numeric(flowValue(flow, "spkts")) + numeric(flowValue(flow, "dpkts"));
    const bytes = flowValue(flow, "bytes")
      ?? numeric(flowValue(flow, "sbytes")) + numeric(flowValue(flow, "dbytes"));
    path = document.createElement("div");
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
    metrics = document.createElement("div");
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
    card.append(path);
  } else {
    card.append(text(
      "p",
      "The primary flow row is unavailable, but related protocol flows were retained.",
      "flow-missing",
    ));
  }
  const tabs = document.createElement("div");
  tabs.className = "evidence-flow-tabs";
  tabs.setAttribute("role", "tablist");
  tabs.setAttribute("aria-label", `Records for flow ${position}`);
  const panels = document.createElement("div");
  panels.className = "evidence-flow-panels";
  const entries = [];
  if (record) {
    entries.push(["conn · flow", () => {
      const connection = document.createElement("div");
      const displayed = ["uid", "starttime", "ts", "endtime", "saddr", "src_ip", "id.orig_h",
        "daddr", "dst_ip", "id.resp_h", "sport", "src_port", "id.orig_p", "dport",
        "dst_port", "id.resp_p", "proto", "protocol", "appproto", "app_proto", "service",
        "state", "conn_state", "pkts", "packets", "spkts", "dpkts", "bytes", "sbytes",
        "dbytes", "dur", "duration", "label", "interface"];
      connection.append(metrics, flowFieldList(flow, displayed), rawBlock(record, "flow"));
      return connection;
    }]);
  }
  related.forEach((protocol, index) => {
    const type = protocolType(protocol);
    entries.push([`Related ${type.toUpperCase()} · ${index + 1}`, () => {
      const panel = document.createElement("div");
      const displayed = ["uid", "starttime", "ts", "type", "type_",
        ...(PROTOCOL_FIELDS[type] || []).flatMap(([, names]) => names)];
      panel.append(protocolFlowCard(protocol), flowFieldList(protocol.flow || protocol, displayed));
      return panel;
    }]);
  });
  const initialIndex = record && related.length ? 1 : 0;
  entries.forEach(([label, build], index) => {
    const panel = document.createElement("div");
    let rendered = false;
    const show = () => {
      if (!rendered) {
        panel.append(build());
        rendered = true;
      }
    };
    const tab = text("button", label, index === initialIndex ? "active" : "");
    tab.type = "button";
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-selected", String(index === initialIndex));
    panel.setAttribute("role", "tabpanel");
    panel.hidden = index !== initialIndex;
    if (!panel.hidden) show();
    tab.addEventListener("click", () => {
      show();
      tabs.querySelectorAll("[role=tab]").forEach((button) => {
        button.classList.toggle("active", button === tab);
        button.setAttribute("aria-selected", String(button === tab));
      });
      panels.querySelectorAll(":scope > [role=tabpanel]").forEach((item) => {
        item.hidden = item !== panel;
      });
    });
    tabs.append(tab);
    panels.append(panel);
  });
  if (entries.length) card.append(tabs, panels);
  return card;
}

/** Return from a full-page evidence investigation to its previous view.
 * @param {boolean} restoreFocus Whether to focus the opening control.
 * @param {boolean} closeAll Whether to discard nested evidence navigation.
 */
function closeEvidenceDetail(restoreFocus = true, closeAll = false) {
  if (!state.evidenceDetail.record) return;
  state.requests.get("evidenceFlows")?.abort();
  state.evidenceDetail.generation += 1;
  const previous = closeAll ? null : state.evidenceDetail.history.pop();
  if (previous) {
    state.evidenceDetail.record = previous.record;
    state.evidenceDetail.records = previous.records;
    byId("evidence-detail-content").replaceChildren(...previous.nodes);
    if (byId("drawer").classList.contains("open")) {
      byId("drawer").classList.add("alert-over-evidence");
      byId("drawer-backdrop").classList.add("alert-over-evidence");
    }
    window.scrollTo(0, previous.scrollY);
    updateDrawerBackButton();
    return;
  }
  state.evidenceDetail.history = [];
  state.evidenceDetail.record = null;
  state.evidenceDetail.records = [];
  if (state.evidenceDetail.inPane) {
    const workspace = byId("evidence-workspace");
    workspace.classList.remove("has-detail");
    byId("evidence-detail-divider").hidden = true;
    document.querySelector("main").append(byId("evidence-detail"));
    state.evidenceDetail.inPane = false;
    state.evidenceWorkspace.record = null;
    highlightEvidenceSelection();
    renderEvidenceGroup();
  }
  if (state.evidenceDetail.inAlertPane) {
    document.querySelector("main").append(byId("evidence-detail"));
    state.evidenceDetail.inAlertPane = false;
    setAlertPaneCount(state.alertsWorkspace.grouping === "individual" ?
      state.alertsWorkspace.alert ? 2 : 1 :
      state.alertsWorkspace.alert ? 3 : state.alertsWorkspace.host ? 2 : 1);
  }
  byId("drawer").classList.remove("alert-over-evidence");
  byId("drawer-backdrop").classList.remove("alert-over-evidence");
  document.body.classList.remove("evidence-detail-active");
  byId("evidence-detail").hidden = true;
  byId("evidence-detail").classList.remove("active");
  byId("evidence-detail-content").replaceChildren();
  if (state.activeTab === "evidence" && !state.evidenceWorkspace.group) {
    state.evidenceWorkspace.record = null;
    highlightEvidenceSelection();
  }
  updateDrawerBackButton();
  if (restoreFocus) state.evidenceDetail.trigger?.focus?.({ preventScroll: true });
}

/** Make an evidence headline from the saved detection and its first connection.
 * @param {object} record Durable evidence record.
 * @param {object[]} groups Triggering flow groups, if loaded.
 * @returns {string} Concise description for the page banner.
 */
function evidenceDetailHeadline(record, groups = []) {
  if (record.evidence_type === "UNKNOWN_PORT") {
    const flow = groups[0]?.network_flow?.flow;
    const source = flowValue(flow, "saddr");
    const destination = flowValue(flow, "daddr");
    const port = flowValue(flow, "dport") ?? record.dst_port;
    const protocol = flowValue(flow, "proto") ?? record.proto;
    if (source && destination && port) {
      return `${source} connected to unknown port ${port}${protocol ? `/${String(protocol).toUpperCase()}` : ""} on ${state.ownAddresses.has(destination) ? "this device" : destination}`;
    }
  }
  return String(record.description || record.evidence_type || "Evidence")
    .split(/\.(?:\s|$)/)[0].slice(0, 180);
}

/** Open an evidence record in its investigation pane or full-width page.
 * @param {object} record Durable evidence record.
 * @param {object[]|null} contextRecords Ordered records for previous/next navigation.
 * @param {boolean} inAlertPane Whether to keep the parent alert beside the evidence.
 * @returns {Promise<void>} Completes after the triggering flows load.
 */
async function openEvidence(record, contextRecords = null, inAlertPane = false) {
  const detail = state.evidenceDetail;
  const drawer = byId("drawer");
  const cameFromDrawer = drawer.classList.contains("open");
  if (detail.record && drawer.classList.contains("alert-over-evidence")) {
    detail.history.push({
      record: detail.record,
      records: detail.records,
      nodes: Array.from(byId("evidence-detail-content").childNodes),
      scrollY: window.scrollY,
    });
    drawer.classList.remove("alert-over-evidence");
    byId("drawer-backdrop").classList.remove("alert-over-evidence");
  }
  if (!detail.record) detail.trigger = document.activeElement;
  const groupRecords = state.evidenceWorkspace.records;
  const pageRecords = state.pages.evidence.items;
  const context = contextRecords || (
    groupRecords.some((item) => item.id === record.id) ? groupRecords
      : pageRecords.some((item) => item.id === record.id) ? pageRecords : [record]
  );
  if (state.activeTab === "evidence"
      && (context === groupRecords || context === pageRecords)) {
    state.evidenceWorkspace.record = record;
    if (state.evidenceWorkspace.group) {
      document.querySelectorAll("#evidence-right .evidence-record-row").forEach((button) => {
        button.classList.toggle("selected", button.dataset.evidenceId === record.id);
      });
    } else highlightEvidenceSelection();
  }
  detail.records = context;
  detail.record = record;
  const generation = ++detail.generation;
  const position = context.findIndex((item) => item.id === record.id);
  const page = byId("evidence-detail");
  const content = byId("evidence-detail-content");
  const inPane = !inAlertPane && state.activeTab === "evidence" && (detail.inPane || !cameFromDrawer);
  if (inPane) {
    const workspace = byId("evidence-workspace");
    workspace.classList.add("has-detail");
    byId("evidence-detail-divider").hidden = false;
    workspace.append(page);
  }
  if (inAlertPane) {
    setAlertPaneCount(state.alertsWorkspace.grouping === "individual" ? 3 : 4);
    byId("alerts-evidence-pane").append(page);
  }
  detail.inPane = inPane;
  detail.inAlertPane = inAlertPane;
  page.hidden = false;
  page.classList.add("active");
  document.body.classList.toggle("evidence-detail-active", !inPane && !inAlertPane);
  content.replaceChildren();
  if (inPane || inAlertPane) page.scrollTop = 0;
  else window.scrollTo(0, 0);

  const toolbar = document.createElement("div");
  toolbar.className = "evidence-detail-toolbar";
  const breadcrumb = document.createElement("div");
  breadcrumb.className = "evidence-detail-breadcrumb";
  const back = text("button", inAlertPane || cameFromDrawer ? "← Back to alert" : inPane ? "← Close record" : "← Back to evidence", "evidence-detail-link");
  back.type = "button";
  back.addEventListener("click", closeEvidenceDetail);
  breadcrumb.append(back, text("span", "›"),
    text("span", `${record.profile_ip || "Unknown host"} · ${record.evidence_type || "Evidence"}`),
    text("span", "›"), text("code", record.id || ""));
  const controls = document.createElement("div");
  controls.className = "evidence-detail-controls";
  if (context.length > 1 && position >= 0) {
    controls.append(text("span", `Record ${position + 1} of ${context.length}`, "muted"));
    [["↑ prev", position - 1], ["next ↓", position + 1]].forEach(([label, index]) => {
      const button = text("button", label, "secondary");
      button.type = "button";
      button.disabled = index < 0 || index >= context.length;
      button.addEventListener("click", () => openEvidence(context[index], context, inAlertPane).catch(() => {}));
      controls.append(button);
    });
  }
  const close = text("button", "×", "secondary evidence-detail-close");
  close.type = "button";
  close.setAttribute("aria-label", "Close evidence details");
  close.addEventListener("click", closeEvidenceDetail);
  controls.append(close);
  toolbar.append(breadcrumb, controls);

  const banner = document.createElement("section");
  banner.className = `evidence-detail-banner threat-${String(record.threat_level || "info").toLowerCase()}`;
  const bannerCopy = document.createElement("div");
  const meta = document.createElement("div");
  meta.className = "evidence-detail-meta";
  meta.append(text("span", record.evidence_type || "EVIDENCE", "type-chip"),
    text("span", record.module || "Unknown module"),
    text("span", formatTime(record.timestamp)),
    text("span", record.twid || record.timewindow?.number || "—"),
    networkContext(record));
  const headline = text("h2", evidenceDetailHeadline(record));
  bannerCopy.append(meta, headline, hostDescription(record, "evidence-detail-description"));
  const bannerStats = document.createElement("div");
  bannerStats.className = "evidence-detail-stats";
  bannerStats.append(investigationStats([
    ["Threat", threat(record.threat_level)],
    ["Host score", slipsScore(record)],
    ["Confidence", `${Math.round(numeric(record.confidence) * 100)}%`],
  ]));
  const alertCount = record.alert_ids?.length || 0;
  if (alertCount) bannerStats.append(text("span", `Part of ${compact(alertCount)} alert${alertCount === 1 ? "" : "s"}`, "evidence-detail-alert-count"));
  banner.append(bannerCopy, bannerStats);

  const columns = document.createElement("div");
  columns.className = "evidence-detail-columns";
  const flowSection = document.createElement("section");
  flowSection.className = "evidence-detail-flows";
  const flowHeading = investigationHeading("Triggering flows", "Each flow includes its related parsed protocol records.");
  const flowList = document.createElement("div");
  flowList.className = "evidence-detail-flow-list";
  flowList.append(text("p", "Loading triggering flows…", "muted"));
  flowSection.append(flowHeading, flowList);
  const side = document.createElement("aside");
  side.className = "evidence-detail-side";
  const recordCard = document.createElement("section");
  recordCard.className = "surface evidence-detail-record";
  const recordHead = document.createElement("div");
  recordHead.className = "evidence-detail-record-head";
  recordHead.append(text("h3", "Evidence record"));
  const recordActions = document.createElement("div");
  const copyId = text("button", "Copy ID", "evidence-detail-link");
  copyId.type = "button";
  copyId.addEventListener("click", () => copyEvidenceId(record.id)
    .catch(() => toast("Could not copy the evidence ID.")));
  recordActions.append(copyId);
  recordHead.append(recordActions);
  recordCard.append(recordHead,
    detailRow("Evidence ID", text("code", record.id || "—")),
    detailRow("Detected", formatTime(record.timestamp)),
    detailRow("Profile host", hostLink(record.profile_ip)),
    detailRow("Network", networkContext(record)),
    detailRow("Time window", record.twid || record.timewindow?.number || "—"),
    detailRow("Module", record.module || "—"),
    detailRow("Method", record.method || "—"),
    detailRow("Signal", record.evidence_signal || "—"),
    detailRow("Protocol", record.proto || "—"),
    detailRow("Source port", record.src_port ?? "—"),
    detailRow("Destination port", record.dst_port ?? "—"));
  if (record.evidence_type === "MALICIOUS_IP_FROM_P2P_NETWORK") {
    recordCard.append(detailRow("Reporting peers", reportingPeers(record)));
  }
  if (record.attacker) recordCard.append(evidenceEntity("Attacker / source", record.attacker));
  if (record.victim) recordCard.append(evidenceEntity("Victim / destination", record.victim));
  if (alertCount) {
    const links = document.createElement("div");
    links.className = "evidence-detail-alert-links";
    record.alert_ids.forEach((id) => {
      const button = text("button", id, "evidence-detail-link");
      button.type = "button";
      button.addEventListener("click", () => {
        openAlert({ alert_id: id }).catch(() => {});
      });
      links.append(button);
    });
    recordCard.append(detailRow("Alerts", links));
  } else recordCard.append(detailRow("Alerts", "None"));
  const whitelistSection = whitelistEditor("evidence-detail", record);
  side.append(recordCard, reviewEditor("evidence", record), whitelistSection);
  const json = document.createElement("section");
  json.className = "surface evidence-detail-json";
  json.append(rawBlock(record, "evidence"));
  const showJson = text("button", "JSON", "evidence-detail-link");
  showJson.type = "button";
  showJson.addEventListener("click", () => {
    json.querySelector("details").open = true;
    json.scrollIntoView({ block: "nearest" });
  });
  recordActions.append(showJson);
  side.append(json);
  columns.append(flowSection, side);
  content.append(toolbar, banner, columns);

  if (record.whitelisted) {
    const notice = document.createElement("section");
    notice.className = "whitelist-notice";
    notice.append(text("h3", "Excluded from scoring by whitelist"),
      text("p", "Slips retained this evidence for visibility, but a whitelist rule prevented it from raising the host score or an alert."));
    const matches = Array.isArray(record.whitelist_matches) ? record.whitelist_matches : [];
    if (matches.length) {
      const list = document.createElement("ul");
      matches.forEach((match) => list.append(text("li",
        `${match.entity} ${match.type.toLowerCase()} ${match.value} matched rule ${match.rule} (${match.direction}; suppress ${match.ignore}).`)));
      notice.append(list);
    } else notice.append(text("p", "The matching entity is unavailable in the retained evidence data.", "muted"));
    flowSection.prepend(notice);
  }
  const portScan = ["HORIZONTAL_PORT_SCAN", "VERTICAL_PORT_SCAN"].includes(String(record.evidence_type).toUpperCase());
  if (portScan) flowHeading.querySelector("p").textContent = "Port-scan evidence links at most 20 flows; each includes related protocol records.";
  if (String(record.evidence_type).toUpperCase() === "ARP_SCAN") {
    const count = numeric(record.flow_count);
    flowList.before(text("p", `ARP scan rule: at least 5 requests to 5 distinct destination IPs within 30 seconds. ${count < 5 ? `This legacy evidence retains only ${count} linked ARP records because its ARP records had no unique UIDs; it was not detected from one packet.` : `This evidence retains ${count} linked ARP records.`}`, count < 5 ? "flow-missing" : "muted"));
  }
  const flowStatus = text("p", "", "muted evidence-flow-status");
  const flowItems = document.createElement("div");
  const moreFlows = text("button", "Load more triggering flows", "secondary");
  moreFlows.type = "button";
  moreFlows.hidden = true;
  let cursor = "";
  let loaded = 0;
  let unavailable = 0;
  let recovered = 0;
  let pendingFlows = [];
  let pageMetadata = {};
  const suggestions = [];
  const loadFlowPage = async () => {
    moreFlows.disabled = true;
    try {
      const params = new URLSearchParams({ limit: "20" });
      if (cursor) params.set("cursor", cursor);
      const payload = pendingFlows.length
        ? { ...pageMetadata, items: pendingFlows.splice(0, 20), recovered_flow_count: 0, unavailable_flow_count: 0 }
        : await api("evidenceFlows", `/api/evidence/${escapePath(record.id)}/flows?${params}`);
      if (!payload || generation !== detail.generation) return;
      if (payload.items.length > 20) {
        pendingFlows = payload.items.slice(20);
        payload.items = payload.items.slice(0, 20);
      }
      pageMetadata = { ...payload, items: [] };
      if (!loaded && !cursor) flowList.replaceChildren(flowStatus, flowItems, moreFlows);
      const batch = document.createDocumentFragment();
      payload.items.forEach((flow, index) => batch.append(
        flowCard(flow, loaded + index + 1, payload.linked_uid_count),
      ));
      flowItems.append(batch);
      loaded += payload.items.length;
      unavailable += numeric(payload.unavailable_flow_count);
      recovered += numeric(payload.recovered_flow_count);
      suggestions.push(...payload.items.slice(0, Math.max(0, 20 - suggestions.length)));
      updateWhitelistSuggestions(whitelistSection, record, suggestions);
      headline.textContent = evidenceDetailHeadline(record, suggestions);
      cursor = payload.next_cursor || "";
      moreFlows.hidden = !cursor && !pendingFlows.length;
      moreFlows.textContent = "Load more triggering flows";
      flowStatus.textContent = `${compact(loaded)} of ${compact(payload.linked_uid_count)} linked flows loaded`
        + (unavailable ? ` · ${compact(unavailable)} unavailable in loaded pages` : "")
        + (recovered ? ` · ${compact(recovered)} recovered from Zeek logs` : "");
      if (!payload.linked_uid_count) {
        flowStatus.textContent = record.evidence_type === "PASSWORD_GUESSING"
          && String(record.description || "").includes("Zeek notice.log")
          ? "Zeek's password-guessing notice supplied no connection IDs. Its sessions cannot be recovered from this notice."
          : "No triggering flow records are available.";
      }
    } catch (_) {
      if (generation !== detail.generation) return;
      if (!loaded) flowList.replaceChildren(flowStatus, flowItems, moreFlows);
      flowStatus.textContent = "Triggering flows could not be loaded. Retry loading this page.";
      moreFlows.hidden = false;
      moreFlows.textContent = "Retry loading flows";
    } finally {
      moreFlows.disabled = false;
    }
  };
  moreFlows.addEventListener("click", loadFlowPage);
  await loadFlowPage();
}

async function openAlert(record) {
  const generation = openDrawer("ALERT", "Alert details");
  if (state.evidenceDetail.record) {
    byId("drawer").classList.add("alert-over-evidence");
    byId("drawer-backdrop").classList.add("alert-over-evidence");
    updateDrawerBackButton();
  }
  const body = byId("drawer-body");
  if (record.evidence === undefined) {
    body.append(text("p", "Loading alert evidence…", "muted"));
    const params = new URLSearchParams({
      range: "all", review: "all", limit: "1", search: record.alert_id,
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
  record.evidence?.forEach((item) => evidenceList.append(evidenceCard(item, record.evidence)));
  body.append(
    reviewEditor("alert", record),
    evidenceList,
    investigationHeading("Complete alert data", "Original durable alert object and evidence links"),
    rawBlock(record, "alert"),
  );
}

function hostRangeParams() {
  const params = rangeQuery("host");
  if (state.hideExcluded) params.set("hide_excluded", "1");
  return params;
}

/**
 * Show host clues saved across runs, separated by local network.
 * @param {Object[]} profiles Permanent host records for this IP.
 * @param {HTMLElement|null} currentEditorTarget Editor location in the identity card.
 */
function renderPermanentProfiles(profiles, currentEditorTarget = null, currentNetworkId = null) {
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
    mdns_hostname: "mDNS address record owners",
    mdns_name: "Old mDNS question associations · ownership unverified", sni: "HTTPS SNI",
    http_host: "HTTP hosts", url: "Requested URLs", mac: "MAC addresses",
    asn: "ASN", country: "Country",
    threat_feed: "Threat feed appearances",
  };
  profiles.forEach((profile, index) => {
    const group = document.createElement("section");
    group.className = "permanent-host-profile";
    const title = text("strong", `Network: ${profile.network_label || profile.network_id}`);
    group.append(title);
    const observation = hostProfileNetworkObservation(profile);
    group.append(text("small", observation.label, "host-network-observation muted"));
    group.append(text("small", `Record first saved ${formatTime(profile.first_seen)} · Last updated ${formatTime(profile.last_seen)}`, "muted"));
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
    const deviceMac = (profile.facts || []).filter((fact) => fact.kind === "mac")
      .sort((a, b) => Number(b.last_seen || 0) - Number(a.last_seen || 0))
      .map((fact) => String(fact.value || "").toLowerCase())
      .find((mac) => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)
        && mac !== "00:00:00:00:00:00" && !(parseInt(mac.slice(0, 2), 16) & 1));
    const nameScope = text("small", "", "muted host-name-scope");
    if (deviceMac && profile.network_id !== "public") {
      nameScope.append("Name and note follow MAC ", macIdentity(deviceMac), " across its observed IP addresses.");
    } else {
      nameScope.textContent = "No device MAC recorded. Name and note are saved on this network profile; a confirmed mDNS hostname can link addresses with unknown MACs.";
    }
    const noteLabel = text("label", "Note");
    const noteInput = document.createElement("textarea");
    noteInput.maxLength = 1000;
    noteInput.rows = 3;
    noteInput.placeholder = "How you recognize this host";
    noteInput.value = state.hostAnnotationDrafts.get(annotationKey)?.note ?? profile.user_note ?? "";
    const statusLabel = text("label", "Review mark");
    const statusInput = document.createElement("select");
    statusInput.setAttribute("aria-label", "Review mark");
    statusInput.append(new Option("Unmarked", ""), ...Object.entries(HOST_REVIEW_LABELS)
      .map(([value, label]) => new Option(label, value)));
    statusInput.value = state.hostAnnotationDrafts.get(annotationKey)?.status ?? profile.user_status ?? "";
    statusLabel.append(statusInput);
    const labelsLabel = text("label", "Labels (comma separated)");
    const labelsInput = document.createElement("input");
    labelsInput.type = "text";
    labelsInput.maxLength = 410;
    labelsInput.placeholder = "e.g. investigate, printer, lab";
    labelsInput.value = state.hostAnnotationDrafts.get(annotationKey)?.labels ?? (profile.user_labels || []).join(", ");
    labelsLabel.append(labelsInput);
    const rememberDraft = () => state.hostAnnotationDrafts.set(annotationKey, {
      name: nameInput.value, note: noteInput.value, status: statusInput.value, labels: labelsInput.value,
    });
    statusInput.addEventListener("change", rememberDraft);
    labelsInput.addEventListener("input", rememberDraft);
    nameInput.addEventListener("input", rememberDraft);
    noteInput.addEventListener("input", rememberDraft);
    nameLabel.append(nameInput);
    noteLabel.append(noteInput);
    const annotationSave = text("button", "Save host review", "secondary");
    annotationSave.type = "submit";
    const annotationFeedback = text("small", "", "network-name-feedback");
    annotation.append(statusLabel, labelsLabel, nameLabel, nameScope, noteLabel, annotationSave, annotationFeedback);
    const annotationEdit = text("button", profile.user_name || profile.user_note
      ? "Edit host review and identity" : "Mark or name this host", "secondary profile-network-name-action");
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
            status: statusInput.value,
            labels: labelsInput.value.split(",").map((label) => label.trim()).filter(Boolean),
          }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
        profile.user_name = payload.name;
        profile.user_note = payload.note;
        profile.user_status = payload.status;
        profile.user_labels = payload.labels;
        state.hostAnnotationDrafts.delete(annotationKey);
        state.hostAnnotationEditorOpen.delete(annotationKey);
        if (!state.host || state.host.ip !== profile.ip) return;
        const currentProfile = state.host.permanent_profiles?.find(
          (item) => item.network_id === profile.network_id,
        );
        if (currentProfile) {
          currentProfile.user_name = payload.name;
          currentProfile.user_note = payload.note;
          currentProfile.user_status = payload.status;
          currentProfile.user_labels = payload.labels;
        }
        if ((hostVisibleProfiles(state.host)[0]?.network_id || state.host.annotation_profile?.network_id) === profile.network_id) {
          state.host.user_name = payload.name;
          state.host.user_note = payload.note;
          state.host.user_status = payload.status;
          state.host.user_labels = payload.labels;
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
        toast("Host review and identity saved.");
      } catch (error) {
        annotationFeedback.textContent = error.message;
        annotationSave.disabled = false;
      }
    });
    if (profile.user_name) group.append(text("p", `Custom name: ${profile.user_name}`, "host-user-name"));
    if (profile.user_note) group.append(text("p", profile.user_note, "host-user-note"));
    if (currentEditorTarget && (currentNetworkId === null ? index === 0 : profile.network_id === currentNetworkId)) {
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
        title.textContent = `Network: ${profile.network_label}`;
        renderHostNetworkClues(hostVisibleProfiles(state.host));
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
        : ["hostname", "mdns_hostname", "mdns_name", "dns_name"].includes(kind);
      const summary = document.createElement("summary");
      summary.append(text("span", label), text("span", compact(values.length), "count-chip"));
      details.append(summary);
      const list = document.createElement("ul");
      values.forEach((fact) => {
        const item = document.createElement("li");
        item.append(kind === "mac" ? macIdentity(fact.value) : text("span", fact.value, "host-profile-value"));
        item.append(text("small", `Seen ${compact(fact.observations)}× · ${formatTime(fact.first_seen)} to ${formatTime(fact.last_seen)}`, "muted"));
        list.append(item);
      });
      details.append(list);
      group.append(details);
    });
    container.append(group);
  });
}

/** Describe the evidence for associating the selected device with a network.
 * @param {object} profile One network-scoped IP history and its identity facts.
 * @returns {object} Display text, supported observation range and summary eligibility.
 */
function hostProfileNetworkObservation(profile) {
  const selectedMac = normalizeMac(state.host?.mac);
  const macFacts = (profile.facts || []).filter((fact) => fact.kind === "mac"
    && ["locally_administered", "universally_administered"].includes(classifyMac(fact.value)))
    .sort((left, right) => numeric(right.last_seen) - numeric(left.last_seen));
  const mac = normalizeMac(macFacts[0]?.value);
  if (selectedMac && mac === selectedMac && profile.network_id !== "public") {
    const matches = macFacts.filter((fact) => normalizeMac(fact.value) === selectedMac);
    const knownNetwork = String(profile.network_id || "").startsWith("gateway:");
    return { verified: knownNetwork, source: "mac", label: knownNetwork
      ? "Matching device MAC observed on this network."
      : "Matching device MAC recorded in an unidentified capture. Network identity is unverified.",
      first: Math.min(...matches.map((fact) => numeric(fact.first_seen))),
      last: Math.max(...matches.map((fact) => numeric(fact.last_seen))) };
  }
  if (selectedMac && mac && mac !== selectedMac) {
    return { verified: false, differentDevice: true,
      label: "A different device MAC was recorded for this IP on this network." };
  }
  if (profile.endpoint_last_seen !== null && profile.endpoint_last_seen !== undefined) {
    return { verified: !selectedMac, source: "traffic", first: profile.endpoint_first_seen, last: profile.endpoint_last_seen,
      label: "IP traffic was captured from this network. Device attachment is unverified." };
  }
  return { verified: false,
    label: "Device presence is unverified. Saved address metadata alone does not establish a network visit." };
}

/** Summarize supported device observations, keeping address metadata in history. */
function renderHostNetworkClues(profiles) {
  const mdns = byId("host-mdns-names");
  const networks = byId("host-networks-seen");
  mdns.replaceChildren();
  networks.replaceChildren();
  const names = new Map();
  profiles.filter((profile) => !hostProfileNetworkObservation(profile).differentDevice)
    .forEach((profile) => (profile.facts || []).forEach((fact) => {
    if (fact.kind !== "mdns_hostname" || !fact.value) return;
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
  if (!sortedNames.length) mdns.append(text("p", "No mDNS address record owners recorded.", "muted"));
  if (sortedNames.length > 4) mdns.append(text("small", `+ ${sortedNames.length - 4} more saved names`, "muted"));
  const observed = profiles.map((profile) => ({ profile, observation: hostProfileNetworkObservation(profile) }))
    .filter(({ observation }) => observation.verified);
  observed.slice(0, 4).forEach(({ profile, observation }) => {
    const row = document.createElement("div");
    row.className = "host-clue-row";
    row.title = observation.label;
    row.append(text("strong", profile.network_label || profile.network_id || "Unidentified network"),
      text("small", `${observation.source === "mac" ? "MAC observed" : "IP traffic"} · ${new Date(numeric(observation.first) * 1000).toLocaleDateString()} – ${new Date(numeric(observation.last) * 1000).toLocaleDateString()}`));
    networks.append(row);
  });
  if (!observed.length) networks.append(text("p", "No verified device network history recorded.", "muted"));
  if (observed.length > 4) networks.append(text("small", `+ ${observed.length - 4} more verified networks`, "muted"));
  if (profiles.length > observed.length) networks.append(text("small",
    `${profiles.length - observed.length} unverified address histories are available below.`, "muted"));
}

/** Select identity observations for the active network, retaining the full archive separately.
 * @param {object|null} host Host workspace data.
 * @returns {object[]} Identity profiles visible beside current activity.
 */
function hostVisibleProfiles(host) {
  return state.networkOnly && state.networkFilterSupported && Array.isArray(host?.current_network_profiles)
    ? host.current_network_profiles : host?.permanent_profiles || [];
}

/** Describe capture activity separately from saved identity metadata.
 * @param {object} host Current host workspace data.
 */
function renderHostScope(host) {
  const scoped = state.networkOnly && state.networkFilterSupported;
  const capture = host.capture_network;
  const label = capture?.name || state.headerNetwork?.name || "current network";
  const identityNetwork = hostVisibleProfiles(host)[0]?.network_label || "identity network not recorded";
  const status = scoped && capture ? host.seen_on_current_network
    ? `Observed on ${label}` : `No observed activity on ${label}`
    : `${identityNetwork} · ${host.live ? "live metadata" : "saved metadata"}`;
  byId("host-subtitle").replaceChildren(
    document.createTextNode(`${host.scope || "unknown scope"} · ${status} · ${host.mac_vendor || "vendor unknown"} · `),
    host.mac ? macIdentity(host.mac) : document.createTextNode("MAC unknown"));
  byId("host-saved-history-label").textContent = scoped
    ? "History · saved identity clues from all networks" : "All saved identity clues and network names";
  const notice = byId("host-network-scope-note");
  notice.hidden = !scoped || host.seen_on_current_network !== false;
  notice.textContent = "No activity was observed for this host during the current network connection. Its saved identity history is available below; switch off Current network only to inspect older activity.";
}

const HOST_REVIEW_LABELS = { to_analyze: "To analyze", in_review: "Under review", reviewed: "Reviewed" };

function renderHostCards(host) {
  byId("host-title").replaceChildren(deviceIdentity(host));
  renderHostScope(host);
  const scopedProfiles = hostVisibleProfiles(host);
  const networkScoped = state.networkOnly && state.networkFilterSupported;
  const verifiedNetworks = (host.permanent_profiles || [])
    .filter((profile) => hostProfileNetworkObservation(profile).verified).length;
  const exactAggregates = host.exact_aggregates !== false;
  const findingsRange = byId("host-range").selectedOptions[0]?.textContent || "selected range";
  const findingsScope = `${findingsRange}${networkScoped ? " · current network" : ""}`;
  setSummaryCards([
    [`Alerts · ${findingsScope}`, exactAggregates ? compact(host.alert_count) : "—"],
    [`Evidence · ${findingsScope}`, exactAggregates ? compact(host.evidence_count) : "—"],
    [networkScoped ? "Flows in / out · current network" : "Flows in / out", exactAggregates ? compact(host.load?.flows) : "—"],
    [networkScoped ? "Traffic in / out · current network" : "Traffic in / out", exactAggregates ? formatBytes(host.load?.bytes) : "—"],
    [networkScoped ? "Packets · current network" : "Packets", exactAggregates ? compact(host.load?.packets) : "—"],
    [networkScoped ? "IP traffic observed" : host.mac ? "Verified device networks" : "IP capture networks", networkScoped
      ? host.seen_on_current_network ? "Current network" : "No current observations"
      : `${compact(verifiedNetworks)} network${verifiedNetworks === 1 ? "" : "s"}`],
  ], "host-summary");
  const summaryCards = byId("host-summary").children;
  summaryCards[2].append(text("small", `${compact(host.load?.inbound_flows)} in / ${compact(host.load?.outbound_flows)} out`));
  summaryCards[3].append(text("small", `${formatBytes(host.load?.inbound_bytes)} in / ${formatBytes(host.load?.outbound_bytes)} out`));
  byId("host-flows-tab-count").textContent = "";
  byId("host-alerts-tab-count").textContent = "";
  byId("host-evidence-tab-count").textContent = "";
  const scorePill = byId("host-score-pill");
  scorePill.replaceChildren(text("span", "Current "), slipsScore(host),
    text("span", " · Peak "), pastPeakSlipsScore(host));
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
      detailRow("Review", HOST_REVIEW_LABELS[host.user_status] || "Unmarked"),
      detailRow("Labels", (host.user_labels || []).join(", ") || "—"),
      detailRow("Note", host.user_note || "—"),
      ...((networkScoped ? scopedProfiles.length : host.permanent_profiles?.length) || host.annotation_profile?.network_id
        ? [detailRow("Edit identification", annotationEntry)] : []),
      detailRow("Hostname", host.hostname || "Unknown"),
      detailRow("MAC", macIdentity(host.mac)),
      detailRow("Vendor", host.mac_vendor || "Unknown"),
      detailRow("DNS", host.dns?.domains?.[0] || "No A/AAAA record"),
    );
    identity.dataset.profileIp = host.ip;
    refreshHostLabels();
  }
  renderPermanentProfiles(host.permanent_profiles?.length ? host.permanent_profiles
    : host.annotation_profile?.network_id ? [host.annotation_profile] : [], byId("host-annotation-entry"),
  networkScoped && Array.isArray(host.current_network_profiles) ? scopedProfiles[0]?.network_id || "" : null);
  renderHostNetworkClues(scopedProfiles);
  if (networkScoped && host.capture_network) {
    const networks = byId("host-networks-seen");
    networks.replaceChildren();
    if (host.seen_on_current_network) {
      const row = text("div", "", "host-clue-row");
      row.append(text("strong", host.capture_network.name || "Current monitored network"),
        text("small", `IP traffic observed ${formatTime(host.last_seen)}`));
      networks.append(row);
    } else networks.append(text("p", "No observations on the current network.", "muted"));
  }
  byId("host-dns-details").replaceChildren(renderDnsDetails(host.dns));
  byId("host-ti").textContent = Object.keys(host.ti || {}).length
    ? JSON.stringify(displayData(host.ti), null, 2)
    : "No cached threat-intelligence data.";
}

/** Show the selected host's alerts, evidence, or flows and load that page. */
function showHostActivity(name) {
  state.hostActivity = name;
  byId("host-activity-filter-notice").hidden = true;
  ["alerts", "evidence", "flows"].forEach((item) => {
    byId(`host-${item}-panel`).hidden = item !== name;
    const tab = document.querySelector(`[data-host-activity="${item}"]`);
    tab.classList.toggle("active", item === name);
    tab.setAttribute("aria-selected", String(item === name));
  });
  const choices = {
    alerts: [["type", "Evidence type"], ["threat", "Threat"], ["module", "Module"], ["review", "Review state"]],
    evidence: [["type", "Type"], ["threat", "Threat"], ["module", "Module"], ["handling", "Score handling"]],
    flows: [["protocol", "Protocol"], ["direction", "Direction"], ["peer", "Peer"], ["label", "Label"], ["state", "State"], ["threat", "Linked threat"]],
  };
  const grouping = byId("host-activity-group");
  grouping.replaceChildren(new Option("No grouping", ""),
    ...choices[name].map(([value, label]) => new Option(label, value)));
  grouping.value = state.hostActivityGroups[name];
  byId("host-activity-threat").value = state.hostActivityThreats[name];
  byId("host-activity-threat-label").firstChild.textContent = name === "flows" ? "Linked threat " : "Threat ";
  byId("host-alert-search").hidden = name !== "alerts";
  byId("host-evidence-search").hidden = name !== "evidence";
  byId("host-flow-search").hidden = name !== "flows";
  const note = byId("host-activity-group-note");
  note.hidden = !grouping.value;
  note.textContent = grouping.value ? "Groups in this page; filters cover the selected range" : "";
  if (!state.host) return Promise.resolve();
  return ({ alerts: loadHostAlerts, evidence: loadHostEvidence, flows: loadHostFlows })[name]().catch(() => {});
}

/** Explain saved activity filters without silently discarding user choices.
 * @param {string} kind Alerts or evidence activity pane.
 * @param {number} total Matching records returned by the server.
 */
function renderHostActivityFilterNotice(kind, total) {
  if (state.hostActivity !== kind) return;
  const notice = byId("host-activity-filter-notice");
  const search = byId(`host-${kind === "alerts" ? "alert" : "evidence"}-search`);
  const filters = [];
  if (state.hostActivityThreats[kind]) filters.push(`Threat: ${byId("host-activity-threat").selectedOptions[0]?.textContent}`);
  if (search.value.trim()) filters.push(`Search: ${search.value.trim()}`);
  notice.hidden = filters.length === 0;
  notice.replaceChildren();
  if (notice.hidden) return;
  const available = kind === "alerts" ? state.host?.alert_count : state.host?.evidence_count;
  notice.append(text("span", `${compact(total)} matching ${kind} · ${compact(available)} in this range. ${filters.join(" · ")}`));
  const clear = text("button", "Clear activity filters", "secondary");
  clear.type = "button";
  clear.addEventListener("click", () => {
    search.value = "";
    state.hostActivityThreats[kind] = "";
    resetPage(kind === "alerts" ? "hostAlerts" : "host-evidence");
    scheduleViewPreferencesSave();
    showHostActivity(kind);
  });
  notice.append(clear);
}

/** Return the label used to group one host activity record on the current page.
 * @param {string} kind Alerts, evidence, or flows.
 * @param {object} row One activity record.
 * @returns {string} Visible group label.
 */
function hostActivityGroupValue(kind, row) {
  const group = state.hostActivityGroups[kind];
  if (group === "threat") return row.threat_level || row.linked_threat_level || "No linked evidence";
  if (group === "type") {
    const types = alertEvidenceTypes(row);
    return kind === "alerts" ? types.length ? types.map((item) => item.type).join(" + ") : "Unknown type"
      : row.evidence_type || "Unknown type";
  }
  if (group === "module") {
    if (kind === "evidence") return row.module || "Unknown module";
    const modules = (row.evidence_modules || []).map((item) => item.module);
    return modules.length ? modules.join(" + ") : "Module unavailable";
  }
  if (group === "review") return (row.review_status || "active").replaceAll("_", " ");
  if (group === "handling") return row.whitelisted ? "Excluded" : "Scored";
  if (group === "protocol") return [row.proto, row.app_proto].filter(Boolean).join(" / ") || "Unknown protocol";
  if (group === "direction") return row.direction || "Unknown direction";
  if (group === "peer") return row.peer || "Unknown peer";
  if (group === "label") return row.label || "No label";
  if (group === "state") return row.state || "Unknown state";
  return "";
}

/** Keep records with the same visible group adjacent within one loaded page.
 * @param {string} kind Alerts, evidence, or flows.
 * @param {object[]} rows Records from the current page.
 * @returns {object[]} Page records with matching groups adjacent.
 */
function groupHostPageRows(kind, rows) {
  if (!state.hostActivityGroups[kind]) return rows;
  return rows.map((row, index) => ({ row, index })).sort((left, right) =>
    hostActivityGroupValue(kind, left.row).localeCompare(hostActivityGroupValue(kind, right.row))
      || left.index - right.index).map(({ row }) => row);
}

/** Add accessible group headings to a rendered host activity table.
 * @param {string} kind Evidence or flows.
 * @param {string} tableId Host activity table ID.
 * @param {object[]} rows Rendered records in their displayed order.
 */
function addHostTableGroups(kind, tableId, rows) {
  if (!state.hostActivityGroups[kind]) return;
  const body = byId(tableId).querySelector("tbody");
  const rendered = Array.from(body.children);
  const counts = new Map();
  rows.forEach((row) => {
    const label = hostActivityGroupValue(kind, row);
    counts.set(label, (counts.get(label) || 0) + 1);
  });
  let previous = null;
  rows.forEach((row, index) => {
    const label = hostActivityGroupValue(kind, row);
    if (label === previous) return;
    previous = label;
    const heading = document.createElement("tr");
    heading.className = "host-activity-group-row";
    const cell = document.createElement("th");
    cell.colSpan = byId(tableId).querySelectorAll("thead th").length;
    cell.scope = "rowgroup";
    cell.textContent = `${label} · ${counts.get(label)} on this page`;
    heading.append(cell);
    body.insertBefore(heading, rendered[index]);
  });
}

/** Filter the currently loaded flow rows without requesting a new server page. */
function filterVisibleHostFlows() {
  const query = byId("host-flow-search").value.trim().toLowerCase();
  document.querySelectorAll("#host-flows-table tbody tr:not(.host-activity-group-row)").forEach((row) => {
    row.hidden = Boolean(query) && !row.textContent.toLowerCase().includes(query);
  });
  document.querySelectorAll("#host-flows-table tbody .host-activity-group-row").forEach((row) => {
    let next = row.nextElementSibling;
    row.hidden = true;
    while (next && !next.classList.contains("host-activity-group-row")) {
      if (!next.hidden) row.hidden = false;
      next = next.nextElementSibling;
    }
  });
}

/** Load one bounded alert page for the exact host IP and selected time range. */
async function loadHostAlerts() {
  if (!state.host) return;
  const ip = state.host.ip;
  const page = state.pages.hostAlerts;
  const params = hostRangeParams();
  if (state.deviceView && state.host.device_id) params.set("device_id", state.host.device_id);
  else params.set("profile", ip);
  params.set("limit", "50");
  params.set("details", "false");
  params.set("summary", "1");
  params.set("modules", "1");
  if (state.hostActivityThreats.alerts) params.set("threat", state.hostActivityThreats.alerts);
  const search = byId("host-alert-search").value.trim();
  if (search) params.set("search", search);
  const liveRange = byId("host-range").value === "live";
  const newestSavedAlert = Math.max(0, ...(state.host.alerts || [])
    .filter((alert) => !state.deviceView || state.host.all_ips.includes(alert.ip_alerted))
    .map((alert) => numeric(alert.alert_time)));
  let showingEarlier = liveRange && !search && !state.hostActivityThreats.alerts && (page.index > 0
    || (numeric(state.host.alert_count) > 0 && newestSavedAlert > 0
      && newestSavedAlert < Date.now() / 1000 - 3600));
  if (showingEarlier) params.set("range", "all");
  if (page.cursors[page.index]) params.set("cursor", page.cursors[page.index]);
  let payload = await api("hostAlerts", `/api/alerts?${params}`);
  if (payload && !showingEarlier && liveRange && !search && !state.hostActivityThreats.alerts && page.index === 0
    && !numeric(payload.total) && numeric(state.host?.alert_count) > 0) {
    params.set("range", "all");
    payload = await api("hostAlerts", `/api/alerts?${params}`);
    showingEarlier = Boolean(payload?.total);
  }
  if (!payload || state.host?.ip !== ip) return;
  showingEarlier = showingEarlier && params.get("range") === "all";
  const alerts = payload.items.filter((item) =>
    !state.deviceView ? item.ip_alerted === ip : state.host.all_ips.includes(item.ip_alerted));
  page.items = alerts;
  page.total = payload.total;
  page.next = payload.next_cursor;
  byId("host-alerts-tab-count").textContent = showingEarlier
    ? `${compact(payload.total)} earlier` : compact(payload.total);
  byId("host-alerts-title").textContent = showingEarlier
    ? "Earlier alerts for this host" : "Alerts for this host";
  byId("host-alert-count").textContent = showingEarlier
    ? `${alerts.length} shown · ${compact(payload.total)} earlier alerts in the full run`
    : `${alerts.length} shown · ${compact(payload.total)} alerts in this range`;
  const list = byId("host-alerts");
  renderHostActivityFilterNotice("alerts", payload.total);
  list.replaceChildren();
  if (showingEarlier) {
    const context = document.createElement("div");
    context.className = "host-alert-history-context";
    context.append(text("span", "No alerts in Live. Showing earlier alerts from this run."));
    const allRange = document.createElement("button");
    allRange.type = "button";
    allRange.textContent = "Use Full run for all host data";
    allRange.addEventListener("click", () => {
      byId("host-range").value = "all";
      byId("host-range").dispatchEvent(new Event("change"));
    });
    context.append(allRange);
    list.append(context);
  }
  const groupedAlerts = groupHostPageRows("alerts", alerts);
  const groupCounts = new Map();
  groupedAlerts.forEach((item) => {
    const label = hostActivityGroupValue("alerts", item);
    groupCounts.set(label, (groupCounts.get(label) || 0) + 1);
  });
  let previousGroup = null;
  groupedAlerts.forEach((item) => {
    if (state.hostActivityGroups.alerts) {
      const label = hostActivityGroupValue("alerts", item);
      if (label !== previousGroup) list.append(text("h4", `${label} · ${groupCounts.get(label)} on this page`, "host-activity-group-heading"));
      previousGroup = label;
    }
    const button = document.createElement("button");
    button.type = "button";
    button.className = "host-alert-chip";
    button.classList.add(String(item.threat_level || "info").toLowerCase());
    button.append(
      text("time", formatTime(item.alert_time)),
      threat(item.threat_level),
      text("strong", alertComposition(item), "host-alert-label"),
      text("span", `${compact(item.evidence_count)} evidence`, "count-chip"),
    );
    if (item.summary && alertEvidenceTypes(item).length <= 1) {
      button.append(text("small", item.summary, "host-alert-summary"));
    }
    button.addEventListener("click", () => openAlert(item));
    list.append(button);
  });
  if (!alerts.length) list.append(text("p", "No alerts for this host in the selected range.", "muted"));
  pager("hostAlerts", "host-alerts-pager", loadHostAlerts);
}

async function loadHostEvidence() {
  if (!state.host) return;
  const ip = state.host.ip;
  const page = state.pages["host-evidence"];
  const params = hostRangeParams();
  params.set("limit", "100");
  params.set("sort", page.sort);
  params.set("order", page.order);
  const search = byId("host-evidence-search").value.trim();
  if (search) params.set("search", search);
  if (state.hostActivityThreats.evidence) params.set("threat", state.hostActivityThreats.evidence);
  if (page.cursors[page.index]) params.set("cursor", page.cursors[page.index]);
  if (state.deviceView && state.host.device_id) params.set("device_id", state.host.device_id);
  else params.set("profile", ip);
  params.set("details", "false");
  if (state.hideExcluded) params.set("hide_excluded", "1");
  const path = "/api/evidence?" + params;
  const payload = await api("hostEvidence", path);
  if (!payload || state.host?.ip !== ip) return;
  page.items = payload.items;
  page.total = payload.total;
  page.next = payload.next_cursor;
  byId("host-evidence-tab-count").textContent = compact(payload.total);
  renderHostActivityFilterNotice("evidence", payload.total);
  byId("host-evidence-title").textContent = "Related evidence · " + payload.total;
  byId("host-evidence-count").textContent =
    payload.page_size + " shown · " + compact(payload.total) + " evidence records" +
    (search ? " matching search" : "");
  const groupedRows = groupHostPageRows("evidence", payload.items);
  renderTable("host-evidence-table", groupedRows, [
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
  addHostTableGroups("evidence", "host-evidence-table", groupedRows);
  applySortIndicators("host-evidence");
  pager("host-evidence", "host-evidence-pager", loadHostEvidence);
}

async function loadHostFlows() {
  if (!state.host) return;
  const ip = state.host.ip;
  const page = state.pages.hostFlows;
  const params = hostRangeParams();
  params.set("limit", byId("host-flow-limit").value);
  params.set("sort", state.localSorts["host-flows-table"].key);
  params.set("order", state.localSorts["host-flows-table"].order);
  if (state.hostActivityThreats.flows) params.set("threat", state.hostActivityThreats.flows);
  if (state.hideExcluded) params.set("hide_excluded", "1");
  if (page.cursors[page.index]) params.set("cursor", page.cursors[page.index]);
  const path = `/api/hosts/${escapePath(ip)}/flows?${params}`;
  const payload = await api("hostFlows", path);
  if (!payload || state.host?.ip !== ip) return;
  const exactItems = payload.items.filter((row) =>
    row.src_ip === ip || row.dst_ip === ip);
  const discarded = payload.items.length - exactItems.length;
  page.items = exactItems;
  page.total = discarded ? exactItems.length : payload.total;
  page.next = payload.next_cursor;
  byId("host-flows-tab-count").textContent = compact(page.total);
  byId("host-flow-count").textContent =
    `${exactItems.length} shown · exact profile IP only` +
    (discarded ? ` · ${discarded} stale MAC-alias rows discarded` :
      ` · ${compact(payload.total)} flows match this range`);
  renderHostFlows();
}

/** Inspect a host-table flow with the shared connection and protocol cards.
 * @param {object} row Selected host flow, including its indexed context and raw data.
 */
async function openHostFlow(row) {
  const title = [row.app_proto, row.proto].filter(Boolean).join(" · ").toUpperCase();
  openDrawer("FLOW", `${title || "Flow"} · ${row.src_port ?? "—"} → ${row.dst_port ?? "—"}`);
  const container = document.createElement("section");
  container.className = "host-flow-inspector";
  const context = document.createElement("div");
  context.className = "host-flow-context";
  context.append(text("span", row.direction || "Flow", "status"), text("span", "Peer", "muted"), hostIdentity(row.peer));
  const contents = document.createElement("div");
  const group = { uid: row.uid, protocol_flows: [], network_flow: {
    uid: row.uid, table: "flows", event_time: row.event_time, label: row.label,
    flow: Object.keys(row.raw || {}).length ? row.raw : {
      uid: row.uid, starttime: row.event_time, saddr: row.src_ip, daddr: row.dst_ip,
      sport: row.src_port, dport: row.dst_port, proto: row.proto, appproto: row.app_proto,
      state: row.state, dur: row.duration, pkts: row.packets, bytes: row.bytes,
    },
  } };
  contents.append(flowCard(group, 1, 1, "Connection details"));
  const footer = document.createElement("div");
  footer.className = "host-flow-protocol-status";
  const status = text("span", "Loading related protocol records…", "muted");
  status.setAttribute("role", "status");
  const more = text("button", "Load related protocol records", "secondary");
  more.type = "button";
  footer.append(status, more);
  container.append(context, contents, footer);
  byId("drawer-body").append(container);
  let cursor = null;
  const loadProtocols = async () => {
    const generation = state.drawerGeneration;
    more.disabled = true;
    try {
      const params = new URLSearchParams({ limit: "20" });
      if (cursor) params.set("cursor", cursor);
      const payload = await api("hostFlowDetail", `/api/flows/${escapePath(row.uid)}?${params}`, false, true);
      if (!payload || generation !== state.drawerGeneration || !container.isConnected) return;
      if (payload.not_found) throw new Error("Flow detail endpoint unavailable");
      if (payload.network_flow && Object.keys(payload.network_flow.flow || {}).length) {
        group.network_flow = payload.network_flow;
      }
      group.protocol_flows.push(...(payload.protocol_flows || []));
      cursor = payload.next_cursor;
      const active = contents.querySelector('[role="tab"].active')?.textContent;
      contents.replaceChildren(flowCard(group, 1, 1, "Connection details"));
      if (active) [...contents.querySelectorAll('[role="tab"]')]
        .find((tab) => tab.textContent === active)?.click();
      const total = numeric(payload.protocol_flow_total);
      status.textContent = total
        ? `${group.protocol_flows.length} of ${compact(total)} related protocol records loaded`
        : "No related protocol records were stored for this UID.";
      more.textContent = "Load more protocol records";
      more.hidden = !cursor;
    } catch (_) {
      if (generation !== state.drawerGeneration || !container.isConnected) return;
      status.textContent = "Related protocol records could not be loaded. The connection details remain available.";
      more.textContent = "Retry loading protocol records";
      more.hidden = false;
    } finally {
      more.disabled = false;
    }
  };
  more.addEventListener("click", loadProtocols);
  await loadProtocols();
}

/** Sort and render the currently loaded host flow page.
 * Later pages keep their own cursor and can be loaded with the existing pager.
 */
function renderHostFlows() {
  const page = state.pages.hostFlows;
  const rows = groupHostPageRows("flows", sortLocalRows("host-flows-table", page.items.map((row) => ({
    ...row,
    protocol: [row.proto, row.app_proto].filter(Boolean).join(" / "),
    ports: `${row.src_port ?? "—"} → ${row.dst_port ?? "—"}`,
  }))));
  renderTable("host-flows-table", rows, [
    (row) => formatTime(row.event_time),
    (row) => text("span", row.direction, `status ${row.direction === "inbound" ? "ok" : "warn"}`),
    (row) => hostIdentity(row.peer),
    (row) => row.protocol,
    (row) => row.ports,
    (row) => row.state || "—",
    (row) => compact(row.packets),
    (row) => formatBytes(row.bytes),
    (row) => `${numeric(row.duration).toFixed(3)} s`,
    (row) => row.label || "—",
    (row) => row.linked_threat_level ? threat(row.linked_threat_level) : "—",
  ], openHostFlow);
  addHostTableGroups("flows", "host-flows-table", rows);
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
  if (includesAliases && !state.deviceView) {
    status.textContent = "Traffic aggregates withheld because the running backend grouped unrelated addresses through a shared next-hop MAC. Historical rows below are filtered to the exact profile IP.";
    renderLineChart("host-flow-chart", [], [{ key: "inbound_flows" }]);
    renderLineChart("host-byte-chart", [], [{ key: "inbound_bytes" }]);
    renderBars("host-protocols", []);
    renderBars("host-peers", []);
    return;
  }
  status.textContent = state.deviceView && includesAliases
    ? `Traffic and peers combine ${payload.host_ips.length} MAC-matched local addresses.`
    : "Traffic and peers match the exact profile IP only.";
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
  if (state.archiveSource) params.set("archive", state.archiveSource);
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
  if (summary) {
    ["range", "from", "to"].forEach((name) => {
      byId(`host-${name}`).value = byId(`hosts-${name}`).value;
    });
    const custom = byId("host-range").value === "custom";
    byId("host-from").hidden = byId("host-to").hidden = !custom;
    scheduleViewPreferencesSave();
  }
  const detailParams = hostRangeParams();
  if (state.networkOnly && state.networkFilterSupported) detailParams.set("network", "current");
  if (state.deviceView) detailParams.set("device", "1");
  const detail = await api("host", `/api/hosts/${escapePath(ip)}${detailParams.size ? `?${detailParams}` : ""}`, true, true);
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
  host.exact_aggregates = state.deviceView || staleAliases.length === 0;
  host.ignored_aliases = state.deviceView ? [] : staleAliases;
  host.all_ips = state.deviceView ? detail.all_ips : [ip];
  ["hostAlerts", "hostEvidence", "hostFlows", "hostSummary"].forEach((key) => {
    state.requests.get(key)?.abort();
  });
  state.host = host;
  rememberHostRecord(host);
  refreshHostLabels();
  resetPage("hostAlerts");
  resetPage("hostFlows");
  resetPage("host-evidence");
  byId("host-alerts").replaceChildren(text("p", "Loading alerts…", "muted"));
  byId("host-evidence-table").querySelector("tbody").replaceChildren();
  byId("host-flows-table").querySelector("tbody").replaceChildren();
  ["host-alert-count", "host-evidence-count", "host-flow-count"].forEach((id) => {
    byId(id).textContent = "";
  });
  byId("hosts-list-view").hidden = true;
  byId("host-detail-view").hidden = false;
  byId("host-detail-view").classList.remove("unprofiled");
  byId("host-unprofiled").hidden = true;
  renderHostCards(host);
  const hasExactAlerts = host.alerts?.some((alert) => host.all_ips.includes(alert.ip_alerted));
  const initialActivity = hasExactAlerts || (host.exact_aggregates !== false && host.alert_count)
    ? "alerts" : host.evidence_count ? "evidence" : "flows";
  await Promise.all([
    showHostActivity(state.hostActivityPreferred ? state.hostActivity : initialActivity),
    loadHostSummary(), loadHostScoreHistory(),
  ]);
}

async function refreshHostWorkspace() {
  if (!state.host) return;
  const ip = state.host.ip;
  const params = hostRangeParams();
  if (state.networkOnly && state.networkFilterSupported) params.set("network", "current");
  if (state.deviceView) params.set("device", "1");
  const detail = await api("host", `/api/hosts/${escapePath(ip)}${params.size ? `?${params}` : ""}`);
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
    all_ips: state.deviceView ? detail.all_ips : [ip],
    exact_aggregates: state.deviceView || staleAliases.length === 0,
    ignored_aliases: state.deviceView ? [] : staleAliases,
  };
  state.host = host;
  rememberHostRecord(host);
  refreshHostLabels();
  renderHostCards(host);
  await Promise.all([
    ({ alerts: loadHostAlerts, evidence: loadHostEvidence,
      flows: loadHostFlows })[state.hostActivity](),
    loadHostSummary(), loadHostScoreHistory(),
  ]);
}

function closeHost() {
  state.host = null;
  state.requests.get("hostAlerts")?.abort();
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
  if (state.archiveSource && ["alerts", "evidence", "hosts"].includes(state.activeTab)) return false;
  if (["configuration", "whitelists"].includes(state.activeTab)) return false;
  if (state.activeTab === "metadata") return true;
  if (["firewall", "arp-poisoning", "p2p", "logs"].includes(state.activeTab)) return true;
  if (state.activeTab === "overview") return true;
  if (state.activeTab === "hosts" && state.host) {
    const page = state.hostActivity === "alerts" ? state.pages.hostAlerts
      : state.hostActivity === "evidence" ? state.pages["host-evidence"]
        : state.pages.hostFlows;
    return rangeIsLive("host") && page.index === 0;
  }
  return rangeIsLive(state.activeTab) && state.pages[state.activeTab].index === 0;
}

function schedulePoll() {
  window.clearTimeout(state.timer);
  if (document.hidden || !activeRangeIsLive()) return;
  const interval = state.activeTab === "alerts" && byId("alerts-range").value === "all"
    ? 30000 : 5000;
  const delay = Math.min(interval * (2 ** state.failures), 60000);
  state.timer = window.setTimeout(() => {
    const pending = state.requests.has(state.activeTab)
      || (state.activeTab === "hosts"
        && (state.pages.hosts.refreshing || state.requests.has("host")));
    if (pending) schedulePoll();
    else refreshActive();
  }, delay);
}

/** Poll backend liveness independently from the active tab's data range. */
async function pollBackendStatus() {
  if (document.hidden) return;
  try {
    const identity = await api("backendStatus", "/api/identity", false);
    if (identity) {
      updateReviewAvailability(identity.review_actions === true);
      updateNetworkFilterAvailability(identity);
      updateDeviceViewAvailability(identity);
      state.headerNetwork = identity.current_network || null;
      if (state.overview) renderHeaderNetwork(state.overview);
    }
    if (Date.now() - state.archivesCheckedAt > 60000) loadArchiveCatalog().catch(() => {});
  } catch (_) {
    // renderConnectionState() already exposes the failure persistently.
  } finally {
    scheduleBackendStatusPoll();
  }
}

/** Refresh archive choices and expose cleanup progress without opening history files. */
async function loadArchiveCatalog() {
  state.archivesCheckedAt = Date.now();
  const payload = await api("archiveCatalog", "/api/archives", false, true);
  if (!payload || payload.not_found) return;
  const select = byId("history-source");
  select.replaceChildren(new Option("Active detection history", ""));
  (payload.items || []).forEach((item) => select.add(new Option(`Archive · ${item.label}`, item.id)));
  byId("history-source-label").hidden = !payload.items?.length;
  if ([...select.options].some((option) => option.value === state.archiveSource)) select.value = state.archiveSource;
  else if (state.archiveSource) {
    state.archiveSource = "";
    toast("The selected archive expired. Showing active detection history.");
    refreshNetworkScopedViews();
  }
  const status = payload.maintenance || {};
  const storage = byId("history-storage-status");
  storage.replaceChildren();
  [["Monthly archives", `${payload.items?.length || 0} · ${formatBytes(payload.archive_size_bytes)}`],
    ["Last maintenance pass", status.last_run ? formatTime(status.last_run) : "Waiting for the next pass"],
    ["History maintenance", status.disk_pressure ? "Paused: low disk space" : status.pending_hours || status.pending_archives
      ? `Catching up · ${compact(status.pending_hours || 0)} hours pending · ${status.pending_archives || 0} transfers pending` : "Up to date"]]
    .forEach(([label, value]) => storage.append(detailRow(label, value)));
}

byId("history-source").addEventListener("change", (event) => {
  state.archiveSource = event.currentTarget.value;
  if (state.archiveSource) {
    state.networkOnly = false;
    byId("network-filter").checked = false;
    byId("alerts-review").value = "all";
    byId("evidence-review").value = "all";
    ["alerts", "evidence", "hosts", "host"].forEach((name) => { byId(`${name}-range`).value = "all"; });
  }
  updateReviewAvailability(true);
  byId("network-filter").disabled = Boolean(state.archiveSource) || !state.networkFilterSupported;
  refreshNetworkScopedViews();
});

/** Enable device grouping only when the running backend supports it. */
function updateDeviceViewAvailability(identity) {
  const supported = identity.device_view_supported === true;
  const changed = supported !== state.deviceViewSupported;
  state.deviceViewSupported = supported;
  state.deviceView = supported && byId("device-view").checked;
  byId("device-view-label").hidden = !supported;
  byId("device-view").disabled = !supported;
  if (changed) {
    byId("alerts-list-heading").textContent = state.alertsWorkspace.grouping === "host"
      ? `Alerts grouped by ${state.deviceView ? "device" : "host"}` : "All alerts";
    renderEvidenceGroupControls();
  }
  if (changed && state.overview) refreshNetworkScopedViews();
}

/** Apply backend support and refresh scoped panes when the network changes.
 * @param {Object} identity Current web server identity and network scope.
 */
function updateNetworkFilterAvailability(identity) {
  const supported = identity.network_filter_supported === true
    && identity.input_type === "interface";
  const start = Number.isFinite(Number(identity.current_network_start))
    && identity.current_network_start !== null
    ? Number(identity.current_network_start) : null;
  const changed = supported !== state.networkFilterSupported
    || start !== state.currentNetworkStart;
  state.networkFilterSupported = supported;
  state.currentNetworkStart = start;
  if (changed) state.hostNames.clear();
  const label = byId("network-filter-label");
  label.hidden = !supported;
  byId("network-filter").disabled = !supported || start === null || Boolean(state.archiveSource);
  label.title = start === null
    ? "Waiting for a monitored network connection"
    : "Show hosts, traffic, alerts and evidence observed during the current continuous network connection only";
  if (changed && state.networkOnly && supported && state.overview) {
    refreshNetworkScopedViews();
  }
}

/** Reload all detection views after changing the network scope. */
function refreshNetworkScopedViews() {
  ["alerts", "evidence", "hosts", "hostAlerts", "host-evidence", "hostFlows"].forEach(resetPage);
  document.activeElement?.blur();
  state.filteredBadgeCounts = { alerts: null, evidence: null, hosts: null };
  ["alerts-badge", "evidence-badge", "hosts-badge"].forEach((id) => {
    byId(id).textContent = "—";
  });
  closeAlertHostPane();
  closeEvidenceDetail(false, true);
  state.evidenceWorkspace.group = null;
  state.evidenceWorkspace.record = null;
  state.evidenceWorkspace.records = [];
  state.evidenceWorkspace.generation += 1;
  renderEvidenceEmptyState();
  state.overviewAlertQuery = "";
  state.overviewAlertGroups = null;
  state.overviewEvidence = null;
  loadLiveTitleCounts().catch(() => {});
  if (state.activeTab !== "hosts") loadHosts().catch(() => {});
  if (state.activeTab === "overview") loadOverview().catch(() => {});
  else {
    refreshActive().catch(() => {});
    loadOverview().catch(() => {});
  }
}

byId("network-filter").addEventListener("change", (event) => {
  state.networkOnly = event.currentTarget.checked;
  try {
    window.localStorage.setItem("slips-network-only", state.networkOnly ? "1" : "0");
  } catch (_) {
    // The filter still works when browser storage is unavailable.
  }
  refreshNetworkScopedViews();
});
byId("device-view").addEventListener("change", (event) => {
  state.deviceView = event.currentTarget.checked;
  renderEvidenceGroupControls();
  byId("alerts-list-heading").textContent = state.alertsWorkspace.grouping === "host"
    ? `Alerts grouped by ${state.deviceView ? "device" : "host"}` : "All alerts";
  refreshNetworkScopedViews();
});

/** Enable review controls only after the running server advertises support.
 * @param {boolean} available Whether the server accepts review actions.
 */
function updateReviewAvailability(available) {
  available = available && !state.archiveSource;
  byId("evidence-export").hidden = Boolean(state.archiveSource);
  state.reviewAvailable = available;
  ["alerts-review", "evidence-review"].forEach((id) => {
    byId(id).disabled = !available;
  });
  document.querySelectorAll(".review-editor").forEach((editor) => {
    editor.querySelectorAll(".review-actions button").forEach((button) => {
      button.disabled = !available;
    });
    const notice = editor.querySelector(".review-availability");
    if (notice) {
      notice.hidden = available;
      notice.textContent = state.archiveSource ? "Detection archives are read-only."
        : "Restart Slips manually to enable review actions in the running web server.";
    }
  });
}

/** Schedule the next lightweight backend heartbeat check. */
function scheduleBackendStatusPoll() {
  window.clearTimeout(state.statusTimer);
  if (document.hidden) return;
  state.statusTimer = window.setTimeout(pollBackendStatus, 5000);
}

function switchTab(name) {
  closeEvidenceDetail(false, true);
  state.activeTab = name;
  document.body.classList.toggle("overview-active", name === "overview");
  document.body.classList.toggle("alerts-active", name === "alerts");
  document.body.classList.toggle("evidence-active", name === "evidence");
  document.body.classList.toggle("hosts-active", name === "hosts");
  document.body.classList.toggle("metadata-active", name === "metadata");
  document.body.classList.toggle("configuration-active", name === "configuration");
  document.body.classList.toggle("p2p-active", name === "p2p");
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

let viewPreferencesTimer = null;
/** Debounce browser-only view settings after any filter or layout interaction. */
function scheduleViewPreferencesSave() {
  window.clearTimeout(viewPreferencesTimer);
  viewPreferencesTimer = window.setTimeout(saveViewPreferences, 200);
}

document.addEventListener("input", (event) => {
  if (VIEW_CONTROL_IDS.includes(event.target.id)) scheduleViewPreferencesSave();
});
document.addEventListener("change", (event) => {
  if (VIEW_CONTROL_IDS.includes(event.target.id)
      || event.target.closest?.(".hosts-columns, .excluded-visibility-select")) {
    scheduleViewPreferencesSave();
  }
});
document.addEventListener("click", (event) => {
  if (event.target.closest?.("[data-alert-group], [data-config-filter], [data-p2p-filter], "
      + "#alerts-severity-filters, #evidence-threat-chips, #evidence-group-controls, "
      + "#hosts-threat-chips, #hosts-scope-chips, #alerts-host-order, #alerts-item-order, "
      + "th[data-sort], [data-host-activity], #configuration-navigation, #p2p-peers-table")) {
    scheduleViewPreferencesSave();
  }
});
document.addEventListener("keyup", (event) => {
  if (event.target.matches?.("th[data-sort], [role=separator]")) scheduleViewPreferencesSave();
});
document.addEventListener("pointerup", (event) => {
  if (event.target.matches?.("[role=separator]")) scheduleViewPreferencesSave();
});

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
byId("p2p-message-filter").addEventListener("change", () => {
  state.p2pVisibleMessages = 12;
  renderP2PMessages();
});
document.querySelectorAll("[data-p2p-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    byId("p2p-message-filter").value = button.dataset.p2pFilter;
    state.p2pVisibleMessages = 12;
    renderP2PMessages();
  });
});
byId("p2p-load-more").addEventListener("click", () => {
  state.p2pVisibleMessages += 20;
  renderP2PMessages();
});
bindLocalTableSort("p2p-activity-table", renderP2PMessages);
bindLocalTableSort("p2p-peers-table", renderP2PPeers);
bindLocalTableSort("logs-table", () => loadLogs().catch(() => {}));
bindLocalTableSort("whitelists-table", renderWhitelists);
bindLocalTableSort("firewall-table", () => loadFirewall().catch(() => {}));
bindLocalTableSort("firewall-history-table", () => {
  resetPage("firewall");
  loadFirewall().catch(() => {});
});
bindLocalTableSort("host-flows-table", () => {
  resetPage("hostFlows");
  loadHostFlows().catch(() => {});
});
byId("module-search").addEventListener("input", () =>
  state.overview && renderModules(state.overview.modules));
byId("drawer-close").addEventListener("click", closeDrawer);
byId("drawer-back").addEventListener("click", backDrawer);
byId("drawer-backdrop").addEventListener("click", closeDrawer);
/** Return to the nearest visible investigation with Escape. */
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  const drawer = byId("drawer");
  if (drawer.classList.contains("open")
      && drawer.classList.contains("alert-over-evidence")) {
    event.preventDefault();
    if (state.drawerHistory.length) backDrawer();
    else closeDrawer();
  } else if (state.evidenceDetail.record) {
    event.preventDefault();
    closeEvidenceDetail();
  } else if (drawer.classList.contains("open")) {
    event.preventDefault();
    if (state.drawerHistory.length) backDrawer();
    else closeDrawer();
  }
});
byId("host-back").addEventListener("click", closeHost);
document.querySelectorAll("[data-host-activity]").forEach((button) =>
  button.addEventListener("click", () => {
    state.hostActivityPreferred = true;
    showHostActivity(button.dataset.hostActivity);
  }));
byId("host-activity-group").addEventListener("change", () => {
  const kind = state.hostActivity;
  state.hostActivityGroups[kind] = byId("host-activity-group").value;
  const note = byId("host-activity-group-note");
  note.hidden = !state.hostActivityGroups[kind];
  note.textContent = note.hidden ? "" : "Groups in this page; filters cover the selected range";
  if (kind === "alerts") loadHostAlerts().catch(() => {});
  else if (kind === "evidence") loadHostEvidence().catch(() => {});
  else renderHostFlows();
});
byId("host-activity-threat").addEventListener("change", () => {
  const kind = state.hostActivity;
  state.hostActivityThreats[kind] = byId("host-activity-threat").value;
  resetPage({ alerts: "hostAlerts", evidence: "host-evidence", flows: "hostFlows" }[kind]);
  ({ alerts: loadHostAlerts, evidence: loadHostEvidence, flows: loadHostFlows })[kind]().catch(() => {});
});
byId("host-flow-search").addEventListener("input", filterVisibleHostFlows);
bindFilters("hostAlerts", ["host-alert-search"], loadHostAlerts);
byId("host-whitelist-action").addEventListener("click", () => {
  if (!state.host) return;
  openDrawer("HOST WHITELIST", state.host.user_name || state.host.ip);
  byId("drawer-body").append(whitelistEditor("host", null, state.host));
});
byId("hosts-alerts-only").addEventListener("change", () => {
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
document.querySelector(".hosts-list-table").addEventListener("scroll", maybeLoadMoreHosts);
byId("hosts-export").addEventListener("click", () => {
  const rows = state.pages.hosts.items;
  const fields = ["ip", "user_name", "user_status", "user_labels", "user_note", "hostname", "mac", "mac_address_type", "mac_vendor", "scope", "max_threat_level", "peak_alert_score", "alert_score", "flows", "bytes", "evidence_count", "alert_count", "last_seen"];
  const escapeCsv = (value) => {
    const plain = String(value ?? "");
    const safe = /^[=+\-@\t\r]/.test(plain) ? `'${plain}` : plain;
    return `"${safe.replaceAll('"', '""')}"`;
  };
  const csv = [fields.join(","), ...rows.map((row) => fields.map((key) =>
    escapeCsv(key === "last_seen" ? row.last_seen || row.load?.last_seen
      : key === "mac_address_type" ? classifyMac(row.mac)
      : ["flows", "bytes"].includes(key) ? row.load?.[key] : row[key])).join(","))].join("\n");
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
    ["alerts", "evidence", "hostAlerts", "host-evidence", "hostFlows"].forEach(resetPage);
    if (state.activeTab === "hosts" && state.host) {
      refreshHostWorkspace().catch(() => {});
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
byId("alerts-host-sort").querySelectorAll("[data-alert-mode]")
  .forEach((option) => {
    option.disabled = option.dataset.alertMode !== state.alertsWorkspace.grouping;
  });
byId("alerts-list-heading").textContent = state.alertsWorkspace.grouping === "host"
  ? `Alerts grouped by ${state.deviceView ? "device" : "host"}` : "All alerts";
document.querySelectorAll("[data-alert-group]").forEach((button) => {
  button.addEventListener("click", () => {
    if (byId("alerts-group").value === button.dataset.alertGroup) return;
    byId("alerts-group").value = button.dataset.alertGroup;
    byId("alerts-group").dispatchEvent(new Event("change"));
  });
});
byId("alerts-group").addEventListener("change", () => {
  const workspace = state.alertsWorkspace;
  workspace.grouping = byId("alerts-group").value;
  closeAlertHostPane();
  document.querySelectorAll("[data-alert-group]").forEach((button) => {
    const selected = button.dataset.alertGroup === workspace.grouping;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  const sort = byId("alerts-host-sort");
  sort.querySelectorAll("[data-alert-mode]").forEach((option) => {
    option.disabled = option.dataset.alertMode !== workspace.grouping;
  });
  if (sort.selectedOptions[0].disabled) {
    sort.value = "time";
    state.pages.alerts.sort = "time";
    state.pages.alerts.order = "desc";
    byId("alerts-host-order").textContent = "↓";
  }
  byId("alerts-list-heading").textContent = workspace.grouping === "host"
    ? `Alerts grouped by ${state.deviceView ? "device" : "host"}` : "All alerts";
  byId("alerts-description").textContent = workspace.grouping === "host"
    ? "Alerts grouped by host. Select a host, then an alert, its evidence, and triggering flows."
    : "Individual alerts. Select an alert to inspect its evidence and triggering flows.";
  byId("alerts-host-sort").previousSibling.textContent = workspace.grouping === "host" ? "Sort hosts " : "Sort alerts ";
  resetPage("alerts");
  loadAlerts().catch(() => {});
});
byId("alerts-review").addEventListener("change", () => {
  closeAlertHostPane();
  resetPage("alerts");
  loadAlerts().catch(() => {});
});
byId("alerts-host-sort").addEventListener("change", () => {
  const page = state.pages.alerts;
  page.sort = byId("alerts-host-sort").value;
  page.order = ["host", "label"].includes(page.sort) ? "asc" : "desc";
  byId("alerts-host-order").textContent = page.order === "asc" ? "↑" : "↓";
  resetPage("alerts");
  loadAlerts().catch(() => {});
});
byId("alerts-host-order").addEventListener("click", () => {
  const page = state.pages.alerts;
  page.order = page.order === "asc" ? "desc" : "asc";
  byId("alerts-host-order").textContent = page.order === "asc" ? "↑" : "↓";
  resetPage("alerts");
  loadAlerts().catch(() => {});
});
byId("alerts-item-sort").addEventListener("change", () => {
  const workspace = state.alertsWorkspace;
  workspace.itemSort = byId("alerts-item-sort").value;
  workspace.itemOrder = ["label", "tw", "id"].includes(workspace.itemSort) ? "asc" : "desc";
  byId("alerts-item-order").textContent = workspace.itemOrder === "asc" ? "↑" : "↓";
  loadAlertHostAlerts(true).catch(() => {});
});
byId("alerts-item-order").addEventListener("click", () => {
  const workspace = state.alertsWorkspace;
  workspace.itemOrder = workspace.itemOrder === "asc" ? "desc" : "asc";
  byId("alerts-item-order").textContent = workspace.itemOrder === "asc" ? "↑" : "↓";
  loadAlertHostAlerts(true).catch(() => {});
});
byId("alerts-range").addEventListener("change", () => {
  state.alertsWorkspace.rangeTouched = true;
  state.alertsWorkspace.autoRange = "";
  byId("alerts-range-note").hidden = true;
});
bindFilters("evidence", ["evidence-search", "evidence-threat", "evidence-link"], loadEvidence);
byId("evidence-review").addEventListener("change", () => {
  clearEvidenceSelection();
  resetPage("evidence");
  loadEvidence().catch(() => {});
});
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
bindFilters("hosts", ["hosts-search", "hosts-scope", "hosts-threat", "hosts-review"], loadHosts);
byId("configuration-search").addEventListener("input", renderConfiguration);
document.querySelectorAll("[data-config-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    state.configurationFilter = button.dataset.configFilter;
    document.querySelectorAll("[data-config-filter]").forEach((item) => {
      item.classList.toggle("active", item === button);
      item.setAttribute("aria-pressed", String(item === button));
    });
    renderConfiguration();
  });
});
byId("configuration-yaml-button").addEventListener("click", () => {
  const panel = byId("configuration-yaml");
  panel.hidden = !panel.hidden;
  byId("configuration-yaml-button").setAttribute("aria-expanded", String(!panel.hidden));
  if (!panel.hidden) panel.scrollIntoView({ block: "nearest" });
});
byId("configuration-yaml-close").addEventListener("click", () => {
  byId("configuration-yaml").hidden = true;
  byId("configuration-yaml-button").setAttribute("aria-expanded", "false");
  byId("configuration-yaml-button").focus();
});
byId("whitelists-search").addEventListener("input", renderWhitelists);
byId("whitelists-type").addEventListener("change", renderWhitelists);
byId("whitelists-editor").append(whitelistEditor("tab"));
bindView("evidence", loadEvidence);
bindRange("alerts", "alerts", loadAlerts);
bindRange("evidence", "evidence", loadEvidence);
bindRange("hosts", "hosts", loadHosts);
bindRange("host", "hostFlows", async () => {
  resetPage("hostAlerts");
  resetPage("host-evidence");
  await refreshHostWorkspace();
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
    loadLiveTitleCounts().catch(() => {});
  }
});
window.addEventListener("beforeunload", () => {
  saveViewPreferences();
  window.clearTimeout(state.statusTimer);
  window.clearInterval(state.titleTimer);
  state.requests.forEach((controller) => controller.abort());
});

initDrawerResize();
initAlertPaneResize();
initEvidencePaneResize();
window.addEventListener("resize", updateEvidenceViewportHeight);
window.addEventListener("resize", updateHostViewportHeight);
window.addEventListener("resize", updateMetadataViewportHeight);
window.setInterval(renderHeaderUptime, 1000);
loadWhitelists().catch(() => {});
startLiveTitlePolling();
updateReviewAvailability(false);
pollBackendStatus().catch(() => {}).finally(() => {
  loadOverview().catch(() => {}).finally(() => {
    if (state.activeTab === "overview") schedulePoll();
  });
});
