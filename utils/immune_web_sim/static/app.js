const PARAM_GROUPS = [
  {
    title: "Tissue and Pathogen",
    open: true,
    items: [
      ["grid_width", "Grid width", 1],
      ["grid_height", "Grid height", 1],
      ["healthy_cells", "Benign cells", 1],
      ["infected_cells", "Initial infected cells", 1],
      ["initial_healthy_density", "Tissue density", 0.01],
      ["viruses", "Initial viruses", 1],
      ["bacteria", "Initial bacteria", 1],
      ["infection_strength", "Infection strength", 0.01],
      ["infection_ratio", "Infection ratio", 0.01],
      ["virus_growth_rate", "Virus growth", 0.01],
      ["bacteria_growth_rate", "Bacteria growth", 0.01],
      ["virus_spread_rate", "Virus spread", 0.01],
      ["bacteria_spread_rate", "Bacteria spread", 0.01],
      ["cell_recovery_rate", "Cell recovery", 0.001],
    ],
  },
  {
    title: "Innate Sensing and Mobility",
    open: false,
    items: [
      ["dendritic_cells", "Dendritic cells", 1],
      ["dendritic_detection_rate", "Detection rate", 0.01],
      ["antigen_presentation_efficiency", "Presentation efficiency", 0.01],
      ["recruitment_rate", "Recruitment rate", 0.01],
      ["dendritic_patrol_speed", "Dendritic patrol speed", 0.01],
      ["chemotaxis_strength", "Chemotaxis strength", 0.01],
    ],
  },
  {
    title: "Adaptive Response",
    open: false,
    items: [
      ["t_cells", "T cells", 1],
      ["b_cells", "B cells", 1],
      ["t_activation_rate", "T-cell activation", 0.01],
      ["b_activation_rate", "B-cell activation", 0.01],
      ["t_cell_patrol_speed", "T-cell mobility", 0.01],
      ["b_cell_patrol_speed", "B-cell mobility", 0.01],
      ["pathogen_kill_by_t", "T-cell kill strength", 0.01],
      ["pathogen_kill_by_antibody", "Antibody neutralization", 0.01],
      ["infected_clearance_rate", "Clearance rate", 0.01],
      ["antibody_production_rate", "Antibody production", 0.01],
      ["antibody_decay_rate", "Antibody decay", 0.01],
    ],
  },
  {
    title: "Cytokines and Regulation",
    open: false,
    items: [
      ["treg_cells", "Treg cells", 1],
      ["treg_patrol_speed", "Treg mobility", 0.01],
      ["cytokine_production_rate", "Pro-cytokine production", 0.01],
      ["cytokine_decay_rate", "Cytokine decay", 0.01],
      ["anti_inflammatory_rate", "Anti-inflammatory rate", 0.01],
      ["pro_diffusion_rate", "Pro diffusion", 0.01],
      ["anti_diffusion_rate", "Anti diffusion", 0.01],
      ["pathogen_decay_rate", "Pathogen decay", 0.01],
    ],
  },
  {
    title: "Self Reactivity and Runtime",
    open: false,
    items: [
      ["self_attack_probability", "Self-attack probability", 0.001],
      ["collateral_damage_rate", "Collateral damage", 0.001],
      ["sample_world_every", "Snapshot interval", 1],
      ["random_seed", "Random seed", 1],
      ["time_scale", "Time scale", 0.1],
    ],
  },
];

const PRESETS = {
  mild_viral: {
    viruses: 140,
    bacteria: 20,
    infected_cells: 10,
    infection_strength: 0.42,
    virus_growth_rate: 0.12,
    bacteria_growth_rate: 0.08,
    t_cells: 110,
    treg_cells: 28,
    self_attack_probability: 0.01,
  },
  bacterial_burst: {
    viruses: 40,
    bacteria: 280,
    infected_cells: 24,
    infection_strength: 0.7,
    bacteria_growth_rate: 0.22,
    bacteria_spread_rate: 0.24,
    pro_diffusion_rate: 0.38,
    t_cells: 90,
    b_cells: 60,
  },
  autoimmune_prone: {
    viruses: 190,
    bacteria: 70,
    infected_cells: 18,
    self_attack_probability: 0.12,
    collateral_damage_rate: 0.05,
    treg_cells: 12,
    anti_inflammatory_rate: 0.12,
    t_activation_rate: 0.28,
  },
  high_treg: {
    treg_cells: 72,
    anti_inflammatory_rate: 0.4,
    anti_diffusion_rate: 0.4,
    cytokine_decay_rate: 0.12,
    t_cells: 85,
    b_cells: 70,
    self_attack_probability: 0.008,
  },
};

const els = {
  metricStrip: document.getElementById("metricStrip"),
  tissueCanvas: document.getElementById("tissueCanvas"),
  hoverCard: document.getElementById("hoverCard"),
  parameterGroups: document.getElementById("parameterGroups"),
  applyBtn: document.getElementById("applyBtn"),
  resetBtn: document.getElementById("resetBtn"),
  startBtn: document.getElementById("startBtn"),
  stopBtn: document.getElementById("stopBtn"),
  runName: document.getElementById("runName"),
  saveBtn: document.getElementById("saveBtn"),
  refreshRunsBtn: document.getElementById("refreshRunsBtn"),
  runSelect: document.getElementById("runSelect"),
  loadRunBtn: document.getElementById("loadRunBtn"),
  runSummary: document.getElementById("runSummary"),
  runPlot: document.getElementById("runPlot"),
  comparisonSummary: document.getElementById("comparisonSummary"),
  speedSlider: document.getElementById("speedSlider"),
  speedValue: document.getElementById("speedValue"),
  canvasSizeSlider: document.getElementById("canvasSizeSlider"),
  canvasSizeValue: document.getElementById("canvasSizeValue"),
  runStatus: document.getElementById("runStatus"),
  outcomeBadge: document.getElementById("outcomeBadge"),
};

const burdenChart = new window.LabLineChart(document.getElementById("burdenChart"));
const immuneChart = new window.LabLineChart(document.getElementById("immuneChart"));
const regulationChart = new window.LabLineChart(document.getElementById("regulationChart"));

const tissueCtx = els.tissueCanvas.getContext("2d");

const TISSUE_COLORS = {
  ".": "#d7e1ea",
  h: "#2d936c",
  v: "#d1495b",
  b: "#6f4ef2",
  x: "#ff9f1c",
  d: "#3d405b",
};

const AGENT_COLORS = {
  dc: "#f4d35e",
  tc: "#ffffff",
  bc: "#62c9ff",
  tr: "#7bd389",
};

const TISSUE_LABELS = {
  ".": "Empty extracellular space",
  h: "Healthy benign tissue cell",
  v: "Virus-infected tissue cell",
  b: "Bacteria-infected tissue cell",
  x: "Damaged tissue cell",
  d: "Dead tissue remnant",
};

const AGENT_LABELS = {
  dc: "Dendritic cell",
  tc: "T cell",
  bc: "B cell",
  tr: "Treg cell",
};

let latest = null;
let currentConfig = null;
let compareRun = null;
let controlsBuilt = false;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatValue(value) {
  if (typeof value !== "number") return String(value);
  if (Math.abs(value) >= 100) return value.toFixed(0);
  if (Math.abs(value) >= 10) return value.toFixed(1);
  return value.toFixed(2);
}

function resizeCanvas(canvas, ctx) {
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  const width = Math.floor(rect.width * ratio);
  const height = Math.floor(rect.height * ratio);
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
  }
  ctx.setTransform(1, 0, 0, 1, 0, 0);
}

function applyCanvasSize(px) {
  const clamped = Math.max(60, Math.min(100, px));
  document.documentElement.style.setProperty("--stage-canvas-scale", `${clamped}`);
  els.canvasSizeValue.textContent = `${Math.round(clamped)}%`;
}

function buildControls(config) {
  els.parameterGroups.innerHTML = "";
  PARAM_GROUPS.forEach((group) => {
    const details = document.createElement("details");
    details.className = "control-group";
    details.open = group.open;

    const summary = document.createElement("summary");
    summary.textContent = group.title;
    details.appendChild(summary);

    const grid = document.createElement("div");
    grid.className = "control-grid";

    group.items.forEach(([key, label, step]) => {
      const wrap = document.createElement("div");
      wrap.className = "control-field";

      const labelEl = document.createElement("label");
      labelEl.setAttribute("for", `param_${key}`);
      labelEl.textContent = label;

      const input = document.createElement("input");
      input.id = `param_${key}`;
      input.type = "number";
      input.step = step;
      input.value = config[key] ?? 0;
      wrap.appendChild(labelEl);
      wrap.appendChild(input);
      grid.appendChild(wrap);
    });

    details.appendChild(grid);
    els.parameterGroups.appendChild(details);
  });

  els.speedSlider.value = config.time_scale ?? 1;
  els.speedValue.textContent = `${formatValue(Number(els.speedSlider.value))}x`;
  controlsBuilt = true;
}

function readParams() {
  const payload = {};
  PARAM_GROUPS.forEach((group) => {
    group.items.forEach(([key]) => {
      const input = document.getElementById(`param_${key}`);
      if (!input) return;
      payload[key] = Number(input.value);
    });
  });
  payload.time_scale = Number(els.speedSlider.value);
  return payload;
}

function setInputs(values) {
  Object.entries(values).forEach(([key, value]) => {
    const input = document.getElementById(`param_${key}`);
    if (input) input.value = value;
  });
  if (values.time_scale != null) {
    els.speedSlider.value = values.time_scale;
    els.speedValue.textContent = `${formatValue(Number(values.time_scale))}x`;
  }
}

function renderMetricStrip(state) {
  const cards = [
    ["Healthy tissue", state.healthy_cells],
    ["Infected tissue", state.infected_cells],
    ["Total pathogen", state.viruses + state.bacteria],
    ["Active T cells", state.activated_t_cells],
    ["Antibodies", state.antibodies],
    ["Damage index", state.tissue_damage_index],
  ];

  els.metricStrip.innerHTML = cards
    .map(
      ([label, value]) =>
        `<div class="metric-card"><div class="label">${label}</div><div class="value">${formatValue(value)}</div></div>`
    )
    .join("");
}

function decodeHeat(char) {
  return parseInt(char, 16) / 15;
}

function renderTissueWorld() {
  if (!latest || !latest.world) return;

  resizeCanvas(els.tissueCanvas, tissueCtx);
  const { world } = latest;
  const width = world.width;
  const height = world.height;
  const cellW = els.tissueCanvas.width / width;
  const cellH = els.tissueCanvas.height / height;

  tissueCtx.clearRect(0, 0, els.tissueCanvas.width, els.tissueCanvas.height);
  tissueCtx.fillStyle = "#f4f8fc";
  tissueCtx.fillRect(0, 0, els.tissueCanvas.width, els.tissueCanvas.height);

  for (let y = 0; y < height; y += 1) {
    const tissueRow = world.tissue_rows[y];
    const pathogenRow = world.pathogen_rows[y];
    const proRow = world.pro_rows[y];
    const antiRow = world.anti_rows[y];

    for (let x = 0; x < width; x += 1) {
      const px = x * cellW;
      const py = y * cellH;
      const tissue = tissueRow[x];

      tissueCtx.fillStyle = TISSUE_COLORS[tissue] || "#dfe7ef";
      tissueCtx.fillRect(px, py, Math.ceil(cellW) + 0.4, Math.ceil(cellH) + 0.4);

      if (tissue === ".") {
        tissueCtx.strokeStyle = "rgba(90,109,130,0.28)";
        tissueCtx.lineWidth = Math.max(0.6, Math.min(cellW, cellH) * 0.06);
        tissueCtx.beginPath();
        tissueCtx.moveTo(px + cellW * 0.18, py + cellH * 0.82);
        tissueCtx.lineTo(px + cellW * 0.82, py + cellH * 0.18);
        tissueCtx.stroke();
      } else if (tissue === "h") {
        tissueCtx.fillStyle = "rgba(232,255,245,0.58)";
        tissueCtx.beginPath();
        tissueCtx.arc(px + cellW * 0.5, py + cellH * 0.5, Math.min(cellW, cellH) * 0.18, 0, Math.PI * 2);
        tissueCtx.fill();
      }

      const pathogenAlpha = decodeHeat(pathogenRow[x]) * 0.55;
      if (pathogenAlpha > 0.02) {
        tissueCtx.fillStyle = `rgba(209,73,91,${pathogenAlpha})`;
        tissueCtx.fillRect(px, py, Math.ceil(cellW) + 0.4, Math.ceil(cellH) + 0.4);
      }

      const proAlpha = decodeHeat(proRow[x]) * 0.35;
      if (proAlpha > 0.02) {
        tissueCtx.fillStyle = `rgba(255,104,107,${proAlpha})`;
        tissueCtx.fillRect(px, py, Math.ceil(cellW) + 0.4, Math.ceil(cellH) + 0.4);
      }

      const antiAlpha = decodeHeat(antiRow[x]) * 0.32;
      if (antiAlpha > 0.02) {
        tissueCtx.fillStyle = `rgba(58,110,165,${antiAlpha})`;
        tissueCtx.fillRect(px, py, Math.ceil(cellW) + 0.4, Math.ceil(cellH) + 0.4);
      }
    }
  }

  if (cellW > 9 && cellH > 9) {
    tissueCtx.strokeStyle = "rgba(255,255,255,0.08)";
    tissueCtx.lineWidth = 1;
    for (let x = 0; x <= width; x += 1) {
      tissueCtx.beginPath();
      tissueCtx.moveTo(x * cellW, 0);
      tissueCtx.lineTo(x * cellW, els.tissueCanvas.height);
      tissueCtx.stroke();
    }
    for (let y = 0; y <= height; y += 1) {
      tissueCtx.beginPath();
      tissueCtx.moveTo(0, y * cellH);
      tissueCtx.lineTo(els.tissueCanvas.width, y * cellH);
      tissueCtx.stroke();
    }
  }

  world.agents.forEach((agent) => {
    const cx = (agent.x + 0.5) * cellW;
    const cy = (agent.y + 0.5) * cellH;
    const radius = Math.max(2, Math.min(cellW, cellH) * 0.4);
    const activationAlpha = Math.min(1, 0.45 + agent.activation / 3.5);

    tissueCtx.fillStyle = AGENT_COLORS[agent.kind] || "#ffffff";
    tissueCtx.globalAlpha = activationAlpha;
    if (agent.kind === "dc") {
      tissueCtx.beginPath();
      tissueCtx.moveTo(cx, cy - radius);
      tissueCtx.lineTo(cx + radius, cy);
      tissueCtx.lineTo(cx, cy + radius);
      tissueCtx.lineTo(cx - radius, cy);
      tissueCtx.closePath();
      tissueCtx.fill();
    } else {
      tissueCtx.beginPath();
      tissueCtx.arc(cx, cy, radius, 0, Math.PI * 2);
      tissueCtx.fill();
    }
    tissueCtx.globalAlpha = 1;
  });
}

function describeWorldCell(x, y) {
  if (!latest || !latest.world) return null;
  const { world } = latest;
  if (x < 0 || y < 0 || x >= world.width || y >= world.height) return null;

  const tissue = world.tissue_rows[y][x];
  const pathogen = decodeHeat(world.pathogen_rows[y][x]);
  const pro = decodeHeat(world.pro_rows[y][x]);
  const anti = decodeHeat(world.anti_rows[y][x]);
  const localAgents = world.agents.filter((agent) => agent.x === x && agent.y === y);

  return {
    x,
    y,
    tissue,
    tissueLabel: TISSUE_LABELS[tissue] || "Unknown",
    pathogen,
    pro,
    anti,
    localAgents,
  };
}

function renderHoverCard(info, clientX, clientY) {
  if (!info) {
    els.hoverCard.classList.add("hidden");
    return;
  }

  const agentText = info.localAgents.length
    ? info.localAgents
        .map((agent) => `${AGENT_LABELS[agent.kind] || agent.kind} (${agent.state}, act ${formatValue(agent.activation)})`)
        .join(", ")
    : "No immune agent on this location";

  els.hoverCard.innerHTML = `
    <strong>${escapeHtml(info.tissueLabel)}</strong>
    <div>Grid site: (${info.x}, ${info.y})</div>
    <div>Pathogen burden: ${formatValue(info.pathogen)}</div>
    <div>Pro-cytokines: ${formatValue(info.pro)}</div>
    <div>Anti-cytokines: ${formatValue(info.anti)}</div>
    <div>Agents: ${escapeHtml(agentText)}</div>
  `;
  els.hoverCard.classList.remove("hidden");

  const frame = els.tissueCanvas.getBoundingClientRect();
  const card = els.hoverCard.getBoundingClientRect();
  let left = clientX - frame.left + 18;
  let top = clientY - frame.top + 18;
  if (left + card.width > frame.width - 8) left = clientX - frame.left - card.width - 18;
  if (top + card.height > frame.height - 8) top = clientY - frame.top - card.height - 18;
  els.hoverCard.style.left = `${Math.max(8, left)}px`;
  els.hoverCard.style.top = `${Math.max(8, top)}px`;
}

function buildChartSeries(history, keyMap) {
  return keyMap.map(([label, color, key]) => ({
    label,
    color,
    values: history.map((point) => {
      if (typeof key === "function") return key(point);
      return Number(point[key] || 0);
    }),
  }));
}

function renderCharts() {
  if (!latest) return;

  const current = latest.history_tail || [];
  const compareHistory = compareRun?.history || [];

  burdenChart.setData(
    buildChartSeries(current, [
      ["Pathogen", "#d1495b", (point) => (point.viruses || 0) + (point.bacteria || 0)],
      ["Healthy", "#187f6d", "healthy_cells"],
      ["Infected", "#ff9f1c", "infected_cells"],
    ]),
    buildChartSeries(compareHistory, [
      ["Pathogen compare", "#d1495b", (point) => (point.viruses || 0) + (point.bacteria || 0)],
      ["Healthy compare", "#187f6d", "healthy_cells"],
      ["Infected compare", "#ff9f1c", "infected_cells"],
    ])
  );

  immuneChart.setData(
    buildChartSeries(current, [
      ["Active T", "#004e89", "activated_t_cells"],
      ["Active B", "#118ab2", "activated_b_cells"],
      ["Antibodies", "#06d6a0", "antibodies"],
    ]),
    buildChartSeries(compareHistory, [
      ["Active T compare", "#004e89", "activated_t_cells"],
      ["Active B compare", "#118ab2", "activated_b_cells"],
      ["Antibodies compare", "#06d6a0", "antibodies"],
    ])
  );

  regulationChart.setData(
    buildChartSeries(current, [
      ["Pro cytokines", "#ef476f", "pro_cytokines"],
      ["Anti cytokines", "#3a6ea5", "anti_cytokines"],
      ["Damage", "#6d597a", "tissue_damage_index"],
      ["Autoimmune", "#bc4749", "autoimmune_events"],
    ]),
    buildChartSeries(compareHistory, [
      ["Pro cytokines compare", "#ef476f", "pro_cytokines"],
      ["Anti cytokines compare", "#3a6ea5", "anti_cytokines"],
      ["Damage compare", "#6d597a", "tissue_damage_index"],
      ["Autoimmune compare", "#bc4749", "autoimmune_events"],
    ])
  );
}

async function getJSON(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json();
}

async function postJSON(url, payload = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json();
}

function renderState() {
  if (!latest) return;

  renderMetricStrip(latest.state);
  renderTissueWorld();
  renderCharts();

  els.runStatus.textContent = latest.running ? "running" : "paused";
  els.outcomeBadge.textContent = latest.state.outcome;
  els.speedValue.textContent = `${formatValue(Number(els.speedSlider.value))}x`;
}

async function refreshState() {
  try {
    latest = await getJSON("/api/state");
    currentConfig = latest.config;
    if (!controlsBuilt) buildControls(latest.config);
    renderState();
  } catch (error) {
    console.error(error);
  }
}

async function refreshRuns() {
  const data = await getJSON("/api/runs");
  els.runSelect.innerHTML = "";
  data.runs.forEach((run) => {
    const option = document.createElement("option");
    option.value = run.run_id;
    option.textContent = run.run_id;
    els.runSelect.appendChild(option);
  });
}

function renderCompareSummary(run) {
  const state = run.state;
  els.comparisonSummary.textContent =
    `Loaded compare run ${run.run_id}. In the live charts, solid lines are the current run and dashed lines are this saved run. Both runs are aligned from their own simulation start.`;
  els.runSummary.textContent = JSON.stringify(
    {
      run_id: run.run_id,
      saved_at_utc: run.saved_at_utc,
      summary: run.summary,
      final_state: run.state,
      config: {
        healthy_cells: run.config.healthy_cells,
        infected_cells: run.config.infected_cells,
        viruses: run.config.viruses,
        bacteria: run.config.bacteria,
        t_cells: run.config.t_cells,
        b_cells: run.config.b_cells,
        treg_cells: run.config.treg_cells,
        self_attack_probability: run.config.self_attack_probability,
      },
    },
    null,
    2
  );
  els.runPlot.src = `/runs/${run.run_id}.svg`;
}

async function loadRun(runId) {
  if (!runId) return;
  const data = await getJSON(`/api/load_run/${encodeURIComponent(runId)}`);
  if (!data.ok) return;
  compareRun = data.run;
  renderCompareSummary(compareRun);
  renderCharts();
}

function wireCanvasHover() {
  els.tissueCanvas.addEventListener("mousemove", (event) => {
    if (!latest || !latest.world) return;
    const rect = els.tissueCanvas.getBoundingClientRect();
    const x = Math.floor(((event.clientX - rect.left) / rect.width) * latest.world.width);
    const y = Math.floor(((event.clientY - rect.top) / rect.height) * latest.world.height);
    renderHoverCard(describeWorldCell(x, y), event.clientX, event.clientY);
  });

  els.tissueCanvas.addEventListener("mouseleave", () => {
    els.hoverCard.classList.add("hidden");
  });
}

function wirePresetButtons() {
  document.querySelectorAll("[data-preset]").forEach((button) => {
    button.addEventListener("click", () => {
      const preset = PRESETS[button.dataset.preset];
      if (!preset) return;
      setInputs(preset);
    });
  });
}

function wireEvents() {
  els.applyBtn.addEventListener("click", async () => {
    await postJSON("/api/config", readParams());
    await refreshState();
  });

  els.resetBtn.addEventListener("click", async () => {
    latest = await postJSON("/api/reset", readParams());
    renderState();
  });

  els.startBtn.addEventListener("click", async () => {
    await postJSON("/api/start");
    await refreshState();
  });

  els.stopBtn.addEventListener("click", async () => {
    await postJSON("/api/stop");
    await refreshState();
  });

  els.saveBtn.addEventListener("click", async () => {
    const name = els.runName.value || "immune_experiment";
    const compare_run_id = compareRun?.run_id || els.runSelect.value || "";
    const data = await postJSON("/api/save_run", { name, compare_run_id });
    els.runPlot.src = data.plot;
    els.runSummary.textContent = JSON.stringify(data.summary, null, 2);
    els.comparisonSummary.textContent = `Saved ${data.run_id}`;
    await refreshRuns();
  });

  els.refreshRunsBtn.addEventListener("click", refreshRuns);
  els.loadRunBtn.addEventListener("click", async () => {
    await loadRun(els.runSelect.value);
  });

  els.speedSlider.addEventListener("input", async () => {
    const value = Number(els.speedSlider.value);
    els.speedValue.textContent = `${formatValue(value)}x`;
    const hiddenInput = document.getElementById("param_time_scale");
    if (hiddenInput) hiddenInput.value = value;
    try {
      await postJSON("/api/config", { time_scale: value });
    } catch (error) {
      console.error(error);
    }
  });

  els.canvasSizeSlider.addEventListener("input", () => {
    applyCanvasSize(Number(els.canvasSizeSlider.value));
    renderState();
  });
}

async function init() {
  wireEvents();
  wirePresetButtons();
  wireCanvasHover();
  applyCanvasSize(Number(els.canvasSizeSlider.value));
  await refreshState();
  await refreshRuns();
  setInterval(refreshState, 260);
  window.addEventListener("resize", () => {
    renderState();
  });
}

init();
