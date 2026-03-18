# Immune Microenvironment Simulator

Local interactive simulator for a spatial immune control loop: tissue-anchored cells, local pathogen spread, mobile immune effectors, antigen presentation, cytokine downregulation, and self-reactivity.

## Features
- 2D tissue grid with explicit cell states: healthy, infected by virus, infected by bacteria, damaged, dead.
- Local pathogen burden and spread, rather than detached global counters only.
- Mobile dendritic, T, B, and Treg agents with chemotaxis-like movement.
- Diffusing pro- and anti-inflammatory cytokine fields.
- Adjustable benign-cell count, pathogen load, infection strength, activation rates, self-attack probability, and time speed.
- Lab-style dashboard with live tissue rendering, live charts, saved-run comparison, and static SVG summary plots.
- Saved run payloads include the config, final state, time series, and sampled world snapshots.

## Model provenance

The systemic immune-response layer was updated after reviewing:

- Fields Institute talk: `Modelling Immunity` by Jane Heffernan
  - <https://www.youtube.com/watch?v=HoIT-kr7HnQ>
- Fields page for that talk
  - <https://www.fields.utoronto.ca/talks/Modelling-Immunity>
- Linked paper whose ODE structure is used here
  - Korosec et al., `Long-Term Predictions of Humoral Immunity after Two Doses of BNT162b2 and mRNA-1273 Vaccines...`
  - <https://pmc.ncbi.nlm.nih.gov/articles/PMC8402548/>

What was used from that material:

- The simulator now uses the same seven-variable systemic immune model structure for:
  - effective antigen / vaccine-like particles `V`
  - helper T-cells `T`
  - IFN-gamma `F`
  - IL-6 `I`
  - plasma B-cells `B`
  - antibodies `A`
  - cytotoxic T-cells `C`
- The 2D tissue model is still spatial and local. The ODE system is coupled into it as the global immune-control layer.

## Systemic equations

The systemic layer follows this equation structure:

```text
dV/dt = input - α16 V A - γv V
dT/dt = μ21 V - γt T
dF/dt = μ32 T - γf F - α37 F C
dI/dt = μ42 T - γi I - α45 I B
dB/dt = μ52 T + α54 (I / (Si + I)) B - γb B
dA/dt = μ65 B - γa A - α61 A V
dC/dt = μ71 V + α73 (F / (Sf + F)) C - γc C
```

In this simulator:

- `V` is not a literal vaccine compartment. It is used as an effective systemic antigen load derived from the current 2D pathogen field.
- `F` and `I` feed the pro-inflammatory signaling layer.
- `A` contributes to pathogen neutralization.
- `C` and `T` modulate T-cell activation and killing pressure.
- `B` drives antibody production.

This is an adapted hybrid model, not a direct reproduction of the paper's vaccine-only setting.

## Antigen recognition and danger signaling

The simulator does not implement explicit receptor-level matching between a dendritic cell peptide-MHC complex and a clone-specific T-cell receptor or B-cell receptor. Recognition is modeled phenomenologically as activation driven by local antigen presentation plus inflammatory context.

### Dendritic cells

- Dendritic cells patrol the tissue and evaluate a local detection drive:
  - `detect_drive = local_pathogen + local_damage`
- If that drive crosses threshold and passes a stochastic detection test, the dendritic cell:
  - switches to a `presenting` state
  - accumulates internal antigen
  - increases the local `antigen_field`
  - emits additional pro-inflammatory cytokine signal
- Infected tissue cells also contribute directly to the antigen field, so dendritic presentation and infected-cell antigen release both help expose local threat to the adaptive layer.

### T cells

- T-cell activation is a weighted combination of:
  - local antigen
  - local pro-inflammatory cytokines
  - systemic effective antigen
  - systemic IFN-gamma
  - systemic helper-T signal
- Anti-inflammatory cytokines reduce that activation.
- Once activation crosses threshold, the T cell becomes `active` and can:
  - kill infected cells
  - clear local pathogen burden
  - in autoimmune-prone settings, probabilistically damage healthy tissue

### B cells

- B-cell activation is a weighted combination of:
  - local antigen
  - nearby active T-cell help
  - systemic effective antigen
  - systemic IL-6
- Anti-inflammatory cytokines reduce B-cell activation as well.
- Active B cells feed the plasma-B / antibody arm of the systemic model, which then contributes to pathogen neutralization.

### What counts as the danger signal

There is no single explicit `danger_signal` variable. Danger is represented by the combination of:

- local pathogen burden: `virus_field + bacteria_field`
- tissue damage: `damage_field`
- pro-inflammatory cytokines: `pro_field`
- systemic inflammatory mediators: IFN-gamma and IL-6
- effective systemic antigen derived from the tissue infection field

In practical terms, the clearest local danger trigger is:

```text
danger ~= pathogen burden + tissue damage
```

That local danger drives dendritic detection and antigen presentation, and the resulting antigen plus cytokine environment determines whether T and B cells activate or remain quiescent.

### Biological interpretation

- This captures the control logic of `antigen + costimulation + inflammatory context`.
- It does not yet model:
  - clone-specific antigen identity
  - peptide-MHC specificity
  - receptor affinity
  - clonal expansion by exact antigen match
  - explicit self-antigen and foreign-antigen label sets

So the current simulator is appropriate for studying response-shape and regulation tradeoffs, but not for studying molecular antigen specificity.

## Run
From repository root:

```bash
python3 utils/immune_web_sim/app.py
```

Open `http://127.0.0.1:5012`.

## Validation

The utility was validated locally with:

```bash
python3 -m py_compile utils/immune_web_sim/app.py utils/immune_web_sim/simulation.py
python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path('tests/unit').resolve()))
import test_immune_web_sim as t
for name in [
    'test_more_healthy_cells_change_occupancy_and_dynamics',
    'test_high_treg_settings_downregulate_effectors',
    'test_high_self_attack_increases_autoimmune_damage',
    'test_stronger_pathogen_overwhelms_more_than_weaker_case',
    'test_engine_state_contains_world_and_history_shape',
]:
    getattr(t, name)()
PY
```

## Outputs
Saved runs are written to:
- `utils/immune_web_sim/runs/<run_id>.json`
- `utils/immune_web_sim/runs/<run_id>.svg`
