from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List


STATE_EMPTY = 0
STATE_HEALTHY = 1
STATE_INFECTED_VIRUS = 2
STATE_INFECTED_BACTERIA = 3
STATE_DEAD = 4
STATE_DAMAGED = 5

STATE_CHARS = {
    STATE_EMPTY: ".",
    STATE_HEALTHY: "h",
    STATE_INFECTED_VIRUS: "v",
    STATE_INFECTED_BACTERIA: "b",
    STATE_DEAD: "d",
    STATE_DAMAGED: "x",
}

INT_FIELDS = {
    "grid_width",
    "grid_height",
    "healthy_cells",
    "infected_cells",
    "dendritic_cells",
    "t_cells",
    "b_cells",
    "treg_cells",
    "sample_world_every",
    "random_seed",
}

KIND_CODE = {
    "dendritic": "dc",
    "t_cell": "tc",
    "b_cell": "bc",
    "treg": "tr",
}


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _sigmoidish(value: float) -> float:
    return value / (1.0 + abs(value))


@dataclass
class Agent:
    kind: str
    x: int
    y: int
    state: str = "patrolling"
    activation: float = 0.0
    antigen: float = 0.0
    presenting_timer: float = 0.0
    age: float = 0.0


@dataclass
class ImmuneConfig:
    grid_width: int = 96
    grid_height: int = 60
    healthy_cells: int = 2000
    infected_cells: int = 18
    initial_healthy_density: float = 0.82

    dendritic_cells: int = 36
    t_cells: int = 120
    b_cells: int = 80
    treg_cells: int = 24

    viruses: float = 260.0
    bacteria: float = 120.0
    infection_strength: float = 0.62
    infection_ratio: float = 0.28

    virus_growth_rate: float = 0.18
    bacteria_growth_rate: float = 0.14
    virus_spread_rate: float = 0.22
    bacteria_spread_rate: float = 0.18
    pathogen_decay_rate: float = 0.05
    cell_recovery_rate: float = 0.015

    dendritic_detection_rate: float = 0.18
    antigen_presentation_efficiency: float = 0.72
    t_activation_rate: float = 0.22
    b_activation_rate: float = 0.16
    recruitment_rate: float = 0.32

    dendritic_patrol_speed: float = 0.95
    t_cell_patrol_speed: float = 1.0
    b_cell_patrol_speed: float = 0.72
    treg_patrol_speed: float = 0.88
    chemotaxis_strength: float = 1.15

    antibody_production_rate: float = 0.32
    antibody_decay_rate: float = 0.08

    cytokine_production_rate: float = 0.24
    cytokine_decay_rate: float = 0.1
    anti_inflammatory_rate: float = 0.22
    pro_diffusion_rate: float = 0.32
    anti_diffusion_rate: float = 0.28

    pathogen_kill_by_t: float = 0.28
    pathogen_kill_by_antibody: float = 0.19
    infected_clearance_rate: float = 0.26

    self_attack_probability: float = 0.02
    collateral_damage_rate: float = 0.022
    time_scale: float = 1.0

    sample_world_every: int = 10
    random_seed: int = 7


@dataclass
class ImmuneState:
    t: float = 0.0
    step_index: int = 0

    healthy_cells: float = 0.0
    infected_cells: float = 0.0
    dead_cells: float = 0.0
    damaged_cells: float = 0.0

    viruses: float = 0.0
    bacteria: float = 0.0
    effective_antigen: float = 0.0
    helper_t_cells: float = 0.0
    ifn_gamma: float = 0.0
    il6: float = 0.0
    plasma_b_cells: float = 0.0
    cytotoxic_t_cells: float = 0.0

    antigen_signal: float = 0.0
    activated_t_cells: float = 0.0
    activated_b_cells: float = 0.0

    antibodies: float = 0.0
    pro_cytokines: float = 0.0
    anti_cytokines: float = 0.0

    tissue_damage_index: float = 0.0
    autoimmune_events: float = 0.0

    history: List[Dict[str, float]] = field(default_factory=list)
    sampled_worlds: List[Dict[str, object]] = field(default_factory=list)


class ImmuneSimulation:
    def __init__(self, cfg: ImmuneConfig | None = None) -> None:
        self.cfg = cfg or ImmuneConfig()
        self.rng = random.Random(self.cfg.random_seed)
        self.width = self.cfg.grid_width
        self.height = self.cfg.grid_height
        self.neighbors: list[list[int]] = []
        self.tissue: list[int] = []
        self.virus_field: list[float] = []
        self.bacteria_field: list[float] = []
        self.pro_field: list[float] = []
        self.anti_field: list[float] = []
        self.antigen_field: list[float] = []
        self.damage_field: list[float] = []
        self.agents: list[Agent] = []
        self.extra_agent_caps: dict[str, int] = {}
        self.antibody_level = 0.0
        self.state = ImmuneState()
        self.reset()

    def update_config(self, params: Dict[str, float]) -> None:
        for key, value in params.items():
            if not hasattr(self.cfg, key):
                continue
            coerced = int(round(value)) if key in INT_FIELDS else float(value)
            setattr(self.cfg, key, coerced)

    def reset(self, params: Dict[str, float] | None = None) -> None:
        if params:
            self.update_config(params)

        self.rng = random.Random(self.cfg.random_seed)
        self.width = max(24, int(self.cfg.grid_width))
        self.height = max(18, int(self.cfg.grid_height))
        total = self.width * self.height
        self.neighbors = self._build_neighbors()

        self.tissue = [STATE_EMPTY] * total
        self.virus_field = [0.0] * total
        self.bacteria_field = [0.0] * total
        self.pro_field = [0.0] * total
        self.anti_field = [0.0] * total
        self.antigen_field = [0.0] * total
        self.damage_field = [0.0] * total
        self.antibody_level = 0.0
        self.agents = []

        region = self._eligible_tissue_region()
        occupancy_target = min(len(region), max(0, int(self.cfg.healthy_cells)))
        occupied = self.rng.sample(region, occupancy_target) if occupancy_target else []
        for idx in occupied:
            self.tissue[idx] = STATE_HEALTHY

        infected_target = min(max(0, int(self.cfg.infected_cells)), len(occupied))
        infected_sites = self.rng.sample(occupied, infected_target) if infected_target else []

        total_pathogen = max(0.0, self.cfg.viruses) + max(0.0, self.cfg.bacteria)
        virus_fraction = 0.5 if total_pathogen <= 0 else self.cfg.viruses / total_pathogen
        virus_infected = min(len(infected_sites), int(round(len(infected_sites) * virus_fraction)))
        virus_sites = infected_sites[:virus_infected]
        bacteria_sites = infected_sites[virus_infected:]

        for idx in virus_sites:
            self.tissue[idx] = STATE_INFECTED_VIRUS
        for idx in bacteria_sites:
            self.tissue[idx] = STATE_INFECTED_BACTERIA

        self._seed_pathogen(self.cfg.viruses, virus_sites, self.virus_field)
        self._seed_pathogen(self.cfg.bacteria, bacteria_sites, self.bacteria_field)
        self._spawn_initial_agents()

        self.state = ImmuneState(
            healthy_cells=float(sum(1 for s in self.tissue if s == STATE_HEALTHY)),
            infected_cells=float(
                sum(1 for s in self.tissue if s in (STATE_INFECTED_VIRUS, STATE_INFECTED_BACTERIA))
            ),
            dead_cells=float(sum(1 for s in self.tissue if s == STATE_DEAD)),
            damaged_cells=float(sum(1 for s in self.tissue if s == STATE_DAMAGED)),
            viruses=sum(self.virus_field),
            bacteria=sum(self.bacteria_field),
            effective_antigen=max(0.1, 0.002 * (sum(self.virus_field) + sum(self.bacteria_field))),
        )
        self.extra_agent_caps = {
            "t_cell": max(1, int(self.cfg.t_cells * 1.5)),
            "b_cell": max(1, int(self.cfg.b_cells * 1.2)),
            "treg": max(1, int(self.cfg.treg_cells * 1.1)),
        }
        self.record_snapshot(force_world_sample=True)

    def step(self, dt: float = 0.12) -> None:
        eff_dt = _clamp(dt * self.cfg.time_scale, 0.03, 1.5)
        substeps = max(1, int(math.ceil(eff_dt / 0.2)))
        local_dt = eff_dt / substeps
        for _ in range(substeps):
            self._step_once(local_dt)
        self.record_snapshot()

    def _step_once(self, dt: float) -> None:
        self.state.t += dt
        self.state.step_index += 1

        self.virus_field = self._diffuse(
            self.virus_field,
            self.cfg.virus_spread_rate * dt,
            self.cfg.pathogen_decay_rate * dt,
        )
        self.bacteria_field = self._diffuse(
            self.bacteria_field,
            self.cfg.bacteria_spread_rate * dt,
            self.cfg.pathogen_decay_rate * dt,
        )
        self.pro_field = self._diffuse(
            self.pro_field,
            self.cfg.pro_diffusion_rate * dt,
            self.cfg.cytokine_decay_rate * dt,
        )
        self.anti_field = self._diffuse(
            self.anti_field,
            self.cfg.anti_diffusion_rate * dt,
            self.cfg.cytokine_decay_rate * dt,
        )
        self.antigen_field = self._diffuse(self.antigen_field, 0.22 * dt, 0.08 * dt)

        next_tissue = list(self.tissue)
        autoimmune_hits = 0.0

        for idx, state in enumerate(self.tissue):
            virus_here = self.virus_field[idx]
            bacteria_here = self.bacteria_field[idx]
            pro_here = self.pro_field[idx]
            anti_here = self.anti_field[idx]
            threat = virus_here + bacteria_here
            threat += 0.25 * self._neighbor_mean(self.virus_field, idx)
            threat += 0.25 * self._neighbor_mean(self.bacteria_field, idx)

            if state == STATE_HEALTHY:
                infection_drive = self.cfg.infection_strength * (0.45 + self.cfg.infection_ratio)
                infection_drive *= threat / (1.1 + threat)
                infection_drive *= 1.0 / (1.0 + 0.65 * anti_here + 0.2 * self.antibody_level)
                if self.rng.random() < infection_drive * dt:
                    next_tissue[idx] = (
                        STATE_INFECTED_VIRUS if virus_here >= bacteria_here else STATE_INFECTED_BACTERIA
                    )

                if pro_here > 1.8 and self.rng.random() < self.cfg.collateral_damage_rate * pro_here * dt * 0.28:
                    next_tissue[idx] = STATE_DAMAGED
                    self.damage_field[idx] += 0.35

            elif state == STATE_DAMAGED:
                if threat > 0.55 and self.rng.random() < self.cfg.infection_strength * threat * dt * 0.18:
                    next_tissue[idx] = (
                        STATE_INFECTED_VIRUS if virus_here >= bacteria_here else STATE_INFECTED_BACTERIA
                    )
                elif anti_here > pro_here and threat < 0.2 and self.rng.random() < self.cfg.cell_recovery_rate * dt:
                    next_tissue[idx] = STATE_HEALTHY
                    self.damage_field[idx] *= 0.7

            elif state == STATE_INFECTED_VIRUS:
                self.virus_field[idx] += 0.05 + self.virus_field[idx] * self.cfg.virus_growth_rate * dt
                self.pro_field[idx] += self.cfg.cytokine_production_rate * 0.45 * dt
                self.antigen_field[idx] += 0.44 * self.cfg.antigen_presentation_efficiency * dt
                self.damage_field[idx] += (0.02 + 0.05 * self.virus_field[idx]) * dt
                if self.damage_field[idx] > 1.35:
                    next_tissue[idx] = STATE_DEAD

            elif state == STATE_INFECTED_BACTERIA:
                self.bacteria_field[idx] += 0.04 + self.bacteria_field[idx] * self.cfg.bacteria_growth_rate * dt
                self.pro_field[idx] += self.cfg.cytokine_production_rate * 0.38 * dt
                self.antigen_field[idx] += 0.36 * self.cfg.antigen_presentation_efficiency * dt
                self.damage_field[idx] += (0.015 + 0.04 * self.bacteria_field[idx]) * dt
                if self.damage_field[idx] > 1.15:
                    next_tissue[idx] = STATE_DEAD

            elif state == STATE_DEAD:
                self.virus_field[idx] *= 0.92
                self.bacteria_field[idx] *= 0.92
                self.pro_field[idx] += 0.04 * dt

            if threat < 0.02 and next_tissue[idx] in (STATE_INFECTED_VIRUS, STATE_INFECTED_BACTERIA):
                next_tissue[idx] = STATE_DAMAGED
                self.damage_field[idx] += 0.1

            if pro_here > 2.7 and next_tissue[idx] in (STATE_HEALTHY, STATE_DAMAGED):
                if self.rng.random() < self.cfg.collateral_damage_rate * pro_here * dt * 0.12:
                    next_tissue[idx] = STATE_DEAD if pro_here > 4.2 else STATE_DAMAGED
                    self.damage_field[idx] += 0.25

        self.tissue = next_tissue
        self.antibody_level = max(
            0.0,
            self.antibody_level - self.cfg.antibody_decay_rate * self.antibody_level * dt,
        )

        self._update_systemic_immune_model(dt)
        self.antibody_level = self.state.antibodies

        for idx in range(len(self.tissue)):
            antibody_kill = self.antibody_level * self.cfg.pathogen_kill_by_antibody * dt * 0.045
            self.virus_field[idx] = max(0.0, self.virus_field[idx] - antibody_kill)
            self.bacteria_field[idx] = max(0.0, self.bacteria_field[idx] - antibody_kill * 0.85)

        autoimmune_hits += self._update_agents(dt)
        self._recruit_agents(dt)
        self._refresh_scalars(autoimmune_hits)

    def _update_agents(self, dt: float) -> float:
        autoimmune_hits = 0.0
        active_t = 0
        active_b = 0
        systemic_antigen = self.state.effective_antigen + sum(self.antigen_field) / max(1, len(self.antigen_field))
        systemic_ifn = self.state.ifn_gamma
        systemic_il6 = self.state.il6
        systemic_t_help = self.state.helper_t_cells

        for agent in self.agents:
            agent.age += dt
            idx = self._idx(agent.x, agent.y)
            local_pathogen = self.virus_field[idx] + self.bacteria_field[idx]
            local_antigen = self.antigen_field[idx]
            local_pro = self.pro_field[idx]
            local_anti = self.anti_field[idx]

            if agent.kind == "dendritic":
                detect_drive = local_pathogen + self.damage_field[idx]
                if detect_drive > 0.35 and self.rng.random() < self.cfg.dendritic_detection_rate * detect_drive * dt:
                    agent.state = "presenting"
                    agent.antigen = min(5.0, agent.antigen + detect_drive * self.cfg.antigen_presentation_efficiency)
                    agent.presenting_timer = min(8.0, agent.presenting_timer + 2.8)
                    self.antigen_field[idx] += 0.45 * agent.antigen * dt
                    self.pro_field[idx] += 0.18 * self.cfg.cytokine_production_rate * dt
                else:
                    agent.antigen *= 0.97
                if agent.presenting_timer > 0:
                    agent.presenting_timer = max(0.0, agent.presenting_timer - dt)
                    agent.state = "presenting" if agent.presenting_timer > 0 else "patrolling"
                    self.antigen_field[idx] += 0.38 * agent.antigen * dt
                    self.pro_field[idx] += 0.08 * dt

            elif agent.kind == "t_cell":
                activation_gain = (
                    1.25 * local_antigen
                    + 0.45 * local_pro
                    + 0.9 * systemic_antigen
                    + 0.7 * systemic_ifn
                    + 0.35 * systemic_t_help
                ) * self.cfg.t_activation_rate * dt
                activation_loss = (0.08 + 0.24 * local_anti) * dt
                agent.activation = _clamp(agent.activation + activation_gain - activation_loss, 0.0, 3.5)
                agent.state = "active" if agent.activation > 0.35 else "patrolling"
                if agent.state == "active":
                    active_t += 1
                    autoimmune_hits += self._t_cell_action(agent, idx, dt)

            elif agent.kind == "b_cell":
                t_help = self._count_agents_near(agent.x, agent.y, "t_cell", "active", radius=2)
                activation_gain = (
                    0.95 * local_antigen + 0.22 * t_help + 0.7 * systemic_antigen + 0.8 * systemic_il6
                ) * self.cfg.b_activation_rate * dt
                activation_loss = (0.06 + 0.18 * local_anti) * dt
                agent.activation = _clamp(agent.activation + activation_gain - activation_loss, 0.0, 3.0)
                agent.state = "active" if agent.activation > 0.42 else "patrolling"
                if agent.state == "active":
                    active_b += 1
                    self.pro_field[idx] += 0.025 * dt

            elif agent.kind == "treg":
                activation_gain = max(0.0, local_pro - 0.2 * local_anti) * self.cfg.anti_inflammatory_rate * dt
                agent.activation = _clamp(agent.activation + activation_gain - 0.05 * dt, 0.0, 2.4)
                agent.state = "regulating" if agent.activation > 0.18 else "patrolling"
                anti_boost = (0.14 + 0.32 * agent.activation) * dt
                self.anti_field[idx] += anti_boost
                self.pro_field[idx] = max(0.0, self.pro_field[idx] - anti_boost * 0.8)
                self._suppress_nearby_effectors(agent.x, agent.y, anti_boost * 1.3)

            self._move_agent(agent, dt)

        self.state.activated_t_cells = float(active_t)
        self.state.activated_b_cells = float(active_b)
        return autoimmune_hits

    def _update_systemic_immune_model(self, dt: float) -> None:
        total_pathogen = sum(self.virus_field) + sum(self.bacteria_field)
        tissue_sites = max(1.0, self.state.healthy_cells + self.state.infected_cells + self.state.damaged_cells)
        pathogen_input = total_pathogen / tissue_sites

        v = self.state.effective_antigen
        t = self.state.helper_t_cells
        f = self.state.ifn_gamma
        i = self.state.il6
        b = self.state.plasma_b_cells
        a = self.state.antibodies
        c = self.state.cytotoxic_t_cells

        mu21 = self.cfg.dendritic_detection_rate * self.cfg.antigen_presentation_efficiency * 0.9
        mu32 = self.cfg.cytokine_production_rate * 1.2
        mu42 = self.cfg.cytokine_production_rate
        mu52 = self.cfg.b_activation_rate * 1.25
        mu65 = self.cfg.antibody_production_rate * 0.9
        mu71 = self.cfg.t_activation_rate * 1.15

        alpha16 = self.cfg.pathogen_kill_by_antibody * 0.06
        alpha37 = 0.03
        alpha45 = 0.02
        alpha54 = self.cfg.b_activation_rate * 0.75
        alpha61 = self.cfg.pathogen_kill_by_antibody * 0.04
        alpha73 = self.cfg.t_activation_rate * 0.85

        gamma_v = self.cfg.pathogen_decay_rate + 0.04
        gamma_t = 0.08
        gamma_f = self.cfg.cytokine_decay_rate
        gamma_i = self.cfg.cytokine_decay_rate
        gamma_b = 0.05
        gamma_a = self.cfg.antibody_decay_rate
        gamma_c = 0.07

        s_i = 0.8
        s_f = 0.8

        dv = pathogen_input - alpha16 * v * a - gamma_v * v
        dt_h = mu21 * v - gamma_t * t
        df = mu32 * t - gamma_f * f - alpha37 * f * c
        di = mu42 * t - gamma_i * i - alpha45 * i * b
        db = mu52 * t + alpha54 * (i / (s_i + i)) * b - gamma_b * b
        da = mu65 * b - gamma_a * a - alpha61 * a * v
        dc = mu71 * v + alpha73 * (f / (s_f + f)) * c - gamma_c * c

        self.state.effective_antigen = max(0.0, v + dv * dt)
        self.state.helper_t_cells = max(0.0, t + dt_h * dt)
        self.state.ifn_gamma = max(0.0, f + df * dt)
        self.state.il6 = max(0.0, i + di * dt)
        self.state.plasma_b_cells = max(0.0, b + db * dt)
        self.state.antibodies = max(0.0, a + da * dt)
        self.state.cytotoxic_t_cells = max(0.0, c + dc * dt)

        mean_ifn = self.state.ifn_gamma / max(1.0, tissue_sites / 60.0)
        mean_il6 = self.state.il6 / max(1.0, tissue_sites / 60.0)
        for idx in range(len(self.tissue)):
            if self.tissue[idx] in (STATE_INFECTED_VIRUS, STATE_INFECTED_BACTERIA, STATE_DAMAGED):
                self.pro_field[idx] += (0.02 * mean_ifn + 0.015 * mean_il6) * dt
                self.antigen_field[idx] += 0.012 * self.state.effective_antigen * dt

    def _t_cell_action(self, agent: Agent, idx: int, dt: float) -> float:
        autoimmune_hits = 0.0
        candidate_cells = [idx] + self.neighbors[idx]
        self.rng.shuffle(candidate_cells)

        for target in candidate_cells:
            if self.tissue[target] in (STATE_INFECTED_VIRUS, STATE_INFECTED_BACTERIA):
                kill_strength = self.cfg.pathogen_kill_by_t * agent.activation * dt * 2.2
                self.virus_field[target] = max(0.0, self.virus_field[target] - kill_strength * 0.8)
                self.bacteria_field[target] = max(0.0, self.bacteria_field[target] - kill_strength * 0.7)
                if self.rng.random() < self.cfg.infected_clearance_rate * agent.activation * dt * 0.55:
                    self.tissue[target] = STATE_DAMAGED if self.rng.random() < 0.45 else STATE_DEAD
                    self.damage_field[target] += 0.2
                    self.pro_field[target] += 0.12
                break

        anti_brake = 1.0 / (1.0 + self.anti_field[idx] * 1.2)
        self_hit = self.cfg.self_attack_probability * agent.activation * anti_brake * dt * 0.35
        if self_hit > 0 and self.rng.random() < self_hit:
            healthy_candidates = [i for i in candidate_cells if self.tissue[i] == STATE_HEALTHY]
            if healthy_candidates:
                target = self.rng.choice(healthy_candidates)
                self.tissue[target] = STATE_DAMAGED if self.rng.random() < 0.7 else STATE_DEAD
                self.damage_field[target] += 0.35
                self.pro_field[target] += 0.18
                autoimmune_hits += 1.0

        return autoimmune_hits

    def _move_agent(self, agent: Agent, dt: float) -> None:
        speed_map = {
            "dendritic": self.cfg.dendritic_patrol_speed,
            "t_cell": self.cfg.t_cell_patrol_speed,
            "b_cell": self.cfg.b_cell_patrol_speed,
            "treg": self.cfg.treg_patrol_speed,
        }
        if self.rng.random() > _clamp(speed_map[agent.kind] * dt, 0.05, 1.0):
            return

        current_idx = self._idx(agent.x, agent.y)
        options = [current_idx] + self.neighbors[current_idx]
        best_idx = current_idx
        best_score = -10_000.0

        for candidate in options:
            x = candidate % self.width
            y = candidate // self.width
            random_bias = self.rng.uniform(-0.05, 0.05)
            score = random_bias

            if agent.kind == "dendritic":
                score += self.virus_field[candidate] + self.bacteria_field[candidate] + 0.5 * self.damage_field[candidate]
            elif agent.kind == "t_cell":
                score += (
                    self.cfg.chemotaxis_strength
                    * (
                        self.antigen_field[candidate]
                        + 0.65 * self.pro_field[candidate]
                        + 0.2 * (self.virus_field[candidate] + self.bacteria_field[candidate])
                    )
                )
                score -= 0.75 * self.anti_field[candidate]
            elif agent.kind == "b_cell":
                score += 0.7 * self.antigen_field[candidate] + 0.2 * self.pro_field[candidate]
                score += 0.08 * self._count_agents_near(x, y, "t_cell", "active", radius=2)
                score -= 0.5 * self.anti_field[candidate]
            elif agent.kind == "treg":
                score += self.pro_field[candidate] - 0.15 * self.anti_field[candidate]

            if self.tissue[candidate] == STATE_DEAD and agent.kind != "dendritic":
                score -= 0.1

            if score > best_score:
                best_score = score
                best_idx = candidate

        agent.x = best_idx % self.width
        agent.y = best_idx // self.width

    def _recruit_agents(self, dt: float) -> None:
        mean_pro = sum(self.pro_field) / max(1, len(self.pro_field))
        mean_antigen = sum(self.antigen_field) / max(1, len(self.antigen_field))
        signal = (
            mean_pro
            + 1.2 * mean_antigen
            + 0.6 * self.state.ifn_gamma
            + 0.4 * self.state.il6
            + 0.4 * self.state.effective_antigen
        )
        recruit_drive = self.cfg.recruitment_rate * signal * dt

        for kind in ("t_cell", "b_cell", "treg"):
            current = sum(1 for agent in self.agents if agent.kind == kind)
            cap = getattr(self.cfg, {"t_cell": "t_cells", "b_cell": "b_cells", "treg": "treg_cells"}[kind])
            cap += self.extra_agent_caps.get(kind, 0)
            if current >= cap:
                continue
            if self.rng.random() < recruit_drive * {"t_cell": 0.28, "b_cell": 0.16, "treg": 0.12}[kind]:
                x, y = self._edge_position()
                self.agents.append(Agent(kind=kind, x=x, y=y))

    def _refresh_scalars(self, autoimmune_hits: float) -> None:
        healthy = 0
        infected = 0
        dead = 0
        damaged = 0
        for state in self.tissue:
            if state == STATE_HEALTHY:
                healthy += 1
            elif state in (STATE_INFECTED_VIRUS, STATE_INFECTED_BACTERIA):
                infected += 1
            elif state == STATE_DEAD:
                dead += 1
            elif state == STATE_DAMAGED:
                damaged += 1

        self.state.healthy_cells = float(healthy)
        self.state.infected_cells = float(infected)
        self.state.dead_cells = float(dead)
        self.state.damaged_cells = float(damaged)
        self.state.viruses = round(sum(self.virus_field), 6)
        self.state.bacteria = round(sum(self.bacteria_field), 6)
        self.state.antigen_signal = round(sum(self.antigen_field) + self.state.effective_antigen, 6)
        self.state.antibodies = round(self.state.antibodies, 6)
        self.state.pro_cytokines = round(sum(self.pro_field) + self.state.ifn_gamma + self.state.il6, 6)
        self.state.anti_cytokines = round(sum(self.anti_field), 6)
        self.state.autoimmune_events += autoimmune_hits
        tissue_space = max(1.0, self.state.healthy_cells + self.state.infected_cells + self.state.damaged_cells)
        self.state.tissue_damage_index = round(
            (dead + 0.6 * damaged) / tissue_space * 100.0 + self.state.autoimmune_events * 0.12,
            6,
        )

    def outcome_label(self) -> str:
        pathogen = self.state.viruses + self.state.bacteria
        if pathogen < 25 and self.state.infected_cells < 12 and self.state.tissue_damage_index < 12:
            return "Controlled resolution"
        if pathogen < 90 and self.state.infected_cells < 40 and self.state.tissue_damage_index < 20:
            return "Suppressed with residual burden"
        if self.state.tissue_damage_index > 45:
            return "Hyperinflammatory tissue damage"
        if self.state.autoimmune_events > 14:
            return "Autoimmune-prone response"
        return "Persistent infection"

    def record_snapshot(self, force_world_sample: bool = False) -> None:
        snapshot = {
            "t": self.state.t,
            "healthy_cells": self.state.healthy_cells,
            "infected_cells": self.state.infected_cells,
            "dead_cells": self.state.dead_cells,
            "damaged_cells": self.state.damaged_cells,
            "viruses": self.state.viruses,
            "bacteria": self.state.bacteria,
            "effective_antigen": self.state.effective_antigen,
            "helper_t_cells": self.state.helper_t_cells,
            "ifn_gamma": self.state.ifn_gamma,
            "il6": self.state.il6,
            "plasma_b_cells": self.state.plasma_b_cells,
            "cytotoxic_t_cells": self.state.cytotoxic_t_cells,
            "antigen_signal": self.state.antigen_signal,
            "activated_t_cells": self.state.activated_t_cells,
            "activated_b_cells": self.state.activated_b_cells,
            "antibodies": self.state.antibodies,
            "pro_cytokines": self.state.pro_cytokines,
            "anti_cytokines": self.state.anti_cytokines,
            "tissue_damage_index": self.state.tissue_damage_index,
            "autoimmune_events": self.state.autoimmune_events,
        }
        self.state.history.append(snapshot)

        every = max(1, int(self.cfg.sample_world_every))
        if force_world_sample or self.state.step_index % every == 0:
            self.state.sampled_worlds.append({"t": round(self.state.t, 3), "world": self.public_world()})

    def public_state(self) -> Dict[str, float | str]:
        return {
            "t": round(self.state.t, 3),
            "healthy_cells": round(self.state.healthy_cells, 3),
            "infected_cells": round(self.state.infected_cells, 3),
            "dead_cells": round(self.state.dead_cells, 3),
            "damaged_cells": round(self.state.damaged_cells, 3),
            "viruses": round(self.state.viruses, 3),
            "bacteria": round(self.state.bacteria, 3),
            "effective_antigen": round(self.state.effective_antigen, 3),
            "helper_t_cells": round(self.state.helper_t_cells, 3),
            "ifn_gamma": round(self.state.ifn_gamma, 3),
            "il6": round(self.state.il6, 3),
            "plasma_b_cells": round(self.state.plasma_b_cells, 3),
            "cytotoxic_t_cells": round(self.state.cytotoxic_t_cells, 3),
            "antigen_signal": round(self.state.antigen_signal, 3),
            "activated_t_cells": round(self.state.activated_t_cells, 3),
            "activated_b_cells": round(self.state.activated_b_cells, 3),
            "antibodies": round(self.state.antibodies, 3),
            "pro_cytokines": round(self.state.pro_cytokines, 3),
            "anti_cytokines": round(self.state.anti_cytokines, 3),
            "tissue_damage_index": round(self.state.tissue_damage_index, 3),
            "autoimmune_events": round(self.state.autoimmune_events, 3),
            "outcome": self.outcome_label(),
        }

    def public_world(self) -> Dict[str, object]:
        return {
            "width": self.width,
            "height": self.height,
            "tissue_rows": self._encode_tissue_rows(),
            "pathogen_rows": self._encode_heat_rows(
                [self.virus_field[i] + self.bacteria_field[i] for i in range(len(self.tissue))]
            ),
            "pro_rows": self._encode_heat_rows(self.pro_field),
            "anti_rows": self._encode_heat_rows(self.anti_field),
            "agents": [
                {
                    "x": agent.x,
                    "y": agent.y,
                    "kind": KIND_CODE[agent.kind],
                    "state": agent.state,
                    "activation": round(agent.activation, 2),
                }
                for agent in self.agents
            ],
        }

    def config_dict(self) -> Dict[str, float]:
        return {k: getattr(self.cfg, k) for k in vars(self.cfg)}

    def history_tail(self, length: int = 240) -> List[Dict[str, float]]:
        return self.state.history[-length:]

    def _build_neighbors(self) -> list[list[int]]:
        neighbors: list[list[int]] = []
        for idx in range(self.width * self.height):
            x = idx % self.width
            y = idx // self.width
            local: list[int] = []
            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    if dx == 0 and dy == 0:
                        continue
                    nx = x + dx
                    ny = y + dy
                    if 0 <= nx < self.width and 0 <= ny < self.height:
                        local.append(self._idx(nx, ny))
            neighbors.append(local)
        return neighbors

    def _eligible_tissue_region(self) -> list[int]:
        total = self.width * self.height
        target = max(1, min(total, int(total * _clamp(self.cfg.initial_healthy_density, 0.08, 1.0))))
        cx = (self.width - 1) / 2.0
        cy = (self.height - 1) / 2.0
        ranked = list(range(total))
        ranked.sort(
            key=lambda idx: (
                (((idx % self.width) - cx) / max(1.0, self.width / 2.2)) ** 2
                + (((idx // self.width) - cy) / max(1.0, self.height / 2.2)) ** 2
            )
        )
        return ranked[:target]

    def _seed_pathogen(self, total_load: float, seeds: list[int], field: list[float]) -> None:
        if total_load <= 0 or not seeds:
            return
        per_seed = total_load / len(seeds)
        for seed in seeds:
            field[seed] += per_seed * 0.55
            neighbors = self.neighbors[seed]
            share = per_seed * 0.45 / max(1, len(neighbors))
            for neighbor in neighbors:
                field[neighbor] += share

    def _spawn_initial_agents(self) -> None:
        for _ in range(max(0, int(self.cfg.dendritic_cells))):
            x, y = self._random_tissue_position(prefer_occupied=True)
            self.agents.append(Agent(kind="dendritic", x=x, y=y))
        for _ in range(max(0, int(self.cfg.t_cells))):
            x, y = self._edge_position()
            self.agents.append(Agent(kind="t_cell", x=x, y=y))
        for _ in range(max(0, int(self.cfg.b_cells))):
            x, y = self._edge_position()
            self.agents.append(Agent(kind="b_cell", x=x, y=y))
        for _ in range(max(0, int(self.cfg.treg_cells))):
            x, y = self._edge_position()
            self.agents.append(Agent(kind="treg", x=x, y=y))

    def _diffuse(self, field: list[float], rate: float, decay: float) -> list[float]:
        rate = _clamp(rate, 0.0, 0.45)
        decay = _clamp(decay, 0.0, 0.35)
        if rate <= 0 and decay <= 0:
            return list(field)

        new_field = [0.0] * len(field)
        stay = 1.0 - rate
        for idx, value in enumerate(field):
            mean_neighbors = self._neighbor_mean(field, idx)
            mixed = value * stay + mean_neighbors * rate
            new_field[idx] = max(0.0, mixed * (1.0 - decay))
        return new_field

    def _suppress_nearby_effectors(self, x: int, y: int, anti_boost: float) -> None:
        for agent in self.agents:
            if agent.kind not in ("t_cell", "b_cell"):
                continue
            if abs(agent.x - x) <= 2 and abs(agent.y - y) <= 2:
                agent.activation = max(0.0, agent.activation - anti_boost * 0.9)

    def _count_agents_near(self, x: int, y: int, kind: str, state: str, radius: int) -> int:
        total = 0
        for agent in self.agents:
            if agent.kind != kind or agent.state != state:
                continue
            if abs(agent.x - x) <= radius and abs(agent.y - y) <= radius:
                total += 1
        return total

    def _neighbor_mean(self, field: list[float], idx: int) -> float:
        local = self.neighbors[idx]
        if not local:
            return field[idx]
        return sum(field[neighbor] for neighbor in local) / len(local)

    def _random_tissue_position(self, prefer_occupied: bool) -> tuple[int, int]:
        if prefer_occupied:
            occupied = [idx for idx, state in enumerate(self.tissue) if state != STATE_EMPTY]
            if occupied:
                idx = self.rng.choice(occupied)
                return idx % self.width, idx // self.width
        idx = self.rng.randrange(self.width * self.height)
        return idx % self.width, idx // self.width

    def _edge_position(self) -> tuple[int, int]:
        side = self.rng.choice(("top", "bottom", "left", "right"))
        if side == "top":
            return self.rng.randrange(self.width), 0
        if side == "bottom":
            return self.rng.randrange(self.width), self.height - 1
        if side == "left":
            return 0, self.rng.randrange(self.height)
        return self.width - 1, self.rng.randrange(self.height)

    def _encode_tissue_rows(self) -> list[str]:
        rows: list[str] = []
        for y in range(self.height):
            start = y * self.width
            rows.append("".join(STATE_CHARS[self.tissue[start + x]] for x in range(self.width)))
        return rows

    def _encode_heat_rows(self, field: list[float]) -> list[str]:
        alphabet = "0123456789abcdef"
        rows: list[str] = []
        for y in range(self.height):
            start = y * self.width
            chars = []
            for x in range(self.width):
                value = field[start + x]
                level = int(_clamp(_sigmoidish(value * 1.8) * 15.0, 0.0, 15.0))
                chars.append(alphabet[level])
            rows.append("".join(chars))
        return rows

    def _idx(self, x: int, y: int) -> int:
        return y * self.width + x
