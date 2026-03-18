from __future__ import annotations

import sys
from pathlib import Path


SIM_DIR = Path(__file__).resolve().parents[2] / "utils" / "immune_web_sim"
sys.path.insert(0, str(SIM_DIR))

from app import Engine  # noqa: E402
from simulation import ImmuneConfig, ImmuneSimulation  # noqa: E402


BASE = {
    "grid_width": 48,
    "grid_height": 30,
    "healthy_cells": 520,
    "infected_cells": 8,
    "dendritic_cells": 18,
    "t_cells": 50,
    "b_cells": 32,
    "treg_cells": 10,
    "viruses": 90,
    "bacteria": 40,
    "random_seed": 11,
}


def run_simulation(steps: int = 70, **overrides: float) -> dict[str, float | str]:
    sim = ImmuneSimulation(ImmuneConfig(**{**BASE, **overrides}))
    for _ in range(steps):
        sim.step(0.12)
    return sim.public_state()


def test_more_healthy_cells_change_occupancy_and_dynamics() -> None:
    base = run_simulation()
    more_healthy = run_simulation(healthy_cells=900)

    assert more_healthy["healthy_cells"] > base["healthy_cells"]
    assert more_healthy["infected_cells"] != base["infected_cells"]
    assert (more_healthy["viruses"] + more_healthy["bacteria"]) != (base["viruses"] + base["bacteria"])


def test_high_treg_settings_downregulate_effectors() -> None:
    base = run_simulation()
    high_treg = run_simulation(treg_cells=36, anti_inflammatory_rate=0.4, anti_diffusion_rate=0.42)

    assert high_treg["anti_cytokines"] > base["anti_cytokines"]
    assert high_treg["activated_t_cells"] < base["activated_t_cells"]
    assert high_treg["tissue_damage_index"] < base["tissue_damage_index"]


def test_high_self_attack_increases_autoimmune_damage() -> None:
    base = run_simulation(steps=110)
    autoimmune = run_simulation(
        steps=110,
        self_attack_probability=0.25,
        t_activation_rate=0.38,
        t_cells=80,
    )

    assert autoimmune["autoimmune_events"] > base["autoimmune_events"]
    assert autoimmune["tissue_damage_index"] > base["tissue_damage_index"]


def test_stronger_pathogen_overwhelms_more_than_weaker_case() -> None:
    weak = run_simulation(
        steps=110,
        viruses=45,
        bacteria=10,
        infection_strength=0.3,
        t_cells=80,
        b_cells=50,
        pathogen_kill_by_t=0.34,
        pathogen_kill_by_antibody=0.28,
    )
    strong = run_simulation(viruses=180, bacteria=90, infection_strength=0.82)

    assert strong["infected_cells"] > weak["infected_cells"]
    assert strong["viruses"] + strong["bacteria"] > weak["viruses"] + weak["bacteria"]


def test_engine_state_contains_world_and_history_shape() -> None:
    engine = Engine()
    payload = engine.state()

    assert payload["running"] is False
    assert "state" in payload
    assert "world" in payload
    assert "history_tail" in payload
    assert "config" in payload
    assert payload["world"]["width"] > 0
    assert len(payload["world"]["tissue_rows"]) == payload["world"]["height"]
