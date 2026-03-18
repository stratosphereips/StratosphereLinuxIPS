from __future__ import annotations

import json
import mimetypes
import threading
import time
from datetime import datetime
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import unquote, urlparse

from simulation import ImmuneConfig, ImmuneSimulation


BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
RUNS_DIR = BASE_DIR / "runs"
RUNS_DIR.mkdir(exist_ok=True)


class Engine:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.sim = ImmuneSimulation(ImmuneConfig())
        self.running = False
        self.loop_interval_sec = 0.12
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False

    def _run_loop(self) -> None:
        while self.running:
            with self.lock:
                self.sim.step(dt=self.loop_interval_sec)
            time.sleep(self.loop_interval_sec)

    def state(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "running": self.running,
                "state": self.sim.public_state(),
                "world": self.sim.public_world(),
                "config": self.sim.config_dict(),
                "history_tail": self.sim.history_tail(),
            }

    def reset(self, params: Dict[str, float] | None = None) -> Dict[str, Any]:
        with self.lock:
            self.sim.reset(params)
            return {
                "running": self.running,
                "state": self.sim.public_state(),
                "world": self.sim.public_world(),
                "config": self.sim.config_dict(),
                "history_tail": self.sim.history_tail(),
            }

    def update_config(self, params: Dict[str, float]) -> Dict[str, Any]:
        with self.lock:
            self.sim.update_config(params)
            return self.sim.config_dict()

    def full_payload(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "config": self.sim.config_dict(),
                "state": self.sim.public_state(),
                "world": self.sim.public_world(),
                "history": list(self.sim.state.history),
                "sampled_worlds": list(self.sim.state.sampled_worlds),
            }


engine = Engine()


def _float_dict(payload: Dict[str, Any]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for key, value in payload.items():
        try:
            out[key] = float(value)
        except (TypeError, ValueError):
            continue
    return out


def _safe_run_name(name: str) -> str:
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in ("_", "-", "."))
    return cleaned[:80] or "immune_run"


def _polyline_points(values: list[float], width: int, height: int, max_y: float) -> str:
    points = []
    count = len(values)
    for index, value in enumerate(values):
        x = int((index / max(1, count - 1)) * (width - 26)) + 14
        y = int(height - 18 - (value / max_y) * (height - 34))
        points.append(f"{x},{y}")
    return " ".join(points)


def _series_panel(
    x0: int,
    y0: int,
    width: int,
    height: int,
    title: str,
    series: list[tuple[str, str, list[float]]],
    compare_series: list[tuple[str, str, list[float]]] | None = None,
) -> str:
    max_y = 1.0
    for _, _, values in series:
        for value in values:
            max_y = max(max_y, value)
    if compare_series:
        for _, _, values in compare_series:
            for value in values:
                max_y = max(max_y, value)

    chunks = [
        f'<g transform="translate({x0},{y0})">',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff" stroke="#d3dceb"/>',
        f'<text x="12" y="18" font-size="12" font-family="Segoe UI, sans-serif" fill="#132238">{escape(title)}</text>',
    ]

    for index, (name, color, values) in enumerate(series):
        chunks.append(
            f'<polyline fill="none" stroke="{color}" stroke-width="2.2" points="{_polyline_points(values, width, height, max_y)}"/>'
        )
        lx = 12 + index * 150
        chunks.append(f'<rect x="{lx}" y="{height - 18}" width="10" height="10" rx="2" fill="{color}"/>')
        chunks.append(
            f'<text x="{lx + 15}" y="{height - 9}" font-size="10" font-family="Segoe UI, sans-serif" fill="#5d7288">{escape(name)}</text>'
        )

    if compare_series:
        for name, color, values in compare_series:
            chunks.append(
                f'<polyline fill="none" stroke="{color}" stroke-width="1.5" stroke-dasharray="5 4" opacity="0.7" points="{_polyline_points(values, width, height, max_y)}"/>'
            )
        chunks.append(
            f'<text x="{width - 130}" y="18" font-size="10" font-family="Segoe UI, sans-serif" fill="#5d7288">dashed = comparison</text>'
        )

    chunks.append("</g>")
    return "".join(chunks)


def _make_plot(
    history: list[dict[str, float]],
    output_svg: Path,
    compare_history: list[dict[str, float]] | None = None,
) -> None:
    def collect(source: list[dict[str, float]], key: str) -> list[float]:
        return [float(item.get(key, 0.0)) for item in source]

    if len(history) < 2:
        history = [{"t": 0.0}, {"t": 1.0}]

    compare_history = compare_history or []

    panels = [
        (
            "Pathogen burden",
            [
                ("Viruses", "#c1121f", collect(history, "viruses")),
                ("Bacteria", "#7b2cbf", collect(history, "bacteria")),
                ("Infected", "#ff7f11", collect(history, "infected_cells")),
            ],
            [
                ("Viruses", "#c1121f", collect(compare_history, "viruses")),
                ("Bacteria", "#7b2cbf", collect(compare_history, "bacteria")),
                ("Infected", "#ff7f11", collect(compare_history, "infected_cells")),
            ]
            if compare_history
            else None,
        ),
        (
            "Host preservation",
            [
                ("Healthy", "#187f6d", collect(history, "healthy_cells")),
                ("Dead", "#3d405b", collect(history, "dead_cells")),
                ("Damaged", "#e76f51", collect(history, "damaged_cells")),
            ],
            [
                ("Healthy", "#187f6d", collect(compare_history, "healthy_cells")),
                ("Dead", "#3d405b", collect(compare_history, "dead_cells")),
                ("Damaged", "#e76f51", collect(compare_history, "damaged_cells")),
            ]
            if compare_history
            else None,
        ),
        (
            "Adaptive response",
            [
                ("Active T", "#004e89", collect(history, "activated_t_cells")),
                ("Active B", "#118ab2", collect(history, "activated_b_cells")),
                ("Antibodies", "#06d6a0", collect(history, "antibodies")),
            ],
            [
                ("Active T", "#004e89", collect(compare_history, "activated_t_cells")),
                ("Active B", "#118ab2", collect(compare_history, "activated_b_cells")),
                ("Antibodies", "#06d6a0", collect(compare_history, "antibodies")),
            ]
            if compare_history
            else None,
        ),
        (
            "Regulation and cost",
            [
                ("Pro cytokines", "#ef476f", collect(history, "pro_cytokines")),
                ("Anti cytokines", "#26547c", collect(history, "anti_cytokines")),
                ("Damage idx", "#6d597a", collect(history, "tissue_damage_index")),
                ("Autoimmune", "#bc4749", collect(history, "autoimmune_events")),
            ],
            [
                ("Pro cytokines", "#ef476f", collect(compare_history, "pro_cytokines")),
                ("Anti cytokines", "#26547c", collect(compare_history, "anti_cytokines")),
                ("Damage idx", "#6d597a", collect(compare_history, "tissue_damage_index")),
                ("Autoimmune", "#bc4749", collect(compare_history, "autoimmune_events")),
            ]
            if compare_history
            else None,
        ),
    ]

    positions = [(18, 18), (620, 18), (18, 308), (620, 308)]
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1220" height="590" viewBox="0 0 1220 590">',
        '<rect x="0" y="0" width="1220" height="590" fill="#f5f8fc"/>',
    ]
    for (title, series, compare), (x, y) in zip(panels, positions):
        parts.append(_series_panel(x, y, 580, 254, title, series, compare))
    parts.append("</svg>")
    output_svg.write_text("".join(parts), encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    def _json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def _serve_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            return self._serve_file(TEMPLATES_DIR / "index.html")
        if path.startswith("/static/"):
            return self._serve_file(STATIC_DIR / unquote(path[len("/static/") :]))
        if path.startswith("/runs/"):
            return self._serve_file(RUNS_DIR / unquote(path[len("/runs/") :]))

        if path == "/api/state":
            return self._json(engine.state())

        if path == "/api/runs":
            runs = []
            for json_file in sorted(RUNS_DIR.glob("*.json"), reverse=True):
                svg_file = json_file.with_suffix(".svg")
                runs.append(
                    {
                        "run_id": json_file.stem,
                        "json": f"/runs/{json_file.name}",
                        "plot": f"/runs/{svg_file.name}" if svg_file.exists() else None,
                        "mtime": json_file.stat().st_mtime,
                    }
                )
            return self._json({"runs": runs})

        if path.startswith("/api/load_run/"):
            run_id = unquote(path[len("/api/load_run/") :])
            json_file = RUNS_DIR / f"{run_id}.json"
            if not json_file.exists():
                return self._json({"ok": False, "error": "run not found"}, status=404)
            return self._json({"ok": True, "run": json.loads(json_file.read_text(encoding="utf-8"))})

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        payload = self._read_json()

        if path == "/api/start":
            engine.start()
            return self._json({"ok": True, "running": True})

        if path == "/api/stop":
            engine.stop()
            return self._json({"ok": True, "running": False})

        if path == "/api/reset":
            result = engine.reset(_float_dict(payload))
            return self._json({"ok": True, **result})

        if path == "/api/config":
            config = engine.update_config(_float_dict(payload))
            return self._json({"ok": True, "config": config})

        if path == "/api/save_run":
            run_name = _safe_run_name(str(payload.get("name") or "immune_run").replace(" ", "_"))
            compare_run_id = str(payload.get("compare_run_id") or "").strip()
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            run_id = f"{run_name}_{timestamp}"
            run_json = RUNS_DIR / f"{run_id}.json"
            run_svg = RUNS_DIR / f"{run_id}.svg"

            data = engine.full_payload()
            data["run_id"] = run_id
            data["saved_at_utc"] = datetime.utcnow().isoformat() + "Z"
            data["summary"] = {
                "outcome": data["state"]["outcome"],
                "final_pathogen_burden": round(data["state"]["viruses"] + data["state"]["bacteria"], 3),
                "final_damage_index": data["state"]["tissue_damage_index"],
                "autoimmune_events": data["state"]["autoimmune_events"],
            }

            compare_history = None
            if compare_run_id:
                compare_json = RUNS_DIR / f"{compare_run_id}.json"
                if compare_json.exists():
                    compare_payload = json.loads(compare_json.read_text(encoding="utf-8"))
                    compare_history = compare_payload.get("history", [])
                    data["comparison_run_id"] = compare_run_id

            run_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
            _make_plot(data.get("history", []), run_svg, compare_history)

            return self._json(
                {
                    "ok": True,
                    "run_id": run_id,
                    "json": f"/runs/{run_json.name}",
                    "plot": f"/runs/{run_svg.name}",
                    "summary": data["summary"],
                }
            )

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")


def run_server(host: str = "127.0.0.1", port: int = 5014) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Immune web simulation running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        server.server_close()


if __name__ == "__main__":
    run_server()
