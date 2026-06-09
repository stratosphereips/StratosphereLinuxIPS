#!/usr/bin/env python3
"""Log Slips RATL and alert-count metrics, then plot them."""

import argparse
import csv
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import matplotlib
import redis

matplotlib.use("Agg")
import matplotlib.pyplot as plt


CSV_HEADER = [
    "elapsed_seconds",
    "ratl",
    "current_timewindow",
    "number_of_alerts",
]
CSV_PATH = Path("metrics.csv")
GRAPH_PATH = Path("metrics.png")
CONFIG_PATH = Path("config/slips.yaml")
SAMPLE_INTERVAL_SECONDS = 5
DEFAULT_REDIS_HOST = "localhost"
DEFAULT_REDIS_PORT = 6379
RATL_HASH_KEYS = (
    "max_risk_weight_of_all_profiles",
    "MAX_RISK_WEIGHT_OF_ALL_PROFILES",
)
CURRENT_TIMEWINDOW_KEYS = ("current_timewindow", "CURRENT_TIMEWINDOW")
RATL_REGION_BOUNDARIES = (0.32, 1.0)
REDIS_METRIC_SNAPSHOT_SCRIPT = """
local ratl_key_count = tonumber(ARGV[1])
local timewindow_key_count = tonumber(ARGV[2])
local ratl = ""
local current_timewindow = ""

for index = 1, ratl_key_count do
    local key = KEYS[index]
    local key_type = redis.call("TYPE", key).ok
    if key_type == "hash" then
        local value = redis.call("HGET", key, "risk_weight")
        if value then
            ratl = value
            break
        end
    elseif key_type ~= "none" then
        local value = redis.call("GET", key)
        if value then
            ratl = value
            break
        end
    end
end

for index = 1, timewindow_key_count do
    local key = KEYS[ratl_key_count + index]
    local value = redis.call("GET", key)
    if value then
        current_timewindow = value
        break
    end
end

return {ratl, current_timewindow}
"""


@dataclass(frozen=True)
class MetricSample:
    """A single row of sampled RATL and alert metrics.

    Parameters:
        elapsed_seconds: Seconds elapsed since this script started.
        ratl: Current maximum risk weight across all profiles.
        current_timewindow: Current Slips timewindow from Redis, if available.
        number_of_alerts: Count of distinct alert IDs in the current timewindow.
    """

    elapsed_seconds: int
    ratl: float
    current_timewindow: str
    number_of_alerts: int


@dataclass(frozen=True)
class PlotData:
    """CSV metrics converted to plot-ready series.

    Parameters:
        elapsed_seconds: X-axis values in seconds.
        ratl: RATL values for the left y-axis.
        current_timewindows: Timewindow values sampled from Redis.
        alert_counts: Distinct alert counts for the right y-axis.
    """

    elapsed_seconds: list[int]
    ratl: list[float]
    current_timewindows: list[str]
    alert_counts: list[int]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Return value:
        Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Periodically log Slips RATL and SQLite alert counts to "
            "metrics.csv, then plot metrics.png when stopped."
        )
    )
    parser.add_argument(
        "-s",
        "--sqlite-path",
        required=True,
        help=(
            "Path to the Slips SQLite database. Relative and absolute paths "
            "are allowed."
        ),
    )
    parser.add_argument(
        "--redis-host",
        default=DEFAULT_REDIS_HOST,
        help=f"Redis host to query. Defaults to {DEFAULT_REDIS_HOST}.",
    )
    parser.add_argument(
        "--redis-port",
        default=DEFAULT_REDIS_PORT,
        type=int,
        help=f"Redis port to query. Defaults to {DEFAULT_REDIS_PORT}.",
    )
    parser.add_argument(
        "--timewindow-duration",
        type=float,
        default=None,
        help=(
            "Timewindow duration in seconds for vertical plot boundaries. "
            "Defaults to config/slips.yaml when available."
        ),
    )
    return parser.parse_args()


def create_redis_client(host: str, port: int) -> redis.Redis:
    """Create a Redis client for direct key reads.

    Parameters:
        host: Redis host name or address.
        port: Redis TCP port.

    Return value:
        Redis client configured to return decoded strings.
    """
    return redis.Redis(
        host=host,
        port=port,
        socket_connect_timeout=1,
        socket_timeout=1,
        decode_responses=True,
    )


def warn_once(warnings: set[str], warning_id: str, message: str) -> None:
    """Print a warning once per warning identifier.

    Parameters:
        warnings: Mutable set of warning identifiers already printed.
        warning_id: Stable warning identifier.
        message: Warning text shown to the user.
    """
    if warning_id in warnings:
        return

    warnings.add(warning_id)
    print(f"Warning: {message}")


def parse_float(value: object, default: float = 0.0) -> float:
    """Convert a value to float with a safe fallback.

    Parameters:
        value: Value to convert.
        default: Value returned when conversion fails.

    Return value:
        Converted float or the fallback value.
    """
    if value in (None, ""):
        return default

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_non_negative_float(value: object, default: float = 0.0) -> float:
    """Convert a value to a non-negative float with a safe fallback.

    Parameters:
        value: Value to convert.
        default: Value returned when conversion fails.

    Return value:
        Converted float clamped to zero or greater.
    """
    return max(0.0, parse_float(value, default))


def read_ratl(redis_client: redis.Redis, warnings: set[str]) -> float:
    """Read the maximum risk weight from Redis.

    Parameters:
        redis_client: Connected Redis client.
        warnings: Warning identifiers already printed.

    Return value:
        Current RATL value, or 0.0 when unavailable.
    """
    try:
        for key in RATL_HASH_KEYS:
            if redis_client.type(key) == "hash":
                ratl = redis_client.hget(key, "risk_weight")
                return parse_non_negative_float(ratl)

            value = redis_client.get(key)
            if value is not None:
                return parse_non_negative_float(value)
    except redis.RedisError as err:
        warn_once(
            warnings,
            "redis_ratl",
            f"could not read RATL from Redis: {err}. Using 0.0.",
        )
        return 0.0

    warn_once(
        warnings,
        "missing_ratl",
        "RATL Redis value is missing. Using 0.0 until it appears.",
    )
    return 0.0


def read_current_timewindow(
    redis_client: redis.Redis, warnings: set[str]
) -> str:
    """Read the current timewindow from Redis.

    Parameters:
        redis_client: Connected Redis client.
        warnings: Warning identifiers already printed.

    Return value:
        Current timewindow as a string, or an empty string when unavailable.
    """
    try:
        for key in CURRENT_TIMEWINDOW_KEYS:
            value = redis_client.get(key)
            if value is not None:
                return str(value)
    except redis.RedisError as err:
        warn_once(
            warnings,
            "redis_timewindow",
            f"could not read current_timewindow from Redis: {err}. Leaving it blank.",
        )
        return ""

    warn_once(
        warnings,
        "missing_timewindow",
        "current_timewindow Redis value is missing. Leaving it blank until it appears.",
    )
    return ""


def read_redis_metric_snapshot(
    redis_client: redis.Redis, warnings: set[str]
) -> tuple[float, str]:
    """Read RATL and current timewindow from one Redis server-side snapshot.

    Parameters:
        redis_client: Connected Redis client.
        warnings: Warning identifiers already printed.

    Return value:
        Tuple of RATL and current timewindow. Missing values are returned as
        0.0 and an empty string.
    """
    keys = (*RATL_HASH_KEYS, *CURRENT_TIMEWINDOW_KEYS)
    try:
        ratl, current_timewindow = redis_client.eval(
            REDIS_METRIC_SNAPSHOT_SCRIPT,
            len(keys),
            *keys,
            len(RATL_HASH_KEYS),
            len(CURRENT_TIMEWINDOW_KEYS),
        )
    except redis.RedisError as err:
        warn_once(
            warnings,
            "redis_metrics_snapshot",
            f"could not read Redis metrics atomically: {err}. Using defaults.",
        )
        return 0.0, ""

    if ratl in (None, ""):
        warn_once(
            warnings,
            "missing_ratl",
            "RATL Redis value is missing. Using 0.0 until it appears.",
        )

    if current_timewindow in (None, ""):
        warn_once(
            warnings,
            "missing_timewindow",
            "current_timewindow Redis value is missing. "
            "Leaving it blank until it appears.",
        )

    return parse_non_negative_float(ratl), str(current_timewindow or "")


def get_timewindow_query_values(current_timewindow: str) -> tuple[str, ...]:
    """Build SQLite timewindow values matching a sampled timewindow.

    Parameters:
        current_timewindow: Current Slips timewindow from Redis.

    Return value:
        Candidate SQLite timewindow values for the sampled timewindow.
    """
    current_timewindow = current_timewindow.strip()
    if not current_timewindow:
        return ()

    values = [current_timewindow]
    if current_timewindow.isdigit():
        values.append(f"timewindow{current_timewindow}")

    return tuple(dict.fromkeys(values))


def count_alerts(
    sqlite_path: Path, current_timewindow: str, warnings: set[str]
) -> int:
    """Count distinct alert IDs in the current timewindow.

    Parameters:
        sqlite_path: SQLite database path provided by the user.
        current_timewindow: Current Slips timewindow from Redis.
        warnings: Warning identifiers already printed.

    Return value:
        Number of distinct alert IDs, or 0 when unavailable.
    """
    timewindow_values = get_timewindow_query_values(current_timewindow)
    if not timewindow_values:
        return 0

    if not sqlite_path.exists():
        warn_once(
            warnings,
            "missing_sqlite",
            f"SQLite database {sqlite_path} does not exist. Using alert count 0.",
        )
        return 0

    try:
        with sqlite3.connect(sqlite_path) as connection:
            placeholders = ", ".join("?" for _ in timewindow_values)
            cursor = connection.execute(
                "SELECT COUNT(DISTINCT alert_id) FROM alerts "
                f"WHERE timewindow IN ({placeholders});",
                timewindow_values,
            )
            row = cursor.fetchone()
    except sqlite3.OperationalError as err:
        warn_once(
            warnings,
            "sqlite_operational_error",
            f"could not query alerts table in {sqlite_path}: {err}. "
            "Using alert count 0.",
        )
        return 0
    except sqlite3.Error as err:
        warn_once(
            warnings,
            "sqlite_error",
            f"could not read SQLite database {sqlite_path}: {err}. "
            "Using alert count 0.",
        )
        return 0

    if not row or row[0] is None:
        return 0

    return int(row[0])


def initialize_csv(csv_path: Path) -> None:
    """Create a fresh metrics CSV with the required header.

    Parameters:
        csv_path: Path to the CSV file to create.
    """
    with csv_path.open("w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(CSV_HEADER)


def append_sample(csv_path: Path, sample: MetricSample) -> None:
    """Append a metric sample to the CSV file.

    Parameters:
        csv_path: Path to the metrics CSV.
        sample: Metric sample to append.
    """
    with csv_path.open("a", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            [
                sample.elapsed_seconds,
                sample.ratl,
                sample.current_timewindow,
                sample.number_of_alerts,
            ]
        )


def sample_metrics(
    redis_client: redis.Redis,
    sqlite_path: Path,
    start_time: float,
    warnings: set[str],
) -> MetricSample:
    """Read Redis and SQLite metrics for one sample point.

    Parameters:
        redis_client: Connected Redis client.
        sqlite_path: SQLite database path provided by the user.
        start_time: Monotonic timestamp when the script started.
        warnings: Warning identifiers already printed.

    Return value:
        Metric sample containing elapsed time, RATL, timewindow, and alerts.
    """
    elapsed_seconds = int(time.monotonic() - start_time)
    ratl, current_timewindow = read_redis_metric_snapshot(
        redis_client, warnings
    )
    return MetricSample(
        elapsed_seconds=elapsed_seconds,
        ratl=ratl,
        current_timewindow=current_timewindow,
        number_of_alerts=count_alerts(
            sqlite_path, current_timewindow, warnings
        ),
    )


def parse_timewindow_duration(config_path: Path) -> Optional[float]:
    """Read the timewindow duration from a simple Slips YAML setting.

    Parameters:
        config_path: Path to the Slips YAML configuration file.

    Return value:
        Timewindow duration in seconds, or None when unavailable.
    """
    if not config_path.exists():
        return None

    for raw_line in config_path.read_text().splitlines():
        line = raw_line.strip()
        if line.startswith("#") or not line.startswith("time_window_width"):
            continue

        _, value = line.split(":", 1)
        value = value.strip().strip("'\"")
        if value == "only_one_tw":
            return None

        duration = parse_float(value, default=0.0)
        if duration > 0:
            return duration

    return None


def resolve_timewindow_duration(override: Optional[float]) -> Optional[float]:
    """Resolve the timewindow duration used for plot boundary lines.

    Parameters:
        override: Optional user-provided duration in seconds.

    Return value:
        Positive timewindow duration in seconds, or None when unavailable.
    """
    if override is not None:
        if override <= 0:
            print(
                "Warning: --timewindow-duration must be greater than 0. "
                "Skipping periodic boundary lines."
            )
            return None
        return override

    return parse_timewindow_duration(CONFIG_PATH)


def read_plot_data(csv_path: Path) -> PlotData:
    """Read metric rows from a CSV file.

    Parameters:
        csv_path: Path to the metrics CSV.

    Return value:
        PlotData containing parsed metric series.
    """
    elapsed_seconds: list[int] = []
    ratl: list[float] = []
    current_timewindows: list[str] = []
    alert_counts: list[int] = []

    with csv_path.open(newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            elapsed_seconds.append(
                int(parse_float(row.get("elapsed_seconds")))
            )
            ratl.append(parse_non_negative_float(row.get("ratl")))
            current_timewindows.append(row.get("current_timewindow", ""))
            alert_counts.append(
                int(parse_non_negative_float(row.get("number_of_alerts")))
            )

    return PlotData(
        elapsed_seconds=elapsed_seconds,
        ratl=ratl,
        current_timewindows=current_timewindows,
        alert_counts=alert_counts,
    )


def get_observed_timewindow_boundaries(plot_data: PlotData) -> list[int]:
    """Find elapsed times where the sampled current timewindow changed.

    Parameters:
        plot_data: Plot-ready metric series.

    Return value:
        Elapsed seconds where a new sampled timewindow value appeared.
    """
    boundaries: list[int] = []
    previous_timewindow = ""

    for elapsed_seconds, current_timewindow in zip(
        plot_data.elapsed_seconds, plot_data.current_timewindows
    ):
        if not current_timewindow:
            continue

        if previous_timewindow and current_timewindow != previous_timewindow:
            boundaries.append(elapsed_seconds)

        previous_timewindow = current_timewindow

    return boundaries


def get_periodic_timewindow_boundaries(
    max_elapsed_seconds: int, timewindow_duration: Optional[float]
) -> list[float]:
    """Build periodic boundary positions from a timewindow duration.

    Parameters:
        max_elapsed_seconds: Maximum elapsed time covered by the plot.
        timewindow_duration: Timewindow duration in seconds, if known.

    Return value:
        X-axis positions where vertical boundary lines should be drawn.
    """
    if timewindow_duration is None:
        return []

    boundaries: list[float] = []
    boundary = timewindow_duration
    while boundary <= max_elapsed_seconds:
        boundaries.append(boundary)
        boundary += timewindow_duration

    return boundaries


def add_timewindow_boundaries(
    axis: plt.Axes,
    plot_data: PlotData,
    timewindow_duration: Optional[float],
) -> None:
    """Draw vertical dotted timewindow boundary lines.

    Parameters:
        axis: Matplotlib axis receiving the boundary lines.
        plot_data: Plot-ready metric series.
        timewindow_duration: Timewindow duration in seconds, if known.
    """
    if not plot_data.elapsed_seconds:
        return

    max_elapsed_seconds = max(plot_data.elapsed_seconds)
    boundaries = get_periodic_timewindow_boundaries(
        max_elapsed_seconds, timewindow_duration
    )
    if not boundaries:
        boundaries = get_observed_timewindow_boundaries(plot_data)

    for boundary in boundaries:
        axis.axvline(
            x=boundary,
            color="0.45",
            linestyle=":",
            linewidth=1,
            alpha=0.75,
        )


def add_ratl_region_boundaries(axis: plt.Axes) -> None:
    """Draw fixed horizontal RATL region separator lines.

    Parameters:
        axis: Matplotlib axis receiving the RATL region lines.
    """
    for boundary in RATL_REGION_BOUNDARIES:
        axis.axhline(
            y=boundary,
            color="0.2",
            linestyle="--",
            linewidth=1,
            alpha=0.7,
        )


def plot_metrics(
    csv_path: Path, graph_path: Path, timewindow_duration: Optional[float]
) -> None:
    """Generate a two-axis metrics graph from the CSV file.

    Parameters:
        csv_path: Path to the metrics CSV.
        graph_path: Path where the generated graph image is saved.
        timewindow_duration: Timewindow duration in seconds, if known.
    """
    plot_data = read_plot_data(csv_path)

    fig, ratl_axis = plt.subplots(figsize=(11, 6))
    alerts_axis = ratl_axis.twinx()
    add_ratl_region_boundaries(ratl_axis)

    if plot_data.elapsed_seconds:
        ratl_line = ratl_axis.plot(
            plot_data.elapsed_seconds,
            plot_data.ratl,
            color="#1f77b4",
            marker="o",
            linewidth=2,
            label="RATL",
        )
        alerts_line = alerts_axis.plot(
            plot_data.elapsed_seconds,
            plot_data.alert_counts,
            color="#d62728",
            marker="s",
            linewidth=2,
            label="Number of alerts per current timewindow",
        )
        add_timewindow_boundaries(ratl_axis, plot_data, timewindow_duration)
        lines = ratl_line + alerts_line
        labels = [line.get_label() for line in lines]
        ratl_axis.legend(lines, labels, loc="upper left")
    else:
        ratl_axis.text(
            0.5,
            0.5,
            "No metric samples were logged.",
            ha="center",
            va="center",
            transform=ratl_axis.transAxes,
        )

    ratl_axis.set_xlabel("Elapsed time since script start (seconds)")
    ratl_axis.set_ylabel("RATL", color="#1f77b4")
    alerts_axis.set_ylabel("Number of alerts", color="#d62728")
    ratl_axis.set_ylim(bottom=0)
    alerts_axis.set_ylim(bottom=0)
    ratl_axis.tick_params(axis="y", labelcolor="#1f77b4")
    alerts_axis.tick_params(axis="y", labelcolor="#d62728")
    ratl_axis.grid(True, axis="y", linestyle="--", alpha=0.35)
    ratl_axis.set_title("RATL and generated alerts over time")
    fig.tight_layout()
    fig.savefig(graph_path, dpi=150)
    plt.close(fig)


def log_metrics_until_interrupted(
    redis_client: redis.Redis,
    sqlite_path: Path,
    csv_path: Path,
) -> None:
    """Log metric samples every five seconds until Ctrl+C.

    Parameters:
        redis_client: Connected Redis client.
        sqlite_path: SQLite database path provided by the user.
        csv_path: Path to the metrics CSV.
    """
    warnings: set[str] = set()
    start_time = time.monotonic()
    next_sample_time = start_time

    while True:
        sample = sample_metrics(
            redis_client, sqlite_path, start_time, warnings
        )
        append_sample(csv_path, sample)
        print(
            "Logged sample: "
            f"elapsed={sample.elapsed_seconds}s, "
            f"ratl={sample.ratl}, "
            f"current_timewindow={sample.current_timewindow or 'missing'}, "
            f"number_of_alerts={sample.number_of_alerts}"
        )

        next_sample_time += SAMPLE_INTERVAL_SECONDS
        sleep_seconds = max(0.0, next_sample_time - time.monotonic())
        time.sleep(sleep_seconds)


def main() -> int:
    """Run the metric logger and graph generator.

    Return value:
        Process exit code.
    """
    args = parse_args()
    sqlite_path = Path(args.sqlite_path)
    timewindow_duration = resolve_timewindow_duration(args.timewindow_duration)
    redis_client = create_redis_client(args.redis_host, args.redis_port)

    if CSV_PATH.exists():
        print(f"Overwriting existing {CSV_PATH} for a clean run.")
    initialize_csv(CSV_PATH)
    print(
        "Logging metrics every "
        f"{SAMPLE_INTERVAL_SECONDS} seconds. Press Ctrl+C to stop."
    )

    try:
        log_metrics_until_interrupted(redis_client, sqlite_path, CSV_PATH)
    except KeyboardInterrupt:
        print(
            "Stopping metric logging after Ctrl+C. No new rows will be written."
        )
    finally:
        redis_client.close()

    print(f"Generated CSV: {CSV_PATH}")
    plot_metrics(CSV_PATH, GRAPH_PATH, timewindow_duration)
    print(f"Generated graph: {GRAPH_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
