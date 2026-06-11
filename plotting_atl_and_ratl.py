"""Plot accumulated threat level CSV values by Slips elapsed time."""

import argparse
from pathlib import Path
from typing import Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

DEFAULT_OUTPUT_FILE = "threat_level_plot.png"
CHUNK_SIZE = 10000
TIME_COLUMN = "time_since_slips_started"
LEGACY_TIME_COLUMN = "evidence_timestamp"
VALUE_COLUMNS = {
    "accumulated_threat_level",
    "risk_accumulated_threat_level",
}
READABLE_COLUMNS = VALUE_COLUMNS | {TIME_COLUMN, LEGACY_TIME_COLUMN}


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Plot accumulated threat level CSV values."
    )
    parser.add_argument(
        "csv_file",
        help="Path to accumulated_threat_level.csv.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Directory where the generated plot image will be saved.",
    )
    parser.add_argument(
        "--output-file",
        default=DEFAULT_OUTPUT_FILE,
        help="Filename for the generated plot image.",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Show the plot interactively after saving it.",
    )
    return parser.parse_args()


def read_csv_chunks(csv_file: str) -> Iterable[pd.DataFrame]:
    """
    Read only the columns needed for the elapsed-time plot.

    Parameters:
        csv_file: CSV file path to read.

    Returns:
        Iterable of normalized CSV chunks.
    """
    return pd.read_csv(
        csv_file,
        chunksize=CHUNK_SIZE,
        usecols=lambda column: column.strip() in READABLE_COLUMNS,
    )


def get_time_column(chunk: pd.DataFrame) -> str:
    """
    Select the x-axis column from the new or legacy CSV schema.

    Parameters:
        chunk: Normalized CSV chunk.

    Return value:
        Column name containing x-axis values.
    """
    if TIME_COLUMN in chunk.columns:
        return TIME_COLUMN
    if LEGACY_TIME_COLUMN in chunk.columns:
        return LEGACY_TIME_COLUMN
    raise ValueError(f"Missing required CSV column: {TIME_COLUMN}")


def parse_timestamps(series: pd.Series) -> pd.Series:
    """
    Convert evidence timestamps to values matplotlib can use on the x axis.

    Parameters:
        series: Raw evidence timestamp values.

    Returns:
        Parsed datetime values when possible, otherwise original string values.
    """
    numeric_timestamps = pd.to_numeric(series, errors="coerce")
    if numeric_timestamps.notna().all():
        return pd.to_datetime(numeric_timestamps, unit="s")

    parsed_timestamps = pd.to_datetime(series, errors="coerce")
    if parsed_timestamps.notna().all():
        return parsed_timestamps

    return series.astype(str)


def parse_elapsed_time(series: pd.Series, column_name: str) -> pd.Series:
    """
    Convert CSV x-axis values to plottable values.

    Parameters:
        series: Raw x-axis values.
        column_name: Name of the CSV x-axis column.

    Return value:
        Numeric elapsed seconds for the new CSV format, or parsed timestamps
        for legacy CSV files.
    """
    if column_name == LEGACY_TIME_COLUMN:
        return parse_timestamps(series)
    return pd.to_numeric(series, errors="coerce")


def build_valid_plot_frame(
    chunk: pd.DataFrame, time_column: str
) -> pd.DataFrame:
    """
    Build a clean plot frame from one CSV chunk.

    Parameters:
        chunk: CSV chunk containing time and threat level values.
        time_column: Name of the column containing x-axis values.

    Returns:
        DataFrame containing valid numeric threat level rows.
    """
    time_values = parse_elapsed_time(chunk[time_column], time_column)
    accumulated_threat_level = pd.to_numeric(
        chunk["accumulated_threat_level"], errors="coerce"
    )
    risk_accumulated_threat_level = pd.to_numeric(
        chunk["risk_accumulated_threat_level"], errors="coerce"
    )
    valid_rows = (
        time_values.notna()
        & accumulated_threat_level.notna()
        & risk_accumulated_threat_level.notna()
    )

    plot_frame = pd.DataFrame(
        {
            "time": time_values,
            "accumulated_threat_level": accumulated_threat_level,
            "risk_accumulated_threat_level": risk_accumulated_threat_level,
        }
    )
    return plot_frame.loc[valid_rows]


def plot_csv(csv_file: str, output_file: str, show_plot: bool = False) -> None:
    """
    Plot ATL and risk-weighted ATL against elapsed Slips time.

    Parameters:
        csv_file: CSV file path to plot.
        output_file: Image path where the plot will be saved.
        show_plot: Whether to show the plot interactively after saving it.
    """
    chunk_count = 0
    row_count = 0
    selected_time_column = ""
    plot_frames: list[pd.DataFrame] = []

    for chunk in read_csv_chunks(csv_file):
        chunk.columns = [column.strip() for column in chunk.columns]
        time_column = get_time_column(chunk)
        if selected_time_column and selected_time_column != time_column:
            raise ValueError("CSV chunks contain inconsistent time columns.")
        selected_time_column = time_column

        missing_columns = VALUE_COLUMNS - set(chunk.columns)
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(f"Missing required CSV columns: {missing}")

        plot_frame = build_valid_plot_frame(chunk, time_column)
        plot_frames.append(plot_frame)
        chunk_count += 1
        row_count += len(plot_frame)
        print(f"Processed chunk {chunk_count}: {len(plot_frame)} rows")

    if row_count == 0:
        raise ValueError("No valid rows found in the CSV file.")

    plot_data = pd.concat(plot_frames, ignore_index=True)
    plot_data = plot_data.sort_values("time", kind="mergesort")

    fig, ax = plt.subplots(figsize=(14, 7))
    line1 = ax.plot(
        plot_data["time"],
        plot_data["accumulated_threat_level"],
        color="#d1495b",
        alpha=0.85,
        linewidth=0.9,
    )[0]
    line2 = ax.plot(
        plot_data["time"],
        plot_data["risk_accumulated_threat_level"],
        color="#247ba0",
        alpha=0.85,
        linewidth=0.9,
    )[0]

    ax.set_title("Threat Level Analysis Over Slips Runtime", fontweight="bold")
    ax.set_xlabel("Time Since Slips Started (seconds)", fontweight="bold")
    ax.set_ylabel("Threat Level", fontweight="bold")
    ax.grid(True, alpha=0.25)
    ax.legend(
        [line1, line2],
        ["Accumulated Threat Level", "Risk Accumulated Threat Level"],
        loc="upper left",
    )
    if selected_time_column == LEGACY_TIME_COLUMN:
        fig.autofmt_xdate()
    plt.tight_layout()
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    if show_plot:
        plt.show()
    plt.close(fig)
    print(f"Done. Processed {row_count} rows from {chunk_count} chunks.")


def build_output_path(output_dir: str, output_file: str) -> Path:
    """
    Build the output path for the generated plot.

    Parameters:
        output_dir: Directory where the plot should be saved.
        output_file: Name of the plot image file.

    Returns:
        Path to the generated plot image.
    """
    return Path(output_dir) / output_file


def main() -> None:
    """Run the CSV plotting command."""
    args = parse_args()
    output_path = build_output_path(args.output_dir, args.output_file)
    plot_csv(args.csv_file, str(output_path), show_plot=args.show)


if __name__ == "__main__":
    main()
