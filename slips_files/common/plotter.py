# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import csv
import math
import os
import statistics


class Plotter:
    def __init__(self, output_dir, print_func):
        self.output_dir = output_dir or ""
        self.print = print_func
        self.plots_dir = os.path.join(self.output_dir, "plots")

    def plot_latency_csv(self):
        latency_path = os.path.join(self.output_dir, "latency.csv")
        if not self._is_valid_input(latency_path):
            return

        ts_values = []
        latency_values = []
        try:
            with open(latency_path, newline="") as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    ts = row.get("ts")
                    latency = row.get("latency")
                    if ts is None or latency is None:
                        continue
                    try:
                        ts_values.append(float(ts))
                        latency_values.append(float(latency))
                    except ValueError:
                        continue
        except Exception as exc:
            self._log(f"[Plotter] Failed to read latency.csv: {exc}")
            return

        if not ts_values:
            return

        output_path = os.path.join(self.plots_dir, "latency_plot")
        self._save_plot(
            output_path,
            ts_values,
            {"latency": latency_values},
            xlabel="ts",
            ylabel="latency",
            title="Latency",
        )

    def write_latency_metrics(self, metrics_path=None):
        latency_path = os.path.join(self.output_dir, "latency.csv")
        if not self.output_dir or not os.path.exists(latency_path):
            return

        latency_values = []
        try:
            with open(latency_path, newline="") as csv_file:
                reader = csv.DictReader(csv_file)
                if not reader.fieldnames or "latency" not in reader.fieldnames:
                    return
                for row in reader:
                    raw_latency = row.get("latency")
                    try:
                        latency_values.append(float(raw_latency))
                    except (TypeError, ValueError):
                        pass
        except Exception as exc:
            self._log(f"[Plotter] Failed to read latency.csv: {exc}")
            return

        latency_p50 = self._percentile(latency_values, 50)
        latency_p95 = self._percentile(latency_values, 95)
        latency_p99 = self._percentile(latency_values, 99)
        latency_avg = self._average(latency_values)

        if metrics_path is None:
            metrics_path = os.path.join(self.output_dir, "metrics.txt")
        lines = [
            f"p50 for latency: {self._format_metric(latency_p50)}",
            f"p95 for latency: {self._format_metric(latency_p95)}",
            f"p99 for latency: {self._format_metric(latency_p99)}",
            f"avg for latency: {self._format_metric(latency_avg)}",
        ]
        try:
            with open(metrics_path, "a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        except Exception as exc:
            self._log(f"[Plotter] Failed to write metrics.txt: {exc}")

    def plot_throughput_csv(self):
        throughput_path = os.path.join(self.output_dir, "flows_per_minute.csv")
        if not self._is_valid_input(throughput_path):
            return

        ts_values = []
        series = {}
        profiler_columns = []
        try:
            with open(throughput_path, newline="") as csv_file:
                reader = csv.DictReader(csv_file)
                if not reader.fieldnames or "ts" not in reader.fieldnames:
                    return

                # recognize profiler columns
                for column in reader.fieldnames:
                    if column == "ts":
                        continue
                    series[column] = []
                    if column.startswith("profiler_flows_per_min_worker"):
                        profiler_columns.append(column)

                for row in reader:
                    ts = row.get("ts")
                    if ts is None:
                        continue
                    try:
                        ts_values.append(float(ts))
                    except ValueError:
                        continue

                    for column in series:
                        raw_value = row.get(column)
                        try:
                            series[column].append(float(raw_value))
                        except (TypeError, ValueError):
                            series[column].append(float("nan"))
        except Exception as exc:
            self._log(f"[Plotter] Failed to read flows_per_minute.csv: {exc}")
            return

        if not ts_values:
            return

        labeled_series = {}
        for column, values in series.items():
            label = column
            if column == "input_flows_per_min":
                label = "input"
            elif column.startswith("profiler_flows_per_min_worker"):
                suffix = column.replace("profiler_flows_per_min_worker", "")
                label = f"profiler{suffix}"
            labeled_series[label] = values

        throughput_output_path = os.path.join(
            self.plots_dir, "throughput_plot"
        )
        self._save_plot(
            throughput_output_path,
            ts_values,
            labeled_series,
            xlabel="ts",
            ylabel="flows_per_min",
            title="Flows per minute",
        )

        if profiler_columns:
            profiler_sum = []
            for idx in range(len(ts_values)):
                total = 0.0
                for column in profiler_columns:
                    try:
                        value = series[column][idx]
                    except IndexError:
                        value = float("nan")
                    if value == value:
                        total += value
                profiler_sum.append(total)

            combined_output_path = os.path.join(
                self.plots_dir, "flows_per_minute_for_all_profilers"
            )
            self._save_plot(
                combined_output_path,
                ts_values,
                {"combined": profiler_sum},
                xlabel="ts",
                ylabel="flows_per_min",
                title="flows_per_minute_for_all_profilers.csv combined",
            )

    def write_throughput_metrics(self):
        throughput_path = os.path.join(self.output_dir, "flows_per_minute.csv")
        if not self.output_dir or not os.path.exists(throughput_path):
            return

        input_values = []
        profiler_sums = []
        profiler_columns = []
        try:
            with open(throughput_path, newline="") as csv_file:
                reader = csv.DictReader(csv_file)
                if not reader.fieldnames or "ts" not in reader.fieldnames:
                    return

                for column in reader.fieldnames:
                    if column.startswith("profiler_flows_per_min"):
                        profiler_columns.append(column)

                for row in reader:
                    raw_input = row.get("input_flows_per_min")
                    try:
                        input_values.append(float(raw_input))
                    except (TypeError, ValueError):
                        pass

                    total = 0.0
                    for column in profiler_columns:
                        raw_value = row.get(column)
                        try:
                            value = float(raw_value)
                        except (TypeError, ValueError):
                            continue
                        if not math.isnan(value):
                            total += value
                    profiler_sums.append(total)
        except Exception as exc:
            self._log(f"[Plotter] Failed to read flows_per_minute.csv: {exc}")
            return

        input_p50 = self._percentile(input_values, 50)
        input_p95 = self._percentile(input_values, 95)
        input_p99 = self._percentile(input_values, 99)
        input_avg = self._average(input_values)
        profiler_p50 = self._percentile(profiler_sums, 50)
        profiler_p95 = self._percentile(profiler_sums, 95)
        profiler_p99 = self._percentile(profiler_sums, 99)
        profiler_avg = self._average(profiler_sums)

        metrics_path = os.path.join(self.output_dir, "metrics.txt")
        lines = [
            f"p50 for input: {self._format_metric(input_p50)}",
            f"p95 for input: {self._format_metric(input_p95)}",
            f"p99 for input: {self._format_metric(input_p99)}",
            f"avg for input: {self._format_metric(input_avg)}",
            ("p50 for all profilers: " f"{self._format_metric(profiler_p50)}"),
            ("p95 for all profilers: " f"{self._format_metric(profiler_p95)}"),
            ("p99 for all profilers: " f"{self._format_metric(profiler_p99)}"),
            ("avg for all profilers: " f"{self._format_metric(profiler_avg)}"),
        ]
        try:
            with open(metrics_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        except Exception as exc:
            self._log(f"[Plotter] Failed to write metrics.txt: {exc}")
            return

        self.write_latency_metrics(metrics_path=metrics_path)

    def _is_valid_input(self, csv_path):
        if not self.output_dir:
            return False
        if not os.path.exists(csv_path):
            return False
        os.makedirs(self.plots_dir, exist_ok=True)
        return True

    def _save_plot(
        self, output_path, ts_values, series, xlabel, ylabel, title
    ):
        try:
            import matplotlib

            matplotlib.use("Agg")
            from matplotlib import pyplot as plt
        except Exception as exc:
            self._log(f"[Plotter] Skipping plot {output_path}: {exc}")
            return

        try:
            plt.figure(figsize=(10, 4))
            for label, values in series.items():
                plt.plot(ts_values, values, linewidth=1.0, label=label)
            plt.xlabel(xlabel)
            plt.ylabel(ylabel)
            plt.title(title)
            if len(series) > 1:
                plt.legend(fontsize="small", ncol=2)
            plt.tight_layout()
            plt.savefig(output_path, format="png")
            plt.close()
            self._log(f"[Plotter] Saved plot to {output_path}")
        except Exception as exc:
            self._log(f"[Plotter] Failed to save plot {output_path}: {exc}")

    def _log(self, message):
        if self.print:
            self.print(message, log_to_logfiles_only=True)

    def _percentile(self, values, percentile):
        clean = []
        for value in values:
            if value is None:
                continue
            try:
                if math.isnan(value):
                    continue
            except TypeError:
                continue
            clean.append(value)
        if not clean:
            return float("nan")
        clean.sort()
        if len(clean) == 1:
            return clean[0]
        rank = (len(clean) - 1) * (percentile / 100.0)
        lower = math.floor(rank)
        upper = math.ceil(rank)
        if lower == upper:
            return clean[int(rank)]
        lower_value = clean[lower]
        upper_value = clean[upper]
        return lower_value + (upper_value - lower_value) * (rank - lower)

    def _average(self, values):
        clean = []
        for value in values:
            if value is None:
                continue
            try:
                if math.isnan(value):
                    continue
            except TypeError:
                continue
            clean.append(value)
        if not clean:
            return float("nan")
        return statistics.fmean(clean)

    def _format_metric(self, value):
        if math.isnan(value):
            return "nan"
        return f"{value}"
