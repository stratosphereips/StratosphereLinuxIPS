"""Unit tests for slips_files/common/plotter.py."""

from slips_files.common.plotter import Plotter
from tests.module_factory import ModuleFactory


def test_write_throughput_metrics_saves_metrics_inside_performance_plots(
    tmp_path,
):
    module_factory = ModuleFactory()
    assert module_factory is not None

    output_dir = tmp_path / "output"
    csv_dir = output_dir / "performance_plots" / "csv"
    csv_dir.mkdir(parents=True)
    (csv_dir / "flows_per_minute.csv").write_text(
        "ts,input_flows_per_min,profiler_flows_per_min_worker_1\n" "60,10,5\n",
        encoding="utf-8",
    )
    (csv_dir / "latency.csv").write_text(
        "ts,evidence_id,latency\n" "1,evidence-1,2\n",
        encoding="utf-8",
    )

    plotter = Plotter(str(output_dir), lambda *_args, **_kwargs: None)

    plotter.write_throughput_metrics()

    assert (output_dir / "performance_plots" / "metrics.txt").exists()
    assert not (output_dir / "metrics.txt").exists()
