# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
from unittest.mock import Mock

from slips_files.common.plotter import (
    ACCUMULATED_THREAT_LEVEL_PLOT,
    Plotter,
)
from tests.module_factory import ModuleFactory


def test_plot_accumulated_threat_level_csv(tmp_path: Path) -> None:
    """Test profile ATL CSV data is plotted with 1-minute TW context."""
    module_factory = ModuleFactory()
    output_dir = tmp_path
    alerts_dir = output_dir / "alerts"
    alerts_dir.mkdir()
    csv_path = alerts_dir / "accumulated_threat_level.csv"
    csv_path.write_text(
        "accumulated_threat_level,risk_accumulated_threat_level\n"
        "1.5,3.0\n"
        "2.0,4.0\n",
        encoding="utf-8",
    )
    plotter = Plotter(str(output_dir), Mock())
    plotter._save_plot = Mock()

    plotter.plot_accumulated_threat_level_csv()

    module_factory.logger.assert_not_called()
    plotter._save_plot.assert_called_once()
    args = plotter._save_plot.call_args[0]
    assert args[0].endswith(ACCUMULATED_THREAT_LEVEL_PLOT)
    assert args[1] == [0, 1]
    assert args[2] == {"accumulated_threat_level": [1.5, 2.0]}
    kwargs = plotter._save_plot.call_args.kwargs
    assert kwargs["xlabel"] == "time (minutes)"
    assert kwargs["ylabel"] == "accumulated_threat_level"
    assert "timewindow width: 1 minute" in kwargs["title"]
