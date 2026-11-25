# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import patch

import pytest

from slips_files.common.startup_report import format_started_line


def test_format_started_line_includes_all_fields():
    with patch(
        "slips_files.common.startup_report.neon_teal",
        side_effect=lambda txt: f"neon_teal({txt})",
    ), patch(
        "slips_files.common.startup_report.grey",
        side_effect=lambda txt: f"grey({txt})",
    ):
        line = format_started_line(
            "profiler_worker_2",
            2,
            3,
            12345,
            "Test description",
            category="worker",
        )

    assert "neon_teal([profiler_worker_2]" in line
    assert "grey([2/3]" in line
    assert "grey([PID 12345])" in line
    assert "neon_teal(Test description)" in line


def test_format_started_line_pads_columns_consistently():
    with patch(
        "slips_files.common.startup_report.leaf_green",
        side_effect=lambda t: t,
    ), patch(
        "slips_files.common.startup_report.grey", side_effect=lambda t: t
    ):
        short_kind = format_started_line("main", 1, 19, 1, "d")
        long_kind = format_started_line(
            "anomaly_detection_https", 1, 19, 1, "d"
        )

    # the pid column (and everything after it) starts at the same
    # position regardless of how long the kind text is
    assert short_kind.index("[PID ") == long_kind.index("[PID ")


def test_format_started_line_right_aligns_progress_digits():
    with patch(
        "slips_files.common.startup_report.leaf_green",
        side_effect=lambda t: t,
    ), patch(
        "slips_files.common.startup_report.grey", side_effect=lambda t: t
    ):
        line = format_started_line("arp", 1, 19, 1, "d")

    assert "[ 1/19]" in line


@pytest.mark.parametrize(
    "category, color_func",
    [
        ("core", "electric_lime"),
        ("worker", "neon_teal"),
        ("module", "leaf_green"),
    ],
)
def test_format_started_line_colors_by_category(category, color_func):
    with patch(
        f"slips_files.common.startup_report.{color_func}",
        side_effect=lambda txt: f"{color_func}({txt})",
    ), patch(
        "slips_files.common.startup_report.grey",
        side_effect=lambda txt: f"grey({txt})",
    ):
        line = format_started_line("name", 1, 19, 1, "d", category=category)

    assert f"{color_func}([name]" in line
    assert f"{color_func}(d)" in line
