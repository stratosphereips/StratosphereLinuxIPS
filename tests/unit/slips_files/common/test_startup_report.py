# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import patch

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


def test_format_started_line_colors_core_category_electric_lime():
    with patch(
        "slips_files.common.startup_report.electric_lime",
        side_effect=lambda txt: f"electric_lime({txt})",
    ), patch(
        "slips_files.common.startup_report.grey",
        side_effect=lambda txt: f"grey({txt})",
    ):
        line = format_started_line("profiler", 1, 19, 1, "d", category="core")

    assert "electric_lime([profiler]" in line
    assert "electric_lime(d)" in line


def test_format_started_line_colors_worker_category_neon_teal():
    with patch(
        "slips_files.common.startup_report.neon_teal",
        side_effect=lambda txt: f"neon_teal({txt})",
    ), patch(
        "slips_files.common.startup_report.grey",
        side_effect=lambda txt: f"grey({txt})",
    ):
        line = format_started_line(
            "profiler_worker_2", 1, 19, 1, "d", category="worker"
        )

    assert "neon_teal([profiler_worker_2]" in line
    assert "neon_teal(d)" in line


def test_format_started_line_colors_module_category_leaf_green():
    with patch(
        "slips_files.common.startup_report.leaf_green",
        side_effect=lambda txt: f"leaf_green({txt})",
    ), patch(
        "slips_files.common.startup_report.grey",
        side_effect=lambda txt: f"grey({txt})",
    ):
        line = format_started_line("arp", 1, 19, 1, "d", category="module")

    assert "leaf_green([arp]" in line
    assert "leaf_green(d)" in line
