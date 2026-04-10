# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import os

import pytest

from slips_files.common.output_paths import (
    get_performance_csv_dir,
    get_performance_csv_path,
    get_performance_plots_dir,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "parent_dir, expected_path",
    [
        ("output", os.path.join("output", "performance_plots")),
        ("", "performance_plots"),
    ],
)
def test_get_performance_plots_dir(parent_dir, expected_path):
    _ = ModuleFactory()

    assert get_performance_plots_dir(parent_dir) == expected_path


@pytest.mark.parametrize(
    "parent_dir, expected_path",
    [
        (
            "output",
            os.path.join("output", "performance_plots", "csv"),
        ),
        ("", os.path.join("performance_plots", "csv")),
    ],
)
def test_get_performance_csv_dir(parent_dir, expected_path):
    _ = ModuleFactory()

    assert get_performance_csv_dir(parent_dir) == expected_path


@pytest.mark.parametrize(
    "output_dir, filename, expected_path",
    [
        (
            "output",
            "latency.csv",
            os.path.join("output", "performance_plots", "csv", "latency.csv"),
        ),
        (
            "",
            "metrics.csv",
            os.path.join("performance_plots", "csv", "metrics.csv"),
        ),
    ],
)
def test_get_performance_csv_path(output_dir, filename, expected_path):
    _ = ModuleFactory()

    assert get_performance_csv_path(output_dir, filename) == expected_path
