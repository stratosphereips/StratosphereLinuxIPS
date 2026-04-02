# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os


PERFORMANCE_PLOTS_DIRNAME = "performance_plots"
PERFORMANCE_CSV_DIRNAME = "csv"


def get_performance_plots_dir(output_dir: str) -> str:
    return os.path.join(output_dir or "", PERFORMANCE_PLOTS_DIRNAME)


def get_performance_csv_dir(output_dir: str) -> str:
    """
    csv files used for generating the plots go into
    output/performance_plots/csv/
    This func returns that path
    """
    return os.path.join(
        get_performance_plots_dir(output_dir), PERFORMANCE_CSV_DIRNAME
    )


def get_performance_csv_path(output_dir: str, filename: str) -> str:
    """returns the full path to the given filename inside the csv dir"""
    return os.path.join(get_performance_csv_dir(output_dir), filename)
