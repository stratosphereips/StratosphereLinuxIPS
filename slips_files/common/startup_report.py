# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Shared formatting for slips' live startup progress report - one line
# per process/module/worker that announces itself while starting, all
# sharing the same columns. Used by both the process manager (main,
# core processes, detection modules) and the profiler/evidence workers,
# which live in separate class hierarchies and can't share a mixin.
from slips_files.common.style import (
    electric_lime,
    grey,
    leaf_green,
    neon_teal,
)

# these are sized off the longest real value slips currently prints,
# e.g. the module name "anomaly_detection_https" (24 chars), so real
# lines never overflow their column and lose alignment
KIND_COLUMN_WIDTH = 26  # "[anomaly_detection_https]"
PROGRESS_COLUMN_WIDTH = 9  # "[NNN/NNN]"


def format_started_line(
    kind: str,
    started_count: int,
    total: int,
    pid: int,
    description: str,
    category: str = "module",
) -> str:
    """
    Build one line of slips' live startup progress report.

    Parameters:
        kind: Name of the thing that started, e.g. "arp", "main", or
            "profiler_worker_2" for a specific profiler worker.
        started_count: How many things of this run have finished
            starting so far, including this one. Shared across every
            process/module/worker, so this is the thing's position in
            slips' overall startup, not a per-kind count.
        total: Total number of things slips is starting this run.
        pid: Started process/worker PID.
        description: Human-readable description.
        category: One of "module" (detection modules), "core" (main,
            profiler, input, evidence handler), or "worker" (profiler
            and evidence workers). Picks the line's color group.

    Returns:
        The fully formatted, colored line, ready to print.
    """
    # one (kind_color, description_color) pair per category, so the
    # three kinds of things slips starts - detection modules, core
    # processes, and profiler/evidence workers - are visually
    # distinguishable at a glance. "Forest Signal" palette (core and
    # module swapped): lime for core, teal for workers, deep green for
    # modules.
    if category == "core":
        kind_color, description_color = electric_lime, electric_lime
    elif category == "worker":
        kind_color, description_color = neon_teal, neon_teal
    else:
        kind_color, description_color = leaf_green, leaf_green

    count_width = len(str(total))
    kind_text = f"[{kind}]".ljust(KIND_COLUMN_WIDTH)
    progress_text = f"[{started_count:>{count_width}}/{total}]".ljust(
        PROGRESS_COLUMN_WIDTH
    )
    return (
        f"{kind_color(kind_text)} {grey(progress_text)} "
        f"{grey(f'[PID {pid}]')}  {description_color(description)}"
    )
