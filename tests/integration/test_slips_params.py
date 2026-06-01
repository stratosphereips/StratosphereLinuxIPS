# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Integration tests for Slips command-line parameters.
"""

import subprocess
import sys

from tests.common_test_utils import skip_if_missing_runtime_dependencies


def run_slips_param(param: str) -> subprocess.CompletedProcess[str]:
    """
    Run slips.py with a single command-line parameter.

    :param param: Slips command-line parameter to pass
    :return: Completed Slips subprocess
    """
    return subprocess.run(
        [sys.executable, "./slips.py", param],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )


def test_multiinstance_requires_input_source() -> None:
    """
    Check that -m exits cleanly with the expected missing-input message.

    :return: None
    """
    skip_if_missing_runtime_dependencies(python_modules=("termcolor",))

    result = run_slips_param("-m")
    output = result.stdout + result.stderr

    assert result.returncode == 255
    assert "[Main] You need to define an input source." in output


def test_clearcache_deletes_cache_database() -> None:
    """
    Check that -cc clears the Redis cache database successfully.

    :return: None
    """
    skip_if_missing_runtime_dependencies(
        python_modules=("termcolor",), binaries=("redis-server",)
    )

    result = run_slips_param("-cc")
    output = result.stdout + result.stderr

    assert result.returncode == 0
    assert "Deleting the cache database in the Redis server" in output
    assert "Done deleting the cache database." in output
