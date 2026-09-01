# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import time

import pytest

from modules.regex_generator.log_rotator import LogRotator


@pytest.mark.parametrize(
    ("rotation_period", "expected_seconds"),
    [
        (30, 30),
        (0, 1),
        ("2hr", 7200),
        ("3 days", 259200),
        ("bad", 86400),
    ],
)
def test_parse_rotation_period_seconds(
    rotation_period: object, expected_seconds: int
) -> None:
    """
    Check conversion of supported and invalid rotation period values.

    Parameters:
        rotation_period: Rotation period value to parse.
        expected_seconds: Expected parsed value in seconds.

    Returns:
        None
    """
    assert (
        LogRotator.parse_rotation_period_seconds(rotation_period)
        == expected_seconds
    )


def test_rotate_log_file_if_needed_rotates_non_empty_log_file(
    tmp_path,
) -> None:
    """
    Check that rotation moves a stale non-empty log out of the active path.

    Parameters:
        tmp_path: Temporary pytest path fixture.

    Returns:
        None
    """
    output_dir = tmp_path / "output"
    log_file_path = output_dir / "regex_generator.log"
    log_rotator = LogRotator(
        str(output_dir),
        str(log_file_path),
        create_log_file=True,
        enable_log_rotation=True,
        log_rotation_period=1,
    )
    log_rotator.init_log_file()

    with open(log_file_path, "a", encoding="utf-8") as log_file:
        log_file.write("old line\n")
    log_rotator.last_log_rotation_time = time.time() - 10

    log_rotator.rotate_log_file_if_needed()

    rotated_logs = list(output_dir.glob("regex_generator.log.*"))
    assert rotated_logs
    with open(log_file_path, encoding="utf-8") as log_file:
        log_contents = log_file.read()
    assert "old line" not in log_contents
