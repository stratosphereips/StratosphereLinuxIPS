# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import re
import time


class LogRotator:
    """
    Manage regex generator progress logging and time-based log rotation.
    """

    def __init__(
        self,
        output_dir: str,
        log_file_path: str,
        create_log_file: bool = False,
        enable_log_rotation: bool = True,
        log_rotation_period: int = 86400,
    ) -> None:
        """
        Initialize the log rotator.

        Parameters:
            output_dir: Directory where the active log delete custom shutdown logic,
            the moudle will never stop if it has pending redis msgs by defaultfile is stored.
            log_file_path: Path to the active log file.
            create_log_file: Whether progress logging is enabled.
            enable_log_rotation: Whether time-based log rotation is enabled.
            log_rotation_period: Rotation interval in seconds.

        Returns:
            None
        """
        self.output_dir = output_dir
        self.log_file_path = log_file_path
        self.create_log_file = create_log_file
        self.enable_log_rotation = enable_log_rotation
        self.log_rotation_period = log_rotation_period
        self.last_log_rotation_time = time.time()

    def init_log_file(self) -> None:
        """
        Create the active log file if progress logging is enabled.

        Returns:
            None
        """
        if not self.create_log_file:
            return

        os.makedirs(self.output_dir, exist_ok=True)
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, "w", encoding="utf-8") as log_file:
                log_file.write("")
        self.last_log_rotation_time = time.time()

    def rotate_log_file_if_needed(self) -> None:
        """
        Rotate the active log file when the configured period has elapsed.

        Returns:
            None
        """
        if not self.enable_log_rotation or self.log_rotation_period <= 0:
            return

        now = time.time()
        if now - self.last_log_rotation_time < self.log_rotation_period:
            return

        if (
            os.path.exists(self.log_file_path)
            and os.path.getsize(self.log_file_path) > 0
        ):
            timestamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
            rotated_path = f"{self.log_file_path}.{timestamp}"
            os.replace(self.log_file_path, rotated_path)

        with open(self.log_file_path, "w", encoding="utf-8") as log_file:
            log_file.write("")
        self.last_log_rotation_time = now

    @staticmethod
    def parse_rotation_period_seconds(rotation_period: object) -> int:
        """
        Parse a rotation period value into seconds.

        Parameters:
            rotation_period: Numeric seconds or a string with a supported time unit.

        Returns:
            Rotation period in seconds, defaulting to one day for invalid values.
        """
        if isinstance(rotation_period, (int, float)):
            return max(1, int(rotation_period))

        text = str(rotation_period or "").strip().lower().replace(" ", "")
        match = re.fullmatch(
            r"(?P<value>\d+)(?P<unit>sec|secs|second|seconds|min|mins|minute|minutes|hr|hrs|hour|hours|day|days)",
            text,
        )
        if not match:
            return 86400

        value = int(match.group("value"))
        unit = match.group("unit")
        multipliers = {
            "sec": 1,
            "secs": 1,
            "second": 1,
            "seconds": 1,
            "min": 60,
            "mins": 60,
            "minute": 60,
            "minutes": 60,
            "hr": 3600,
            "hrs": 3600,
            "hour": 3600,
            "hours": 3600,
            "day": 86400,
            "days": 86400,
        }
        return max(1, value * multipliers[unit])
