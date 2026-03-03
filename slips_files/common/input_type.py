# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from enum import Enum
from typing import Any


class InputType(str, Enum):
    DATABASE = "database"
    FILE = "file"
    PCAP = "pcap"
    INTERFACE = "interface"
    NFDUMP = "nfdump"
    BINETFLOW = "binetflow"
    BINETFLOW_TABS = "binetflow-tabs"
    ZEEK_FOLDER = "zeek_folder"
    ZEEK_LOG_FILE = "zeek_log_file"
    SURICATA = "suricata"
    STDIN = "stdin"
    ZEEK = "zeek"
    ZEEK_TABS = "zeek-tabs"
    CYST = "CYST"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def coerce(cls, value: Any) -> Any:
        try:
            return cls(value)
        except ValueError:
            return value
