# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from abc import ABC, abstractmethod


class IInputType(ABC):
    """
    Interface for all input types supported by slips placed in slips_files/core/profiler.py
    """

    @abstractmethod
    def process_line(self, line: str):
        """
        Process all fields of a given line
        """
