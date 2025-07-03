# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
An interface for modules that export evidence somewhere, whether to slack,
warden etc.
"""

from abc import ABC, abstractmethod

from slips_files.common.printer import Printer
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output


class IExporter(ABC):
    def __init__(self, logger: Output, db: DBManager, **kwargs):
        self.printer = Printer(logger, self.name)
        self.db = db
        self.init(**kwargs)

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def init(self):
        """
        handles the initialization of exporters
        the goal of this is to have one common __init__() for all
        modules, which is the one in this file, and a different init() per
        expoerter
        this init will have access to all keyword args passes when
        initializing the module
        """

    @abstractmethod
    def export(self, *args, **kwargs):
        """exports evidence/alerts to the destination"""

    @abstractmethod
    def shutdown_gracefully(self):
        """Exits gracefully"""

    @abstractmethod
    def should_export(self) -> bool:
        """Determines whether to export or not"""

    @abstractmethod
    def read_configuration(self):
        """Reads configuration"""
