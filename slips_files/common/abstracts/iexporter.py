# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
An interface for modules that export evidence somewhere, whether to slack,
warden etc.
"""

import os

from abc import ABC, abstractmethod

from slips_files.common.output_paths import (
    get_databases_dir_path_inside_output_dir,
)
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

    def get_output_path(
        self, *relative_path_parts: str, module_name: str | None = None
    ) -> str:
        output_dir = (
            getattr(self.db, "output_dir", None) or self.db.get_output_dir()
        )
        if isinstance(output_dir, bytes):
            output_dir = output_dir.decode("utf-8")
        if not output_dir:
            output_dir = "."
        module_output_dir = os.path.join(output_dir, module_name or self.name)
        os.makedirs(module_output_dir, exist_ok=True)
        return os.path.join(module_output_dir, *relative_path_parts)

    def get_database_path(self, filename: str) -> str:
        output_dir = (
            getattr(self.db, "output_dir", None) or self.db.get_output_dir()
        )
        if isinstance(output_dir, bytes):
            output_dir = output_dir.decode("utf-8")
        if not output_dir:
            output_dir = "."
        return get_databases_dir_path_inside_output_dir(output_dir, filename)

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
