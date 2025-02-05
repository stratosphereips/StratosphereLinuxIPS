# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from abc import ABC, abstractmethod

from modules.flowalerts.set_evidence import SetEvidnceHelper
from slips_files.core.database.database_manager import DBManager


class IFlowalertsAnalyzer(ABC):
    def __init__(self, db: DBManager, flowalerts=None, **kwargs):
        self.db = db
        self.flowalerts = flowalerts
        self.whitelist = self.flowalerts.whitelist
        self.set_evidence = SetEvidnceHelper(self.db)
        self.init(**kwargs)

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def shutdown_gracefully(self):
        """Exits gracefully"""

    def read_configuration(self):
        """Reads configuration"""

    @abstractmethod
    def init(self):
        """
        the goal of this is to have one common __init__() above for all
        flowalerts helpers, which is the one in this file, and a different
        init() per helper
        this init will have access to all keyword args passes when
        initializing the module
        """

    def pre_analyze(self):
        """
        runs once before analyze() is run in a loop
        triggered by flowalert's pre_main()
        """
        pass

    @abstractmethod
    def analyze(self, msg: dict) -> bool:
        """
        Analyzes a certain flow type and runs all supported detections
        returns True if there was a detection
        """
