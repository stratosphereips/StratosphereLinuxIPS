from abc import ABC, abstractmethod

from slips_files.core.database.database_manager import DBManager


class IFlowalertsHelper(ABC):
    def __init__(self, db: DBManager, **kwargs):
        self.db = db
        self.init(**kwargs)

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def shutdown_gracefully(self):
        """Exits gracefully"""
        pass

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

    @abstractmethod
    def analyze(self) -> bool:
        """
        Analyzes a certain flow type and runs all supported detections
        returns True if there was a detection
        """
