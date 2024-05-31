from abc import ABC, abstractmethod

from modules.flowalerts.set_evidence import SetEvidnceHelper
from slips_files.common.slips_utils import utils
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

    def get_msg(self, channel_name):
        message = self.db.get_message(self.channels[channel_name])
        if utils.is_msg_intended_for(message, channel_name):
            self.msg_received = True
            return message
        else:
            self.msg_received = False
            return False

    @abstractmethod
    def analyze(self) -> bool:
        """
        Analyzes a certain flow type and runs all supported detections
        returns True if there was a detection
        """
