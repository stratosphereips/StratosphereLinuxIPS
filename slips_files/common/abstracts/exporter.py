"""
An interface for modules that export evidence somewhere, whether to slack,
warden etc.
"""

from abc import ABC, abstractmethod

from slips_files.common.abstracts.observer import IObservable
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output


class IExporter(IObservable, ABC):
    def __init__(self, logger: Output, db: DBManager, **kwargs):
        IObservable.__init__(self)
        self.logger = logger
        self.add_observer(self.logger)
        self.db = db
        self.init(**kwargs)

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def print(self, text, verbose=1, debug=0, log_to_logfiles_only=False):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text
        by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format
                    like 'Test {}'.format('here')
        :param log_to_logfiles_only: logs to slips.log only, not to cli
        """
        self.notify_observers(
            {
                "from": self.name,
                "txt": str(text),
                "verbose": verbose,
                "debug": debug,
                "log_to_logfiles_only": log_to_logfiles_only,
            }
        )

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
