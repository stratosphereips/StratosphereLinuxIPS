# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import sys
import traceback
import threading
from abc import ABC, abstractmethod

from slips_files.common.printer import Printer
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output


class IThread(ABC):
    """
    An interface for thread-based classes like FlowProcessor and similar classes.
    This interface provides common functionality including database initialization,
    stop signal handling, and print functionality.
    """

    name = "Thread"
    description = "Template thread"
    authors = ["Template Author"]

    @classmethod
    async def create(
        cls,
        stop_signal: threading.Event,
        logger: Output = None,
        output_dir=None,
        redis_port=None,
        conf=None,
        slips_args=None,
        main_pid: int = None,
        flush_db=False,
        start_redis_server=False,
        **kwargs,
    ):
        """
        Factory method that creates an instance of the thread class and
        initializes it completely.

        This method:
        1. Creates the class instance (minimal __init__)
        2. Sets all instance attributes
        3. Initializes the database connection
        4. Calls the subclass init() method
        5. Returns the fully initialized instance

        Args:
            stop_signal: Threading event to signal when the thread should stop
            logger: Output logger instance
            output_dir: Directory for output files
            redis_port: Redis server port
            conf: Configuration object
            slips_args: Command line arguments
            main_pid: Main process PID
            flush_db: Whether to flush the database
            start_redis_server: Whether to start Redis server
            **kwargs: Additional keyword arguments for subclass init()

        Returns:
            Fully initialized instance of the class
        """
        # Create the instance with minimal __init__
        instance = cls()

        # Set all instance attributes
        instance.stop_signal = stop_signal
        instance.logger = logger
        instance.output_dir = output_dir
        instance.redis_port = redis_port
        instance.conf = conf
        instance.slips_args = slips_args
        instance.main_pid = main_pid
        instance.flush_db = flush_db
        instance.start_redis_server = start_redis_server
        instance.printer = Printer(logger, instance.name)

        # Initialize the database
        instance.db = await DBManager.create(
            logger=logger,
            output_dir=slips_args.output if slips_args else output_dir,
            redis_port=redis_port,
            conf=conf,
            slips_args=slips_args,
            main_pid=main_pid,
            flush_db=flush_db,
            start_redis_server=start_redis_server,
        )

        # Call the subclass-specific initialization
        await instance.init(**kwargs)

        return instance

    @abstractmethod
    async def init(self, **kwargs):
        """
        Abstract initialization method that must be implemented by subclasses.
        This method handles the specific initialization logic for each thread class.

        Args:
            **kwargs: Keyword arguments passed during initialization
        """
        pass

    @abstractmethod
    async def start(self):
        """
        Abstract start method that must be implemented by subclasses.
        This method contains the main logic that runs in the thread.
        """
        pass

    def stop(self) -> bool:
        """
        Check if the stop signal is set.

        Returns:
            bool: True if the thread should stop, False otherwise
        """
        return self.stop_signal.is_set()

    def print(self, *args, **kwargs):
        """
        Print function that uses the printer instance.
        This provides the same printing functionality as in flow_processor.py

        Args:
            *args: Arguments to pass to the printer
            **kwargs: Keyword arguments to pass to the printer
        """
        return self.printer.print(*args, **kwargs)

    def print_traceback(self):
        """
        Print traceback information for debugging purposes.
        """
        exception_line = sys.exc_info()[2].tb_lineno
        self.print(f"Problem in line {exception_line}", 0, 1)
        self.print(traceback.format_exc(), 0, 1)
