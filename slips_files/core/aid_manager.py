import os
from concurrent.futures import ProcessPoolExecutor

from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager


class AIDManager:
    """
    just a ProcessPoolExecutor manager to handle calculating AID hashes and
    storing flows in the sqlite in a separate process because they're cpu
    intensive and they slow down the profiler workers
    """

    def __init__(
        self, logger, output_dir, redis_port, conf, ppid, max_workers=2
    ):
        """
        Initializes the ProcessPoolExecutor and keeps track of the executor
        so get_aid_and_add_flow can be submitted to it.
        """
        self.logger = logger
        self.output_dir = output_dir
        self.redis_port = redis_port
        self.conf = conf
        self.ppid = ppid

        self.aid_calculator_executor = ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=self._init_process_pool_executor,
            initargs=(logger, output_dir, redis_port, conf, ppid),
        )

    @staticmethod
    def _init_process_pool_executor(
        logger, output_dir, redis_port, conf, ppid
    ):
        """
        Initializer for each worker process in the ProcessPoolExecutor.
        Creates a global db instance accessible to worker processes.
        """
        global db
        db = DBManager(logger, output_dir, redis_port, conf, ppid)
        print(f"@@@@@@@@@@@@@@@@ {os.getpid()}::  db initialized {db}")

    @staticmethod
    def _get_aid_and_add_flow_task(flow, profileid, twid, label):
        """
        The actual task run in the worker process.
        Note: Must be static for pickling in ProcessPoolExecutor.
        """
        flow.aid = utils.get_aid(flow)
        db.add_flow(flow, profileid, twid, label=label)
        print(f"@@@@@@@@@@@@@@@@ done adding {flow.aid}")

    def submit_aid_task(self, flow, profileid, twid, label):
        """
        Submit a flow to the executor for background aid calculation and DB insert.
        Returns a Future.
        """
        print("@@@@@@@@@@@@@@@@ submit_aid_task is called")
        return self.aid_calculator_executor.submit(
            self._get_aid_and_add_flow_task, flow, profileid, twid, label
        )

    def shutdown(self, wait=True):
        """
        Cleanly shutdown the executor when done.
        """
        self.aid_calculator_executor.shutdown(wait=wait)
