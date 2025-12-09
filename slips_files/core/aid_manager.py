import os
from multiprocessing import Process, Queue
from threading import Event

from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager


class AIDManager:
    """
    just a Process to handle calculating AID hashes and
    storing flows in the sqlite? why in a separate process? because they're cpu
    intensive and they slow down the profiler workers
    Tasks are submitted to this class via the _aid_queue
    """

    def __init__(
        self,
        logger,
        output_dir,
        redis_port,
        conf,
        ppid,
        _aid_queue: Queue,
        stop_profiler_workers_event: Event,
    ):
        self.logger = logger
        self.output_dir = output_dir
        self.redis_port = redis_port
        self.conf = conf
        self.ppid = ppid
        self._aid_queue: Queue = _aid_queue
        # returns true when this process should shutdown
        self.stop_profiler_workers_event = stop_profiler_workers_event

        self._process = Process(
            target=self._worker_loop,
            args=(self._aid_queue, logger, output_dir, redis_port, conf, ppid),
            daemon=True,
        )

        self._process.start()

    def _worker_loop(
        self, aid_queue, logger, output_dir, redis_port, conf, ppid
    ):
        """
        TRuns in its own process
        - Initialize DBManager once.
        - Loop forever processing tasks.
        """

        # Each process has its own DBManager
        db = DBManager(logger, output_dir, redis_port, conf, ppid)
        print(f"@@@@@@ Worker started {os.getpid()} db={db}")

        while not self.stop_profiler_workers_event.is_set():
            task = aid_queue.get(timeout=1)
            if task == "stop":
                print(f"@@@@@@ Worker {os.getpid()} shutting down")
                break

            flow = task["flow"]
            profileid = task["profileid"]
            twid = task["twid"]
            label = task["label"]

            # CPU-heavy hashing
            flow.aid = utils.get_aid(flow)
            db.add_flow(flow, profileid, twid, label=label)
            print(f"@@@@@@ Worker done: {flow.aid}")

    def submit_aid_task(self, flow, profileid: str, twid: str, label: str):
        """
        Push a task into the worker's queue.
        """
        self._aid_queue.put(
            {
                "flow": flow,
                "profileid": profileid,
                "twid": twid,
                "label": label,
            }
        )
        print(f"@@@@@@ Task submitted to process {self._process.pid}")

    def shutdown(self, wait=True):
        """
        Gracefully stop the background process.
        """
        self._aid_queue.put("stop")  # sentinel
        if wait:
            self._process.join()
