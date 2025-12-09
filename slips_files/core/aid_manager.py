from multiprocessing import Process, Queue
from queue import Empty
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
        db: DBManager,
        _aid_queue: Queue,
        stop_profiler_workers_event: Event,
    ):
        self.db = db
        self._aid_queue: Queue = _aid_queue
        # returns true when this process should shutdown
        self.stop_profiler_workers_event = stop_profiler_workers_event

        self._process = Process(
            target=self._worker_loop,
            args=(self._aid_queue, self.db),
            name="AIDManager",
            daemon=True,
        )
        utils.start_process(self._process, self.db)

    def _worker_loop(self, aid_queue, db: DBManager):
        """
        TRuns in its own process
        - Initialize DBManager once.
        - Loop forever processing tasks.
        """
        while not self.stop_profiler_workers_event.is_set():
            try:
                task = aid_queue.get(timeout=1)
                if task == "stop":
                    break

                flow = task["flow"]
                profileid = task["profileid"]
                twid = task["twid"]
                label = task["label"]

                # CPU-heavy hashing
                flow.aid = utils.get_aid(flow)
                self.db.add_flow(flow, profileid, twid, label=label)
            except KeyboardInterrupt:
                continue
            except Empty:
                continue

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

    def shutdown(self, wait=True):
        """
        Gracefully stop the background process.
        """
        self._aid_queue.put("stop")  # sentinel
        if wait:
            self._process.join()
