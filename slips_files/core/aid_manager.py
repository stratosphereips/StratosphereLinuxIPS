from multiprocessing import Process, Queue
from queue import Empty

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
    ):
        self.db = db
        self._aid_queue: Queue = _aid_queue

        self._process = Process(
            target=self._run_worker,
            args=(
                self._aid_queue,
                {
                    "logger": db.logger,
                    "output_dir": db.output_dir,
                    "redis_port": db.redis_port,
                    "conf": db.conf,
                    "main_pid": db.main_pid,
                    "start_redis_server": False,
                    "flush_db": False,
                },
            ),
            name="aid_manager",
            daemon=True,
        )
        utils.start_process(self._process, self.db)

    @classmethod
    def for_queue(cls, aid_queue: Queue) -> "AIDManager":
        """Return a submission-only client for an existing AID worker.

        Parameters:
            aid_queue: Queue consumed by the existing worker.

        Returns:
            Client containing only the shared task queue.
        """
        client = cls.__new__(cls)
        client._aid_queue = aid_queue
        return client

    @staticmethod
    def _run_worker(aid_queue: Queue, database_options: dict) -> None:
        """Open a child-local database and consume AID tasks.

        Parameters:
            aid_queue: Queue of flow-storage tasks.
            database_options: Serializable database connection settings.
        """
        db = DBManager(**database_options)
        AIDManager.for_queue(aid_queue)._worker_loop(aid_queue, db)

    def _worker_loop(self, aid_queue, db: DBManager):
        """
        Runs in its own process
        """
        while True:
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
                db.add_flow(flow, profileid, twid, label=label)
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

    def shutdown(self):
        """
        Gracefully stop the background process.
        """
        self._aid_queue.put("stop")  # sentinel
        self._process.join()
