import threading
import time


class ThroughputLogger:
    def __init__(
        self,
        db,
        component_name: str,
        interval_seconds: int = 180,  # 3 mins
    ):
        self.db = db
        self.component_name = component_name
        self.interval_seconds = interval_seconds
        self._last_ts = time.time()
        self._stop_event = threading.Event()
        # self._thread = threading.Thread(
        #     target=self._run,
        #     name=f"throughput_logger_{component_name}",
        #     daemon=True,
        # )
        # self._thread.start()

    def record_flow(self, count: int = 1) -> None:
        self.db.increment_throughput_counter(self.component_name, count)

    def shutdown(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)

    #
    # def _run(self) -> None:
    #     next_deadline = time.time() + self.interval_seconds
    #     while not self._stop_event.wait(timeout=1):
    #         now = time.time()
    #         if now < next_deadline:
    #             continue
    #         self._update_fps(now)
    #         next_deadline = now + self.interval_seconds
    #
    # def _update_fps(self, now: float) -> None:
    #     delta = self.db.pop_throughput_counter(self.component_name)
    #     last_ts = self._last_ts
    #     self._last_ts = now
    #
    #     time_delta = max(now - last_ts, 1e-6)
    #     fps = delta / time_delta
    #     self.db.store_throughput_fps(self.component_name, fps)
