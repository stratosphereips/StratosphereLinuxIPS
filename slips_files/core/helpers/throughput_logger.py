import os
import threading
import time


class ThroughputLogger:
    def __init__(
        self,
        db,
        output_dir: str,
        component_name: str,
        interval_seconds: int = 180,  # 3 mins
        is_writer: bool = False,
    ):
        self.db = db
        self.output_dir = output_dir
        self.component_name = component_name
        self.interval_seconds = interval_seconds
        self.is_writer = is_writer
        self._count = 0
        self._lock = threading.Lock()
        self._last_ts = time.time()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"throughput_logger_{component_name}",
            daemon=True,
        )
        self._thread.start()

    def record_flow(self, count: int = 1) -> None:
        with self._lock:
            self._count += count

    def shutdown(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)

    def _run(self) -> None:
        next_deadline = time.time() + self.interval_seconds
        while not self._stop_event.wait(timeout=1):
            now = time.time()
            if now < next_deadline:
                continue
            self._update_fps(now)
            if self.is_writer:
                self._write_snapshot(now)
            next_deadline = now + self.interval_seconds

    def _update_fps(self, now: float) -> None:
        with self._lock:
            delta = self._count
            self._count = 0
            last_ts = self._last_ts
            self._last_ts = now

        time_delta = max(now - last_ts, 1e-6)
        fps = delta / time_delta
        self.db.store_throughput_fps(self.component_name, fps)

    def _write_snapshot(self, now: float) -> None:
        output_path = os.path.join(self.output_dir, "throughput.csv")
        write_header = (
            not os.path.exists(output_path)
            or os.path.getsize(output_path) == 0
        )

        input_fps = self.db.get_throughput_fps("input")
        profiler_0_fps = self.db.get_throughput_fps("profiler_0")
        profiler_1_fps = self.db.get_throughput_fps("profiler_1")

        line = f"{int(now)},{input_fps},{profiler_0_fps},{profiler_1_fps}\n"
        with open(output_path, "a") as handle:
            if write_header:
                handle.write(
                    "timestamp,input_flows_per_second,"
                    "profiler_0_fps,profiler_1_fps\n"
                )
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
