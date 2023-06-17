import viztracer
import time
import threading
import yappi
import pstats

from slips_files.common.abstracts import ProfilerInterface

class CPUProfiler(ProfilerInterface):
    def __init__(self, mode="dev", limit=20, interval=20):
        valid_modes = ["dev", "live"]
        if mode not in valid_modes:
            raise Exception("cpu_profiler_mode = " + mode + " is invalid, must be one of " + str(valid_modes) + ", CPU Profiling will be disabled")
        if mode == "dev":
            self.profiler = DevProfiler(limit)
        if mode == "live":
            self.profiler = LiveProfiler(limit, interval)
    
    def _create_profiler(self):
        self.profiler._create_profiler()

    def start(self):
        print("CPU Profiler Started")
        self.profiler.start()

    def stop(self):
        self.profiler.stop()
        print("CPU Profiler Ended")

    def print(self):
        self.profiler.print()

class DevProfiler(ProfilerInterface):
    def __init__(self, limit):
        self.profiler = self._create_profiler()
        self.limit = limit
    
    def _create_profiler(self):
        return viztracer.VizTracer()

    def start(self):
        self.profiler.start()

    def stop(self):
        self.profiler.stop()

    def print(self):
        self.profiler.save('output/result.json')

class LiveProfiler(ProfilerInterface):
    def __init__(self, limit=20, interval=20):
        self.profiler = self._create_profiler()
        self.limit = limit
        self.interval = interval
        self.is_running = False
        self.timer_thread = threading.Thread(target=self._sampling_loop)

    def _create_profiler(self):
        return yappi

    def start(self):
        if not self.is_running:
            self.is_running = True
            self.profiler.start()
            self.timer_thread.start()

    def stop(self):
        if self.is_running:
            self.is_running = False
            self.profiler.stop()

    def print(self):
        stats = self.profiler.convert2pstats(self.profiler.get_func_stats())
        stats.sort_stats('cumulative')
        stats.print_stats(self.limit)
    
    def _sampling_loop(self):
        while self.is_running:
            # replace the print with a redis update
            self.print()
            time.sleep(self.interval)
            self.profiler.clear_stats()