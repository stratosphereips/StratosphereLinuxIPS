import memray
from slips_files.common.abstracts import ProfilerInterface

class MemoryProfiler(ProfilerInterface):
    profiler = None
    def __init__(self, output, mode="dev"):
        valid_modes = ["dev", "live"]
        if mode not in valid_modes:
            print("memory_profiler_mode = " + mode + " is invalid, must be one of " +
                            str(valid_modes) + ", Memory Profiling will be disabled")
        if mode == "dev":
            self.profiler = DevProfiler(output)

    def _create_profiler(self):
        self.profiler._create_profiler()

    def start(self):
        print("Memory Profiler Started")
        self.profiler.start()

    def stop(self):
        self.profiler.stop()
        print("Memory Profiler Ended")

    def print(self):
        pass

class DevProfiler(ProfilerInterface):
    output = None
    profiler = None
    def __init__(self, output):
        self.output = output
        self.profiler = self._create_profiler()

    def _create_profiler(self):
        return memray.Tracker(self.output)

    def start(self):
        self.profiler.__enter__()

    def stop(self):
        self.profiler.__exit__(None, None, None)

    def print(self):
        pass