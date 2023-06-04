import viztracer
import pstats

class CPUProfiler():
    def __init__(self, mode="dev", limit=20):
        valid_modes = ["dev", "live"]
        if mode not in valid_modes:
            raise Exception(mode + " is invalid, must be one of " + valid_modes)
        self.profiler = viztracer.VizTracer()
        self.mode = mode
        self.limit = limit

    def start(self):
        self.profiler.start()

    def stop(self):
        self.profiler.stop()
    
    def print(self):
        self.profiler.save()
        # stats = pstats.Stats(self.profiler).sort_stats('cumulative')
        # stats.print_stats(self.limit)
        # self.profiler.print_stats(sort="cumulative")