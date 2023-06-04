import cProfile
import pstats

class CPUProfiler():
    def __init__(self, mode="dev", limit=20):
        valid_modes = ["dev", "live"]
        if mode not in valid_modes:
            raise Exception(mode + " is invalid, must be one of " + valid_modes)
        self.profiler = cProfile.Profile()
        self.mode = mode
        self.limit = limit

    def start(self):
        self.profiler.enable()

    def end(self):
        self.profiler.disable()
    
    def print(self):
        stats = pstats.Stats(self.profiler).sort_stats('cumulative')
        stats.print_stats(self.limit)
        # self.profiler.print_stats(sort="cumulative")