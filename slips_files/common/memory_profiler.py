import memray
import glob
import os
import subprocess
from termcolor import colored
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
        print(colored("Memory Profiler Started", 'green'))
        self.profiler.start()

    def stop(self):
        self.profiler.stop()
        print(colored("Memory Profiler Ended", 'green'))

    def print(self):
        pass

class DevProfiler(ProfilerInterface):
    output = None
    profiler = None
    def __init__(self, output):
        self.output = output
        self.profiler = self._create_profiler()

    def _create_profiler(self):
        return memray.Tracker(file_name=self.output, follow_fork=True)

    def start(self):
        self.profiler.__enter__()

    def stop(self):
        self.profiler.__exit__(None, None, None)
        print(colored("Converting memory profile bin files to html...", 'green'))
        output_files = glob.glob(self.output + '*')
        directory = os.path.dirname(self.output)
        flamegraph_dir = directory + '/flamegraph/'
        if not os.path.exists(flamegraph_dir):
            os.makedirs(flamegraph_dir)
        table_dir = directory + '/table/'
        if not os.path.exists(table_dir):
            os.makedirs(table_dir)
        for file in output_files:
            filename = os.path.basename(file)
            flame_output = flamegraph_dir + filename + '.html'
            subprocess.run(['memray', 'flamegraph', '--temporal', '--leaks', '--split-threads', '--output', flame_output, file])
            table_output = table_dir + filename + '.html'
            subprocess.run(['memray', 'table', '--output', table_output, file])

    def print(self):
        pass