import memray
import glob
import os
import subprocess
from termcolor import colored
from slips_files.common.abstracts import ProfilerInterface
import socket
import multiprocessing

class MemoryProfiler(ProfilerInterface):
    profiler = None
    def __init__(self, output, mode="dev", multiprocess=True):
        valid_modes = ["dev", "live"]
        if mode not in valid_modes:
            print("memory_profiler_mode = " + mode + " is invalid, must be one of " +
                            str(valid_modes) + ", Memory Profiling will be disabled")
        if mode == "dev":
            self.profiler = DevProfiler(output, multiprocess)
        elif mode == "live":
            self.profiler = LiveProfiler(multiprocess)

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
    multiprocess = None
    def __init__(self, output, multiprocess):
        self.output = output
        self.multiprocess = multiprocess
        self.profiler = self._create_profiler()

    def _create_profiler(self):
        return memray.Tracker(file_name=self.output, follow_fork=self.multiprocess)

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

class LiveProfiler(ProfilerInterface):
    multiprocess = None
    profiler = None
    def __init__(self, multiprocess=False):
        self.multiprocess = multiprocess
        if multiprocess:
            self.profiler=LiveMultiprocessProfiler()
        else:
            self.profiler=LiveSingleProcessProfiler()
    def _create_profiler(self):
        self.profiler._create_profiler()

    def start(self):
        self.profiler.start()

    def stop(self):
        self.profiler.stop()

    def print(self):
        self.profiler.print()

class LiveSingleProcessProfiler(ProfilerInterface):
    profiler = None
    port = 1234
    def __init__(self):
        self.profiler = self._create_profiler()
    def _create_profiler(self):
        print("start: " + str(self.port))
        dest = memray.SocketDestination(server_port=self.port, address='127.0.0.1')
        return memray.Tracker(destination=dest)

    def start(self):
        self.profiler.__enter__()

    def stop(self):
        self.profiler.__exit__(None, None, None)

    def print(self):
        pass

class LiveMultiprocessProfiler(ProfilerInterface):
    original_process_class = None
    profiler = None
    def __init__(self):
        self.original_process_class = multiprocessing.Process

    def _create_profiler(self):
        pass

    def start(self):
        multiprocessing.Process = MultiprocessPatch

    def stop(self):
        multiprocessing.Process = self.original_process_class

    def print(self):
        pass

class MultiprocessPatch(multiprocessing.Process):
    def start(self):
        print("hello this is a new process")
        super().start()
    
    def join(self):
        print("This is the end of the process")
        super.join()