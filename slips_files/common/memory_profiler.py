import memray
import glob
import os
import subprocess
from termcolor import colored
from slips_files.common.abstracts import ProfilerInterface
import time
import multiprocessing
from multiprocessing.managers import SyncManager
from multiprocessing.synchronize import Lock
import threading
from typing import Set
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
    port = 5000
    def __init__(self):
        self.profiler = self._create_profiler()
    def _create_profiler(self):
        print("Memory profiling running on port " + str(self.port))
        print("Connect to continue")
        with open(os.devnull, 'w') as devnull:
            subprocess.Popen(["memray", "live", str(self.port)], stdout=devnull)
        dest = memray.SocketDestination(server_port=self.port, address='127.0.0.1')
        return memray.Tracker(destination=dest)

    def start(self):
        self.profiler.__enter__()

    def stop(self):
        self.profiler.__exit__(None, None, None)

    def print(self):
        pass

class LiveMultiprocessProfiler(ProfilerInterface):
    original_process_class: multiprocessing.Process
    signal_handler_thread: threading.Thread
    tracker_possessor: int
    def __init__(self):
        self.original_process_class = multiprocessing.Process
        global mp_manager
        mp_manager = multiprocessing.Manager()
        global tracker_lock_global
        tracker_lock_global = mp_manager.Lock()
        global proc_array_global
        proc_array_global = set()
        global proc_array_lock_global
        proc_array_lock_global = mp_manager.Lock()

    def _create_profiler(self):
        pass

    def _handle_signal(self):
        while True:
            # check redis channel
            # poll for signal
            time.sleep(3)

    def start(self):
        multiprocessing.Process = MultiprocessPatch
        self.signal_handler_thread = threading.Thread(target=self._handle_signal, daemon=True)
        self.signal_handler_thread.start()

    def stop(self):
        multiprocessing.Process = self.original_process_class

    def print(self):
        pass

class MultiprocessPatch(multiprocessing.Process):
    tracker = None
    tracker_start = None
    tracker_end = None
    signal_interval = 1
    port = 1234
    def __init__(self, *args, **kwargs):
        super(MultiprocessPatch, self).__init__(*args, **kwargs)
        self.tracker_start = multiprocessing.Event()
        self.tracker_end = multiprocessing.Event()
    
    def start(self) -> None:
        print("Start of new process", os.getpid())
        global proc_array_global
        global proc_array_lock_global
        proc_array_lock_global.acquire()
        proc_array_global.add(self)
        proc_array_lock_global.release()
        print("Start:", proc_array_global)
        return super().start()
    
    def join(self, timeout: "float | None" = None) -> None:
        print("This is the end of the process")
        global proc_array_global
        global proc_array_lock_global
        proc_array_lock_global.acquire()
        proc_array_global.remove(self)
        proc_array_lock_global.release()
        print("End:", proc_array_global)
        return super().join(timeout)
    
    def terminate(self) -> None:
        return super().terminate()
    
    def set_start_signal(self):
        self.tracker_start.set()
    
    def set_end_signal(self):
        self.tracker_end.set()
    
    def start_tracker(self):
        print(f"Memory profiler starting on {os.getpid()}, connect on port {self.port}")
        dest = memray.SocketDestination(server_port=self.port, address='127.0.0.1')
        self.tracker = memray.Tracker(destination=dest)
    
    def end_tracker(self):
        print(f"Memory profiler ending on {os.getpid()}")
        self.tracker.__exit__(None, None, None)

    def _check_start_signal(self):
        global tracker_lock_global
        while True:
            while not self.tracker_start.is_set():
                time.sleep(self.signal_interval)
                continue
            if not self.tracker and not tracker_lock_global.locked():
                tracker_lock_global.acquire()
                self.start_tracker()
            self.tracker_start.clear()
    
    def _check_end_signal(self):
        while True:
            while not self.tracker_end.is_set():
                time.sleep(self.signal_interval)
                continue
            if self.tracker:
                self.end_tracker()
                tracker_lock_global.release()
            self.tracker_end.clear()
    
    def run(self) -> None:
        start_signal_thread = threading.Thread(target=self._check_start_signal, daemon=True)
        start_signal_thread.start()
        end_signal_thread = threading.Thread(target=self._check_end_signal, daemon=True)
        end_signal_thread.start()
        global proc_array_global
        global proc_array_lock_global
        proc_array_lock_global.acquire()
        proc_array_global[os.getpid()] = self
        proc_array_lock_global.release()
        return super().run()

mp_manager: SyncManager = None
tracker_lock_global: Lock = None # process holds when running profiling
proc_array_global: Set[MultiprocessPatch] = None # port to process object mapping
proc_array_lock_global: Lock = None