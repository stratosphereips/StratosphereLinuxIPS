import memray
import glob
import os
import subprocess
from termcolor import colored
from slips_files.common.abstracts import ProfilerInterface
import time
import multiprocessing
from multiprocessing.managers import SyncManager
from multiprocessing.synchronize import Lock, Event
import threading
from typing import Dict
import psutil
import random

class MemoryProfiler(ProfilerInterface):
    profiler = None
    def __init__(self, output, db=None, mode="dev", multiprocess=True):
        valid_modes = ["dev", "live"]
        if mode not in valid_modes:
            print("memory_profiler_mode = " + mode + " is invalid, must be one of " +
                            str(valid_modes) + ", Memory Profiling will be disabled")
        if mode == "dev":
            self.profiler = DevProfiler(output, multiprocess)
        elif mode == "live":
            self.profiler = LiveProfiler(multiprocess, db=db)

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
    def __init__(self, multiprocess=False, db=None):
        self.multiprocess = multiprocess
        if multiprocess:
            self.profiler=LiveMultiprocessProfiler(db=db)
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

def proc_is_running(pid):
    try:
        process = psutil.Process(pid)
        # Check if the process exists by accessing any attribute of the Process object
        process.name()
        return True
    except psutil.NoSuchProcess:
        return False

class LiveMultiprocessProfiler(ProfilerInterface):
    original_process_class: multiprocessing.Process
    signal_handler_thread: threading.Thread
    tracker_possessor: int
    db = None
    def __init__(self, db=None):
        self.original_process_class = multiprocessing.Process
        global mp_manager
        mp_manager = multiprocessing.Manager()
        global tracker_lock_global
        tracker_lock_global = mp_manager.Lock()
        
        global proc_map_global
        proc_map_global = {}
        global proc_map_lock_global
        proc_map_lock_global = mp_manager.Lock()
        self.db = db
        self.pid_channel = self.db.subscribe('memory_profile')
        self.db.publish('memory_profile', 5)
        self.db.publish('memory_profile', "Hello")

    def _create_profiler(self):
        pass

    def _handle_signal(self):
        global proc_map_global
        global tracker_lock_holder_pid
        while True:
            # check redis channel
            # poll for signal
            timeout = 0.01
            msg = self.pid_channel.get_message(timeout=timeout)
            pid_to_profile: int = None
            while msg:
                pid: int = None
                try:
                    pid = int(msg['data'])
                except ValueError:
                    msg = self.pid_channel.get_message(timeout=timeout)
                    continue
                if pid in proc_map_global.keys():
                    print(colored(f"Handle signal {pid}"))
                    if proc_is_running(pid):
                        pid_to_profile = pid
                    else:
                        try:
                            proc_map_global.pop(pid)
                        except KeyError:
                            pass
                msg = self.pid_channel.get_message(timeout=timeout)
            
            if pid_to_profile:
                print(colored(f"Sending end signal {tracker_lock_holder_pid}", "red"))
                if tracker_lock_holder_pid in proc_map_global.keys():
                    proc_map_global[tracker_lock_holder_pid].set_end_signal()
                print(colored(f"Sending start signal {pid_to_profile}", "red"))
                print(proc_map_global[pid_to_profile])
                proc_map_global[pid_to_profile].set_start_signal()
                #send stop first, send start new process
            
            time.sleep(1)
    
    def _test_thread(self):
        global proc_map_global
        while True:
            print("Test thread:", proc_map_global)
            if len(proc_map_global):
                pid = random.choice(list(proc_map_global.keys()))
                self.db.publish('memory_profile', pid)
                print(colored(f"Published {pid}", "red"))
                break

    def start(self):
        multiprocessing.Process = MultiprocessPatch
        self.signal_handler_thread = threading.Thread(target=self._handle_signal, daemon=True)
        self.signal_handler_thread.start()
        #Remove Later
        self.test_thread = threading.Thread(target=self._test_thread, daemon=True)
        self.test_thread.start()

    def stop(self):
        multiprocessing.Process = self.original_process_class

    def print(self):
        pass

class MultiprocessPatch(multiprocessing.Process):
    tracker: memray.Tracker = None
    tracker_start: Event = multiprocessing.Event()
    tracker_end: Event = multiprocessing.Event()
    signal_interval: int = 1 # sleep time for checking start and end signals to process
    poll_interval: int = 0.1 # sleep time for checking if signal has finished processing
    port = 1234
    def __init__(self, *args, **kwargs):
        super(MultiprocessPatch, self).__init__(*args, **kwargs)
    
    def start(self) -> None:
        super().start()
        global proc_map_global
        global proc_map_lock_global
        proc_map_lock_global.acquire()
        proc_map_global[self.pid] = self
        proc_map_lock_global.release()
    
    def join(self, timeout: "float | None" = None) -> None:
        global proc_map_global
        global proc_map_lock_global
        proc_map_lock_global.acquire()
        try:
            proc_map_global.pop(self.pid)
        except KeyError:
            print(f"{self.pid} no longer in memory profile map, continuing...")
        proc_map_lock_global.release()
        return super().join(timeout)
    
    def set_start_signal(self):
        self.tracker_start.set()
        while self.tracker_start.is_set():
            time.sleep(self.poll_interval)
    
    def set_end_signal(self):
        self.tracker_end.set()
        while self.tracker_end.is_set():
            time.sleep(self.poll_interval)
    
    def start_tracker(self):
        global tracker_lock_global
        global tracker_lock_holder_pid
        if not self.tracker:
            tracker_lock_global.acquire()
            tracker_lock_holder_pid = self.pid
            dest = memray.SocketDestination(server_port=self.port, address='127.0.0.1')
            self.tracker = memray.Tracker(destination=dest)
    
    def end_tracker(self):
        global tracker_lock_global
        global tracker_lock_holder_pid
        if self.tracker:
            self.tracker.__exit__(None, None, None)
            self.tracker = None
            tracker_lock_holder_pid = None
            tracker_lock_global.release()

    def _check_start_signal(self):
        global tracker_lock_global
        while True:
            while not self.tracker_start.is_set():
                time.sleep(self.signal_interval)
                continue
            self.start_tracker()
            self.tracker_start.clear()
    
    def _check_end_signal(self):
        global tracker_lock_global
        while True:
            while not self.tracker_end.is_set():
                time.sleep(self.signal_interval)
                continue
            self.end_tracker()
            self.tracker_end.clear()
    
    def run(self) -> None:
        start_signal_thread = threading.Thread(target=self._check_start_signal, daemon=True)
        start_signal_thread.start()
        end_signal_thread = threading.Thread(target=self._check_end_signal, daemon=True)
        end_signal_thread.start()
        global proc_map_global
        global proc_map_lock_global
        proc_map_lock_global.acquire()
        proc_map_global[os.getpid()] = self
        proc_map_lock_global.release()
        return super().run()

mp_manager: SyncManager = None
tracker_lock_global: Lock = None # process holds when running profiling
tracker_lock_holder_pid: int = None # process that holds the lock
proc_map_global: Dict[int, MultiprocessPatch] = None # port to process object mapping
proc_map_lock_global: Lock = None # hold when modifying proc_map_global