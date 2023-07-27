import memray
import glob
import os
import subprocess
from termcolor import colored
import time
import multiprocessing
from multiprocessing.managers import SyncManager
from multiprocessing.synchronize import Lock, Event
from multiprocessing.sharedctypes import SynchronizedBase
import threading
from typing import Dict, List
import psutil
import random

def proc_is_running(pid):
    try:
        process = psutil.Process(pid)
        # Check if the process exists by accessing any attribute of the Process object
        process.name()
        return True
    except psutil.NoSuchProcess:
        return False
    
class LiveMultiprocessProfiler:
    original_process_class: multiprocessing.Process
    signal_handler_thread: threading.Thread
    tracker_possessor: int
    db = None
    # def __init__(self, db=None):
    #     self.original_process_class = multiprocessing.Process
    #     global mp_manager
    #     mp_manager = multiprocessing.Manager()
    #     global tracker_lock_global
    #     tracker_lock_global = mp_manager.Lock()
        
    #     global proc_map_global
    #     proc_map_global = {}
    #     global proc_map_lock_global
    #     proc_map_lock_global = mp_manager.Lock()
    #     self.db = db
    #     self.pid_channel = self.db.subscribe('memory_profile')
    #     self.db.publish('memory_profile', 5)
    #     self.db.publish('memory_profile', "Hello")

    # def _create_profiler(self):
    #     pass

    # def _handle_signal(self):
    #     global proc_map_global
    #     global tracker_lock_holder_pid
    #     while True:
    #         # check redis channel
    #         # poll for signal
    #         timeout = 0.01
    #         msg = self.pid_channel.get_message(timeout=timeout)
    #         pid_to_profile: int = None
    #         while msg:
    #             pid: int = None
    #             try:
    #                 pid = int(msg['data'])
    #             except ValueError:
    #                 msg = self.pid_channel.get_message(timeout=timeout)
    #                 continue
    #             if pid in proc_map_global.keys():
    #                 print(colored(f"Handle signal {pid}"))
    #                 if proc_is_running(pid):
    #                     pid_to_profile = pid
    #                 else:
    #                     try:
    #                         proc_map_global.pop(pid)
    #                     except KeyError:
    #                         pass
    #             msg = self.pid_channel.get_message(timeout=timeout)
            
    #         if pid_to_profile:
    #             time.sleep(5)
    #             print(colored(f"Sending end signal {tracker_lock_holder_pid}", "red"))
    #             if tracker_lock_holder_pid in proc_map_global.keys():
    #                 proc_map_global[tracker_lock_holder_pid].set_end_signal()
    #             print(colored(f"Sending start signal {pid_to_profile}", "red"))
    #             print(proc_map_global[pid_to_profile])

    #             proc_map_global[pid_to_profile].set_start_signal()
    #             #send stop first, send start new process
            
    #         time.sleep(1)
    
    def __init__(self, db=None):
        self.original_process_class = multiprocessing.Process
        global mp_manager
        global tracker_lock_global
        global tracker_lock_holder_pid
        global proc_map_global
        global proc_map_lock_global
        mp_manager = multiprocessing.Manager()
        tracker_lock_global = mp_manager.Lock() # process holds when running profiling
        tracker_lock_holder_pid = multiprocessing.Value("i", 0) # process that holds the lock
        proc_map_global = {} # port to process object mapping
        proc_map_lock_global = mp_manager.Lock() # hold when modifying proc_map_global
        self.db = db
        self.pid_channel = self.db

    def _create_profiler(self):
        pass

    def _handle_signal(self):
        global proc_map_global
        global tracker_lock_holder_pid
        while True:
            # check redis channel
            # poll for signal
            timeout = 0.01
            msg: str = None
            pid_to_profile: int = None
            while not self.pid_channel.empty():
                msg = self.pid_channel.get()
                print(f"Msg {msg}")
                pid: int = None
                try:
                    pid = int(msg)
                except TypeError:
                    continue
                if pid in proc_map_global.keys():
                    if proc_is_running(pid):
                        pid_to_profile = pid
                    else:
                        try:
                            proc_map_global.pop(pid)
                        except KeyError:
                            pass
            if pid_to_profile:
                print(colored(f"Sending end signal {tracker_lock_holder_pid.value}", "red"))
                if tracker_lock_holder_pid.value in proc_map_global.keys():
                    print(proc_map_global[tracker_lock_holder_pid.value])
                    proc_map_global[tracker_lock_holder_pid.value].set_end_signal()
                print(colored(f"Sending start signal {pid_to_profile}", "red"))
                proc_map_global[pid_to_profile].set_start_signal()
                #send stop first, send start new process
            
            time.sleep(1)
    
    def _test_thread(self):
        global proc_map_global
        while True:
            print("Test thread:", proc_map_global)
            if len(proc_map_global):
                pid = random.choice(list(proc_map_global.keys()))
                self.db.put(pid)
                print(colored(f"Published {pid}", "red"))
                break
            time.sleep(1)

    def start(self):
        multiprocessing.Process = MultiprocessPatch
        self.signal_handler_thread = threading.Thread(target=self._handle_signal, daemon=True)
        self.signal_handler_thread.start()
        #Remove Later
        # self.test_thread = threading.Thread(target=self._test_thread, daemon=True)
        # self.test_thread.start()

    def stop(self):
        multiprocessing.Process = self.original_process_class

    def print(self):
        pass

class MultiprocessPatch(multiprocessing.Process):
    tracker: memray.Tracker = None
    tracker_start: Event = None
    tracker_end: Event = None
    signal_interval: int = 1 # sleep time for checking start and end signals to process
    poll_interval: int = 1 # sleep time for checking if signal has finished processing
    port = 1234
    def __init__(self, *args, **kwargs):
        super(MultiprocessPatch, self).__init__(*args, **kwargs)
        self.tracker_start = multiprocessing.Event()
        self.tracker_end = multiprocessing.Event()
    
    def set_start_signal(self, block=False):
        print(f"set start signal {self.pid}")
        if self.tracker_start:
            self.tracker_start.set()
            while block and self.tracker_start.is_set():
                time.sleep(self.poll_interval)
    
    def set_end_signal(self, block=False):
        print(f"set end signal {self.pid}")
        if self.tracker_end:
            self.tracker_end.set()
            while block and self.tracker_start.is_set():
                time.sleep(self.poll_interval)
    
    def execute_tracker(self, destination):
        self.tracker = memray.Tracker(destination=destination)
        
    def start_tracker(self):
        global tracker_lock_global
        global tracker_lock_holder_pid
        print(colored(f"start_tracker lock {self.pid}", "red"))
        if not self.tracker and tracker_lock_global.acquire(blocking=False):
            print(colored(f"start_tracker memray at PID {self.pid} started {self.port}", "red"))
            tracker_lock_holder_pid.value = self.pid
            print(colored(f"start_tracker lock holder pid {tracker_lock_holder_pid.value}", "red"))
            dest = memray.SocketDestination(server_port=self.port, address='127.0.0.1')
            self.tracker = memray.Tracker(destination=dest)
            self.tracker.__enter__()
        
    def end_tracker(self):
        global tracker_lock_global
        global tracker_lock_holder_pid
        print(f"end_tracker Lock Holder {tracker_lock_holder_pid.value}, {self.tracker}")
        if self.tracker:
            print(colored(f"end_tracker memray at PID {self.pid} ended", "red"))
            self.tracker.__exit__(None, None, None)
            self.tracker = None
            tracker_lock_holder_pid.value = 0
            tracker_lock_global.release()
            
    def _check_start_signal(self):
        while True:
            while not self.tracker_start.is_set():
                time.sleep(self.signal_interval)
                continue
            self.start_tracker()
            self.tracker_start.clear()
    
    def _check_end_signal(self):
        while True:
            while not self.tracker_end.is_set():
                time.sleep(self.signal_interval)
                continue
            self.end_tracker()
            self.tracker_end.clear()
    
    def start(self) -> None:
        super().start()
        global proc_map_global
        global proc_map_lock_global
        proc_map_lock_global.acquire()
        proc_map_global[self.pid] = self
        proc_map_lock_global.release()
    
    def _pop_map(self):
        global proc_map_global
        global proc_map_lock_global
        proc_map_lock_global.acquire()
        try:
            proc_map_global.pop(self.pid)
        except KeyError:
            print(f"_pop_map {self.pid} no longer in memory profile map, continuing...")
        proc_map_lock_global.release()
    
    def _release_lock(self):
        global tracker_lock_global
        global tracker_lock_holder_pid
        if tracker_lock_holder_pid.value == self.pid:
            tracker_lock_global.release()

    def _cleanup(self):
        self._pop_map()
        self._release_lock()
    
    def run(self):
        print(f"Child process started - PID: {self.pid}")
        start_signal_thread = threading.Thread(target=self._check_start_signal, daemon=True)
        start_signal_thread.start()
        end_signal_thread = threading.Thread(target=self._check_end_signal, daemon=True)
        end_signal_thread.start()
        super().run()
        self._cleanup()

mp_manager: SyncManager = None
tracker_lock_global: Lock = None # process holds when running profiling
tracker_lock_holder_pid: SynchronizedBase = None # process that holds the lock
proc_map_global: Dict[int, MultiprocessPatch] = None # port to process object mapping
proc_map_lock_global: Lock = None # hold when modifying proc_map_global

def target_function():
    print("Target function started")
    time.sleep(5)

def mem_function():
    print("Mem function started")
    while True:
        time.sleep(1)
        array = []
        for i in range(1000000):
            array.append(i)

if __name__ == "__main__":
    # mp_manager = multiprocessing.Manager()
    # tracker_lock_global = mp_manager.Lock()
    # proc_map_global = {}
    # proc_map_lock_global = mp_manager.Lock()

    db = multiprocessing.Queue()
    profiler = LiveMultiprocessProfiler(db=db)
    profiler.start()

    processes: List[MultiprocessPatch] = []
    num_processes = 3
    
    for _ in range(num_processes):
        process = multiprocessing.Process(target=target_function if _%2 else mem_function)
        process.start()
        processes.append(process)
    
    # Message passing
    db.put(processes[1].pid) # successful
    time.sleep(5) # target_function will timeout and tracker will be cleared
    db.put(processes[0].pid) # end but maybe don't start
    time.sleep(5) # mem_function will get tracker started
    db.put(processes[0].pid) # start successfully

    # Direct process access
    # processes[0].set_start_signal()
    # time.sleep(5)
    # processes[0].set_end_signal()
    # time.sleep(2)
    # processes[1].set_start_signal()
    # time.sleep(10)
    # processes[0].set_end_signal()

    for process in processes:
        process.join()