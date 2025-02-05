# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import memray
import glob
import os
import subprocess
from termcolor import colored
from slips_files.common.abstracts.performance_profiler import (
    IPerformanceProfiler,
)
import time
import multiprocessing
from multiprocessing.managers import SyncManager
from multiprocessing.synchronize import Lock
from multiprocessing.sharedctypes import SynchronizedBase
import threading
from typing import Dict
import psutil
import random
from abc import ABCMeta


class MemoryProfiler(IPerformanceProfiler):
    profiler = None

    def __init__(self, output, db=None, mode="dev", multiprocess=True):
        valid_modes = ["dev", "live"]
        if mode not in valid_modes:
            print(
                "memory_profiler_mode = "
                + mode
                + " is invalid, must be one of "
                + str(valid_modes)
                + ", Memory Profiling will be disabled"
            )
        if mode == "dev":
            self.profiler = DevProfiler(output, multiprocess)
        elif mode == "live":
            self.profiler = LiveProfiler(multiprocess, db=db)

    def _create_profiler(self):
        self.profiler._create_profiler()

    def start(self):
        print(colored("Memory Profiler Started", "green"))
        self.profiler.start()

    def stop(self):
        self.profiler.stop()
        print(colored("Memory Profiler Ended", "green"))

    def print(self):
        pass


class DevProfiler(IPerformanceProfiler):
    output = None
    profiler = None
    multiprocess = None

    def __init__(self, output, multiprocess):
        self.output = output
        self.multiprocess = multiprocess
        self.profiler = self._create_profiler()

    def _create_profiler(self):
        return memray.Tracker(
            file_name=self.output, follow_fork=self.multiprocess
        )

    def start(self):
        self.profiler.__enter__()

    def stop(self):
        self.profiler.__exit__(None, None, None)
        print(
            colored("Converting memory profile bin files to html...", "green")
        )
        output_files = glob.glob(self.output + "*")
        directory = os.path.dirname(self.output)
        flamegraph_dir = directory + "/flamegraph/"
        if not os.path.exists(flamegraph_dir):
            os.makedirs(flamegraph_dir)
        table_dir = directory + "/table/"
        if not os.path.exists(table_dir):
            os.makedirs(table_dir)
        for file in output_files:
            filename = os.path.basename(file)
            flame_output = flamegraph_dir + filename + ".html"
            subprocess.run(
                [
                    "memray",
                    "flamegraph",
                    "--temporal",
                    "--leaks",
                    "--split-threads",
                    "--output",
                    flame_output,
                    file,
                ]
            )
            table_output = table_dir + filename + ".html"
            subprocess.run(["memray", "table", "--output", table_output, file])

    def print(self):
        pass


class LiveProfiler(IPerformanceProfiler):
    multiprocess = None
    profiler = None

    def __init__(self, multiprocess=False, db=None):
        self.multiprocess = multiprocess
        if multiprocess:
            self.profiler = LiveMultiprocessProfiler(db=db)
        else:
            self.profiler = LiveSingleProcessProfiler()

    def _create_profiler(self):
        self.profiler._create_profiler()

    def start(self):
        self.profiler.start()

    def stop(self):
        self.profiler.stop()

    def print(self):
        self.profiler.print()


class LiveSingleProcessProfiler(IPerformanceProfiler):
    profiler = None
    port = 5000

    def __init__(self):
        self.profiler = self._create_profiler()

    def _create_profiler(self):
        print("Memory profiling running on port " + str(self.port))
        print("Connect to continue")
        with open(os.devnull, "w") as devnull:
            subprocess.Popen(
                ["memray", "live", str(self.port)], stdout=devnull
            )
        dest = memray.SocketDestination(
            server_port=self.port, address="127.0.0.1"
        )
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


class LiveMultiprocessProfiler(IPerformanceProfiler):
    # restores the original process behavior once profiler is stopped
    original_process_class: multiprocessing.Process
    # thread checks redis db for which process to start profiling
    signal_handler_thread: threading.Thread
    db = None

    def __init__(self, db=None):
        self.original_process_class = multiprocessing.Process
        global mp_manager
        global tracker_lock_global
        global tracker_lock_holder_pid
        global proc_map_global
        global proc_map_lock_global
        mp_manager = multiprocessing.Manager()
        tracker_lock_global = (
            mp_manager.Lock()
        )  # process holds when running profiling
        tracker_lock_holder_pid = multiprocessing.Value(
            "i", 0
        )  # process that holds the lock
        proc_map_global = {}  # port to process object mapping
        proc_map_lock_global = (
            mp_manager.Lock()
        )  # hold when modifying proc_map_global
        self.db = db
        self.pid_channel = self.db.subscribe("memory_profile")

    def _create_profiler(self):
        pass

    # on signal received, check if pid is valid and stop currently profiled process. Then start new pid profiling.
    def _handle_signal(self):
        global proc_map_global
        global tracker_lock_holder_pid
        while True:
            # check redis channel
            # poll for signal
            timeout = 0.01
            msg: str = self.pid_channel.get_message(timeout=timeout)
            pid_to_profile: int = None
            while msg:
                # print(f"Msg {msg}")
                pid: int = None
                try:
                    pid = int(msg["data"])
                except ValueError:
                    msg = self.pid_channel.get_message(timeout=timeout)
                    continue
                if pid in proc_map_global.keys():
                    if proc_is_running(pid):
                        pid_to_profile = pid
                    else:
                        try:
                            proc_map_global.pop(pid)
                        except KeyError:
                            pass
                msg = self.pid_channel.get_message(timeout=timeout)

            if pid_to_profile:
                print(
                    colored(
                        f"Sending end signal {tracker_lock_holder_pid.value}",
                        "red",
                    )
                )
                if tracker_lock_holder_pid.value in proc_map_global.keys():
                    print(proc_map_global[tracker_lock_holder_pid.value])
                    proc_map_global[
                        tracker_lock_holder_pid.value
                    ].set_end_signal()
                print(colored(f"Sending start signal {pid_to_profile}", "red"))
                proc_map_global[pid_to_profile].set_start_signal()
                # send stop first, send start new process

            time.sleep(1)

    # set pid in redis channel for testing
    def _test_thread(self):
        global proc_map_global
        while True:
            if len(proc_map_global):
                pid = random.choice(list(proc_map_global.keys()))
                self.db.publish("memory_profile", pid)
                print(colored(f"Published {pid}", "red"))
                time.sleep(5)
                subprocess.Popen(["memray", "live", "1234"])
                break
            time.sleep(1)

    def start(self):
        multiprocessing.Process = MultiprocessPatchMeta(
            "Process", (multiprocessing.Process,), {}
        )
        self.signal_handler_thread = threading.Thread(
            target=self._handle_signal, daemon=True
        )
        self.signal_handler_thread.start()
        # Remove Later
        # self.test_thread = threading.Thread(target=self._test_thread, daemon=True)
        # self.test_thread.start()

    def stop(self):
        multiprocessing.Process = self.original_process_class

    def print(self):
        pass


class MultiprocessPatchMeta(ABCMeta):
    def __new__(cls, name, bases, dct):
        new_cls = super().__new__(cls, name, bases, dct)
        new_cls.tracker: memray.Tracker = None
        new_cls.signal_interval: int = (
            1  # sleep time in sec for checking start and end signals to process
        )
        new_cls.poll_interval: int = (
            1  # sleep time in sec for checking if signal has finished processing
        )
        new_cls.port = 1234
        return new_cls

    def __init__(cls, name, bases, dct):
        super().__init__(name, bases, dct)

        def __init__(self, *args, **kwargs):
            super(cls, self).__init__(*args, **kwargs)
            self.tracker_start = multiprocessing.Event()
            self.tracker_end = multiprocessing.Event()

        cls.__init__ = __init__

        # synchonous signal processing, block until event is processed. Then returns.
        def set_start_signal(self, block=False):
            print(f"set start signal {self.pid}")
            if self.tracker_start:
                self.tracker_start.set()
                while block and self.tracker_start.is_set():
                    time.sleep(self.poll_interval)

        cls.set_start_signal = set_start_signal

        # synchonous signal as well.
        def set_end_signal(self, block=False):
            print(f"set end signal {self.pid}")
            if self.tracker_end:
                self.tracker_end.set()
                while block and self.tracker_start.is_set():
                    time.sleep(self.poll_interval)

        cls.set_end_signal = set_end_signal

        # start profiling current process. Profiles current process context.
        def execute_tracker(self, destination):
            self.tracker = memray.Tracker(destination=destination)

        cls.execute_tracker = execute_tracker

        def start_tracker(self):
            global tracker_lock_global
            global tracker_lock_holder_pid
            print(colored(f"start_tracker lock {self.pid}", "red"))
            if not self.tracker and tracker_lock_global.acquire(
                blocking=False
            ):
                print(
                    colored(
                        f"start_tracker memray at PID {self.pid} started {self.port}",
                        "red",
                    )
                )
                tracker_lock_holder_pid.value = self.pid
                print(
                    colored(
                        f"start_tracker lock holder pid {tracker_lock_holder_pid.value}",
                        "red",
                    )
                )
                dest = memray.SocketDestination(
                    server_port=self.port, address="127.0.0.1"
                )
                self.tracker = memray.Tracker(destination=dest)
                self.tracker.__enter__()

        cls.start_tracker = start_tracker

        def end_tracker(self):
            global tracker_lock_global
            global tracker_lock_holder_pid
            print(
                f"end_tracker Lock Holder {tracker_lock_holder_pid.value}, {self.tracker}"
            )
            if self.tracker:
                print(
                    colored(
                        f"end_tracker memray at PID {self.pid} ended", "red"
                    )
                )
                self.tracker.__exit__(None, None, None)
                self.tracker = None
                tracker_lock_holder_pid.value = 0
                tracker_lock_global.release()

        cls.end_tracker = end_tracker

        # checks if the start signal is set. Runs in a different thread.
        def _check_start_signal(self):
            while True:
                while not self.tracker_start.is_set():
                    time.sleep(self.signal_interval)
                    continue
                self.start_tracker()
                self.tracker_start.clear()

        cls._check_start_signal = _check_start_signal

        # checks if the end signal is set. Runs in a different thread.
        def _check_end_signal(self):
            while True:
                while not self.tracker_end.is_set():
                    time.sleep(self.signal_interval)
                    continue
                self.end_tracker()
                self.tracker_end.clear()

        cls._check_end_signal = _check_end_signal

        # Sets up data before running. super() starts first to set initialize pid. Then adds itself to proc_map_global
        def start(self) -> None:
            super(cls, self).start()
            global proc_map_global
            global proc_map_lock_global
            proc_map_lock_global.acquire()
            proc_map_global[self.pid] = self
            proc_map_lock_global.release()

        cls.start = start

        # Removes itself from the proc_map_global. Intended to run when process stops.
        def _pop_map(self):
            global proc_map_global
            global proc_map_lock_global
            proc_map_lock_global.acquire()
            try:
                proc_map_global.pop(self.pid)
            except KeyError:
                print(
                    f"_pop_map {self.pid} no longer in memory profile map, continuing..."
                )
            proc_map_lock_global.release()

        cls._pop_map = _pop_map

        # release tracker_lock_global, which must be acquired while profiling.
        def _release_lock(self):
            global tracker_lock_global
            global tracker_lock_holder_pid
            if tracker_lock_holder_pid.value == self.pid:
                tracker_lock_global.release()

        cls._release_lock = _release_lock

        def _cleanup(self):
            self._pop_map()
            self._release_lock()

        cls._cleanup = _cleanup

        # Preserve the original run method
        original_run = cls.run

        # # Define a new run method that adds the print statements
        def patched_run(self, *args, **kwargs):
            print(f"Child process started - PID: {self.pid}")
            start_signal_thread = threading.Thread(
                target=self._check_start_signal, daemon=True
            )
            start_signal_thread.start()
            end_signal_thread = threading.Thread(
                target=self._check_end_signal, daemon=True
            )
            end_signal_thread.start()
            original_run(self, *args, **kwargs)
            self._cleanup()

        # Replace the original run method with the new one
        cls.run = patched_run


# All the following should have a shared state between all instances of MultiprocessPatch
# and be accessible from the separate processes.
# proc_map_global only needs to be accessible from the main process. This is because
# adding a processes pid as a key creates a pickle error.
# tracker_lock_global must be possessed by the process currently being profiled and released
# when profiling is completed so another process can be profiled.
mp_manager: SyncManager = None
tracker_lock_global: Lock = None  # process holds when running profiling
tracker_lock_holder_pid: SynchronizedBase = None  # process that holds the lock
proc_map_global: Dict[int, multiprocessing.Process] = (
    None  # port to process object mapping
)
proc_map_lock_global: Lock = None  # hold when modifying proc_map_global
