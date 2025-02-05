# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import memray
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
from abc import ABC, ABCMeta


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
        self.pid_channel = self.db

    def _create_profiler(self):
        pass

    def _handle_signal(self):
        global proc_map_global
        global tracker_lock_holder_pid
        while True:
            # check redis channel
            # poll for signal
            # timeout = 0.01
            # msg: str = None
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


class MultiprocessPatch(multiprocessing.Process):
    tracker: memray.Tracker = None
    tracker_start: Event = None
    tracker_end: Event = None
    signal_interval: int = (
        1  # sleep time for checking start and end signals to process
    )
    poll_interval: int = (
        1  # sleep time for checking if signal has finished processing
    )
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

    def end_tracker(self):
        global tracker_lock_global
        global tracker_lock_holder_pid
        print(
            f"end_tracker Lock Holder {tracker_lock_holder_pid.value}, {self.tracker}"
        )
        if self.tracker:
            print(
                colored(f"end_tracker memray at PID {self.pid} ended", "red")
            )
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
            print(
                f"_pop_map {self.pid} no longer in memory profile map, continuing..."
            )
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
        start_signal_thread = threading.Thread(
            target=self._check_start_signal, daemon=True
        )
        start_signal_thread.start()
        end_signal_thread = threading.Thread(
            target=self._check_end_signal, daemon=True
        )
        end_signal_thread.start()
        super().run()
        self._cleanup()


mp_manager: SyncManager = multiprocessing.Manager()
tracker_lock_global: Lock = (
    mp_manager.Lock()
)  # process holds when running profiling
tracker_lock_holder_pid: SynchronizedBase = multiprocessing.Value(
    "i", 0
)  # process that holds the lock
proc_map_global: Dict[int, MultiprocessPatch] = (
    {}
)  # port to process object mapping
proc_map_lock_global: Lock = (
    mp_manager.Lock()
)  # hold when modifying proc_map_global


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


class MultiprocessPatchMeta(ABCMeta):
    def __new__(cls, name, bases, dct):
        new_cls = super().__new__(cls, name, bases, dct)
        new_cls.tracker: memray.Tracker = None
        new_cls.tracker_start: Event = None
        new_cls.signal_interval: int = 1
        new_cls.poll_interval: int = 1
        new_cls.port = 1234
        return new_cls

    def __init__(cls, name, bases, dct):
        super().__init__(name, bases, dct)

        def __init__(self, *args, **kwargs):
            super(cls, self).__init__(*args, **kwargs)
            self.tracker_start = multiprocessing.Event()
            self.tracker_end = multiprocessing.Event()

        cls.__init__ = __init__

        def set_start_signal(self, block=False):
            print(f"set start signal {self.pid}")
            if self.tracker_start:
                self.tracker_start.set()
                while block and self.tracker_start.is_set():
                    time.sleep(self.poll_interval)

        cls.set_start_signal = set_start_signal

        def set_end_signal(self, block=False):
            print(f"set end signal {self.pid}")
            if self.tracker_end:
                self.tracker_end.set()
                while block and self.tracker_start.is_set():
                    time.sleep(self.poll_interval)

        cls.set_end_signal = set_end_signal

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

        def _check_start_signal(self):
            while True:
                while not self.tracker_start.is_set():
                    time.sleep(self.signal_interval)
                    continue
                self.start_tracker()
                self.tracker_start.clear()

        cls._check_start_signal = _check_start_signal

        def _check_end_signal(self):
            while True:
                while not self.tracker_end.is_set():
                    time.sleep(self.signal_interval)
                    continue
                self.end_tracker()
                self.tracker_end.clear()

        cls._check_end_signal = _check_end_signal

        def start(self) -> None:
            super(cls, self).start()
            global proc_map_global
            global proc_map_lock_global
            proc_map_lock_global.acquire()
            proc_map_global[self.pid] = self
            proc_map_lock_global.release()

        cls.start = start

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


# Apply the metaclass to multiprocessing.Process
multiprocessing.Process = MultiprocessPatchMeta(
    "Process", (multiprocessing.Process,), {}
)


class Module(ABC):
    def __init__(self):
        multiprocessing.Process.__init__(self)

    def main(self):
        print("Module main")

    def run(self):
        print("Module run")
        self.main()


class A(Module, multiprocessing.Process):
    def main(self):
        print("Target function started")
        time.sleep(5)


class B(Module, multiprocessing.Process):
    def main(self):
        print("Mem function started")
        while True:
            time.sleep(1)
            array = []
            for i in range(1000000):
                array.append(i)


if __name__ == "__main__":
    # Notes
    # set signal start and end are non-blocking, only sends the signal but doesn't guarantee success
    # start_tracker will block until lock is acquired and memray is connected, can change later
    # end_tracker works even if memray client quits

    db = multiprocessing.Queue()
    # profiler = LiveMultiprocessProfiler(db=db)
    # profiler.start()

    p = A()
    p.start()
    pp = B()
    pp.start()
    p.join()
    pp.join()
    exit()
    processes: List[MultiprocessPatch] = []
    num_processes = 3

    for _ in range(num_processes):
        process = multiprocessing.Process(
            target=target_function if _ % 2 else mem_function
        )
        process.start()
        processes.append(process)

    # Message passing
    db.put(processes[1].pid)  # successful
    time.sleep(5)  # target_function will timeout and tracker will be cleared
    db.put(processes[0].pid)  # end but maybe don't start
    time.sleep(5)  # mem_function will get tracker started
    db.put(processes[0].pid)  # start successfully

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
