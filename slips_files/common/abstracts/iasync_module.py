# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import sys
import traceback
import warnings
import asyncio
import os
import threading
from asyncio import Task
from typing import (
    Dict,
    Callable,
    List,
)
from abc import ABC, abstractmethod
from argparse import Namespace
from multiprocessing import Process, Event

from slips_files.common.printer import Printer
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output

warnings.filterwarnings("ignore", category=RuntimeWarning)


class IAsyncModule(ABC, Process):
    """
    An async interface for all slips modules
    """

    name = "AsyncModule"
    description = "Template module"
    authors = ["Template Author"]
    # should be filled with the channels each module subscribes to and
    # their handlers
    channels = {}

    def __init__(
        self,
        logger: Output = None,
        output_dir=None,
        redis_port=None,
        termination_event=None,
        slips_args=None,
        conf=None,
        ppid: int = None,
        **kwargs,
    ):
        Process.__init__(self)
        self.redis_port = redis_port
        self.output_dir = output_dir
        self.msg_received = False
        # as parsed by arg_parser, these are the cli args
        self.args: Namespace = slips_args
        # to be able to access the configuration file
        self.conf = conf
        # the parent pid of this module, used for strating the db
        self.ppid = ppid
        # used to tell all slips.py children to stop
        self.termination_event: Event = termination_event
        self.logger = logger
        self.printer = Printer(self.logger, self.name)
        self.keyboard_int_ctr = 0
        self.did_main_run = False
        # list of async functions to await before flowalerts shuts down
        self.tasks: List[Task] = []
        self.init_kwargs = kwargs

    @classmethod
    async def create(cls, **kwargs):
        """
        Factory mehtod that creates an instance of the module and
        initializes it.
        calls the __init__ of thihs class, then the init() of the module.
        """
        # run the __init_ method of this class
        self = cls(**kwargs)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            await self.init_db()
            await self.init(**self.init_kwargs)
            self.channel_tracker = self.init_channel_tracker()
            return self

        except KeyboardInterrupt:
            await self.gather_tasks_and_shutdown_gracefully()
            return None

        except RuntimeError as e:
            if "Event loop stopped before Future completed" in str(e):
                await self.gather_tasks_and_shutdown_gracefully()
                return None

        except Exception:
            self.print_traceback()
            return None

    async def init_db(self):
        self.db = await DBManager.create(
            logger=self.logger,
            output_dir=self.args.output,
            redis_port=self.redis_port,
            conf=self.conf,
            slips_args=self.args,
            main_pid=int(os.getpid()),
            # these should only be true if it's the first time ever
            # creating a db instance in the main.py
            flush_db=False,
            start_redis_server=False,
        )
        self.pubsub = self.db.pubsub()

    @abstractmethod
    async def init(self, **kwargs):
        """
        handles the initialization of modules
        the goal of this is to have one common __init__() for all
        modules, which is the one in this file, and a different init() per
        module
        this init will have access to all keyword args passes when
        initializing the module
        """
        ...

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def init_channel_tracker(self) -> Dict[str, Dict[str, bool]]:
        """
        tracks if in the last loop, a msg was received in any of the
        subscribed channels or not
        the goal of this is to keep looping if only 1 channel did receive
        a msg, bc it's possible that that 1 channel will receive another msg
        return a dict with the channel name and the values are either 0 or 1
        False: received a msg in the last loop for this channel
        True: didn't receive a msg
        The goal of this whole thing is to terminate the module only if no
        channels receive msgs in the last iteration, but keep looping
        otherwise.
        """
        tracker = {}
        for channel_name in self.channels:
            tracker[channel_name] = {"msg_received": False}
        return tracker

    def is_msg_received_in_any_channel(self) -> bool:
        """
        return True if a msg was received in any channel of the ones
        this module is subscribed to
        """
        return any(
            info["msg_received"] for info in self.channel_tracker.values()
        )

    def print_traceback(self):
        exception_line = sys.exc_info()[2].tb_lineno
        self.print(f"Problem in line {exception_line}", 0, 1)
        self.print(traceback.format_exc(), 0, 1)

    def create_task(self, func, *args) -> Task:
        """
        wrapper for asyncio.create_task
        The goal here is to add a callback to tasks to be able to handle
        exceptions. because asyncio Tasks do not raise exceptions
        """
        task = asyncio.create_task(func(*args))
        task.add_done_callback(self.handle_exception)

        # Allow the event loop to run the scheduled task
        # await asyncio.sleep(0)

        # to wait for these functions before this module shuts down
        self.tasks.append(task)
        return task

    def handle_exception(self, task):
        """
        in asyncmodules we use Async.Task to run some of the functions
        If an exception occurs in a coroutine that was wrapped in a Task
        (e.g., asyncio.create_task), the exception does not crash the program
         but remains in the task.
        This function is used to handle the exception in the task
        """
        try:
            # Access task result to raise the exception if it occurred
            task.result()
        except (KeyboardInterrupt, asyncio.exceptions.CancelledError):
            pass
        except Exception:
            self.print_traceback()

    async def gather_tasks_and_shutdown_gracefully(self):
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.shutdown_gracefully()

    def run_async_function(self, func: Callable, *args, **kwargs):
        """
        If the func argument is a coroutine object it is implicitly
        scheduled to run as a asyncio.Task.
        Returns the Future’s result or raise its exception.
        """
        if not asyncio.iscoroutinefunction(func):
            func(*args, **kwargs)
            return

        loop = asyncio.get_event_loop()
        loop.set_exception_handler(self.handle_exception)
        return loop.run_until_complete(func(*args, **kwargs))

    async def get_msg(self) -> None | tuple:
        """
        gets a msg from the pubsub and yields it
        returns None if no message is received
        Returns the channel and the message if a message is received
        """
        try:
            msg = await self.db.get_message(self.pubsub)
            if msg:
                channel = msg["channel"].decode()
                # data = msg["data"]
                self.channel_tracker[channel]["msg_received"] = True
                await self.db.incr_msgs_received_in_channel(self.name, channel)
                yield channel, msg
            else:
                for channel in self.channel_tracker:
                    self.channel_tracker[channel]["msg_received"] = False
                yield None

            # This is a yield point to the event loop.
            # Forces the coroutine to yield control and give the event loop a
            # chance to run other tasks.
            # Prevents your loop from hogging the CPU when no message is received.
            await asyncio.sleep(0)

        except KeyboardInterrupt:
            return

    async def call_msg_handler(self, channel: str, data: dict):
        handler = self.channel_tracker[channel]
        if asyncio.iscoroutinefunction(handler):
            await handler(data)
        else:
            handler(data)

    def dispatch_msgs(self):
        """
        fetches each msg from the pubsub and calls the msg handler
        """
        if not self.channel_tracker:
            return

        if msg := self.run_async_function(self.get_msg):
            channel, data = msg
            self.run_async_function(self.call_msg_handler, channel, data)

    def create_thread(self, func: Callable, *args, **kwargs):
        """
        to ensure all created threads by all modules have their own
        event loop
        """

        def wrapper(*args, **kwargs):
            asyncio.run(func(*args, **kwargs))

        t = threading.Thread(
            target=wrapper, args=args, kwargs=kwargs, name=func.__name__
        )
        t.daemon = True
        return t

    def should_stop(self) -> bool:
        """
        The module should stop on the following 2 conditions
        1. no new msgs are received in any of the channels the
            module is subscribed to
        2. the termination event is set by the process_manager.py
        """
        if (
            self.is_msg_received_in_any_channel()
            or not self.termination_event.is_set()
        ):
            # this module is still receiving msgs,
            # don't stop
            return False
        return True

    async def shutdown_gracefully(self):
        """
        Tells slips.py that this module is
        done processing and does necessary cleanup
        """
        pass

    async def pre_main(self) -> bool:
        """
        This function is for initializations that are
        executed once before the main loop
        """

    @abstractmethod
    async def main(self):
        """
        Main function of every module, all the logic implemented
        here will be executed in a loop
        """

    def run(self):
        try:
            error: bool = self.run_async_function(self.pre_main)
            if error or self.should_stop():
                self.run_async_function(
                    self.gather_tasks_and_shutdown_gracefully
                )
                return None

        except KeyboardInterrupt:
            self.run_async_function(self.gather_tasks_and_shutdown_gracefully)
            return None
        except RuntimeError as e:
            if "Event loop stopped before Future completed" in str(e):
                self.run_async_function(
                    self.gather_tasks_and_shutdown_gracefully
                )
                return None
        except Exception:
            self.print_traceback()
            return None

        while True:
            try:
                if self.should_stop():
                    self.run_async_function(
                        self.gather_tasks_and_shutdown_gracefully
                    )
                    return

                self.dispatch_msgs()

                # if a module's main() returns 1, it means there's an
                # error and it needs to stop immediately
                error: bool = self.run_async_function(self.main)
                if error:
                    self.run_async_function(
                        self.gather_tasks_and_shutdown_gracefully
                    )
                    return

            except KeyboardInterrupt:
                self.keyboard_int_ctr += 1
                if self.keyboard_int_ctr >= 2:
                    # on the second ctrl+c Slips immediately stops
                    return True
                # on the first ctrl + C keep looping until the should_stop()
                # returns true
                continue
            except RuntimeError as e:
                if "Event loop stopped before Future completed" in str(e):
                    self.run_async_function(
                        self.gather_tasks_and_shutdown_gracefully
                    )
                    return
            except Exception:
                self.print_traceback()
                return

    def __del__(self):
        # each module has its own sqlite db connection. once this module is
        # done the connection should be closed
        self.db.close_sqlite()
