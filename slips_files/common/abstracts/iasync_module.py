# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
from asyncio import Task
from typing import (
    Callable,
    List,
)
from slips_files.common.abstracts.imodule import IModule


class IAsyncModule(IModule):
    """
    An abstract class for asynchronous slips modules
    """

    name = "AsyncModule"
    # by default, all slips modules' main() methods run in a loop
    # unless this is set to False in the module's init()
    should_run_in_a_loop = True

    def __init__(self, *args, **kwargs):
        IModule.__init__(self, *args, **kwargs)
        self.did_main_run = False
        # list of async functions to await before flowalerts shuts down
        self.tasks: List[Task] = []

    async def init(self, **kwargs):
        # PS don't call the self.db from any of the modukes' init()
        # methods, init can't be async, and most db calls are async,
        # so instead, put your async logic in the pre_main() method
        ...

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

    async def pre_main(self): ...

    async def main(self): ...

    async def shutdown_gracefully(self):
        """
        Implement the async shutdown logic here
        """
        pass

    async def gather_tasks_and_shutdown_gracefully(self):
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.shutdown_gracefully()

    def run_async_function(self, func: Callable, *args):
        """
        If the func argument is a coroutine object it is implicitly
        scheduled to run as a asyncio.Task.
        Returns the Future’s result or raise its exception.
        """
        if not asyncio.iscoroutinefunction(func):
            func(*args)
            return

        loop = asyncio.get_event_loop()
        loop.set_exception_handler(self.handle_exception)
        return loop.run_until_complete(func(*args))

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

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            self.run_async_function(self.init)
            # should be after the module's init() so the module has a chance to
            # set its own channels
            self.channel_tracker = self.init_channel_tracker()

            error: bool = self.run_async_function(self.pre_main)
            if error or self.should_stop():
                self.run_async_function(
                    self.gather_tasks_and_shutdown_gracefully
                )
                return

        except KeyboardInterrupt:
            self.run_async_function(self.gather_tasks_and_shutdown_gracefully)
            return
        except RuntimeError as e:
            if "Event loop stopped before Future completed" in str(e):
                self.run_async_function(
                    self.gather_tasks_and_shutdown_gracefully
                )
                return
        except Exception:
            self.print_traceback()
            return

        while True:
            try:
                if self.should_stop():
                    self.run_async_function(
                        self.gather_tasks_and_shutdown_gracefully
                    )
                    return

                self.dispatch_msgs()

                if not self.should_run_in_a_loop and self.did_main_run:
                    continue

                # if a module's main() returns 1, it means there's an
                # error and it needs to stop immediately
                error: bool = self.run_async_function(self.main)
                if error:
                    self.run_async_function(
                        self.gather_tasks_and_shutdown_gracefully
                    )
                    return
                self.did_main_run = True

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
