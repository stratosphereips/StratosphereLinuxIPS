# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
from asyncio import Task
from typing import (
    Callable,
    List,
)
from slips_files.common.abstracts.module import IModule


class AsyncModule(IModule):
    """
    An abstract class for asynchronous slips modules
    """

    name = "AsyncModule"

    def __init__(self, *args, **kwargs):
        IModule.__init__(self, *args, **kwargs)
        # list of async functions to await before flowalerts shuts down
        self.tasks: List[Task] = []

    def init(self, **kwargs): ...

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

    async def main(self): ...

    async def shutdown_gracefully(self):
        """
        Implement the async shutdown logic here
        """
        pass

    async def gather_tasks_and_shutdown_gracefully(self):
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.shutdown_gracefully()

    def run_async_function(self, func: Callable):
        """
        If the func argument is a coroutine object it is implicitly
        scheduled to run as a asyncio.Task.
        Returns the Future’s result or raise its exception.
        """
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(self.handle_exception)
        return loop.run_until_complete(func())

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            error: bool = self.pre_main()
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
