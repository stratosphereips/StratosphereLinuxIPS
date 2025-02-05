# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
from asyncio import Task
from typing import (
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

        # to wait for these functions before flowalerts shuts down
        self.tasks.append(task)
        return task

    def handle_exception(self, task):
        """
        in asyncmodules we use Async.Task to run some of the functions
        If an exception occurs in a coroutine that was wrapped in a Task
        (e.g., asyncio.create_task), the exception does not crash the program
         but remains in the task.
        This function is used to handle the exception in the task aka to
        not suppress exceptions
        """
        try:
            # Access task result to raise the exception if it occurred
            task.result()
        except (KeyboardInterrupt, asyncio.exceptions.CancelledError):
            pass
        except Exception as e:
            self.print(e, 0, 1)

    async def main(self): ...

    async def shutdown_gracefully(self):
        """Implement the async shutdown logic here"""
        # why do we need this function to be async? because async modules
        # create Tasks and await them in the shutdown_gracefully function
        pass

    def _run_blocking_async(self, coro_func):
        # you may wonder why are all functions here run in a blocking way
        # yet they are async, it's because inside of them, we create tasks
        # that run asyncronously. but not the function itself that should
        # run asyncronously
        loop = asyncio.get_event_loop()
        if not asyncio.iscoroutinefunction(coro_func):
            raise TypeError(
                f"Function {coro_func} must be a coroutine function"
            )
        # Blocks until func() completes
        return loop.run_until_complete(coro_func())

    def run(self):
        # create and manage the event loop manually because we're inside a
        # non-async function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(self.handle_exception)

        try:
            error: bool = self.pre_main()
            if error or self.should_stop():
                self._run_blocking_async(self.shutdown_gracefully)
                return
        except KeyboardInterrupt:
            self._run_blocking_async(self.shutdown_gracefully)
            return
        except RuntimeError as e:
            if "Event loop stopped before Future completed" in str(e):
                self._run_blocking_async(self.shutdown_gracefully)
                return
        except Exception:
            self.print_traceback()
            return

        while True:
            try:
                if self.should_stop():
                    self._run_blocking_async(self.shutdown_gracefully)
                    return

                # if a module's main() returns 1, it means there's an
                # error and it needs to stop immediately
                error: bool = self._run_blocking_async(self.main)
                if error:
                    self._run_blocking_async(self.shutdown_gracefully)
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
                    self._run_blocking_async(self.shutdown_gracefully)
                    return
            except Exception:
                self.print_traceback()
                return
