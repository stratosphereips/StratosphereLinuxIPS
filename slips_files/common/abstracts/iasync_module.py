# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
from asyncio import Task
from typing import (
    Callable,
    List,
)
from slips_files.common.abstracts.imodule import IModule


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
        task.add_done_callback(self.handle_task_exception)

        # Allow the event loop to run the scheduled task
        # await asyncio.sleep(0)

        # to wait for these functions before this module shuts down
        self.tasks.append(task)
        return task

    def handle_task_exception(self, task: asyncio.Task):
        try:
            exception = task.exception()
        except asyncio.CancelledError:
            return  # Task was cancelled, not an error
        if exception:
            self.print(f"Unhandled exception in task: {exception}")
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
        loop.set_exception_handler(self.handle_loop_exception)
        return loop.run_until_complete(func())

    def handle_loop_exception(self, loop, context):
        """A common loop exception handler"""
        exception = context.get("exception")
        future = context.get("future")

        if future:
            try:
                future.result()
            except Exception:
                self.print_traceback()
        elif exception:
            self.print(f"Unhandled loop exception: {exception}")
        else:
            self.print(f"Unhandled loop error: {context.get('message')}")

    def run(self):
        asyncio.run(self._run_pre_main_and_main())

    async def _run_pre_main_and_main(self):
        """
        runs pre_main() once, then runs main() in a loop
        """
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(self.handle_loop_exception)

        try:
            error: bool = self.pre_main()
            if error or self.should_stop():
                await self.gather_tasks_and_shutdown_gracefully()
                return
        except (KeyboardInterrupt, asyncio.CancelledError):
            await self.gather_tasks_and_shutdown_gracefully()
            return
        except RuntimeError as e:
            if "Event loop stopped before Future completed" in str(e):
                await self.gather_tasks_and_shutdown_gracefully()
                return
        except Exception:
            self.print_traceback()
            return

        while True:
            try:
                if self.should_stop():
                    await self.gather_tasks_and_shutdown_gracefully()
                    return

                # if a module's main() returns 1, it means there's an
                # error and it needs to stop immediately
                error: bool | None = await self.main()
                if error:
                    await self.gather_tasks_and_shutdown_gracefully()
                    return

            except (KeyboardInterrupt, asyncio.CancelledError):
                self.keyboard_int_ctr += 1
                if self.keyboard_int_ctr >= 2:
                    # on the second ctrl+c Slips immediately stops
                    return True
                # on the first ctrl + C keep looping until the should_stop()
                # returns true
                continue
            except RuntimeError as e:
                if "Event loop stopped before Future completed" in str(e):
                    await self.gather_tasks_and_shutdown_gracefully()
                    return
            except Exception:
                self.print_traceback()
                return
