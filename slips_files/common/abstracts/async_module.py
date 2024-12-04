import asyncio
from typing import Callable
from slips_files.common.abstracts.module import IModule


class AsyncModule(IModule):
    """
    An abstract class for asynchronous slips modules
    """

    name = "AsyncModule"

    def __init__(self, *args, **kwargs):
        IModule.__init__(self, *args, **kwargs)

    def init(self, **kwargs): ...

    async def main(self): ...

    async def shutdown_gracefully(self):
        """Implement the async shutdown logic here"""
        pass

    async def run_main(self):
        return await self.main()

    @staticmethod
    def run_async_function(func: Callable):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(func())

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            error: bool = self.pre_main()
            if error or self.should_stop():
                self.run_async_function(self.shutdown_gracefully)
                return
        except KeyboardInterrupt:
            self.run_async_function(self.shutdown_gracefully)
            return
        except Exception:
            self.print_traceback()
            return

        while True:
            try:
                if self.should_stop():
                    self.run_async_function(self.shutdown_gracefully)
                    return

                # if a module's main() returns 1, it means there's an
                # error and it needs to stop immediately
                error: bool = self.run_async_function(self.run_main)
                if error:
                    self.run_async_function(self.shutdown_gracefully)
                    return

            except KeyboardInterrupt:
                self.keyboard_int_ctr += 1
                if self.keyboard_int_ctr >= 2:
                    # on the second ctrl+c Slips immediately stop
                    return True
                # on the first ctrl + C keep looping until the should_stop()
                # returns true
                continue
            except Exception:
                self.print_traceback()
                return
