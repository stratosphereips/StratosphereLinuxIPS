import asyncio


class StartupUpdates:
    """
    just a class to group the updates the happens when slips starts up.
    used by the process_manager.py when starting the update manager
    every method here should have its own event loop because it gets called before
     the update manager "officially starts" and sets its own event loop and inits its own db
    """

    async def setup_loop_and_db(self):
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(self.handle_loop_exception)
        await self.setup()

    async def update_local_files_before_module_starts(self):
        await self.setup_loop_and_db()
        self.create_task(self.update_ports_info)
        self.create_task(self.update_org_files)
        self.create_task(self.update_local_whitelist)
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def update_ti_feeds_before_module_starts(self):
        await self.setup_loop_and_db()
        self.print("Updating TI feeds")
        await self.update_ti_files()
