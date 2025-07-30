import asyncio
import json

from slips_files.core.database.database_manager import DBManager


class FileMonitorHelper:
    """
    filemonitor.py monitors changes, this helper acts upon those changes
    whyy? because filemonitor.py is not async, so we can't use the db
    directly there
    """

    def __init__(
        self,
        event_q: asyncio.Queue,
        db: DBManager,
        termination_event: asyncio.Event,
    ):
        self.event_q = event_q
        self.db = db
        self.termination_event = termination_event

    async def event_handler(self):
        """
        Waits for events from filemonitor.py and acts upon them,
        it is an infinite loop that will run until
        the termination_event is set by input.py.
        """
        while not self.termination_event.is_set():
            # waits until an event is available
            event = await self.event_q.get()
            event = json.loads(event)

            action = event["action"]
            params = event.get("params")

            if action == "add_zeek_file":
                await self.db.add_zeek_file(params["filename"])

            elif action == "remove_old_files":
                # serialized dict
                to_remove: str = params["to_remove"]
                await self.db.publish("remove_old_files", to_remove)

            elif action == "publish_stop":
                await self.db.publish_stop()
                return

            elif action == "reload_whitelist":
                await self.db.publish("reload_whitelist", "reload")
