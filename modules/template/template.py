# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/local_connection_detector.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the class, the module name, description and author in the variables
# 5. The file name of the python file (local_connection_detector.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to be able to disable the module later


from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.iasync_module import IAsyncModule
import json


class Template(IAsyncModule):
    # Name: short name of the module. Do not use spaces
    name = "Template"
    description = "Template module"
    authors = ["Template Author"]

    async def init(self):
        # To which channels do you want to subscribe? When a message
        # arrives on the channel the module will receive a msg

        # You can find the full list of channels at
        # slips_files/core/database/redis_db/database.py

        # Set up channel handlers - this should be the first thing in init()
        self.channels = {
            "new_ip": self.new_ip_msg_handler,
        }
        await self.db.subscribe(self.pubsub, self.channels.keys())

    async def new_ip_msg_handler(self, msg):
        """
        Handler for new_ip channel messages
        """
        try:
            data = json.loads(msg["data"])
            # Process the new IP data here
            # Example: print the number of profiles in the database
            await self.process_new_ip(data)
        except Exception as e:
            self.print(f"Error processing new_ip message: {e}")

    async def process_new_ip(self, data):
        """
        Process new IP data
        """
        # Example processing - replace with actual logic
        pass

    async def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """
        utils.drop_root_privs_permanently()

    async def main(self):
        """Main loop function"""
        # The main loop is now handled by the base class through message dispatching
        # Individual message handlers are called automatically when messages arrive
        pass
