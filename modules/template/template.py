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
from slips_files.common.abstracts.module import IModule
import json


class Template(IModule):
    # Name: short name of the module. Do not use spaces
    name = "Template"
    description = "Template module"
    authors = ["Template Author"]

    def init(self):
        # To which channels do you want to subscribe? When a message
        # arrives on the channel the module will receive a msg

        # You can find the full list of channels at
        # slips_files/core/database/redis_db/database.py
        self.c1 = self.db.subscribe("new_ip")
        self.channels = {
            "new_ip": self.c1,
        }

    def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """
        utils.drop_root_privs()

    def main(self):
        """Main loop function"""
        if msg := self.get_msg("new_ip"):
            # Example of printing the number of profiles in the
            # Database every second
            msg = json.loads(msg["data"])
            ...
