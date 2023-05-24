# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables
# 5. The file name of the python module (template.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to ignore the module
# 7. The name of the class MUST be 'Module', do not change it.

# Must imports
from slips_files.common.imports import *


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'Template'
    description = 'Template module'
    authors = ['Template Author']

    def __init__(self, outputqueue, rdb, sqlite):
        multiprocessing.Process.__init__(self)
        super().__init__(outputqueue, rdb, sqlite)
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        # Remember to subscribe to this channel in database.py
        self.c1 = self.rdb.subscribe('new_ip')
        self.channels = {
            'new_ip': self.c1,
        }


    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        self.rdb.publish('finished_modules', self.name)

    def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """
        utils.drop_root_privs()

    def main(self):
        """Main loop function"""
        if msg:= self.get_msg('new_ip'):
            # Example of printing the number of profiles in the
            # Database every second
            data = len(self.rdb.getProfiles())
            self.print(f'Amount of profiles: {data}', 3, 0)

