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
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils

import cProfile, pstats, io
from pstats import SortKey

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'CPU Profiler'
    description = 'Provides data about CPU usage during program run time'
    authors = ['Daniel Yang']

    def __init__(self, outputqueue, redis_port, mode='dev', verbose=False):
        valid_mode = ['dev', 'live']
        if mode not in valid_mode:
            raise ValueError("cpu profiler must be run with mode in " + str(valid_mode))
        multiprocessing.Process.__init__(self)
        super().__init__(outputqueue)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        # class variables
        self.profiler = cProfile.Profile(builtins=verbose)
        self.profiler.enable()
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        # Remember to subscribe to this channel in database.py
        # self.c1 = __database__.subscribe('new_ip')
        # self.channels = {
        #     'new_ip': self.c1,
        # }


    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)
        self.profiler.disable()
        stats = pstats.Stats(self.profiler).sort_stats('cumtime')
        stats.print_stats()

    def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """

    def main(self):
        """Main loop function"""
        pass

