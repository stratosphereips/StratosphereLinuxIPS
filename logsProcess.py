import multiprocessing
import sys
from datetime import datetime
from datetime import timedelta
import os
import threading
import time


# Logs output Process
class LogsProcess(multiprocessing.Process):
    """ A class to output data in logs files """
    def __init__(self, inputqueue, verbose, debug, config):
        multiprocessing.Process.__init__(self)
        self.queue = inputqueue
        self.verbose = verbose
        self.debug = debug
        self.config = config
        # From the config, read the timeout to read logs. Now defaults to 5 seconds
        self.read_timeout = 5

    def run(self):
        try:
            # Before going into a loop
            # Create our main output folder. The current datetime with microseconds
            self.mainfoldername = datetime.now().strftime('%Y-%m-%d--%H:%M:%s')
            if not os.path.exists(self.mainfoldername):
                    os.makedirs(self.mainfoldername)
            # go into this folder
            os.chdir(self.mainfoldername)

            # Process the data with different strategies
            # Strategy 1: Every X amount of time
            # Create a timer to process the data every X seconds
            timer = TimerThread(self.read_timeout, self.process_global_data)
            timer.start()

            while True:
                if not self.queue.empty():
                    line = self.queue.get()
                    if 'stop' != line:
                        # we are not processing input from the queue yet
                        pass
                    else:
                        # Here we should still print the lines coming in the input for a while after receiving a 'stop'. We don't know how to do it.
                        self.queue.put('stop')
                        return True
                elif self.queue.empty():
                    pass
            # Stop the timer
            timer.shutdown()

        except KeyboardInterrupt:
            # Stop the timer
            timer.shutdown()
            return True
        except Exception as inst:
            # Stop the timer
            timer.shutdown()
            print('\tProblem with LogsProcess()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)

    def process_global_data(self):
        """ Read the global data and output it on logs """
        try:
            print('doing...')

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            print('\tProblem with process_gloabl_data in LogsProcess()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)




class TimerThread(threading.Thread):
    """Thread that executes a task every N seconds. Only to run the process_global_data."""
    
    def __init__(self, interval, function):
        threading.Thread.__init__(self)
        self._finished = threading.Event()
        self._interval = interval
        self.function = function 

    def shutdown(self):
        """Stop this thread"""
        self._finished.set()
    
    def run(self):
        while 1:
            if self._finished.isSet(): return
            self.task()
            
            # sleep for interval or until shutdown
            self._finished.wait(self._interval)
    
    def task(self):
        self.function()
