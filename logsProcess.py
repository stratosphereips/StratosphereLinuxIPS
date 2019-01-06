# This file takes care of creating the log files with information
# Every X amount of time it goes to the database and reports

import multiprocessing
import sys
from datetime import datetime
from datetime import timedelta
import os
import threading
import time
from slips.core.database import __database__
import configparser

def timing(f):
    """ Function to measure the time another function takes. It should be used as decorator: @timing"""
    def wrap(*args):
        time1 = time.time()
        ret = f(*args)
        time2 = time.time()
        print('function took {:.3f} ms'.format((time2-time1)*1000.0))
        return ret
    return wrap

# Logs output Process
class LogsProcess(multiprocessing.Process):
    """ A class to output data in logs files """
    def __init__(self, inputqueue, outputqueue, verbose, debug, config):
        multiprocessing.Process.__init__(self)
        self.verbose = verbose
        self.debug = debug
        self.config = config
        # From the config, read the timeout to read logs. Now defaults to 5 seconds
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        # Read the configuration
        self.read_configuration()

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
            self.report_time = int(self.config.get('parameters', 'log_report_time'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.report_time = 5

    def run(self):
        try:
            # Create our main output folder. The current datetime with microseconds
            # TODO. Do not create the folder if there is no data? (not sure how to)
            self.mainfoldername = datetime.now().strftime('%Y-%m-%d--%H:%M:%s')
            if not os.path.exists(self.mainfoldername):
                    os.makedirs(self.mainfoldername)
            # go into this folder
            os.chdir(self.mainfoldername)

            # Process the data with different strategies
            # Strategy 1: Every X amount of time
            # Create a timer to process the data every X seconds
            timer = TimerThread(self.report_time, self.process_global_data)
            timer.start()

            while True:
                if not self.inputqueue.empty():
                    line = self.inputqueue.get()
                    if 'stop' != line:
                        # we are not processing input from the queue yet
                        # without this line the complete output thread does not work!!
                        print(line)
                        pass
                    else:
                        # Here we should still print the lines coming in the input for a while after receiving a 'stop'. We don't know how to do it.
                        self.outputqueue.put('stop')
                        return True
                elif self.inputqueue.empty():
                    # Nothing to do here either now
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

    def createProfileFolder(self, profileid):
        """
        Receive a profile id, create a folder if its not there. Create the log files.
        """
        # Profileid is like 'profile:10.0.0.2'
        profilefolder = profileid.split('|')[1]
        if not os.path.exists(profilefolder):
            os.makedirs(profilefolder)
            # If we create the folder, add once there the profileid. We have to do this here if we want to do it once.
            self.addDataToFile(profilefolder + '/' + 'ProfileData.txt', 'Profileid : ' + profileid)
        return profilefolder

    def addDataToFile(self, filename, data, mode='w+'):
        """
        Receive data and append it in the general log of this profile
        If the filename was not opened yet, then open it, write the data and return the file object.
        Do not close the file
        """
        try:
            filename.write(data + '\n')
            return filename
        except (NameError, AttributeError) as e:
            # The file was not opened
            fileobj = open(filename, mode)
            fileobj.write(data + '\n')
            # For some reason the files are closed and flushed correclty.
            return fileobj
        except KeyboardInterrupt:
            return True

    def process_global_data(self):
        """ 
        This is the main function called by the timer process
        Read the global data and output it on logs 
        """
        try:
            #1. Get the list of profiles so far
            temp_profs = __database__.getProfiles()
            if not temp_profs:
                return True
            profiles = list(temp_profs)
            # How many profiles we have?
            profilesLen = str(__database__.getProfilesLen())
            # Debug
            self.outputqueue.put('1|logs|# of Profiles: ' + profilesLen)
            # For each profile, get the tw
            for profileid in profiles:
                profileid = profileid.decode('utf-8')
                # Create the folder for this profile if it doesn't exist
                profilefolder = self.createProfileFolder(profileid)
                twLen = str(__database__.getAmountTW(profileid))
                self.outputqueue.put('2|logs|Profile: ' + profileid + '. ' + twLen + ' timewindows')
                # For each TW in this profile
                TWforProfile = __database__.getTWsfromProfile(profileid)
                for (twid, twtime) in TWforProfile:
                    twid = twid.decode("utf-8")
                    twtime = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(twtime))
                    twlog = twtime + '.' + twid
                    # Add data into profile log
                    modified = __database__.wasProfileTWModified(profileid, twid)
                    self.outputqueue.put('2|logs|Profile: {}. TW {}. Modified {}'.format(profileid, twid, modified))
                    if modified: 
                        self.outputqueue.put('2|logs|Profile: {}. TW {}. Was Modified. So process it'.format(profileid, twid))
                        twdata = __database__.getDstIPsfromProfileTW(profileid, twid)
                        # Mark it as not modified anymore
                        __database__.markProfileTWAsNotModified(profileid, twid)
                        for ip in twdata:
                            self.addDataToFile(profilefolder + '/' + twlog, 'DstIP: '+ ip.decode("utf-8"), mode='a+')
                            self.outputqueue.put('2|logs|\tDstIP: ' + ip.decode("utf-8"))
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
        try:
            while 1:
                if self._finished.isSet(): return
                self.task()
                
                # sleep for interval or until shutdown
                self._finished.wait(self._interval)
        except KeyboardInterrupt:
            return True
    
    def task(self):
        self.function()
