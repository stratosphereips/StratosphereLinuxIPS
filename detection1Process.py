# This file takes care of creating the log files with information
# Every X amount of time it goes to the database and reports

import multiprocessing
import sys
from datetime import datetime
from datetime import timedelta
import os
import threading
from slips.core.database import __database__
import configparser
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import pandas as pd



class Detection1Process(multiprocessing.Process):
    """ """
    def __init__(self, inputqueue, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.config = config
        # From the config, read the timeout to read logs. Now defaults to 5 seconds
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        # Read the configuration
        self.read_configuration()
        self.fieldseparator = __database__.getFieldSeparator()
        # For some weird reason the database loses its outputqueue and we have to re set it here.......
        __database__.setOutputQueue(self.outputqueue)
        f = open('scale.bin', 'rb')
        self.scaler = pickle.load(f)
        f.close()
        f = open('model.bin', 'rb')
        self.clf = pickle.load(f)
        f.close()

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
            self.report_time = int(self.config.get('parameters', 'log_report_time'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.report_time = 5
        self.outputqueue.put('01|logs|Logs Process configured to report every: {} seconds'.format(self.report_time))

    def run(self):
        try:
            # Create a timer to process the data every X seconds
            timer = TimerThread(self.report_time, self.process_flow)
            timer.start()

            while True:
                line = self.inputqueue.get()
                if 'stop' != line:
                    # we are not processing input from the queue yet
                    # without this line the complete output thread does not work!!
                    # WTF???????
                    print(line)
                    pass
                else:
                    # Here we should still print the lines coming in the input for a while after receiving a 'stop'. We don't know how to do it.
                    self.outputqueue.put('stop')
                    return True
            # Stop the timer
            timer.shutdown()

        except KeyboardInterrupt:
            # Stop the timer
            timer.shutdown()
            return True
        except Exception as inst:
            # Stop the timer
            timer.shutdown()
            self.outputqueue.put('01|logs|\t[Logs] Error with LogsProcess')
            self.outputqueue.put('01|logs|\t[Logs] {}'.format(type(inst)))
            self.outputqueue.put('01|logs|\t[Logs] {}'.format(inst))
            sys.exit(1)

    def make_categorical(self, dataset, cat):
        '''
        Convert one column to a categorical type
        '''
        # Converts the column to cotegorical
        dataset[cat] = pd.Categorical(dataset[cat])
        # Convert the categories to int. Use this with caution!! we don't want an algorithm
        # to learn that an Orange=1 is less than a pearl=2
        dataset[cat] = dataset[cat].cat.codes
        return dataset

    def process_features(self, dataset):
        '''
        Discards some features of the dataset and can create new.
        '''
        try:
          dataset = dataset.drop('StartTime', axis=1)
        except ValueError:
          pass
        dataset.reset_index()
        try:
          dataset = dataset.drop('SrcAddr', axis=1)
        except ValueError:
          pass
        try:
          dataset = dataset.drop('DstAddr', axis=1)
        except ValueError:
          pass
        try:
          dataset = dataset.drop('sTos', axis=1)
        except ValueError:
          pass
        try:
          dataset = dataset.drop('dTos', axis=1)
        except ValueError:
          pass
        try:
          dataset = dataset.drop('Label', axis=1)
        except ValueError:
          pass
        # Create categorical features
        try:
          dataset = self.make_categorical(dataset, 'Dir')
        except ValueError:
          pass
        try:
          dataset = self.make_categorical(dataset, 'Proto')
        except ValueError:
          pass
        try:
          # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
          dataset = self.make_categorical(dataset, 'Sport')
        except ValueError:
          pass
        try:
          dataset = self.make_categorical(dataset, 'State')
        except ValueError:
          pass
        try:
          # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
          dataset = self.make_categorical(dataset, 'Dport')
        except ValueError:
          pass
        try:
          # Convert Dur to float
          dataset.Dur = dataset.Dur.astype('float64')
        except ValueError:
          pass
        return dataset

    def process_flow(self):
        """ 
        """
        # Read all the pending flows
        flow = __database__.getNextFlowVerbatim()
        while flow:
            self.outputqueue.put('03|detection1|\t[detec1] Flow read: {}'.format(flow))
            flow = __database__.getNextFlowVerbatim()
            # convert the flow to a pandas dataframe
            try:
                #sflow = flow.split(',')
                sflow = flow.split('	')
            except AttributeError:
                return True

            dflow = pd.DataFrame([sflow], columns=['StartTime','Dur','Proto','SrcAddr','Sport','Dir','DstAddr','Dport','State','sTos','dTos','TotPkts','TotBytes','SrcBytes','SrcPkts','Label'])
            dflow = self.process_features(dflow)

            #self.outputqueue.put('03|detection1|\t[detec1] Pandas flow: {}'.format(dflow))

            try:
                flow_std = self.scaler.transform(dflow);
            except ValueError:
                continue

            pred = self.clf.predict(dflow[0:1])
            self.outputqueue.put('10|detection1|\t[detec1] Prediction of flow: {}. -> {}'.format(flow[:-1], pred))




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
