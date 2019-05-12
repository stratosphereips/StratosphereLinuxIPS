# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

import sys
import configparser
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import pandas as pd
import json


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'MLdetection1'
    description = 'Module to train or test a RandomForest to detect malicious flows.'
    authors = ['Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # Subscribe to the channel
        self.c1 = __database__.subscribe('new_flow')
        self.fieldseparator = __database__.getFieldSeparator()
        # Set the output queue of our database instance
        __database__.setOutputQueue(self.outputqueue)
        # Read the configuration
        self.read_configuration()
        # To know when to retrain. We store the number of labels when we last retrain
        self.retrain = 0

    def read_configuration(self):
        """ Read the configuration file for what we need """
        try:
            self.mode = self.config.get('MLdetection1', 'mode')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # Default to test
            self.mode = 'test'

    def print(self, text, verbose=1, debug=0):
        """ 
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')
        
        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def run(self):
        try:
            while True:
                message = self.c1.get_message(timeout=None)
                #self.print('Message received from channel {} with data {}'.format(message['channel'], message['data']), 0, 1)
                if message['channel'] == 'new_flow' and message['data'] != 1:
                    mdata = message['data']
                    # Convert from json to dict
                    mdata = json.loads(mdata)
                    profileid = mdata['profileid']
                    twid = mdata['twid']
                    # Get flow as a json
                    json_flow = mdata['flow']
                    # Convert flow to a dict
                    self.flow = json.loads(json_flow)
                    #self.print('Flow received: {}'.format(self.flow))
                    # First process the flow to convert to pandas
                    if self.mode == 'train':
                        # We are training. 
                        # Then check if we have already more than 1 label in the training data
                        labels = __database__.get_labels()
                        sum_labeled_flows = sum([i[1] for i in labels])
                        if len(labels) <= 1:
                            # We don't: return True and keep waiting for more labels
                            return True
                        elif sum_labeled_flows - self.retrain >= 100:
                            # Did we get more than 100 new flows since we last retrained?
                            self.retrain = sum_labeled_flows
                            # Process all flows in the DB and make them ready for pandas
                            self.process_flows()
                            # Train an algorithm
                            #self.train()
                    elif self.mode == 'test':
                        self.process_flow()
                        pred = self.detect()
                        #self.print('Prediction: {}'.format(pred))
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            # Stop the timer
            self.print('Error in run()')
            self.print(type(inst))
            self.print(inst)
            sys.exit(1)

    def train(self):
        """ 
        Train a model based on the flows we receive and the labels
        """
        try:
            self.flow.label = self.flow.label.str.replace(r'(^.*Normal.*$)', 'Normal')
            self.flow.label = self.flow.label.str.replace(r'(^.*Malware.*$)', 'Malware')

            # Separate
            y_flow = self.flow['label']
            X_flow = self.flow.drop('label', axis=1)

            #sc = StandardScaler()
            #sc.fit(X_flow)
            #X_flow = sc.transform(X_flow)
            #print(X_flow)

            clf = RandomForestClassifier(n_estimators=3, criterion='entropy', random_state=1234)
            clf.fit(X_flow, y_flow)
            score = clf.score(X_flow, y_flow)
            self.print('Score: {}'.format(score))

            f = open('scale-new.bin', 'wb')
            data = pickle.dumps(sc)
            f.write(data)
            f.close()

            f = open('model-new.bin', 'wb')
            data = pickle.dumps(clf)
            f.write(data)
            f.close()
            print(categories)

            f = open('categories.bin', 'wb')
            data = pickle.dumps(categories)
            f.write(data)
            f.close()
        except Exception as inst:
            # Stop the timer
            self.print('Error in train()')
            self.print(type(inst))
            self.print(inst)
            sys.exit(1)

    def process_features(self, dataset):
        '''
        Discards some features of the dataset and can create new.
        '''
        # {"uid": "Ci5mJ63d7iYGzukjCl", "dur": 0, "saddr": "192.168.2.12", "sport": 1652, "daddr": "69.57.14.100", "dport": 23, "proto": "tcp", "state": "NotEstablished", "pkts": 1, "allbytes": 0, "spkts": 1, "sbytes": 0, "appproto": ""}
        try:
          dataset = dataset.drop('appproto', axis=1)
        except ValueError:
          pass
        try:
          dataset = dataset.drop('daddr', axis=1)
        except ValueError:
          pass
        try:
          dataset = dataset.drop('saddr', axis=1)
        except ValueError:
          pass
        try:
          dataset = dataset.drop('uid', axis=1)
        except ValueError:
          pass
        # Convert proto to categorical 
        # Convert state to categorical
        try:
          # Convert Dur to float
          dataset.dur = dataset.dur.astype('float')
        except ValueError:
          pass
        try:
          # Convert TotPkts to float
          dataset.pkts = dataset.pkts.astype('float')
        except ValueError:
          pass
        try:
          # Convert SrcPkts to float
          dataset.spkts = dataset.spkts.astype('float')
        except ValueError:
          pass
        try:
          # Convert TotBytes to float
          dataset.allbytes = dataset.allbytes.astype('float')
        except ValueError:
          pass
        try:
          # Convert SrcBytes to float
          dataset.sbytes = dataset.sbytes.astype('float')
        except ValueError:
          pass
        return dataset

    def process_flows(self):
        """ 
        Process all the flwos in the DB 
        Store the pandas df in self.flows
        """
        flows = __database__.get_all_flows()
        self.print(flows)
        # Forget the timestamp that is the only key of the dict and get the content
        #json_flow = self.flow[list(self.flow.keys())[0]]
        # Convert flow to a dict
        #dict_flow = json.loads(json_flow)
        # Convert the flow to a pandas dataframe
        #raw_flow = pd.DataFrame(dict_flow, index=[0])
        # Process features
        #dflow = self.process_features(raw_flow)
        # Update the flow to the processed version
        #self.flow = dflow

    def process_flow(self):
        """ 
        Process the self.flow 
        Store the pandas df in self.flow
        """
        # Forget the timestamp that is the only key of the dict and get the content
        json_flow = self.flow[list(self.flow.keys())[0]]
        # Convert flow to a dict
        dict_flow = json.loads(json_flow)
        # Convert the flow to a pandas dataframe
        raw_flow = pd.DataFrame(dict_flow, index=[0])
        # Process features
        dflow = self.process_features(raw_flow)
        # Update the flow to the processed version
        self.flow = dflow

    def detect(self):
        """ 
        Detect this flow with the current model stored
        """
        try:
            # Drop the label column here
            # Scale the flow
            #flow_std = self.scaler.transform(dflow)

            # Load the model from disk
            f = open('./modules/MLdetection1/model-new.bin', 'rb')
            self.clf = pickle.load(f)
            f.close()

            #pred = self.clf.predict(self.flow)
            pred = 'Normal'
            return pred
        except Exception as inst:
            # Stop the timer
            self.print('Error in detect()')
            self.print(type(inst))
            self.print(inst)
            sys.exit(1)
