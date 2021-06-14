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
import platform


# This horrible hack is only to stop sklearn from printing those warnings
def warn(*args, **kwargs):
    pass


import warnings

warnings.warn = warn


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'mldetection-1'
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

        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = None
        else:
            # ??
            self.timeout = None

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
            # Load the models only once, depending the mode
            # This should be done here and not in __init__ because the python does not finish correctly then
            if self.mode == 'train':
                # Load the old model if there is one
                try:
                    f = open('./modules/MLdetection1/RFmodel.bin', 'rb')
                    self.print('Found a previous RFmodel.bin file. Trying to load it to update the training', 3, 0)
                    self.clf = pickle.load(f)
                    f.close()
                except FileNotFoundError:
                    pass
            elif self.mode == 'test':
                # Load the model from disk
                try:
                    f = open('./modules/MLdetection1/RFmodel.bin', 'rb')
                    self.clf = pickle.load(f)
                    f.close()
                except FileNotFoundError:
                    self.print(
                        'There is no RF model stored. You need to train first with at least two different labels.')
                    return False
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            # Stop the timer
            self.print('Error in run()')
            self.print(type(inst))
            self.print(inst)
            return True

        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)

                if message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                """
                message = self.c1.get_message(timeout=-1)
                #self.print('Message received from channel {} with data {}'.format(message['channel'], message['data']), 0, 1)
                # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                elif message['channel'] == 'new_flow' and message['data'] != 1:
                    mdata = message['data']
                    # Convert from json to dict
                    mdata = json.loads(mdata)
                    profileid = mdata['profileid']
                    twid = mdata['twid']
                    # Get flow as a json
                    json_flow = mdata['flow']
                    # Convert flow to a dict
                    self.flow = json.loads(json_flow)
                    # The dict has an empty key, just get the real flow from inside
                    self.flow = list(self.flow.values())[0]
                    # Reconvert
                    self.flow = json.loads(self.flow)
                    self.print('Flow received: {}'.format(self.flow))
                    # First process the flow to convert to pandas
                    if self.mode == 'train':
                        # We are training. 
                        # Then check if we have already more than 1 label in the training data
                        labels = __database__.get_labels()
                        sum_labeled_flows = sum([i[1] for i in labels])
                        #self.print('Amount of labels: {}'.format(labels),3,0)
                        if len(labels) <= 1:
                            self.print('Training mode active but only {} labels'.format(len(labels)))
                            # We don't: return True and keep waiting for more labels
                            return True
                        elif sum_labeled_flows - self.retrain >= 100:
                            self.print('Training the model with the last group of flows.')
                            # Did we get more than 100 new flows since we last retrained?
                            self.retrain = sum_labeled_flows
                            # Process all flows in the DB and make them ready for pandas
                            self.process_flows()
                            # Train an algorithm
                            self.train()
                        # Test
                        self.process_flow()
                        # Predict
                        pred = self.detect()
                        self.print('Test Prediction of flow {}: {}'.format(json_flow, pred[0]), 2, 0)
                    elif self.mode == 'test':
                        # Process the flow
                        # If the flow is icmp, just ignore it
                        if not 'icmp' in self.flow['proto']:
                            self.process_flow()
                            # Predict
                            pred = self.detect()
                            self.print('Prediction of flow {}: {}'.format(json_flow, pred[0]), 0, 0)
                """

            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                # Stop the timer
                self.print('Error in run()')
                self.print(type(inst))
                self.print(inst)
                return True

    def train(self):
        """ 
        Train a model based on the flows we receive and the labels
        """
        try:
            self.print('Replace labels')
            self.flows.label = self.flows.label.str.replace(r'(^.*Normal.*$)', 'Normal')
            self.flows.label = self.flows.label.str.replace(r'(^.*Malware.*$)', 'Malware')

            self.print('Separate X and y')
            # Separate
            y_flow = self.flows['label']
            X_flow = self.flows.drop('label', axis=1)
            # self.print('	X_flow without label: {}'.format(X_flow))

            # self.print('Scale')
            # sc = StandardScaler()
            # sc.fit(X_flow)
            # X_flow = sc.transform(X_flow)
            # self.print('	X_flow scaled: {}'.format(X_flow))
            self.print(X_flow)

            self.print('Create the model')
            # Create th RF model. Warm_start is to incrementallly train with new flows inside a previously trained model.
            # self.clf = RandomForestClassifier(n_estimators=3, criterion='entropy', random_state=1234, warm_start=True)
            self.clf = RandomForestClassifier(n_estimators=30, criterion='entropy')
            self.clf.fit(X_flow, y_flow)
            score = self.clf.score(X_flow, y_flow)
            self.print('	Training Score: {}'.format(score))

            # Store the models on disk
            # f = open('./modules/MLdetection1/RFscaler.bin', 'wb')
            # data = pickle.dumps(sc)
            # f.write(data)
            # f.close()

            f = open('./modules/MLdetection1/RFmodel.bin', 'wb')
            data = pickle.dumps(self.clf)
            f.write(data)
            f.close()
            self.print('Finish storing the models')

        except Exception as inst:
            # Stop the timer
            self.print('Error in train()')
            self.print(type(inst))
            self.print(inst)

    def process_features(self, dataset):
        '''
        Discards some features of the dataset and can create new.
        '''
        # For now, discard the ports
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
            dataset = dataset.drop('ts', axis=1)
        except ValueError:
            pass
        try:
            dataset = dataset.drop('origstate', axis=1)
        except ValueError:
            pass
        # Convert state to categorical
        dataset.state = dataset.state.str.replace(r'(^.*NotEstablished.*$)', '0')
        dataset.state = dataset.state.str.replace(r'(^.*Established.*$)', '1')
        dataset.state = dataset.state.astype('float64')
        # Convert proto to categorical. For now we only have to states, so we can hardcode...
        dataset.proto = dataset.proto.str.replace(r'(^.*tcp.*$)', '0')
        dataset.proto = dataset.proto.str.replace(r'(^.*udp.*$)', '1')
        dataset.proto = dataset.proto.str.replace(r'(^.*icmp.*$)', '2')
        dataset.proto = dataset.proto.str.replace(r'(^.*icmp-ipv6.*$)', '3')
        dataset.proto = dataset.proto.astype('float64')
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
        list_flows = []
        for flowdict in flows:
            for flow in flowdict:
                dict_flow = json.loads(flowdict[flow])
                list_flows.append(dict_flow)
        # Convert the list to a pandas dataframe
        df_flows = pd.DataFrame(list_flows)
        # Process features
        df_flows = self.process_features(df_flows)
        # Update the flow to the processed version
        self.flows = df_flows

    def process_flow(self):
        """ 
        Process the self.flow 
        Store the pandas df in self.flow
        """
        # Forget the timestamp that is the only key of the dict and get the content
        # json_flow = self.flow[list(self.flow.keys())[0]]
        # Convert flow to a dict
        # dict_flow = json.loads(json_flow)
        # Convert the flow to a pandas dataframe
        # raw_flow = pd.DataFrame(dict_flow, index=[0])
        raw_flow = pd.DataFrame(self.flow, index=[0])
        # Process features
        dflow = self.process_features(raw_flow)
        # Update the flow to the processed version
        self.flow = dflow

    def detect(self):
        """ 
        Detect this flow with the current model stored
        """
        try:
            # Load the scaler and the model

            # self.print('Scale the flow')
            # Drop the label if there is one
            y_flow = self.flow['label']
            X_flow = self.flow.drop('label', axis=1)
            # Scale the flow
            # self.print('Scale')
            # X_flow = self.sc.transform(X_flow)
            # self.print(X_flow)

            pred = self.clf.predict(X_flow)
            return pred
        except Exception as inst:
            # Stop the timer
            self.print('Error in detect()')
            self.print(type(inst))
            self.print(inst)
