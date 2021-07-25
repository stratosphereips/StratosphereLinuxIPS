# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__

import sys
import configparser
import time
from sklearn.ensemble import RandomForestClassifier
#from sklearn.ensemble import RandomForestReggresor
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
    name = 'rfdetection'
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
        # Channel timeout
        self.timeout = None
        # Minum amount of new lables needed to trigger the train
        self.minimum_lables_to_retrain = 50

    def read_configuration(self):
        """ Read the configuration file for what we need """
        try:
            self.mode = self.config.get('RFdetection', 'mode')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # Default to test
            self.mode = 'test'

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f"{levels}|{self.name}|{text}")


    def train(self):
        """ 
        Train a model based on the flows we receive and the labels
        """
        try:
            self.flows.label = self.flows.label.str.replace(r'(^.*Normal.*$)', 'Normal')
            self.flows.label = self.flows.label.str.replace(r'(^.*Malware.*$)', 'Malware')
            self.flows.label = self.flows.label.str.replace(r'(^.*Malicious.*$)', 'Malware')

            # Separate
            y_flow = self.flows['label']
            self.flow = self.flows.drop('label', axis=1)
            X_flow = self.flow.drop('module_labels', axis=1)
            # self.print('	X_flow without label: {}'.format(X_flow))

            #self.print(X_flow)

            # Create th RF model. Warm_start is to incrementallly train with new flows inside a previously trained model.
            self.clf = RandomForestClassifier(n_estimators=3, criterion='entropy', warm_start=True)
            self.clf.fit(X_flow, y_flow)
            score = self.clf.score(X_flow, y_flow)
            self.print('	Training Score: {}'.format(score))

            # Store the models on disk
            # f = open('./modules/MLdetection1/RFscaler.bin', 'wb')
            # data = pickle.dumps(sc)
            # f.write(data)
            # f.close()

            f = open('./modules/RFdetection/RFmodel.bin', 'wb')
            data = pickle.dumps(self.clf)
            f.write(data)
            f.close()

        except Exception as inst:
            # Stop the timer
            self.print('Error in train()')
            self.print(type(inst))
            self.print(inst)

    def process_features(self, dataset):
        '''
        Discards some features of the dataset and can create new.
        '''
        # Discard flows arp and icmp, since they dont have the ports
        dataset = dataset[dataset.proto != 'arp']
        dataset = dataset[dataset.proto != 'icmp']
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
        dataset.proto = dataset.proto.str.replace(r'(^.*arp.*$)', '4')
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
        try:
            # We get all the flows so far
            # because this retraining happens in batches
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
        except Exception as inst:
            # Stop the timer
            self.print('Error in process_flows()')
            self.print(type(inst))
            self.print(inst)

    def process_flow(self):
        """ 
        Process one flow. Only used during detection in testing
        Store the pandas df in self.flow
        """
        try:
            # Convert the flow to a pandas dataframe
            raw_flow = pd.DataFrame(self.flow_dict, index=[0])
            # Process features
            dflow = self.process_features(raw_flow)
            # Update the flow to the processed version
            self.flow = dflow
        except Exception as inst:
            # Stop the timer
            self.print('Error in process_flow()')
            self.print(type(inst))
            self.print(inst)

    def detect(self):
        """ 
        Detect this flow with the current model stored
        """
        try:
            # Store the real label if there is one
            y_flow = self.flow['label']
            # Drop the real label
            self.flow = self.flow.drop('label', axis=1)
            # Drop the label predictions of the other modules
            X_flow = self.flow.drop('module_labels', axis=1)
            # Scale the flow
            # self.print('Scale')
            # X_flow = self.sc.transform(X_flow)
            # self.print(X_flow)
            pred = self.clf.predict(X_flow)
            return pred
        except Exception as inst:
            # Stop the timer
            self.print('Error in detect()')
            self.print(X_flow)
            self.print(type(inst))
            self.print(inst)

    def run(self):
        # Load the model first
        try:
            # Load the models only once, depending the mode
            # This should be done here and not in __init__ because the python does not finish correctly then
            if self.mode == 'train':
                # Load the old model if there is one
                try:
                    f = open('./modules/RFDetection/RFmodel.bin', 'rb')
                    self.print('Found a previous RFmodel.bin file. Trying to load it to update the training', 2, 0)
                    self.clf = pickle.load(f)
                    f.close()
                except FileNotFoundError:
                    pass
            elif self.mode == 'test':
                # Load the model from disk
                try:
                    f = open('./modules/RFDetection/RFmodel.bin', 'rb')
                    self.clf = pickle.load(f)
                    f.close()
                except FileNotFoundError:
                    self.print('ERROR. There is no RF model stored. You need to train first with at least two different labels.')
                    return False

            while True:
                try:
                    message = self.c1.get_message(timeout=self.timeout)

                    if message['data'] == 'stop_process':
                        # Confirm that the module is done processing
                        __database__.publish('finished_modules', self.name)
                        return True
                    #self.print('Message received from channel {} with data {}'.format(message['channel'], message['data']), 0, 1)
                    # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                    if message['data'] == 'stop_process':
                        # Confirm that the module is done processing
                        __database__.publish('finished_modules', self.name)
                        return True
                    elif message['channel'] == 'new_flow' and message['data'] != 1:
                        # [rfdetection] Flow received: {'ts': 1545138530.000001, 'dur': '2.997325', 'saddr': '147.32.84.147', 'sport': '55898', 'daddr': '54.192.46.117', 'dport': '22', 'proto': 'tcp', 'origstate': 'SRPA_SRPA', 'state': 'Established', 'pkts': 2, 'allbytes': 1300, 'spkts': False, 'sbytes': 661, 'appproto': False, 'label': 'unknown', 'module_labels': {}}

                        data = message['data']
                        # Convert from json to dict
                        data = json.loads(data)
                        profileid = data['profileid']
                        twid = data['twid']

                        # Get flow that is now in json format
                        flow = data['flow']
                        # Convert flow to a dict
                        flow = json.loads(flow)
                        # Convert the common fields to something that can
                        # be interpreted
                        uid = next(iter(flow))
                        self.flow_dict = json.loads(flow[uid])

                        # First process the flow to convert to pandas
                        if self.mode == 'train':
                            # We are training. 
                            # Then check if we have already more than 1 label in the training data
                            labels = __database__.get_labels()
                            sum_labeled_flows = sum([i[1] for i in labels])
                            #self.print(f'{sum_labeled_flows}, {self.minimum_lables_to_retrain}')
                            if sum_labeled_flows <= 1:
                                self.print(f'Training mode active but there are only {len(labels)} labels in the DB.')
                            # Is the amount in the DB of lables enough to retrain?
                            elif sum_labeled_flows >= self.minimum_lables_to_retrain and sum_labeled_flows%self.minimum_lables_to_retrain == 1:
                                self.print(f'Training the model with the last group of flows and labels {labels}.')
                                # Process all flows in the DB and make them ready for pandas
                                self.process_flows()
                                # Train an algorithm
                                self.train()
                            # Test
                            #self.process_flow()
                            # Predict
                            #pred = self.detect()
                            #self.print('Test Prediction of flow {}: {}'.format(json_flow, pred[0]), 2, 0)
                        elif self.mode == 'test':
                            # Process the flow
                            # If the flow is icmp or arp, just ignore it
                            if not 'icmp' in self.flow_dict['proto'] and not 'arp' in self.flow_dict['proto']:
                                self.process_flow()
                                # Predict
                                pred = self.detect()
                                self.print(f'Prediction {pred[0]} for label {self.flow_dict["label"]} flow {self.flow_dict["saddr"]}:{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:{self.flow_dict["dport"]}/{self.flow_dict["proto"]}', 0, 2)
                except KeyboardInterrupt:
                    # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                    continue
                except Exception as inst:
                    # Stop the timer
                    self.print('Error in run()')
                    self.print(type(inst))
                    self.print(inst)
                    return True

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            # Stop the timer
            self.print('Error in run()')
            self.print(type(inst))
            self.print(inst)
            return True
