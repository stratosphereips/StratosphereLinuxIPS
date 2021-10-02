# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__

import sys
import configparser
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import SGDClassifier
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
    description = 'Module to train or test a Machine Learning model to detect malicious flows.'
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
            # Process the labels to have only Normal and Malware
            self.flows.label = self.flows.label.str.replace(r'(^.*Normal.*$)', 'Normal')
            self.flows.label = self.flows.label.str.replace(r'(^.*Malware.*$)', 'Malware')
            self.flows.label = self.flows.label.str.replace(r'(^.*Malicious.*$)', 'Malware')

            # Separate
            y_flow = self.flows['label']
            self.flow = self.flows.drop('label', axis=1)
            X_flow = self.flow.drop('module_labels', axis=1)
            # self.print('	X_flow without label: {}'.format(X_flow))


            # Train 
            try:
                self.clf.fit(X_flow, y_flow)
            except ValueError:
                self.print('Train was not possible yet due to insufficient labels.')
                return False

            # See score so far in training
            score = self.clf.score(X_flow, y_flow)
            self.print('	Training Score: {}'.format(score))

            # Store the models on disk
            self.store_model()

        except Exception as inst:
            # Stop the timer
            self.print('Error in train()')
            self.print(type(inst))
            self.print(inst)

    def process_features(self, dataset):
        '''
        Discards some features of the dataset and can create new.
        '''
        try:
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
        except Exception as inst:
            # Stop the timer
            self.print('Error in process_flows()')
            self.print(type(inst))
            self.print(inst)

    def process_flows(self):
        """ 
        Process all the flwos in the DB 
        Store the pandas df in self.flows
        """
        try:
            # We get all the flows so far
            # because this retraining happens in batches
            flows = __database__.get_all_flows()
            df_flows = pd.DataFrame(flows)
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
            #return [1.0]
        except Exception as inst:
            # Stop the timer
            self.print('Error in detect()')
            self.print(X_flow)
            self.print(type(inst))
            self.print(inst)


    def store_model(self):
        """
        Store the trained model on disk
        """
        self.print(f'Storing the trained model on disk.')
        f = open('./modules/RFdetection/RFmodel.bin', 'wb')
        data = pickle.dumps(self.clf)
        f.write(data)
        f.close()

    def read_model(self):
        """
        Read the trained model from disk
        """
        try:
            self.print(f'Reading the trained model from disk.')
            f = open('./modules/RFdetection/RFmodel.bin', 'rb')
            self.clf = pickle.load(f)
            f.close()
        except FileNotFoundError:
            # If there is no model, create one empty
            #self.clf = RandomForestClassifier(n_estimators=30, criterion='entropy', warm_start=True)
            self.clf = SGDClassifier(warm_start=True)
        except EOFError:
            self.print('Error')
            self.clf = SGDClassifier(warm_start=True)

    def load_known_labeled_flows(self):
        """
        Load the flows and labels from dataset/train
        in order to have a baseline of normal and malware
        before retraining with the data of the user
        """
        pass
        self.print(f'Storing the trained model on disk.')
        f = open('./modules/RFdetection/RFmodel.bin', 'wb')
        data = pickle.dumps(self.clf)

    def run(self):
        # Load the model first
        try:
            # Load the model
            self.read_model()

            while True:
                try:
                    message = self.c1.get_message(timeout=self.timeout)

                    if message['data'] == 'stop_process':
                        # Confirm that the module is done processing
                        self.store_model()
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
                            # Load the normal and malware flows from the dataset/train folder
                            # Then check if we have already more than 1 label in the training data
                            labels = __database__.get_labels()
                            sum_labeled_flows = sum([i[1] for i in labels])
                            #self.print(f'Sum labeled flows: {sum_labeled_flows}, Min Labels to retrain:{self.minimum_lables_to_retrain}')
                            if sum_labeled_flows <= 1:
                                self.print(f'Training mode active but there are only {len(labels)} labels in the DB.')
                                load_known_labeled_flows()
                            # Is the amount in the DB of lables enough to retrain?
                            if sum_labeled_flows >= self.minimum_lables_to_retrain and sum_labeled_flows%self.minimum_lables_to_retrain == 1:
                                self.print(f'Training the model with the last group of flows and labels {labels}.')
                                # Process all flows in the DB and make them ready for pandas
                                self.process_flows()
                                # Train an algorithm
                                self.train()
                        elif self.mode == 'test':
                            if not 'icmp' in self.flow_dict['proto'] and not 'arp' in self.flow_dict['proto']:
                                self.process_flow()
                                # Predict
                                pred = self.detect()
                                self.print(f'Prediction {pred[0]} for label {self.flow_dict["label"]} flow {self.flow_dict["saddr"]}:{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:{self.flow_dict["dport"]}/{self.flow_dict["proto"]}', 0, 2)
                except Exception as inst:
                    # Stop the timer
                    self.print('Error in run()')
                    self.print(type(inst))
                    self.print(inst)
                    return True

        except KeyboardInterrupt:
            self.store_model()
            return True
        except Exception as inst:
            # Stop the timer
            self.print('Error in run()')
            self.print(type(inst))
            self.print(inst)
            return True
