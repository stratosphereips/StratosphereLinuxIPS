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
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import pandas as pd # todo add pandas to install.sh
import pickle # todo add pickle to install.sh
from pyod.models.pca import PCA
import json
import os
import threading
import time

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'anomaly-detection'
    description = 'An anomaly detector for conn.log files of zeek/bro'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        self.mode = self.config.get('parameters', 'anomaly_detection_mode').lower()
        # Start the DB
        __database__.start(self.config)
        self.c2 = __database__.subscribe('new_flow')
        self.c3 = __database__.subscribe('tw_closed')
        # Set the timeout based on the platform. This is because the
        # pyredis lib does not have officially recognized the
        # timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = None
        else:
            # Other systems
            self.timeout = None
        self.is_first_run = True
        self.current_srcip = ''
        self.dataframes = {}
        self.saving_thread = threading.Thread(target=self.save_models_thread,
                         daemon=True)
        self.thread_started = False
        self.models_path = 'modules/anomaly-detection/models/'

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by
        taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to
         be printed
         debug: is the minimum debugging level required for this text to be
         printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the
        minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def save_models_thread(self):
        """ Saves models to disk every 1h """

        while True:
            time.sleep(60*60)
            self.save_models()

    def save_models(self):
        """ Train and save trained models to disk """

        self.print('Saving models to disk...')
        for srcip, bro_df in self.dataframes.items():
            # Add the columns from the log file that we know are numbers. This is only for conn.log files.
            X_train = bro_df[['dur', 'sbytes', 'dport', 'dbytes', 'orig_ip_bytes', 'dpkts', 'resp_ip_bytes']]
            # PCA. Good and fast!
            clf = PCA()
            # extract the value of dataframe to matrix
            X_train = X_train.values
            # Fit the model to the train data
            clf.fit(X_train)
            # make sure there's a dir to save the models to
            if not os.path.isdir(self.models_path):
                os.mkdir(self.models_path)
            # save the model to disk
            path_to_df = self.models_path + srcip
            with open(path_to_df, 'wb') as model:
                pickle.dump(clf, model)
        self.print('Done.')

    def get_model(self) -> str:
        """
        Find the correct model to use for testing depending on the current source ip
        returns the model path
        """
        models = os.listdir(self.models_path)
        for model_name in models:
            if self.current_srcip in model_name:
                return self.models_path + model_name
        else:
            # no model with srcip found
            # return a random model
            return self.models_path + model_name

    def run(self):
        # Main loop function
        while True:
            try:
                if 'train' in self.mode:
                    # start the saving thread only once
                    if self.thread_started == False:
                        self.saving_thread.start()
                        self.thread_started = True

                    message_c3 = self.c3.get_message(timeout=self.timeout)
                    if message_c3['data'] == 'stop_process':
                        # train and save the models before exiting
                        self.save_models()
                        # Confirm that the module is done processing
                        __database__.publish('finished_modules', self.name)
                        return True
                    if message_c3 and message_c3['channel'] == 'tw_closed' and message_c3["type"] == "message":
                        data = message_c3["data"]
                        if type(data) == str:
                            # data example: profile_192.168.1.1_timewindow1
                            data = data.split('_')
                            self.new_srcip = data[1]
                            # make sure it is not first run so we don't save an empty model to disk
                            if self.is_first_run == False and self.current_srcip != self.new_srcip:
                                # srcip changed
                                self.current_srcip = self.new_srcip
                                try:
                                    # there is a dataframe for this src ip, append to it
                                    bro_df = self.dataframes[self.current_srcip]
                                except KeyError:
                                    # there's no saved df for this ip, save it
                                    self.dataframes[self.current_srcip] = bro_df
                                    # empty the current dataframe so we can create a new one for the new srcip
                                    bro_df = None
                            profileid = f'{data[0]}_{data[1]}'
                            twid = data[2]
                            # get all flows in the tw
                            flows = __database__.get_all_flows_in_profileid_twid(profileid, twid)
                            # flows is a dict of uids and keys and actual flows as values
                            for flow in flows.values():
                                flow = json.loads(flow)
                                try:
                                    # Is there a dataframe? append to it
                                    bro_df = bro_df.append(flow, ignore_index=True)
                                except (UnboundLocalError, AttributeError):
                                    # There's no dataframe, create one
                                    # current srcip will be used as the model name
                                    self.current_srcip = data[1]
                                    bro_df = pd.DataFrame(flow, index=[0])
                            # In case you need a label, due to some models being able to work in a
                            # semisupervized mode, then put it here. For now everything is
                            # 'normal', but we are not using this for detection
                            bro_df['label'] = 'normal'
                            # Replace the rows without data (with '-') with 0.
                            # Even though this may add a bias in the algorithms,
                            # is better than not using the lines.
                            # Also fill the no values with 0
                            # Finally put a type to each column
                            bro_df['sbytes'].replace('-', '0', inplace=True)  # orig_bytes
                            bro_df['sbytes'] = bro_df['sbytes'].fillna(0).astype('int32')
                            bro_df['dbytes'].replace('-', '0', inplace=True)  # resp_bytes
                            bro_df['dbytes'] = bro_df['dbytes'].fillna(0).astype('int32')
                            bro_df['dpkts'].replace('-', '0', inplace=True)
                            bro_df['dpkts'] = bro_df['dpkts'].fillna(0).astype('int32')  # resp_packets
                            bro_df['orig_ip_bytes'].replace('-', '0', inplace=True)
                            bro_df['orig_ip_bytes'] = bro_df['orig_ip_bytes'].fillna(0).astype('int32')
                            bro_df['resp_ip_bytes'].replace('-', '0', inplace=True)
                            bro_df['resp_ip_bytes'] = bro_df['resp_ip_bytes'].fillna(0).astype('int32')
                            bro_df['dur'].replace('-', '0', inplace=True)
                            bro_df['dur'] = bro_df['dur'].fillna(0).astype('float64')
                            self.is_first_run = False
                elif 'test' in self.mode:
                    message_c2 = self.c2.get_message(timeout=self.timeout)
                    if message_c2['data'] == 'stop_process':
                        return True
                    if message_c2 and message_c2['channel'] == 'new_flow' and message_c2["type"] == "message":
                        data = message_c2["data"]
                        if type(data) == str:
                            # Check if there's modules to test or not
                            if not os.path.isdir(self.models_path) or not os.listdir(self.models_path) :
                                self.print("No models found! Please train first. https://stratospherelinuxips.readthedocs.io/en/develop/")
                                return True
                            data = json.loads(data)
                            profileid = data['profileid']
                            twid = data['twid']
                            # flow is a json serialized dict of one key {'uid' : str(flow)}
                            flow = json.loads(data['flow'])
                            #  flow contains only one key(uid). Get it.
                            uid = list(flow.keys())[0]
                            # Get the flow as dict
                            flow_dict = json.loads(flow[uid])
                            self.new_srcip = flow_dict['saddr']
                            if self.is_first_run:
                                self.current_srcip = self.new_srcip
                            # Create a dataframe
                            bro_df = pd.DataFrame(flow_dict, index=[0])
                            # Get the values we're interested in from the flow in a list to give the model
                            try:
                                X_test = bro_df[['dur', 'sbytes', 'dport', 'dbytes', 'orig_ip_bytes', 'dpkts', 'resp_ip_bytes']]
                            except KeyError:
                                # This flow doesn't have the fields we're interested in
                                continue
                            # if the srcip changed open the right model (don't reopen the same model on every run)
                            if self.current_srcip != self.new_srcip or (self.current_srcip is self.new_srcip and self.is_first_run):
                                path_to_model = self.get_model()
                                try:
                                    with open(path_to_model, 'rb') as model:
                                        clf = pickle.load(model)
                                except FileNotFoundError :
                                    # probably because slips wasn't run in train mode first
                                    self.print("No models found in modules/anomaly-detection. Stopping.")
                                    return True
                            # Get the prediction on the test data
                            y_test_scores = clf.decision_function(X_test)  # outlier scores
                            # Convert the ndarrays of scores and predictions to  pandas series
                            scores_series = pd.Series(y_test_scores)
                            # Add the score to the flow
                            __database__.set_module_label_to_flow(profileid, twid, uid, 'anomaly-detection-score',
                                                                str(scores_series.values[0]))
                            # update the current srcip
                            self.current_srcip = self.new_srcip
                elif self.mode.lower() is 'none' or self.mode is '':
                    #  ignore this module
                    return True
                else:
                    self.print(f"{self.mode} is not a valid mode, available options are: training or testing. anomaly-detection module stopping.")
                    return True
            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                self.print('Problem on the run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True