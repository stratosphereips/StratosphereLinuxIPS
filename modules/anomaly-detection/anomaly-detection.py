# Must imports
from slips_files.common.abstracts import Module
from slips_files.common.slips_utils import utils
import multiprocessing
from slips_files.core.database import __database__
import platform
import sys

# Your imports
import pandas as pd
import pickle
from pyod.models.pca import PCA
import json
import os
import threading
import time

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'anomaly-detection'
    description = 'Anomaly detector for zeek conn.log files'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config, redis_port):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        self.config = config
        self.mode = self.config.get('parameters', 'anomaly_detection_mode').lower()
        __database__.start(self.config, redis_port)
        self.c2 = __database__.subscribe('new_flow')
        self.c3 = __database__.subscribe('tw_closed')
        self.timeout = 0.0000001
        self.is_first_run = True
        self.current_srcip = ''
        self.dataframes = {}
        self.saving_thread = threading.Thread(
            target=self.save_models_thread,
            daemon=True
        )
        self.thread_started = False
        self.models_path = 'modules/anomaly-detection/models/'

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
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    def save_models_thread(self):
        """ Saves models to disk every 1h """
        while True:
            time.sleep(60*60)
            self.save_models()

    def save_models(self):
        """ Train and save trained models to disk """

        self.print('Saving models to disk...')
        for srcip, bro_df in self.dataframes.items():
            if not bro_df:
                continue
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

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)

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

    def normalize_col_with_no_data(self, column, type):
        """
        Replace the rows without data (with '-') with 0.
        Even though this may add a bias in the algorithms,
        is better than not using the lines.
        Also fill the no values with 0
        Finally put a type to each column
        """
        try:
            self.bro_df[column].replace('-', '0', inplace=True)  # orig_bytes
            self.bro_df[column] = self.bro_df[column].fillna(0).astype(type)
        except KeyError:
            pass

    def run(self):
        # Main loop function
        while True:
            try:
                if 'train' in self.mode:
                    # start the saving thread only once
                    if self.thread_started == False:
                        self.saving_thread.start()
                        self.thread_started = True

                    msg = self.c3.get_message(timeout=self.timeout)
                    if msg and msg['data'] == 'stop_process':
                        # train and save the models before exiting
                        self.save_models()
                        self.shutdown_gracefully()
                        return True

                    if utils.is_msg_intended_for(msg, 'tw_closed'):
                        data = msg["data"]
                        if type(data) == str:
                            # data example: profile_192.168.1.1_timewindow1
                            data = data.split('_')
                            self.new_srcip = data[1]

                            # make sure it is not first run so we don't save an empty model to disk
                            if not self.is_first_run and self.current_srcip != self.new_srcip:
                                # srcip changed
                                self.current_srcip = self.new_srcip
                                try:
                                    # there is a dataframe for this src ip, append to it
                                    self.bro_df = self.dataframes[self.current_srcip]
                                except KeyError:
                                    # there's no saved df for this ip, save it
                                    self.dataframes[self.current_srcip] = None
                                    # empty the current dataframe so we can create a new one for the new srcip
                                    self.bro_df = None

                            profileid = f'{data[0]}_{data[1]}'
                            twid = data[2]
                            # get all flows in the tw
                            flows = __database__.get_all_flows_in_profileid_twid(profileid, twid)
                            if not flows: continue

                            # flows is a dict {uid: serialized flow dict}
                            for flow in flows.values():
                                flow = json.loads(flow)
                                try:
                                    # Is there a dataframe? append to it
                                    self.bro_df = self.bro_df.append(flow, ignore_index=True)
                                except (UnboundLocalError, AttributeError):
                                    # There's no dataframe, create one
                                    # current srcip will be used as the model name
                                    self.current_srcip = data[1]
                                    self.bro_df = pd.DataFrame(flow, index=[0])

                            # In case you need a label, due to some models being able to work in a
                            # semisupervized mode, then put it here. For now everything is
                            # 'normal', but we are not using this for detection
                            self.bro_df['label'] = 'normal'
                            self.normalize_col_with_no_data('sbytes', 'int32')
                            self.normalize_col_with_no_data('dbytes', 'int32')
                            self.normalize_col_with_no_data('orig_ip_bytes', 'int32')
                            self.normalize_col_with_no_data('dpkts', 'int32')
                            self.normalize_col_with_no_data('resp_ip_bytes', 'int32')
                            self.normalize_col_with_no_data('dur', 'float64')
                            self.is_first_run = False

                elif 'test' in self.mode:
                    msg = self.c2.get_message(timeout=self.timeout)
                    if msg and msg['data'] == 'stop_process':
                        self.shutdown_gracefully()
                        return True

                    if utils.is_msg_intended_for(msg, 'new_flow'):
                        data = msg["data"]
                        if type(data) == str:
                            # Check if there's models to test or not
                            if (not os.path.isdir(self.models_path)
                                    or not os.listdir(self.models_path)):
                                self.print("No models found! "
                                           "Please train first. "
                                           "https://stratospherelinuxips.readthedocs.io/en/develop/")
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
                    self.print(f"{self.mode} is not a valid mode, available options are: "
                               f"training or testing. anomaly-detection module stopping.")
                    return True
            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return False
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
