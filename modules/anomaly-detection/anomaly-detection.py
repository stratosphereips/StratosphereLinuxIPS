# Must imports
from slips_files.common.imports import *
from slips_files.common.abstracts._module import IModule
import threading
from multiprocessing import Queue

#from slips_files.common.abstracts import Module
#from slips_files.common.slips_utils import utils
#from slips_files.core.database.database_manager import __database__
#from slips_files.common.parsers.config_parser import ConfigParser
#import sys
#import multiprocessing

# Your imports
import pandas as pd
import pickle
from pyod.models.pca import PCA
import json
import os
import threading
import time

class Module(IModule, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'Anomaly Detector'
    description = 'Anomaly detector for zeek conn.log files'
    authors = ['Sebastian Garcia', 'Alya Gomaa']

    def __init__(self, outputqueue, redis_port):
        self.c1 = self.db.subscribe('new_flow')
        self.c2 = self.db.subscribe('tw_closed')
        self.channels = {
            'new_flow': self.c1,
            'tw_closed': self.c2,
        }
        self.read_configuration()
    
    def read_configuration(self):
        conf = ConfigParser()
        self.mode = conf.get_anomaly_detection_mode()

    def save_models_thread(self):
        """ Saves models to disk every 1h """
        while True:
            time.sleep(60*60)
            self.save_models()

    def save_models(self):
        """ Train and save trained models to disk """

        self.print('Saving models to disk...')
        # make sure there's a dir to save the models to
        if not os.path.isdir(self.models_path):
            os.mkdir(self.models_path)

        for srcip, bro_df in self.dataframes.items():

            if not self.df_exists(bro_df):
                continue
            # Add the columns from the log file that we know are numbers. This is only for conn.log files.
            X_train = bro_df[['dur', 'sbytes', 'dport', 'dbytes', 'orig_ip_bytes', 'dpkts', 'resp_ip_bytes']]
            # PCA. Good and fast!
            clf = PCA()
            # extract the value of dataframe to matrix
            X_train = X_train.values
            # Fit the model to the train data
            clf.fit(X_train)
            # save the model to disk
            path_to_df = os.path.join(self.models_path, srcip)
            with open(path_to_df, 'wb') as model:
                pickle.dump(clf, model)

        self.print('Done.')

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        if self.mode == 'train':
            self.store_model()

    def pre_main(self):
        utils.drop_root_privs()
        # Load the model
        self.read_model()

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

    def normalize_col_with_no_data(self, column, type_):
        """
        Replace the rows without data (with '-') with 0.
        Also fill the no values with 0
        and change the type of each column
        """
        # Even though this may add a bias in the algorithms,
        # is better than not using the lines.
        try:
            self.bro_df[column].replace('-', '0', inplace=True)
            self.bro_df[column].replace('', '0', inplace=True)
            # fillna() replaces the NULL values with a specified value
            self.bro_df[column] = self.bro_df[column].fillna(0)
            # astype converts the result to the given type_
            self.bro_df[column] = self.bro_df[column].astype(type_)
        except KeyError:
            pass

    def are_there_models_to_test(self):
        # Check if there's models to test or not
        if (not os.path.isdir(self.models_path)
                or not os.listdir(self.models_path)):
            self.print("No models found! Please train first. ")
            return False

    def df_exists(self, bro_df):
        """
        return False if the dataframe is None
        """
        try:
            if self.bro_df == None:
                # if it's still None, this means that all flows in this profile and tw
                # were ARP, ignore them
                return False
        except ValueError:
            # this try except is a way to check that there is a df!
            # comes here if there is
            # todo more nice way to do so??
            return True


    def train(self, flows):
        """
        :param flows: flows of the closed tw to train on
        """
        """
        try:
            # there is a dataframe for this src ip, append to it
            self.bro_df = self.dataframes[self.current_srcip]
        except KeyError:
            # there's no saved df for this ip, save it
            self.dataframes[self.current_srcip] = None
            # empty the current dataframe so we can create a new one for the new srcip
            self.bro_df = None
        """

        # flows is a dict {uid: serialized flow dict}
        for flow in flows.values():
            flow = json.loads(flow)
            # execlude ARP flows from this module since they don't have any of these values
            # (pkts allbytes spkts sbytes appproto)
            if flow.get('proto', '') == 'ARP':
                continue

            try:
                # Is there a dataframe? append to it

                self.bro_df = self.bro_df.append(flow, ignore_index=True)
            except (UnboundLocalError, AttributeError):
                # There's no dataframe, create one
                # current srcip will be used as the model name
                # self.current_srcip = self.profileid_twid[1]
                self.bro_df = pd.DataFrame(flow, index=[0])

        self.normalize_col_with_no_data('sbytes', 'int32')
        self.normalize_col_with_no_data('dbytes', 'int32')
        self.normalize_col_with_no_data('orig_ip_bytes', 'int32')
        self.normalize_col_with_no_data('dpkts', 'int32')
        self.normalize_col_with_no_data('resp_ip_bytes', 'int32')
        self.normalize_col_with_no_data('dur', 'float64')
        self.dataframes[self.current_srcip] = self.bro_df


    def test(self, flows):
        """
        test for every flow in the closed tw
        """

        # flows is a dict {uid: serialized flow dict}
        for flow in flows.values():
            flow = json.loads(flow)

            # Create a dataframe
            bro_df = pd.DataFrame(flow, index=[0])

            # Get the values we're interested in from the flow in a list to give the model
            try:
                X_test = bro_df[['dur', 'sbytes', 'dport', 'dbytes', 'orig_ip_bytes', 'dpkts', 'resp_ip_bytes']]
            except KeyError:
                # This flow doesn't have the fields we're interested in
                return

            # if the srcip changed open the right model (don't reopen the same model on every run)
            # first run is the only case that the new ip will be == the curr ip,
            # so we should open the model. but starting from next run, don't open the model unless the ip changes
            if self.current_srcip != self.new_srcip or self.is_first_run:
                self.is_first_run = False
                path_to_model = self.get_model()
                try:
                    with open(path_to_model, 'rb') as model:
                        clf = pickle.load(model)
                except FileNotFoundError :
                    # probably because slips wasn't run in train mode first
                    self.print(f"No models found in modules/anomaly-detection for {self.current_srcip}. Stopping.")
                    return True


            # Get the prediction on the test data
            y_test_scores = clf.decision_function(X_test)  # outlier scores
            # Convert the ndarrays of scores and predictions to  pandas series
            scores_series = pd.Series(y_test_scores)

            # Add the score to the flow
            __database__.set_module_label_to_flow(
                self.profileid,
                self.twid,
                self.uid,
                'anomaly-detection-score',
                str(scores_series.values[0])
            )
            # update the current srcip
            self.current_srcip = self.new_srcip



    def main(self):
        if 'train' in self.mode:
            # In train mode, we wait for a whole TW to be ready
            if msg := self.get_msg('tw_closed'):
                profileid_tw = msg['data']
                # when a tw is closed, this means that it's too old so we don't check for arp scan in this time
                # range anymore
                # this copy is made to avoid dictionary changed size during iteration err

                # get all flows in the tw
                flows = __database__.get_all_flows_in_profileid_twid(self.profileid, self.twid)
                self.train(flows)
        elif 'test' in self.mode:
            # In test mode, we test each new flow
            if msg:= self.get_msg('new_flow'):
                data = msg['data']
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
                # Get the uid which is the key
                uid = next(iter(flow))
                self.flow_dict = json.loads(flow[uid])

                if not self.are_there_models_to_test():
                    return True
                self.test(flows)