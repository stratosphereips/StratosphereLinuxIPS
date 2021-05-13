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
        self.mode = self.config.get('anomaly-detection', 'mode')
        # Start the DB
        __database__.start(self.config)
        self.c1 = __database__.subscribe('new_conn_flow')
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

    def run(self):
        try:
            # Main loop function
            while True:
                if 'training' in self.mode:
                    message_c1 = self.c1.get_message(timeout=self.timeout)
                    # Check that the message is for you. Probably unnecessary...
                    if message_c1['data'] == 'stop_process':
                        return True
                    if message_c1 and message_c1['channel'] == 'new_conn_flow' and message_c1["type"] == "message":
                        data = message_c1["data"]
                        if type(data) == str:
                            connection = json.loads(data)
                            try:
                                # Is there a dataframe? append to it
                                bro_df = bro_df.append(connection , ignore_index=False) #todo fix this
                            except UnboundLocalError:
                                # There's no dataframe, create one
                                bro_df = pd.DataFrame(connection, index=[0])
                            # Amount of anomalies to show
                            amountanom = 10 #todo ??

                            # todo disable this module if not run with -f

                            #todo add read_csv with sep='/t' (tab separated zeek files)

                            # In case you need a label, due to some models being able to work in a
                            # semisupervized mode, then put it here. For now everything is
                            # 'normal', but we are not using this for detection
                            bro_df['label'] = 'normal'
                            # Replace the rows without data (with '-') with 0.
                            # Even though this may add a bias in the algorithms,
                            # is better than not using the lines.
                            # Also fill the no values with 0
                            # Finally put a type to each column
                            bro_df['sbytes'].replace('-', '0', inplace=True) #orig_bytes
                            bro_df['sbytes'] = bro_df['sbytes'].fillna(0).astype('int32')
                            bro_df['dbytes'].replace('-', '0', inplace=True) # resp_bytes
                            bro_df['dbytes'] = bro_df['dbytes'].fillna(0).astype('int32')
                            bro_df['dpkts'].replace('-', '0', inplace=True)
                            bro_df['dpkts'] = bro_df['dpkts'].fillna(0).astype('int32') # resp_packets
                            bro_df['orig_ip_bytes'].replace('-', '0', inplace=True)
                            bro_df['orig_ip_bytes'] = bro_df['orig_ip_bytes'].fillna(0).astype('int32')
                            bro_df['resp_ip_bytes'].replace('-', '0', inplace=True)
                            bro_df['resp_ip_bytes'] = bro_df['resp_ip_bytes'].fillna(0).astype('int32')
                            bro_df['dur'].replace('-', '0', inplace=True)
                            bro_df['dur'] = bro_df['dur'].fillna(0).astype('float64')
                            # Save dataframe to disk as CSV
                            # if not os.path.exists('anomaly-detection-output'):
                            #     os.makedir('anomaly-detection-output')
                            # bro_df.to_csv('anomaly-detection-output/output.csv')

                            # Add the columns from the log file that we know are numbers. This is only for conn.log files.
                            X_train = bro_df[['dur', 'sbytes', 'dport', 'dbytes', 'orig_ip_bytes', 'dpkts', 'resp_ip_bytes']]
                            # X_train = bro_df[['duration', 'orig_bytes', 'id.resp_p', 'resp_bytes', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']]
                            # Our y is the label. But we are not using it now.
                            y = bro_df.label
                            # The X_test is where we are going to search for anomalies. In our case, its the same set of data than X_train.
                            X_test = X_train
                            #################
                            # Select a model from below
                            # ABOD class for Angle-base Outlier Detection. For an observation, the
                            # variance of its weighted cosine scores to all neighbors could be
                            # viewed as the outlying score.
                            # clf = ABOD()
                            # LOF
                            # clf = LOF()
                            # CBLOF
                            # clf = CBLOF()
                            # LOCI
                            # clf = LOCI()
                            # LSCP
                            # clf = LSCP()
                            # MCD
                            # clf = MCD()
                            # OCSVM
                            # clf = OCSVM()
                            # PCA. Good and fast!
                            clf = PCA()
                            # SOD
                            # clf = SOD()
                            # SO_GAAL
                            # clf = SO_GALL()
                            # SOS
                            # clf = SOS()
                            # XGBOD
                            # clf = XGBOD()
                            # KNN
                            # Good results but slow
                            # clf = KNN()
                            # clf = KNN(n_neighbors=10)
                            #################
                            # extract the value of dataframe to matrix
                            X_train = X_train.values
                            # Fit the model to the train data
                            clf.fit(X_train)
                            # *****
                            # Save the model to disk
                            with open("modules/anomaly-detection/anomaly-detection-model",'wb') as file:
                                pickle.dump(clf,file)
                elif 'test' in self.mode:
                    pass
                else:
                    self.print(f"{self.mode} is not a valid mode, available options are: training or test. anomaly-detection module stopping.")
                    return True
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True