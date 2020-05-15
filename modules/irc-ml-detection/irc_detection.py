from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

import time
import pickle
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier


class IRCDetector(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'irc-ml-detection'
    description = 'Module to detect malicious irc communication.'
    authors = ['Ondrej Prenek']
    model_fn = './modules/irc-ml-detection/irc_det_model-12-04-2020.sav'

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Init detection model - load the model from disk
        self.detection_model = pickle.load(open(self.model_fn, 'rb'))
        # Start the DB
        __database__.start(self.config)
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        # The options change, so the last list is on the slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        self.c1 = __database__.subscribe('new_irc_features')
        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = -1
        else:
            # ??
            self.timeout = None

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

    def predict_irc(self, features):
        """
        Function to predict IRC connection whether is malicious or not

        Input
         features: dictionary of all features. The features are: 
         - periodicity
         - duration
         - total size
         - number of messages
         - number of flows
         - destination port
         - mean of special characters in username
         - mean of special charracters in message
         - message word entropy
        
        Output
            prediction: 1 if malicious, 0 otherwise
        """

        X_in = [features['periodicity'], features['duration'], features['size_total'], features['msg_count'],
                features['src_ports_count'], features['dport'], features['spec_chars_username_mean'],
                features['spec_chars_msg_mean'], features['msg_word_entropy']]
        X_in = np.array(X_in).reshape(1, -1)
        return self.detection_model.predict(X_in)

    def set_evidence(self, ip, out='', profileid='', twid=''):
        """
        Set an evidence of IRC Detector output for IRC connection met in the timewindow
        If profileid is None, do not set an Evidence
        Returns nothing
        """

        if profileid != 'None':
            out_str = 'malicious' if out == 1 else 'non-malicious'
            type_evidence = 'IRC Detector'
            key = 'dstip' + ':' + ip + ':' + type_evidence
            description = 'detector output: ' + out_str
            threat_level = 0
            confidence = 1
            __database__.setEvidence(key, threat_level, confidence, description, profileid=profileid, twid=twid)

    def run(self):
        try:
            while True:
                message = self.c1.get_message(timeout=self.timeout)
                if message['data'] == 'stop_process':
                    return True
                elif message['channel'] == 'new_irc_features':
                    
                    # ignore first message that contains only '1' instead of json
                    if message['data'] == 1:
                        continue

                    data = json.loads(message['data'])
                    # irc connection features extracted from zeek
                    features = json.loads(data['features'])

                    profile_id = data['profileid']
                    tw_id = data['twid']
                    new_ip = features['daddr']

                    # predict maliciousness of irc conneciton based on data features
                    out = self.predict_irc(features)
                    
                    # set evidence based on the prediction output
                    self.set_evidence(new_ip, out, profile_id, tw_id)
                    self.print('IRC Detection of {} \n output: {}'.format(message['data'], out))

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
