# Must imports
from slips_files.common.imports import *
import warnings
import json
import traceback

# Your imports
import numpy as np
import sys
from tensorflow.python.keras.models import load_model


warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)


class CCDetection(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'RNN C&C Detection'
    description = 'Detect C&C channels based on behavioral letters'
    authors = ['Sebastian Garcia', 'Kamila Babayeva', 'Ondrej Lukas']

    def init(self):
        self.c1 = self.db.subscribe('new_letters')
        self.channels = {
            'new_letters': self.c1,
        }

    def set_evidence(
        self,
        score,
        confidence,
        uid,
        timestamp,
        tupleid='',
        profileid='',
        twid='',
    ):
        """
        Set an evidence for malicious Tuple
        """

        attacker_direction = 'outTuple'
        attacker = tupleid
        source_target_tag = 'Botnet'
        evidence_type = 'Command-and-Control-channels-detection'
        threat_level = 'high'
        categroy = 'Intrusion.Botnet'
        tupleid = tupleid.split('-')
        dstip, port, proto = tupleid[0], tupleid[1], tupleid[2]
        portproto = f'{port}/{proto}'
        port_info = self.db.get_port_info(portproto)
        ip_identification = self.db.get_ip_identification(dstip)
        description = (
            f'C&C channel, destination IP: {dstip} '
            f'port: {port_info.upper() if port_info else ""} {portproto} '
            f'score: {format(score, ".4f")}. {ip_identification}'
        )
        victim = profileid.split('_')[-1]
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, categroy, source_target_tag=source_target_tag, port=port, proto=proto,
                                 profileid=profileid, twid=twid, uid=uid, victim= victim)



    def convert_input_for_module(self, pre_behavioral_model):
        """
        Takes the input from the letters and converts them
        to whatever is needed by the model
        The pre_behavioral_model is a 1D array of letters in an array
        """
        # TODO: set the max_length in the function call

        # Length of behavioral model with which we trained our module
        max_length = 500

        # Convert each of the stratosphere letters to an integer. There are 50
        vocabulary = list('abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ1234567890,.+*')
        int_of_letters = {}
        for i, letter in enumerate(vocabulary):
            int_of_letters[letter] = float(i)

        # String to test
        # pre_behavioral_model = "88*y*y*h*h*h*h*h*h*h*y*y*h*h*h*y*y*"

        # Be sure only max_length chars come. Not sure why we receive more
        pre_behavioral_model = pre_behavioral_model[:max_length]

        # Add padding to the letters passed
        # self.print(f'Seq sent: {pre_behavioral_model}')
        pre_behavioral_model += '0' * (max_length - len(pre_behavioral_model))
        # self.print(f'Padded Seq sent: {pre_behavioral_model}')

        # Convert to ndarray
        pre_behavioral_model = np.array(
            [[int_of_letters[i]] for i in pre_behavioral_model]
        )
        # self.print(f'The sequence has shape {pre_behavioral_model.shape}')

        # Reshape into (1, 500, 1) We need the first 1, because this is one sample only, but keras expects a 3d vector
        pre_behavioral_model = np.reshape(
            pre_behavioral_model, (1, max_length, 1)
        )

        # self.print(f'Post Padded Seq sent: {pre_behavioral_model}. Shape: {pre_behavioral_model.shape}')
        return pre_behavioral_model

    def pre_main(self):
        utils.drop_root_privs()
        # TODO: set the decision threshold in the function call
        try:
            # Download lstm model
            self.tcpmodel = load_model('modules/rnn-cc-detection/rnn_model.h5')
        except AttributeError as e:
            self.print('Error loading the model.')
            self.print(e)
            return 1

    def main(self):
        # Main loop function
        if msg:= self.get_msg('new_letters'):
            msg = msg['data']
            msg = json.loads(msg)
            pre_behavioral_model = msg['new_symbol']
            profileid = msg['profileid']
            twid = msg['twid']
            tupleid = msg['tupleid']
            flow = msg['flow']

            if 'tcp' in tupleid.lower():
                # to reduce false positives
                threshold = 0.99
                # function to convert each letter of behavioral model to ascii
                behavioral_model = self.convert_input_for_module(
                    pre_behavioral_model
                )
                # predict the score of behavioral model being c&c channel
                self.print(
                    f'predicting the sequence: {pre_behavioral_model}', 3, 0,
                )
                score = self.tcpmodel.predict(behavioral_model)
                self.print(
                    f' >> sequence: {pre_behavioral_model}. final prediction score: {score[0][0]:.20f}', 3, 0,
                )
                # get a float instead of numpy array
                score = score[0][0]
                if score > threshold:
                    threshold_confidence = 100
                    if (
                        len(pre_behavioral_model)
                        >= threshold_confidence
                    ):
                        confidence = 1
                    else:
                        confidence = (
                            len(pre_behavioral_model)
                            / threshold_confidence
                        )
                    uid = msg['uid']
                    stime = flow['starttime']
                    self.set_evidence(
                        score,
                        confidence,
                        uid,
                        stime,
                        tupleid,
                        profileid,
                        twid,
                    )
                    attacker = tupleid.split('-')[0]
                    # port = int(tupleid.split('-')[1])
                    to_send = {
                        'attacker': attacker,
                        'attacker_type': utils.detect_data_type(attacker),
                        'profileid' : profileid,
                        'twid' : twid,
                        'flow': flow,
                        'uid': uid,
                    }
                    self.db.publish('check_jarm_hash', json.dumps(to_send))

            """
            elif 'udp' in tupleid.lower():
                # Define why this threshold
                threshold = 0.7
                # function to convert each letter of behavioral model to ascii
                behavioral_model = self.convert_input_for_module(pre_behavioral_model)
                # predict the score of behavioral model being c&c channel
                self.print(f'predicting the sequence: {pre_behavioral_model}', 4, 0)
                score = udpmodel.predict(behavioral_model)
                self.print(f' >> sequence: {pre_behavioral_model}. final prediction score: {score[0][0]:.20f}', 5, 0)
                # get a float instead of numpy array
                score = score[0][0]
                if score > threshold:
                    self.set_evidence(score, tupleid, profileid, twid)
            """
