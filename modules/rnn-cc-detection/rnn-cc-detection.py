# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
import warnings
import json
import traceback

# Your imports
import numpy as np
import sys
from tensorflow.python.keras.models import load_model


warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'RNN C&C Detection'
    description = 'Detect C&C channels based on behavioral letters'
    authors = ['Sebastian Garcia', 'Kamila Babayeva', 'Ondrej Lukas']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        super().__init__(outputqueue)
        # All the printing output should be sent to the outputqueue. The
        # outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        self.c1 = __database__.subscribe('new_letters')
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
        port_info = __database__.get_port_info(portproto)
        ip_identification = __database__.getIPIdentification(dstip)
        description = (
            f'C&C channel, destination IP: {dstip} '
            f'port: {port_info.upper() if port_info else ""} {portproto} '
            f'score: {format(score, ".4f")}. {ip_identification}'
        )
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, categroy, source_target_tag=source_target_tag, port=port, proto=proto,
                                 profileid=profileid, twid=twid, uid=uid)

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

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)
        return True
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
            data = msg['data']
            data = json.loads(data)
            pre_behavioral_model = data['new_symbol']
            profileid = data['profileid']
            twid = data['twid']
            tupleid = data['tupleid']
            uid = data['uid']
            stime = data['stime']

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
                    self.set_evidence(
                        score,
                        confidence,
                        uid,
                        stime,
                        tupleid,
                        profileid,
                        twid,
                    )
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
