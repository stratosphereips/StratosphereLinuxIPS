# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import platform
import warnings
import json
# Your imports
import numpy as np
import sys
from tensorflow.python.keras.preprocessing.sequence import pad_sequences
from tensorflow.python.keras.models import load_model


warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'rnn-cc-detection-1'
    description = 'Detect C&C channels based on behavioral letters'
    authors = ['Sebastian Garcia', 'Kamila Babayeva', 'Ondrej Lukas']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The
        # outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your
        # own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.c1 = __database__.subscribe('new_letters')
        self.timeout = 0.0000001

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

    def set_evidence(self, score, confidence, uid, timestamp, tupleid='', profileid='', twid=''):
        '''
        Set an evidence for malicious Tuple
        '''
        type_detection = 'outTuple'
        detection_info = tupleid
        source_target_tag = 'Botnet'
        type_evidence = 'Command-and-Control-channels-detection'
        threat_level = 'high'
        categroy =  'Intrusion.Botnet'
        tupleid = tupleid.split('-')
        dstip , port, proto =  tupleid[0], tupleid[1], tupleid[2]
        description = f'C&C channel, destination IP: {dstip} port: {port}/{proto} score: {format(score, ".4f")}'
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description, timestamp,
                                 categroy, source_target_tag=source_target_tag,
                                 port=port, proto=proto,
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
        vocabulary = list("abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ1234567890,.+*")
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
        pre_behavioral_model = np.array([[int_of_letters[i]] for i in pre_behavioral_model])
        # self.print(f'The sequence has shape {pre_behavioral_model.shape}')

        # Reshape into (1, 500, 1) We need the first 1, because this is one sample only, but keras expects a 3d vector
        pre_behavioral_model = np.reshape(pre_behavioral_model, (1, max_length, 1))

        # self.print(f'Post Padded Seq sent: {pre_behavioral_model}. Shape: {pre_behavioral_model.shape}')
        return pre_behavioral_model

    def run(self, model_file="modules/rnn-cc-detection-1/rnn_model.h5"):
        # TODO: set the decision threshold in the function call
        try:
            # Download lstm model
            tcpmodel = load_model(model_file)
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on the run() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
        except AttributeError as e:
            self.print('Error loading the model.')
            self.print(e)
        except KeyboardInterrupt:
            # enter the while loop to recieve stop_process msg
            pass

        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True

                if utils.is_msg_intended_for(message, 'new_letters'):
                    data = message['data']
                    data = json.loads(data)
                    pre_behavioral_model = data['new_symbol']
                    profileid = data['profileid']
                    twid = data['twid']
                    tupleid = data['tupleid']
                    uid = data['uid']
                    stime = data['stime']

                    if 'tcp' in tupleid.lower():
                        # Define why this threshold
                        threshold = 0.7
                        # function to convert each letter of behavioral model to ascii
                        behavioral_model = self.convert_input_for_module(pre_behavioral_model)
                        # predict the score of behavioral model being c&c channel
                        self.print(f'predicting the sequence: {pre_behavioral_model}', 3, 0)
                        score = tcpmodel.predict(behavioral_model)
                        self.print(f' >> sequence: {pre_behavioral_model}. final prediction score: {score[0][0]:.20f}', 3, 0)
                        # get a float instead of numpy array
                        score = score[0][0]
                        if score > threshold:
                            threshold_confidence = 100
                            if len(pre_behavioral_model) >= threshold_confidence:
                                confidence = 1
                            else:
                                confidence = len(pre_behavioral_model)/threshold_confidence
                            self.set_evidence(score, confidence, uid, stime, tupleid, profileid, twid)
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

            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
