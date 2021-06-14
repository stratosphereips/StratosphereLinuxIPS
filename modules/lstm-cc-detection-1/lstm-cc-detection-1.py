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
import warnings
# Your imports
import numpy as np
from tensorflow.python.keras.preprocessing.sequence import pad_sequences
from tensorflow.python.keras.models import load_model

warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'lstm-cc-detection-1'
    description = 'Detect C&C channels based on behavioral letters'
    authors = ['Sebastian Garcia', 'Kamila Babayeva']

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
        # To which channels do you wnat to subscribe? When a message arrives
        # on the channel the module will wakeup
        # The options change, so the last list is on the slips/core/database.py
        # file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        self.c1 = __database__.subscribe('new_letters')
        # Set the timeout based on the platform. This is because the pyredis
        # lib does not have officially recognized the timeout=None as it works
        # in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = None
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

    def set_evidence(self, score, confidence, tupleid='', profileid='', twid=''):
        '''
        Set an evidence for malicious Tuple
        '''
        type_detection = 'outTuple'
        detection_info = tupleid
        type_evidence = 'C&C channels detection'
        threat_level = 100
        description = 'RNN C&C channels detection, score: ' + str(score) + ', tuple ID:\'' + str(tupleid) +'\''

        __database__.setEvidence(type_detection, detection_info, type_evidence,
                                 threat_level, confidence, description, profileid=profileid, twid=twid)

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
        #vocabulary = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ',', '.', '+', '*']
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

    def run(self, model_file="modules/lstm-cc-detection-1/rnn_model.h5"):
        # TODO: set the decision threshold in the function call
        try:
            # Download lstm model
            tcpmodel = load_model(model_file)
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True

        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                if message['channel'] == 'new_letters' and type(message['data']) is not int:
                    data = message['data']
                    data = data.split('-')
                    pre_behavioral_model = data[0]
                    profileid = data[1]
                    twid = data[2]
                    tupleid = data[3]
                    if 'tcp' in tupleid.lower():
                        # Define why this threshold
                        threshold = 0.7
                        # function to convert each letter of behavioral model to ascii
                        behavioral_model = self.convert_input_for_module(pre_behavioral_model)
                        # predict the score of behavioral model being c&c channel
                        self.print(f'predicting the sequence: {pre_behavioral_model}', 4, 0)
                        score = tcpmodel.predict(behavioral_model)
                        self.print(f' >> sequence: {pre_behavioral_model}. final prediction score: {score[0][0]:.20f}', 5, 0)
                        # get a float instead of numpy array
                        score = score[0][0]
                        if score > threshold:
                            threshold_confidence = 100
                            if len(pre_behavioral_model) >= threshold_confidence:
                                confidence = 1
                            else:
                                confidence = len(pre_behavioral_model)/threshold_confidence
                            self.set_evidence(score,confidence, tupleid, profileid, twid)
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
                self.print('Problem on the run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
