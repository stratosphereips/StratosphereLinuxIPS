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
from keras.utils import to_categorical

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

    def set_evidence(self, score, tupleid='', profileid='', twid=''):
        '''
        Set an evidence for malicious IP met in the timewindow
        If profileid is None, do not set an Evidence
        Returns nothing
        '''
        type_evidence = 'C&C channels detection'
        key = 'outTuple' + ':' + tupleid + ':' + type_evidence
        threat_level = 50
        confidence = 1
        description = 'LSTM C&C channels detection, score: ' + str(score)
        __database__.setEvidence(key, threat_level, confidence, description, profileid=profileid, twid=twid)

    def convert_input_for_module(self, pre_behavioral_model):
        """ 
        Takes the input from the letters and converts them 
        to whatever is needed by the model 
        The pre_behavioral_model is a 1D array of letters in an array
        """

        # Length of behavioral model with which we trained our module
        max_length = 500
        # str_to_ascii = lambda i: [ord(x) for x in i]
        # behavioral_model = str_to_ascii(behavioral_model)
        # Convert the string into a list and then into a numpy array
        pre_behavioral_model = np.array(list(pre_behavioral_model))
        #print(f'1 BM: {pre_behavioral_model}')

        # Convert each of the stratosphere letters to an integer. There are 50
        vocabulary = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ',', '.', '+', '*']
        int_of_letters = {}
        for i, letter in enumerate(vocabulary):
            int_of_letters[letter] = i
        # vocabulary_size = len(int_of_letters)
        # Convert each of the letters in the model into the integer
        convert_to_int = lambda x : [int_of_letters[i] for i in x]
        pre_behavioral_model = np.array(convert_to_int(pre_behavioral_model), ndmin=2)
        #print(f'2 BM: {pre_behavioral_model}')
        # Now  the pre_behavioral_model is a list of ints
        # Padd the list to 500
        pre_behavioral_model = np.array(pad_sequences(pre_behavioral_model, maxlen=max_length, padding='post'))
        #print(f'3 BM: {pre_behavioral_model}')
        #print(type(pre_behavioral_model))
        #print(pre_behavioral_model.shape)

        # Convert to one-hot encoding
        pre_behavioral_model_oh = np.empty((pre_behavioral_model.shape[0], 500, 50))
        for i, a_list in enumerate(pre_behavioral_model):
            pre_behavioral_model_oh[i] = to_categorical(a_list, num_classes=50)
        #print(f'4 BM: {pre_behavioral_model_oh}')
        return pre_behavioral_model_oh

    def run(self):
        try:
            # Download lstm model
            model = load_model('modules/lstm-cc-detection-1/detection_model.h5')
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message['data'] == 'stop_process':
                    return True
                if message['channel'] == 'new_letters' and type(message['data']) is not int:
                    # Define why this threshold
                    threshold = 0.8
                    data = message['data']
                    data = data.split('-')
                    pre_behavioral_model = data[0]
                    profileid = data[1]
                    twid = data[2]
                    tupleid = data[3]
                    # Function to convert each letter of behavioral model to ascii
                    behavioral_model = self.convert_input_for_module(pre_behavioral_model)
                    # Predict the score of behavioral model being C&C channel
                    print('a')
                    score = model.predict(behavioral_model, verbose=2)
                    print('b')
                    # get a float instead of numpy array
                    print(score)
                    print(type(score))
                    score = score.item()
                    print('c')
                    if score > threshold:
                        self.set_evidence(score, tupleid, profileid, twid)
                    print('d')

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
