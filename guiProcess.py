import multiprocessing
import configparser
import platform
import os

# Gui Process
class GuiProcess(multiprocessing.Process):
    """ 
    The Gui process is only meant to start the Kalipso interface
    """
    def __init__(self, inputqueue, outputqueue, verbose, debug, config):
        self.myname = 'Gui'
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.config = config
        # Read the configuration
        self.read_configuration()
        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # now linux also needs to be non-negative
            self.timeout = -1
        else:
            #??
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
        self.outputqueue.put(vd_text + '|' + self.myname + '|[' + self.myname + '] ' + str(text))

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the format of the time in the flows
        pass

    def run(self):
        try:
            os.system('cd modules/kalipso;node kalipso.js')
        except KeyboardInterrupt:
            self.print('Stoppting the Gui Process')
            return True
        except Exception as inst:
            self.print('Error in the Gui Process')
            self.print(type(inst))
            self.print(inst)
            return True
