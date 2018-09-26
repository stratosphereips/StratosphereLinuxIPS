import multiprocessing
import globaldata
import sys

# Input Process
class InputProcess(multiprocessing.Process):
    """ A class process to run the process of the flows """
    def __init__(self, inputqueue, outputqueue, profilerqueue, datainput, config):
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.profilerqueue = profilerqueue
        self.config = config
        self.datainput = datainput

    def run(self):
        try:
            # Check if the input its a file or stdinput
            if type(self.datainput) == str:
                # Its a File
                filed = open(self.datainput)
                try:
                    line  = filed.readline()
                except EOFError:
                    return True
                while True:
                    # While the communication queue is empty
                    if self.inputqueue.empty():
                        self.profilerqueue.put(line)
                        try:
                            line  = filed.readline()
                        except EOFError:
                            return True
                    else:
                        # The communication queue is not empty process
                        line = self.inputqueue.get()
                        if 'stop' == line:
                            print('Stopping Input Process')
                            return True
            else:
                print(type(self.datainput))
                # Std input
                while True:
                    # While the communication queue is empty
                    if self.inputqueue.empty():
                            for line in self.datainput:
                                self.profilerqueue.put(line)
                    else:
                        # The communication queue is not empty process
                        line = self.inputqueue.get()
                        if 'stop' == line:
                            print('Stopping Input Process')
                            return True
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            print('\tProblem with Input Process()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)
