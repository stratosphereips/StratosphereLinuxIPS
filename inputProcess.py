import multiprocessing
import globaldata
import sys

# Input Process
class InputProcess(multiprocessing.Process):
    """ A class process to run the process of the flows """
    def __init__(self, inputqueue, outputqueue, profilerqueue, input, config):
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.profilerqueue = profilerqueue
        self.config = config
        self.input = input

    def run(self):
        try:
            if type(self.input) == str:
                filed = open(self.input)
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
                while True:
                    # While the communication queue is empty
                    if self.inputqueue.empty():
                            for line in self.input:
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
