import multiprocessing
import globaldata
import sys

# Input Process
class InputProcess(multiprocessing.Process):
    """ A class process to run the process of the flows """
    def __init__(self, inputqueue, outputqueue, profilerqueue, verbose, debug, stdin, config):
        multiprocessing.Process.__init__(self)
        self.verbose = verbose
        self.debug = debug
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.profilerqueue = profilerqueue
        self.config = config
        self.stdin = stdin

    def run(self):
        try:
            while True:
                # While the communication queue is empty
                if self.inputqueue.empty():
                        for line in self.stdin:
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
