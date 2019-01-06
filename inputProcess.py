import multiprocessing
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
            lines = 0
            # Check if the input its a file or stdinput
            if type(self.datainput) == str:
                # Its a File
                filed = open(self.datainput)
                try:
                    line  = filed.readline()
                except EOFError:
                    return True
                while line != '':
                    # While the input communication queue is empty
                    if self.inputqueue.empty():
                        # Send the line to the profiler
                        self.profilerqueue.put(line)
                        lines += 1
                        try:
                            line  = filed.readline()
                        except EOFError:
                            return True
                    else:
                        # The communication queue is not empty. So process it
                        line = self.inputqueue.get()
                        if 'stop' == line:
                            print('Stopping Input Process')
                            print('Sent {} lines'.format(lines))
                            return True
                # Now this is disable because the output does not know how to handle a 'stop' while still receiving lines. We don't know how to wait a little for
                # the input to finish
                # When the file ends, finish everything
                #if line == '':
                #    self.outputqueue.put("stop")
            else:
                # The input is not str, so it may/should be standard input
                lines = 0
                while True:
                    if self.inputqueue.empty():
                        # While the communication queue is empty, we can read from the file/input
                        for line in self.datainput:
                            self.outputqueue.put("30|input|Sent Line: {}".format(line))
                            self.profilerqueue.put(line)
                            lines += 1
                    else:
                        # The communication queue is not empty process
                        line = self.inputqueue.get()
                        if 'stop' == line:
                            print('Sent {} lines'.format(lines))
                            print('Stopping Input Process')
                            return True
        except KeyboardInterrupt:
            print('Sent {} lines'.format(lines))
            print('Stopping Input Process')
            return True
        except Exception as inst:
            print('Sent {} lines'.format(lines))
            print('Stopping Input Process')
            print('\tProblem with Input Process()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)
