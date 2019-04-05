import multiprocessing
import sys
import os
from datetime import datetime

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
            if not self.datainput:
                # By default read the stdin
                sys.stdin.close()
                sys.stdin = os.fdopen(0, 'r')
                file_stream = sys.stdin

            # If we were given a filename, manage the input from a file instead
            elif self.datainput:
                file_stream = open(self.datainput)

            for line in file_stream:
                self.outputqueue.put("03|input|[In]      > Sent Line: {}".format(line.replace('\n','')))
                self.profilerqueue.put(line)
                lines += 1

            self.profilerqueue.put("stop")
            self.outputqueue.put("01|input|[In] No more input. Stopping input process. Sent {} lines ({}).".format(lines, datetime.now().strftime('%Y-%m-%d--%H:%M:%S')))

            self.outputqueue.close()
            self.profilerqueue.close()

            return True

        except KeyboardInterrupt:
            self.outputqueue.put("04|input|[In] No more input. Stopping input process. Sent {} lines".format(lines))
            return True
        except Exception as inst:
            self.outputqueue.put("04|input|[In] No more input. Stopping input process. Sent {} lines".format(lines))
            self.outputqueue.put("01|input|Problem with Input Process.")
            self.outputqueue.put("01|input|" + type(inst))
            self.outputqueue.put("01|input|" + inst.args)
            self.outputqueue.put("01|input|" + inst)
            sys.exit(1)
