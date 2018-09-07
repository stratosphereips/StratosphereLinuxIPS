import multiprocessing
import globaldata
import sys

# Output Process
class OutputProcess(multiprocessing.Process):
    """ A class process to output everything we need. Manages all the output """
    def __init__(self, queue, verbose, debug, config):
        multiprocessing.Process.__init__(self)
        self.verbose = verbose
        self.debug = debug
        self.queue = queue
        self.config = config
        self.linesprocessed = 0

    def run(self):
        try:
            while True:
                if not self.queue.empty():
                    line = self.queue.get()
                    if 'stop' != line:
                        print(line)
                        self.linesprocessed += 1
                    else:
                        print('Stopping the output thread')
                        return True
        except KeyboardInterrupt:
            print('Lines processed in output: {}'.format(self.linesprocessed))
            return True
        except Exception as inst:
            print('\tProblem with OutputProcessing()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)
