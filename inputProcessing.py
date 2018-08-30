import multiprocessing
import globaldata

# Input Process
class InputProcessing(multiprocessing.Process):
    """ A class process to run the process of the flows """
    def __init__(self, queue, verbose, debug, config):
        multiprocessing.Process.__init__(self)
        self.verbose = verbose
        self.debug = debug
        self.queue = queue
        self.config = config

    def run(self):
        try:
            while True:
                if not self.queue.empty():
                    line = self.queue.get()
                    if 'stop' != line:
                        print(line)
                        print(globaldata.ip_profiles)
                    else:
                        print('other')
                        return True
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            print('\tProblem with Processor()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)
