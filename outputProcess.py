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

    def process_line(self, line):
        """
        Extract the verbosity level, the sender and the message from the line.
        The line is separated by | and the fields are:
        1. The level
        2. The sender
        3. The message

        The level is always an integer from 0 to 10
        """
        try:
            try:
                level = int(line.split('|')[0])
                if int(level) < 0 or int(level) > 100:
                    level = 0
            except TypeError:
                print('Error in the level sent to the Output Process')
            except KeyError:
                level = 0
                print('The level passed to OutputProcess was wrongly formated.')
            except ValueError as inst:
                # We probably received some text instead of an int()
                print('Error receiving a text to output. Check that you are sending the format of the msg correctly: level|sender|msg')
                print(inst)
                sys.exit(-1)
            try:
                sender = line.split('|')[1]
            except KeyError:
                sender = ''
                print('The sender passed to OutputProcess was wrongly formated.')
            try:
                # If there are more | inside he msg, we don't care, just print them
                msg = ''.join(line.split('|')[2:])
            except KeyError:
                msg = ''
                print('The message passed to OutputProcess was wrongly formated.')
            return (level, sender, msg)
        except Exception as inst:
            print('\tProblem with process line in OutputProcess()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)

    def run(self):
        try:
            while True:
                if not self.queue.empty():
                    line = self.queue.get()
                    if 'stop' != line:
                        (level, sender, msg) = self.process_line(line)
                        if level <= self.verbose:
                            print(msg)
                        # This is to test if we are reading the flows completely
                        if self.debug:
                            self.linesprocessed += 1
                    else:
                        print('Stopping the output thread')
                        return True
        except KeyboardInterrupt:
            if self.debug:
                print('Lines processed in output: {}'.format(self.linesprocessed))
            return True
        except Exception as inst:
            print('\tProblem with OutputProcess()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)
