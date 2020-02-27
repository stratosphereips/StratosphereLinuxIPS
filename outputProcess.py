import multiprocessing
import sys


# Output Process
class OutputProcess(multiprocessing.Process):
    """ A class process to output everything we need. Manages all the output """
    def __init__(self, inputqueue, verbose, debug, config):
        multiprocessing.Process.__init__(self)
        self.verbose = verbose
        self.debug = debug
        self.queue = inputqueue
        self.config = config
        # self.quiet manages if we should really print stuff or not
        self.quiet = False
        if self.verbose > 2:
            print('Verbosity: {}. Debugging: {}'.format(str(self.verbose), str(self.debug)))

    def process_line(self, line):
        """
        Extract the verbosity level, the sender and the message from the line.
        The line is separated by | and the fields are:
        1. The level. It means the importance/verbosity we should be. Going from 0 to 100. The lower the less important
            From 0 to 9 we have verbosity levels. 0 is show nothing, 10 show everything
            From 10 to 19 we have debuging levels. 10 is no debug, 19 is all debug
            Messages should be about verbosity or debugging, but not both simultaneously
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
                sys.exit(-1)
            try:
                # If there are more | inside he msg, we don't care, just print them
                msg = ''.join(line.split('|')[2:])
            except KeyError:
                msg = ''
                print('The message passed to OutputProcess was wrongly formated.')
                sys.exit(-1)
            return (level, sender, msg)
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            print('\tProblem with process line in OutputProcess()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)

    def output_line(self, line):
        """ Get a line of text and output it correctly """
        (level, sender, msg) = self.process_line(line)
        verbose_level = int(int(level) / 10)
        debug_level = int(int(level) - (verbose_level * 10))
        # There should be a level 0 that we never print. So its >, and not >=
        if verbose_level > 0 and verbose_level <= 9 and verbose_level <= self.verbose:
            print(msg)
        elif debug_level > 0 and debug_level <= 9 and debug_level <= self.debug:
            # For now print DEBUG, then we can use colors or something
            print(msg)
        # This is to test if we are reading the flows completely

    def run(self):
        try:
            while True:
                line = self.queue.get()
                if 'quiet' == line:
                    self.quiet = True
                # if timewindows are not updated for 25 seconds, we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                elif 'stop_process' in line:
                    return True
                elif 'stop' != line:
                    if not self.quiet:
                        self.output_line(line)

                else:
                    # Here we should still print the lines coming in the input for a while after receiving a 'stop'. We don't know how to do it.
                    print('Stopping the output thread')
                    return True
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            print('\tProblem with OutputProcess()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)
