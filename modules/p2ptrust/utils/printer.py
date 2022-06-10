import multiprocessing


class Printer:
    def __init__(self, output_queue: multiprocessing.Queue, module_name: str):
        self.output_queue = output_queue
        self.name = module_name
        # self.logs_file = "./output/p2ptrust_runtime/pigeon_logs"

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        msg = f'{levels}|{self.name}|{text}'
        self.output_queue.put(msg)
        # with open(self.logs_file,'a') as f:
        #     f.write(f'[p2ptrust] {text}\n')
