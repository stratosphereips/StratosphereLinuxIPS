import multiprocessing


class Printer:
    def __init__(self, output_queue: multiprocessing.Queue, module_name: str):
        self.output_queue = output_queue
        self.name = module_name

    def print(self, text: str, verbose: int = 1, debug: int = 0) -> None:
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.output_queue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def err(self, e: str):
        self.print(e, verbose=0)
