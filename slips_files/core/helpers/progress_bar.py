from multiprocessing import Process, Pipe
from tqdm.auto import tqdm
import sys

class PBar(Process):
    def __init__(self, pipe: Pipe, has_bar, stdout: str):
        self.pipe: Pipe = pipe
        self.stdout = stdout
        # this is a shared obj using mp Manager
        # using mp manager to be able to change this value
        # here and and have it changed in the Output.py
        Process.__init__(self)

        self.has_pbar = has_bar
        if not self.unknown_total_flows():
            self.has_pbar.value = True

    @staticmethod
    def unknown_total_flows() -> bool:
        """
        When running on a pcap, interface, or taking flows from an
        external module, the total amount of flows is unknown
        """
        # todo add pcaps here!

        # whenever any of those is present, slips won't be able to get the
        # total flows when starting, nor init the progress bar
        params = ('-g', '--growing',
                  '-im', '--input_module',
                  '-i', '--interface')
        for param in params:
            if param in sys.argv:
                return True

    def remove_stats(self):
        # remove the stats from the progress bar
        self.progress_bar.set_postfix_str(
            '',
            refresh=True
        )


    def init(self, msg: dict):
        """
        initializes the progress bar when slips is runnning on a file or a zeek dir
        ignores pcaps, interface and dirs given to slips if -g is enabled
        :param bar: dict with input type, total_flows, etc.
        """
        if self.unknown_total_flows():
            # we don't know how to get the total number of flows slips is going to process,
            # because they're growing
            return

        if self.stdout != '':
            # this means that stdout was redirected to a file,
            # no need to print the progress bar
            return

        self.total_flows = int(msg['total_flows'])
        # the bar_format arg is to disable ETA and unit display
        # dont use ncols so tqdm will adjust the bar size according to the terminal size
        self.progress_bar = tqdm(
            total=self.total_flows,
            leave=True,
            colour="green",
            desc="Flows read",
            mininterval=0, # defines how long to wait between each refresh.
            unit=' flow',
            smoothing=1,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} {postfix}",
            position=0,
            initial=0, #initial value of the flows processed
            file=sys.stdout,
        )



    def update_bar(self):
        """
        wrapper for tqdm.update()
        adds 1 to the number of flows processed
        """
        if not self.progress_bar:
            # this module wont have the progress_bar set if it's running on pcap or interface
            # or if the output is redirected to a file!
            return

        if self.slips_mode == 'daemonized':
            return

        self.progress_bar.update(1)
        if self.progress_bar.n == self.total_flows:
            self.remove_stats()
            self.print(self.name,
                       "Done reading all flows. Slips is now processing them.")
            # remove it from the bar because we'll be prining it in a new line
            self.done_reading_flows = True
        # Output.progress_bar.refresh()

    def terminate(self):
        #TODO store the pid of this process somewhere
        # and handle it's termination'
        ...

    def print(self, msg: dict):
        """
        prints using tqdm in order to avoid conflict with the pbar
        """
        tqdm.write(msg['txt'])


    def update_stats(self, msg: dict):
        """writes the stats sent in the msg as a pbar postfix"""
        self.progress_bar.set_postfix_str(
            msg['stats'],
            refresh=True
        )

    def run(self):
        while True and self.has_pbar.value:
            msg: dict = self.pipe.recv()
            event: str = msg['event']
            if event == "init":
                self.init(msg)

            if event == "update_bar":
                self.update_bar()

            if event == "update_stats":
                self.update_stats(msg)


            if event == "terminate":
                self.terminate()

            if event == "print":
                # let tqdm do th eprinting to avoid conflicts with the pbar
                self.print(msg)
