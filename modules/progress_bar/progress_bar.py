from multiprocessing.connection import Connection
from multiprocessing import Event
from tqdm.auto import tqdm
import sys

from slips_files.common.abstracts.module import IModule


class PBar(IModule):
    """
    Here's why this class is run in a separate process
    we need all modules to have access to the pbar.
    so for example, profile is the one always initializing the pbar,
    when this class isn't run as a proc, profiler would be the only proc
    that "knows" about the pbar
    because it initialized it right?
    now when any txt is sent to be printed by the output proc by anyone
    other than the profiler
    the output proc would print it on top of the pbar! and we'd get duplicate
    bars!

    the solution to this is to make the pbar a separate proc
    whenever it's supported, the output.py will forward all txt to be printed
    to this class, and this class would handle the printing nicely
    so that nothing will overlap with the pbar
    once the pbar is done, this proc sets the has_pbar shared var to Flase
    and output.py would know about it and print txt normally
    """

    name = "Progress Bar"
    description = "Shows a pbar of processed flows"
    authors = ["Alya Gomaa"]

    def init(
        self,
        pipe: Connection = None,
        slips_mode: str = None,
        pbar_finished: Event = None,
    ):
        self.slips_mode: str = slips_mode
        # the sender end of this pipe is at output.py
        self.pipe = pipe
        self.done_reading_flows = False
        self.pbar_finished: Event = pbar_finished

    def remove_stats(self):
        # remove the stats from the progress bar
        self.progress_bar.set_postfix_str("", refresh=True)

    def initialize_pbar(self, msg: dict):
        """
        initializes the progress bar when slips is runnning on a file or
         a zeek dir
        ignores pcaps, interface and dirs given to slips if -g is enabled
        """
        self.total_flows = int(msg["total_flows"])
        # the bar_format arg is to disable ETA and unit display
        # dont use ncols so tqdm will adjust the bar size according to the
        # terminal size
        self.progress_bar = tqdm(
            total=self.total_flows,
            leave=True,
            colour="green",
            desc="Flows Processed",
            mininterval=0,  # defines how long to wait between each refresh.
            unit=" flow",
            smoothing=1,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} {postfix}",
            position=0,
            initial=0,  # initial value of the flows processed
            file=sys.stdout,
        )

    def update_bar(self):
        """
        wrapper for tqdm.update()
        adds 1 to the number of flows processed
        """

        if not hasattr(self, "progress_bar"):
            # this module wont have the progress_bar set if it's running
            # on pcap or interface
            # or if the output is redirected to a file!
            return

        if self.slips_mode == "daemonized":
            return

        self.progress_bar.update(1)

    def print_to_cli(self, msg: dict):
        """
        prints using tqdm in order to avoid conflict with the pbar
        """
        tqdm.write(msg["txt"])

    def update_stats(self, msg: dict):
        """writes the stats sent in the msg as a pbar postfix"""
        self.progress_bar.set_postfix_str(msg["stats"], refresh=True)

    def should_stop(self) -> bool:
        """
        overrides IModule.should_stop()
        Returns true if the pbar reached 100%
        """
        if hasattr(self, "progress_bar"):
            return self.progress_bar.n == self.total_flows
        return False

    def shutdown_gracefully(self):
        # remove it from the bar because output.py will be handling it from
        # now on
        self.remove_stats()
        tqdm.write(
            "Profiler is done reading all flows. "
            "Slips is now processing them."
        )
        # the purpose of this pbar_finished Event is to tell output.py to no
        # longer forward msgs to print here
        self.pbar_finished.set()

    def main(self):
        """
        keeps receiving events until pbar reaches 100%
        """
        # the only module that sends in this pipe is output.py
        has_new_msg = self.pipe.poll(timeout=0.1)
        if has_new_msg:
            try:
                msg: dict = self.pipe.recv()
            except UnicodeDecodeError as e:
                self.print(
                    f"Unable to recv from pipe, msg discarded. {e}", 0, 1
                )
                return False

            event: str = msg["event"]
            if event == "init":
                self.initialize_pbar(msg)

            if event == "update_bar":
                self.update_bar()

            if event == "update_stats":
                self.update_stats(msg)

            if event == "print":
                # let tqdm do the printing to avoid conflicts with the pbar
                self.print_to_cli(msg)
