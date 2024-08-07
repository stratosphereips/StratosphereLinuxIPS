from datetime import timedelta
from ipaddress import ip_address
import traceback
from slips_files.common.abstracts.observer import IObservable
from slips_files.core.output import Output


class SymbolHandler(IObservable):
    name = "SymbolHandler"

    def __init__(self, logger: Output, db):
        IObservable.__init__(self)
        self.db = db
        self.logger = logger
        self.add_observer(self.logger)

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
        :param text: text to print. Can include format like f'Test {here}'
        """
        self.notify_observers(
            {
                "from": self.name,
                "txt": text,
                "verbose": verbose,
                "debug": debug,
            }
        )

    def compute_periodicity(
        self,
        now_ts: float,
        last_ts: float,
        last_last_ts: float,
        tto: timedelta,
        tt1: float,
        tt2: float,
        tt3: float,
    ):
        """Function to compute the periodicity"""
        zeros = ""
        if last_last_ts is False or last_ts is False:
            TD = -1
            T1 = None
            T2 = None
        else:
            # Time diff between the past flow and the past-past flow.
            T1 = last_ts - last_last_ts
            # Time diff between the current flow and the past flow.
            # We already computed this before, but we can do it here
            # again just in case
            T2 = now_ts - last_ts
            # We have a time out of 1hs. After that, put 1 number 0
            # for each hs
            # It should not happen that we also check T1... right?
            if T2 >= tto.total_seconds():
                t2_in_hours = T2 / tto.total_seconds()
                # Shoud round it. Because we need the time to pass to
                # really count it
                # For example:
                # 7100 / 3600 =~ 1.972  ->  int(1.972) = 1
                for i in range(int(t2_in_hours)):
                    # Add the zeros to the symbol object
                    zeros += "0"

            # Compute TD
            try:
                TD = T2 / T1 if T2 >= T1 else T1 / T2
            except ZeroDivisionError:
                TD = 1

            # Decide the periodic based on TD and the thresholds
            if TD <= tt1:
                # Strongly periodicity
                TD = 1
            elif TD <= tt2:
                # Weakly periodicity
                TD = 2
            elif TD <= tt3:
                # Weakly not periodicity
                TD = 3
            elif TD > tt3:
                # Strongly not periodicity
                TD = 4

        return TD, zeros, T2

    def compute_duration(
        self, current_duration: float, td1: float, td2: float
    ):
        """Function to compute letter of the duration"""
        if current_duration <= td1:
            return 1
        elif td1 < current_duration <= td2:
            return 2
        else:
            return 3

    def compute_size(self, current_size: int, ts1: float, ts2: float):
        """Function to compute letter of the size"""
        if current_size <= ts1:
            return 1
        elif ts1 < current_size <= ts2:
            return 2
        else:
            return 3

    def compute_letter(self, periodicity: int, size: int, duration: int):
        """
        Function to compute letter based on the periodicity, size, and duration of the flow
        """
        # format of this map is as follows
        # {periodicity: {'size' : {duration: letter, duration: letter, etc.}}
        periodicity_map = {
            # every key in this dict represents a periodicity
            "-1": {
                # every key in this dict is a size 1,2,3
                # 'size' : {duration: letter, diration: letter, etc.}
                "1": {"1": "1", "2": "2", "3": "3"},
                "2": {"1": "4", "2": "5", "3": "6"},
                "3": {"1": "7", "2": "8", "3": "9"},
            },
            "1": {
                "1": {"1": "a", "2": "b", "3": "c"},
                "2": {"1": "d", "2": "e", "3": "f"},
                "3": {"1": "g", "2": "h", "3": "i"},
            },
            "2": {
                "1": {"1": "A", "2": "B", "3": "C"},
                "2": {"1": "D", "2": "E", "3": "F"},
                "3": {"1": "G", "2": "H", "3": "I"},
            },
            "3": {
                "1": {"1": "r", "2": "s", "3": "t"},
                "2": {"1": "u", "2": "v", "3": "w"},
                "3": {"1": "x", "2": "y", "3": "z"},
            },
            "4": {
                "1": {"1": "R", "2": "S", "3": "T"},
                "2": {"1": "U", "2": "V", "3": "W"},
                "3": {"1": "X", "2": "Y", "3": "Z"},
            },
        }
        return periodicity_map[str(periodicity)][str(size)][str(duration)]

    def compute_timechar(self, T2):
        """Function to compute the timechar"""
        # self.print(f'Compute timechar. Profileid: {profileid} T2:
        # {T2}', 0, 5)
        if not isinstance(T2, bool):
            if T2 <= timedelta(seconds=5).total_seconds():
                return "."
            elif T2 <= timedelta(seconds=60).total_seconds():
                return ","
            elif T2 <= timedelta(seconds=300).total_seconds():
                return "+"
            elif T2 <= timedelta(seconds=3600).total_seconds():
                return "*"
            else:
                return ""
        else:
            return ""

    def compute(self, flow, twid: str, tuple_key: str):
        """
        This function computes the new symbol for the tuple according to the
        original stratosphere IPS model of letters
        Here we do not apply any detection model, we just create the letters
        as one more feature twid is the starttime of the flow
        :param tuple_key: can be 'InTuples' or 'OutTuples'
        return the following tuple (symbol_to_add, (previous_two_timestamps))
        previous_two_timestamps is a tuple with the ts of the last flow, and the ts
        of the flow before the last flow
        """
        daddr_as_obj = ip_address(flow.daddr)
        profileid = f"profile_{flow.saddr}"
        tupleid = f"{daddr_as_obj}-{flow.dport}-{flow.proto}"

        current_duration = float(flow.dur)
        current_size = int(flow.bytes)
        now_ts = float(flow.starttime)

        try:
            self.print(
                f"Starting compute symbol. Profileid: {profileid}, "
                f"Tupleid {tupleid}, time:{twid} ({type(twid)}), dur:{current_duration}, size:{current_size}",
                3,
                0,
            )

            # Thresholds learnt from Stratosphere ips first version
            tto = timedelta(seconds=3600)
            tt1, tt2, tt3 = 1.05, 1.3, 5.0
            td1, td2 = 0.1, 10.0
            ts1, ts2 = 250.0, 1100.0

            (last_last_ts, last_ts) = self.db.get_t2_for_profile_tw(
                profileid, twid, tupleid, tuple_key
            )

            periodicity, zeros, T2 = self.compute_periodicity(
                now_ts, last_ts, last_last_ts, tto, tt1, tt2, tt3
            )
            duration = self.compute_duration(current_duration, td1, td2)
            size = self.compute_size(current_size, ts1, ts2)
            letter = self.compute_letter(periodicity, size, duration)
            timechar = self.compute_timechar(T2)

            self.print(
                f"Profileid: {profileid}, Tuple: {tupleid}, Periodicity: {periodicity}, "
                f"Duration: {duration}, Size: {size}, Letter: {letter}. TimeChar: {timechar}",
                3,
                0,
            )

            symbol = zeros + letter + timechar
            return symbol, (last_ts, now_ts)

        except Exception:
            self.print("Error in compute_symbol in Profiler Process.", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
