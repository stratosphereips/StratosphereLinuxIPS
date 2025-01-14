# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from datetime import timedelta
from ipaddress import ip_address
import traceback
from slips_files.common.printer import Printer
from slips_files.core.output import Output


class SymbolHandler:
    name = "SymbolHandler"

    def __init__(self, logger: Output, db):
        self.printer = Printer(logger, self.name)
        self.db = db

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def compute_periodicity(
        self,
        now_ts: float,
        last_ts: float,
        last_last_ts: float,
        tto: timedelta,
        tt1: float,
        tt2: float,
        tt3: float,
        profileid: str,
        tupleid: str,
    ):
        zeros = ""
        if last_last_ts is False or last_ts is False:
            TD = -1
            T1 = None
            T2 = None
        else:
            T1 = last_ts - last_last_ts
            T2 = now_ts - last_ts

            if T2 >= tto.total_seconds():
                t2_in_hours = T2 / tto.total_seconds()
                for i in range(int(t2_in_hours)):
                    zeros += "0"

            try:
                TD = T2 / T1 if T2 >= T1 else T1 / T2
            except ZeroDivisionError:
                TD = 1

            if TD <= tt1:
                TD = 1
            elif TD <= tt2:
                TD = 2
            elif TD <= tt3:
                TD = 3
            elif TD > tt3:
                TD = 4

        self.print(
            f"Compute Periodicity: Profileid: {profileid}, Tuple: {tupleid}, T1={T1}, "
            f"T2={T2}, TD={TD}",
            3,
            0,
        )
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

    def compute_timechar(self, t2):
        if t2 and not isinstance(t2, bool):
            time_thresholds = [(5, "."), (60, ","), (300, "+"), (3600, "*")]

            # Loop through thresholds and return the corresponding time character
            for threshold, char in time_thresholds:
                if t2 <= timedelta(seconds=threshold).total_seconds():
                    return char

        # Return empty string if no conditions are met
        return ""

    def compute(self, flow, twid: str, tuple_key: str):
        """
        This function computes the new symbol for the tuple according to the
        original stratosphere IPS model of letters
        Here we do not apply any detection model, we just create the letters
        as one more feature twid is the starttime of the flow
        :param tuple_key: can be 'InTuples' or 'OutTuples'
        return the following tuple (symbol_to_add, (previous_two_timestamps))
        previous_two_timestamps is a tuple with the ts of the last flow,
        and the ts of the flow before the last flow
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

            tto = timedelta(seconds=3600)
            tt1, tt2, tt3 = 1.05, 1.3, 5.0
            td1, td2 = 0.1, 10.0
            ts1, ts2 = 250.0, 1100.0

            (last_last_ts, last_ts) = self.db.get_t2_for_profile_tw(
                profileid, twid, tupleid, tuple_key
            )

            periodicity, zeros, T2 = self.compute_periodicity(
                now_ts,
                last_ts,
                last_last_ts,
                tto,
                tt1,
                tt2,
                tt3,
                profileid,
                tupleid,
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
