from datetime import timedelta
from ipaddress import ip_address
import traceback
from slips_files.common.abstracts.observer import IObservable
from slips_files.core.output import Output

class SymbolHandler(IObservable):
    name = 'SymbolHandler'

    def __init__(self,
                 logger:Output,
                 db):
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
                'from': self.name,
                'txt': text,
                'verbose': verbose,
                'debug': debug
           }
        )
    def compute(
        self,
        flow,
        twid: str,
        tuple_key: str,
    ):
        """
        This function computes the new symbol for the tuple according to the
        original stratosphere IPS model of letters
        Here we do not apply any detection model, we just create the letters
        as one more feature twid is the starttime of the flow
        :param tuple_key: can be 'InTuples' or 'OutTuples'
        return the following tuple (symbol_to_add, (previous_two_timestamps))
        previous_two_timestamps is a tuple with the ts of the last flow, and th ets
        of the flow before the last flow

        """
        daddr_as_obj = ip_address(flow.daddr)
        profileid = f"profile_{flow.saddr}"
        tupleid = f'{daddr_as_obj}-{flow.dport}-{flow.proto}'

        current_duration = flow.dur
        current_size = flow.bytes

        try:
            current_duration = float(current_duration)
            current_size = int(current_size)
            now_ts = float(flow.starttime)
            self.print(
                'Starting compute symbol. Profileid: {}, '
                'Tupleid {}, time:{} ({}), dur:{}, size:{}'.format(
                    profileid,
                    tupleid,
                    twid,
                    type(twid),
                    current_duration,
                    current_size,
                ),3,0
            )
            # Variables for computing the symbol of each tuple
            T2 = False
            TD = False
            # Thresholds learnt from Stratosphere ips first version
            # Timeout time, after 1hs
            tto = timedelta(seconds=3600)
            tt1 = 1.05
            tt2 = 1.3
            tt3 = float(5)
            td1 = 0.1
            td2 = float(10)
            ts1 = float(250)
            ts2 = float(1100)

            # Get the time of the last flow in this tuple, and the last last
            # Implicitely this is converting what we stored as 'now' into 'last_ts' and what we stored as 'last_ts' as 'last_last_ts'
            (last_last_ts, last_ts) = self.db.getT2ForProfileTW(
                profileid, twid, tupleid, tuple_key
            )
            # self.print(f'Profileid: {profileid}. Data extracted from DB. last_ts: {last_ts}, last_last_ts: {last_last_ts}', 0, 5)

            def compute_periodicity(
                        now_ts: float, last_ts: float, last_last_ts: float
                    ):
                """Function to compute the periodicity"""
                zeros = ''
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
                            zeros += '0'

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
                self.print(
                    'Compute Periodicity: Profileid: {}, Tuple: {}, T1={}, '
                    'T2={}, TD={}'.format(
                        profileid, tupleid, T1, T2, TD
                    ),
                    3,
                    0,
                )
                return TD, zeros

            def compute_duration():
                """Function to compute letter of the duration"""
                if current_duration <= td1:
                    return 1
                elif current_duration > td1 and current_duration <= td2:
                    return 2
                elif current_duration > td2:
                    return 3

            def compute_size():
                """Function to compute letter of the size"""
                if current_size <= ts1:
                    return 1
                elif current_size > ts1 and current_size <= ts2:
                    return 2
                elif current_size > ts2:
                    return 3

            def compute_letter():
                """
                Function to compute letter
                based on the periodicity, size, and dur of the flow
                """
                # format of this map is as follows
                # {periodicity: {'size' : {duration: letter, duration: letter, etc.}}
                periodicity_map = {
                    # every key in this dict represents a periodicity
                    '-1': {
                        # every key in this dict is a size 1,2,3
                        # 'size' : {duration: letter, diration: letter, etc.}
                        '1': {'1': '1', '2': '2', '3': '3'},
                        '2': {'1': '4', '2': '5', '3': '6'},
                        '3': {'1': '7', '2': '8', '3': '9'},
                    },
                    '1': {
                        '1': {'1': 'a', '2': 'b', '3': 'c'},
                        '2': {'1': 'd', '2': 'e', '3': 'f'},
                        '3': {'1': 'g', '2': 'h', '3': 'i'},
                    },
                    '2': {
                        '1': {'1': 'A', '2': 'B', '3': 'C'},
                        '2': {'1': 'D', '2': 'E', '3': 'F'},
                        '3': {'1': 'G', '2': 'H', '3': 'I'},
                    },
                    '3': {
                        '1': {'1': 'r', '2': 's', '3': 't'},
                        '2': {'1': 'u', '2': 'v', '3': 'w'},
                        '3': {'1': 'x', '2': 'y', '3': 'z'},
                    },
                    '4': {
                        '1': {'1': 'R', '2': 'S', '3': 'T'},
                        '2': {'1': 'U', '2': 'V', '3': 'W'},
                        '3': {'1': 'X', '2': 'Y', '3': 'Z'},
                    },
                }
                return periodicity_map[str(periodicity)][str(size)][
                    str(duration)
                ]

            def compute_timechar():
                """Function to compute the timechar"""
                # self.print(f'Compute timechar. Profileid: {profileid} T2:
                # {T2}', 0, 5)
                if not isinstance(T2, bool):
                    if T2 <= timedelta(seconds=5).total_seconds():
                        return '.'
                    elif T2 <= timedelta(seconds=60).total_seconds():
                        return ','
                    elif T2 <= timedelta(seconds=300).total_seconds():
                        return '+'
                    elif T2 <= timedelta(seconds=3600).total_seconds():
                        return '*'
                    else:
                        # Changed from 0 to ''
                        return ''
                else:
                    return ''

            # Here begins the function's code
            try:
                # Update value of T2
                T2 = now_ts - last_ts if now_ts and last_ts else False
                # Are flows sorted?
                if T2 < 0:
                    # Flows are not sorted!
                    # What is going on here when the flows are not
                    # ordered?? Are we losing flows?
                    # Put a warning
                    self.print(
                        'Warning: Coming flows are not sorted -> '
                        'Some time diff are less than zero.',
                        0,
                        2,
                    )
            except TypeError:
                T2 = False
            # self.print("T2:{}".format(T2), 0, 1)
            # p = self.db.start_profiling()
            # Compute the rest
            periodicity, zeros = compute_periodicity(
                now_ts, last_ts, last_last_ts
            )
            duration = compute_duration()
            # self.print("Duration: {}".format(duration), 0, 1)
            size = compute_size()
            # self.print("Size: {}".format(size), 0, 1)
            letter = compute_letter()
            # self.print("Letter: {}".format(letter), 0, 1)
            timechar = compute_timechar()
            # self.print("TimeChar: {}".format(timechar), 0, 1)
            self.print(
                'Profileid: {}, Tuple: {}, Periodicity: {}, '
                'Duration: {}, Size: {}, Letter: {}. TimeChar: {}'.format(
                    profileid,
                    tupleid,
                    periodicity,
                    duration,
                    size,
                    letter,
                    timechar,
                ),
                3, 0,
            )
            # p = self.db.end_profiling(p)
            symbol = zeros + letter + timechar
            # Return the symbol, the current time of the flow and the T1 value
            return symbol, (last_ts, now_ts)
        except Exception:
            # For some reason we can not use the output queue here.. check
            self.print('Error in compute_symbol in Profiler Process.',
                       0, 1)
            self.print(traceback.print_stack(), 0, 1)