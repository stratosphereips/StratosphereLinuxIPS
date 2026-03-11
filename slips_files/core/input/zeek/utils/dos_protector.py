import time


class DoSProtector:
    def __init__(self, db):
        self.db = db
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        # is slips (input.py) is given > this number of flow per min,
        # this protector runs
        self.flows_per_min_threshold = 2000
        self.flow_sampling_stop_time = 0
        # number of seconds slips is going to be skipping flows for before
        # returning to normal (aka before going back to reading all flows)
        self.sampling_time_window = 60

    def _get_input_flows_per_min(self) -> int:
        input_flows_per_s = (
            self.db.get_core_module_flows_per_second("Input") or 0
        )
        input_flows_per_min = input_flows_per_s * 60
        return input_flows_per_min

    def _get_sampling_ratio(self) -> int:
        """
        sr = flow_per_min² / 20000
        this sr is the number of flows we're gonna skip to protect slips
        from DoS (or high traffic in general)
        """
        input_flows_per_min = self._get_input_flows_per_min()
        if not input_flows_per_min:
            return 1

        return input_flows_per_min**2 / 20000

    def _should_run(self) -> bool:
        """
        Returns true if slips is under high traffic and the DoS protector
        should run.
        Runs only when analysing an interface or a growing zeek dir.
        return True if:
        1. if high traffic is detected
        2. we're in the 1 min window after slips has detected a high
        traffic. this is the 1 min of skipping flows before rechecking if
        the read number of flows has decreased.
        """
        if not self.is_running_non_stop:
            return False

        if time.time() < self.flow_sampling_stop_time:
            # we should still be sampling.
            return True

        input_flows_per_min = self._get_input_flows_per_min()
        return input_flows_per_min > self.flows_per_min_threshold

    def _update_flow_sampling_stop_time_if_needed(self):
        """
        sets the next stop time to
        now +  sampling_time_window
        if the time now exceeded the last registered flow_sampling_stop_time
        """
        if time.time() > self.flow_sampling_stop_time:
            # flow sampling is going to take place for the next 1 min
            self.flow_sampling_stop_time = (
                time.time() + self.sampling_time_window
            )

    def get_number_of_flows_to_skip(self) -> int:
        if not self._should_run():
            return 0

        self._update_flow_sampling_stop_time_if_needed()

        # -1 means read 1 flow every sampling_ratio flows.
        # at 2000 flows/min → sr = 200, read 1 flow every 200 flows
        # at 3000 flows/min → sr = 450, read 1 flow every 450 flows
        # at 4000 flows/min → sr = 800, etc.
        return self._get_sampling_ratio() - 1
