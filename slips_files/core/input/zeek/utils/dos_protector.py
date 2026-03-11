import time


class DoSProtector:
    def __init__(self, db):
        self.db = db
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        # is slips (input.py) is given > this number of flow per min,
        # this protector runs
        self.flows_per_min_threshold = 2000
        self.flow_sampling_stop_time = 0

    def get_sampling_ratio(self) -> int:
        """
        sr = flow_per_min² / 20000
        this sr is the number of flows we're gonna skip to protect slips
        from DoS (or high traffic in general)
        """
        ...

    def should_run(self) -> bool:
        """
        Returns true if slips is under high traffic and the DoS protector
        should run.
        """
        if not self.is_running_non_stop:
            return False

        input_flows_per_s = (
            self.db.get_core_module_flows_per_second("Input") or 0
        )
        input_flows_per_min = input_flows_per_s * 60

        should_run: bool = input_flows_per_min > self.flows_per_min_threshold

        # flow sampling is going to take place for the next 1 min
        if should_run:
            self.flow_sampling_stop_time = time.time() + 60
            # sr = self.get_sampling_ratio()

    def get_number_of_flows_to_skip(self) -> int:
        """
        returns the number of flows to skip based on a sampling rate
        """
        if time.time() < self.flow_sampling_stop_time:
            # sample
            ...
        else:
            # if flow_sampling_stop_time has passed, stop sampling,
            # read all flows
            return 0
