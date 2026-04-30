import time

from slips_files.common.slips_utils import utils
from slips_files.common.style import green


class DoSProtector:
    def __init__(self, input):
        self.input = input
        self.db = self.input.db
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        # is slips (input.py) is given > this number of flow per min,
        # this protector runs
        self.flows_per_min_threshold = 20000
        self.flow_sampling_stop_time = 0
        # number of seconds slips is going to be skipping flows for before
        # returning to normal (aka before going back to reading all flows)
        self.sampling_time_window = 60
        self._is_now_sampling = False

    def _get_input_flows_per_min(self) -> int:
        input_flows_per_s = (
            self.db.get_core_module_flows_per_second("Input") or 0
        )
        input_flows_per_min = int(input_flows_per_s) * 60
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
        should_skip_flows = input_flows_per_min > self.flows_per_min_threshold

        if self._is_now_sampling and input_flows_per_min == 0:
            # this means we justtt stopped sampling, now we want slips to
            # keep thinking thta it's in a sampling state until we get a
            # input_flows_per_min = something, once we have a number we can
            # decide whether to stop sampling or not, but until then we want to keep the sampling state
            pass
        elif (
            not should_skip_flows
            and self._is_now_sampling
            and input_flows_per_min
        ):
            # slips was sampling and now stopped officially stopped,
            # we have a input_flows_per_min that's less than the threshold.
            self._is_now_sampling = False
            self.input.print(
                f"Throughput is back to normal. Input "
                f"flows/min = {green(input_flows_per_min)}. "
                f"Slips stopped skipping flows."
            )

        return should_skip_flows

    def _update_flow_sampling_stop_time_if_needed(self) -> bool:
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
            return True
        return False

    def get_number_of_flows_to_skip(self) -> int:
        if not self._should_run():
            return 0

        sampling_time_updated = (
            self._update_flow_sampling_stop_time_if_needed()
        )

        # -1 means read 1 flow every sampling_ratio flows.
        # at 2000 flows/min → sr = 200, read 1 flow every 200 flows
        # at 3000 flows/min → sr = 450, read 1 flow every 450 flows
        # at 4000 flows/min → sr = 800, etc.
        sampling_ratio = int(self._get_sampling_ratio() - 1)
        self.print_skipping_flows_warning(
            sampling_ratio, sampling_time_updated
        )

        return sampling_ratio

    def print_skipping_flows_warning(
        self, sampling_ratio: int, sampling_time_updated: bool
    ):
        """Prints a warning every time slips decides to start sampling
        again"""
        if sampling_time_updated and sampling_ratio:
            sr = green(f"1/{sampling_ratio}")
            human_readable_time_to_stop_sampling = utils.convert_ts_format(
                self.flow_sampling_stop_time, utils.alerts_format
            )
            green_time_to_stop_sampling = green(
                human_readable_time_to_stop_sampling
            )
            if self._is_now_sampling:
                # slips decided to extend the sampling period
                self.input.print(
                    f"Slips is still under high "
                    f"traffic. The time to stop sampling has been extended to "
                    f"{green_time_to_stop_sampling} "
                )
            else:
                # reaching here means slips decided again to start sampling flows
                self.input.print(
                    f"Slips started skipping flows due to high "
                    f"traffic for DoS protection. "
                    f"Sampling ratio: {sr} flows. "
                    f"Time to stop sampling: {green_time_to_stop_sampling} "
                )
            self._is_now_sampling = True
