import json
import time

from slips_files.common.slips_utils import utils


class FlowTracker:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to tracking flow processing rate
    """

    name = "FlowTrackerDB"
    # channels that recv actual flows, not msgs that we need to pass between
    # modules.
    subscribers_of_channels_that_recv_flows = {
        "new_flow": 0,
        "new_dns": 0,
        "new_http": 0,
        "new_ssl": 0,
        "new_ssh": 0,
        "new_notice": 0,
        "new_url": 0,
        "new_downloaded_file": 0,
        "new_service": 0,
        "new_arp": 0,
        "new_smtp": 0,
        "new_dhcp": 0,
        "new_weird": 0,
        "new_software": 0,
        "new_tunnel": 0,
    }

    def _should_track_msg(self, msg: dict) -> bool:
        """
        Check if the msg is a flow msg that we should track. used for
        tracking flow processing rate
        """
        if not msg or msg["type"] != "message":
            # ignore subscribe msgs
            return False

        try:
            channel_name = msg["channel"]
        except KeyError:
            return False

        if channel_name not in self.subscribers_of_channels_that_recv_flows:
            # the msg doesnt contain a flow, we're not interested in it
            return False
        return True

    def _get_current_minute(self) -> str:
        return time.strftime("%Y%m%d%H%M", time.gmtime(time.time()))

    def _incr_flows_analyzed_by_all_modules_per_min(self, pipe):
        """
        Keeps track of the number of flows analyzed by all modules per minute.
        by increasing FLOWS_ANALYZED_BY_ALL_MODULES_PER_MIN by 1.

        Adds the logic of tracking flows per min to the given pipe for
        execution
        """
        current_minute = self._get_current_minute()
        key = (
            f"{self.constants.FLOWS_ANALYZED_BY_ALL_MODULES_PER_MIN}:"
            f"{current_minute}"
        )
        pipe.incr(key)
        # set expiration for 30 mins to avoid long-term storage
        pipe.expire(key, 1800)

    def get_flows_analyzed_per_minute(self):
        current_minute = self._get_current_minute()
        key = (
            f"{self.constants.FLOWS_ANALYZED_BY_ALL_MODULES_PER_MIN}:"
            f"{current_minute}"
        )
        return self.r.get(key) or 0

    def _track_flow_processing_rate(self, msg: dict):
        """
        Every time 1 flow is processed by all the subscribers of the given
        channel, this function increases the
        FLOWS_ANALYZED_BY_ALL_MODULES_PER_MIN
        constant in the db.

        the goal of this is to keep track of the flow
        processing rate and log it in the stats in the cli every 5s.

        - This func only keeps track of flows sent in specific channels(
        self.channels_that_recv_flows)
        - Works by keeping track of all uids and counting the number of
        channel subscribers that access it. once the number of msg accessed
        reaches the number of channel subscribers, we count that as 1 flow
        analyzed.
        - if a flow is kept in memory for 1h without being accessed by all
        of its subscribers, its removed, to avoid dead entries.
        """
        if not self._should_track_msg(msg):
            return

        # we only say that a flow is done being analyzed if it was accessed
        # X times where x is the number of the channel subscribers
        # this way we make sure that all intended receivers did receive the
        # flow
        channel_name = msg["channel"]
        try:
            flow = json.loads(msg["data"])["flow"]
            flow_identifier = flow["uid"]
            if not flow_identifier:
                # some flows have no uid, like weird.log
                flow_identifier = utils.get_md5_hash(flow)
        except KeyError:
            flow_identifier = utils.get_md5_hash(flow)

        # channel name is used here because some flow may be present in
        # conn.log and ssl.log with the same uid, so uid only is not enough
        # as an identifier.
        key = f"{self.constants.SUBS_WHO_PROCESSED_MSG}_{channel_name}_{flow_identifier}"

        with self.r.pipeline() as pipe:
            pipe.incr(key)
            pipe.ttl(key)
            result = pipe.execute()

        subscribers_who_processed_this_msg, ttl = result
        # -1 means the key is new so set expiration 30mins
        if ttl == -1:
            self.r.expire(key, 1800)

        expected_subscribers: int = self.r.pubsub_numsub(channel_name)[0][1]

        if subscribers_who_processed_this_msg == expected_subscribers:
            with self.r.pipeline() as pipe:
                pipe.delete(key)
                self._incr_flows_analyzed_by_all_modules_per_min(pipe)
                pipe.execute()
