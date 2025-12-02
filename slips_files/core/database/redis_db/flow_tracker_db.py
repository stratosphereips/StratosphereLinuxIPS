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

    def _cleanup_old_keys_from_flow_tracker(self):
        """
        Deletes flows older than 1 hour from the
        self.constants.SUBS_WHO_PROCESSED_MSG hash.
        Does this cleanup every 1h
        """
        one_hr = 3600
        now = time.time()

        if now - self.last_cleanup_time < one_hr:
            # Cleanup was done less than an hour ago
            return

        one_hour_ago = int(now) - one_hr
        keys_to_delete = []

        cursor = 0
        while True:
            cursor, key_values = self.r.hscan(
                self.constants.SUBS_WHO_PROCESSED_MSG, cursor
            )
            for msg_id in key_values.keys():
                try:
                    # Extract timestamp from msg_id
                    ts = int(msg_id.rsplit("_", 1)[-1])

                    if ts < one_hour_ago:
                        keys_to_delete.append(msg_id)
                except ValueError:
                    continue  # Skip keys that don't match expected format

            if cursor == 0:
                break  # Exit when full scan is done

        if keys_to_delete:
            self.r.hdel(self.constants.SUBS_WHO_PROCESSED_MSG, *keys_to_delete)
        self.last_cleanup_time = now

    def _get_current_minute(self) -> str:
        return time.strftime("%Y%m%d%H%M", time.gmtime(time.time()))

    def _incr_flows_analyzed_by_all_modules_per_min(self, pipe):
        """
        Adds the logic of tracking flows per min to the given pipe for
        excution
        """
        current_minute = self._get_current_minute()
        key = (
            f"{self.constants.FLOWS_ANALYZED_BY_ALL_MODULES_PER_MIN}:"
            f"{current_minute}"
        )
        pipe.incr(key)
        # set expiration for 1 hour to avoid long-term storage
        pipe.expire(key, 3600)

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

        self._cleanup_old_keys_from_flow_tracker()

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
        # we're storing the ts here to be able to delete the 1h old msgs
        # from redis.
        timestamp = int(time.time())
        msg_id = f"{channel_name}_{flow_identifier}_{timestamp}"

        expected_subscribers: int = self.r.pubsub_numsub(channel_name)[0][1]

        subscribers_who_processed_this_msg = self.r.hincrby(
            self.constants.SUBS_WHO_PROCESSED_MSG, msg_id, 1
        )

        if subscribers_who_processed_this_msg == expected_subscribers:
            pipe = self.r.pipeline()
            pipe.hdel(self.constants.SUBS_WHO_PROCESSED_MSG, msg_id)
            self._incr_flows_analyzed_by_all_modules_per_min(pipe)
            pipe.execute()
