# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import List
from typing import Any, Callable


class CleanupMixin:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to cleanup operations and memory eviction
    """

    r: Any
    constants: Any
    get_blocked_timewindows_of_profile: Callable[..., Any]
    print: Callable[..., Any]

    name = "DB"

    def _del_all_profile_tw_keys(self, profileid: str, twid: str, pipe):
        """
        Deletes all keys that have the profileid and twid in them.
        This is called when the given tw is closed.
        """
        pattern = f"*{profileid}*{twid}*"
        cursor = 0
        while True:
            cursor, keys = pipe.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                pipe.unlink(*keys)
            if cursor == 0:
                break
        return pipe

    def delete_old_tws_from_blocked_profiles(self, profileid: str, twid: str):
        """
        deletes the given twid from the list of blocked timewindows for the
        given profileid.
        """
        timewindows: List[str] = self.get_blocked_timewindows_of_profile(
            profileid
        )
        if twid in timewindows:
            timewindows.remove(twid)
        self.r.hset(
            self.constants.BLOCKED_PROFILES_AND_TWS,
            profileid,
            json.dumps(timewindows),
        )

    def delete_past_timewindows(self, closed_profile_tw: str, pipe):
        """
        Does cleanup of old timewindows data in redis.
        This is called when there's a tw that needs to be closed.

        Deletes the past timewindows data from redis, starting from the
        given tw-2 inclusive, so that redis only has info about the current
        timewindow and the one before it and deletes the rest.

        Deleted keys follow the format:
        profileid_timewindowX (aka keys needed for the portscan module only)

        why do we keep 2 tws instead of the current one in redis? see PR
        #1765 in slips repo

        :param closed_profile_tw: a str like profile_8.8.8.8_timewindow7
        """
        try:
            profile, ip, tw = closed_profile_tw.split("_")
            closed_tw = int(tw.replace("timewindow", ""))
        except ValueError:
            self.print(
                f"Unable to delete old timewindows info from"
                f" {closed_profile_tw}"
            )
            return pipe

        tws_to_keep = 2

        if closed_tw < tws_to_keep:
            # slips needs to always remember 2 tws, so no tws to delete now.
            return pipe

        profileid = f"{profile}_{ip}"
        # if tw 3 is closed, we want to keep tw 2 and tw 1, and del tw 0
        tw_to_del = closed_tw - tws_to_keep
        tw_to_del = f"timewindow{tw_to_del}"

        self.delete_old_tws_from_blocked_profiles(profileid, tw_to_del)
        pipe.zrem(
            self.constants.ACCUMULATED_THREAT_LEVELS,
            f"{profileid}_{tw_to_del}",
        )

        # delete ALL keys that have the profileid and twid in them.
        pipe = self._del_all_profile_tw_keys(profileid, tw_to_del, pipe)
        return pipe

    def zadd_but_keep_n_entries(
        self, key: str, mapping: dict, max_entries: int
    ):
        """
        Adds the given mapping to the sorted set at the given key,
        but keeps only the n entries with the highest scores.
        :param key: The key of the sorted set
        :param mapping: A dict of {member: score} to add to the sorted set
        :param max_entries: The number of entries to keep in the sorted set
        """
        if max_entries <= 0:
            raise ValueError("n must be a positive integer")

        with self.r.pipeline() as pipe:
            pipe.zadd(key, mapping)
            # Remove elements outside the range [0, -limit-1]
            # This keeps only the 'limit' newest members
            pipe.zremrangebyrank(key, 0, -(max_entries + 1))
            pipe.execute()
