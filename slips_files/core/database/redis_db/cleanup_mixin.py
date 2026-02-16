# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only


class CleanupMixin:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to cleanup operations
    """

    name = "DB"

    def _delete_past_timewindows(self, closed_profile_tw: str, pipe):
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

        if closed_tw < 2:
            # slips needs to always remember 2 tws, so no tws to delete now.
            return pipe

        profileid = f"{profile}_{ip}"
        # if tw 3 is closed, we want to keep tw 2 and tw 1, and del tw 0
        tw_to_del = closed_tw - 2
        tw_to_del = f"timewindow{tw_to_del}"

        pipe.zrem(
            self.constants.ACCUMULATED_THREAT_LEVELS,
            f"{profileid}_{tw_to_del}",
        )

        # delete ALL keys that have the profileid and twid in them.
        pattern = f"*{profileid}*{tw_to_del}*"
        cursor = 0
        while True:
            cursor, keys = pipe.r.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                pipe.unlink(*keys)
            if cursor == 0:
                break
        return pipe
