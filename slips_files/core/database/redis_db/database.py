# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.printer import Printer
from slips_files.common.slips_utils import utils
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.database.redis_db.constants import (
    Constants,
    Channels,
)
from slips_files.core.database.redis_db.ioc_handler import IoCHandler
from slips_files.core.database.redis_db.alert_handler import AlertHandler
from slips_files.core.database.redis_db.profile_handler import ProfileHandler
from slips_files.core.database.redis_db.p2p_handler import P2PHandler

import os
import signal
import redis
import time
import json
import subprocess
import ipaddress
import sys
import validators
from typing import (
    List,
    Dict,
    Optional,
    Tuple,
)

RUNNING_IN_DOCKER = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)


class RedisDB(IoCHandler, AlertHandler, ProfileHandler, P2PHandler):
    # this db is a singelton per port. meaning no 2 instances
    # should be created for the same port at the same time
    _obj = None
    _port = None
    constants = Constants()
    channels = Channels()
    # Stores instances per port
    _instances = {}
    supported_channels = {
        "tw_modified",
        "evidence_added",
        "new_ip",
        "new_flow",
        "new_dns",
        "new_http",
        "new_ssl",
        "new_profile",
        "give_threat_intelligence",
        "new_letters",
        "ip_info_change",
        "dns_info_change",
        "tw_closed",
        "core_messages",
        "new_blocking",
        "new_ssh",
        "new_notice",
        "new_url",
        "new_downloaded_file",
        "reload_whitelist",
        "new_service",
        "new_arp",
        "new_MAC",
        "new_smtp",
        "new_blame",
        "new_alert",
        "new_dhcp",
        "new_weird",
        "new_software",
        "p2p_data_request",
        "remove_old_files",
        "export_evidence",
        "p2p_data_request",
        "p2p_gopy",
        "report_to_peers",
        "new_tunnel",
        "check_jarm_hash",
        "control_channel",
        "new_module_flow" "cpu_profile",
        "memory_profile",
        "fides2network",
        "network2fides",
        "fides2slips",
        "slips2fides",
        "iris_internal",
    }
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
    separator = "_"
    normal_label = "benign"
    malicious_label = "malicious"
    sudo = "sudo "
    if RUNNING_IN_DOCKER:
        sudo = ""
    # flag to know if we found the gateway MAC using the most seen MAC method
    _gateway_MAC_found = False
    _conf_file = "config/redis.conf"
    our_ips = utils.get_own_ips()
    # flag to know which flow is the start of the pcap/file
    first_flow = True
    # to make sure we only detect and store the user's localnet once
    is_localnet_set = False
    # in case of redis ConnectionErrors, this is how long we'll wait in
    # seconds before retrying.
    # this will increase exponentially each retry
    backoff = 0.1
    # try to reconnect to redis this amount of times in case of connection
    # errors before terminating
    max_retries = 150
    # to keep track of connection retries. once it reaches max_retries,
    # slips will terminate
    connection_retry = 0
    # used to cleanup flow trackers
    last_cleanup_time = time.time()

    def __new__(
        cls, logger, redis_port, start_redis_server=True, flush_db=True
    ):
        """
        treat the db as a singleton per port
        meaning every port will have exactly 1 single obj of this db
        at any given time
        """
        cls.redis_port = redis_port
        cls.flush_db = flush_db
        # start the redis server using cli if it's not started?
        cls.start_server = start_redis_server
        cls.printer = Printer(logger, cls.name)

        if cls.redis_port not in cls._instances:
            cls._set_redis_options()
            cls._read_configuration()
            initialized, err = cls.init_redis_server()
            if not initialized:
                raise RuntimeError(
                    f"Failed to connect to the redis server "
                    f"on port {cls.redis_port}: {err}"
                )

            cls._instances[cls.redis_port] = super().__new__(cls)
            super().__init__(cls)

            # By default the slips internal time is
            # 0 until we receive something
            cls.set_slips_internal_time(0)
            if not cls.get_slips_start_time():
                cls._set_slips_start_time()

            # useful for debugging using 'CLIENT LIST' redis cmd
            cls.r.client_setname("Slips-DB")

        return cls._instances[cls.redis_port]

    def __init__(self, *args, **kwargs):
        self.set_new_incoming_flows(True)

    @classmethod
    def _set_redis_options(cls):
        """
        Updates the default slips options based on the -s param,
        writes the new configs to cls._conf_file
        """
        # to fix redis.exceptions.ResponseError MISCONF Redis is
        # configured to save RDB snapshots
        # configure redis to stop writing to dump.rdb when an error
        # occurs without throwing errors in slips
        cls._options = {
            "daemonize": "yes",
            "stop-writes-on-bgsave-error": "no",
            "save": '""',
            "appendonly": "no",
        }
        # -s for saving the db
        if "-s" not in sys.argv:
            return

        # Will save the DB if both the given number of seconds
        # and the given number of write operations against the DB
        # occurred.
        # In the example below the behaviour will be to save:
        # after 30 sec if at least 500 keys changed
        # AOF persistence logs every write operation received by
        # the server, that will be played again at server startup
        # save the db to <Slips-dir>/dump.rdb
        cls._options.update(
            {
                "save": "30 500",
                "appendonly": "yes",
                "dir": os.getcwd(),
                "dbfilename": "dump.rdb",
            }
        )

        with open(cls._conf_file, "w") as f:
            for option, val in cls._options.items():
                f.write(f"{option} {val}\n")

    @classmethod
    def _read_configuration(cls):
        conf = ConfigParser()
        # Should we delete the previously stored data in the DB when we start?
        # By default False. Meaning we don't DELETE the DB by default.
        cls.deletePrevdb: bool = conf.delete_prev_db()
        cls.disabled_detections: List[str] = conf.disabled_detections()
        cls.width = conf.get_tw_width_as_float()
        cls.client_ips: List[str] = conf.client_ips()

    @classmethod
    def set_slips_internal_time(cls, timestamp):
        """
        slips internal time is the timestamp of the last tw update done in
        slips
        it is updated each time slips detects a new modification in any
        timewindow
        metadata_manager.py checks for new tw modifications every 5s and
        updates this value accordingly
        """
        cls.r.set(cls.constants.SLIPS_INTERNAL_TIME, timestamp)

    @classmethod
    def get_slips_start_time(cls) -> str:
        """get the time slips started in unix format"""
        return cls.r.get(cls.constants.SLIPS_START_TIME)

    @classmethod
    def init_redis_server(cls) -> Tuple[bool, str]:
        """
        starts the redis server, connects to the it, and andjusts redis
        options.
        Returns a tuple of (connection status, error message).
        """
        try:
            if cls.start_server:
                # starts the redis server using cli.
                # we don't need that when using -k
                cls._start_a_redis_server()

            connected, err = cls.connect_to_redis_server()
            if not connected:
                return False, err

            # these are the cases that we DO NOT flush the db when we
            # connect to it, because we need to use it
            # -d means Read an analysed file (rdb) from disk.
            # -S stop daemon
            # -cb clears the blocking chain
            if (
                cls.deletePrevdb
                and not (
                    "-S" in sys.argv or "-cb" in sys.argv or "-d" in sys.argv
                )
                and cls.flush_db
            ):
                # when stopping the daemon, don't flush bc we need to get
                # the PIDS to close slips files
                cls.r.flushdb()
                cls.r.delete(cls.constants.ZEEK_FILES)

            # Set the memory limits of the output buffer,
            # For normal clients: no limits
            # for pub-sub 4GB maximum buffer size and 2GB for soft limit
            # The original values were 50MB for maxmem and 8MB for soft limit.
            cls.change_redis_limits(cls.r)
            cls.change_redis_limits(cls.rcache)

            return True, ""
        except RuntimeError as err:
            return False, str(err)

        except redis.exceptions.ConnectionError as ex:
            return False, (
                f"Redis ConnectionError: "
                f"Can't connect to redis on port "
                f"{cls.redis_port}: {ex}"
            )

    @staticmethod
    def _connect(port: int, db: int) -> redis.StrictRedis:
        # set health_check_interval to avoid redis ConnectionReset errors:
        # if the connection is idle for more than health_check_interval seconds,
        # a round trip PING/PONG will be attempted before next redis cmd.
        # If the PING/PONG fails, the connection will re-established

        # retry_on_timeout=True after the command times out, it will be retried once,
        # if the retry is successful, it will return normally; if it fails, an exception will be thrown

        return redis.StrictRedis(
            host="localhost",
            port=port,
            db=db,
            charset="utf-8",
            socket_keepalive=True,
            decode_responses=True,
            retry_on_timeout=True,
            health_check_interval=20,
        )

    @classmethod
    def _start_a_redis_server(cls) -> bool:
        cmd = (
            f"redis-server {cls._conf_file} --port {cls.redis_port} "
            f" --daemonize yes"
        )
        process = subprocess.Popen(
            cmd,
            cwd=os.getcwd(),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        stderr = stderr.decode("utf-8")
        stdout = stdout.decode("utf-8")

        # Check for a specific line indicating a successful start
        # if the redis server is already in use, the return code will be 0
        # but we dont care because we checked it in main before starting
        # the DBManager()
        if process.returncode != 0:
            raise RuntimeError(
                f"database._start_a_redis_server: "
                f"Redis did not start properly.\n{stderr}\n{stdout}"
            )

        return True

    @classmethod
    def connect_to_redis_server(cls) -> Tuple[bool, str]:
        """
        Connects to the given port and Sets r and rcache
        Returns a tuple of (bool, error message).
        """
        try:
            # db 0 changes everytime we run slips
            cls.r = cls._connect(cls.redis_port, 0)
            # port 6379 db 0 is cache, delete it using -cc flag
            cls.rcache = cls._connect(6379, 1)

            # fix  ConnectionRefused error by giving redis time to open
            time.sleep(1)

            # the connection to redis is only established
            # when you try to execute a command on the server.
            # so make sure it's established first
            cls.r.client_list()
            return True, ""
        except Exception as e:
            return False, f"database.connect_to_redis_server: {e}"

    @classmethod
    def close_redis_server(cls, redis_port):
        if server_pid := cls.get_redis_server_pid(redis_port):
            os.kill(int(server_pid), signal.SIGKILL)

    @classmethod
    def change_redis_limits(cls, client: redis.StrictRedis):
        """
        changes redis soft and hard limits to fix redis closing/resetting
        the pub/sub connection,
        """
        # maximum buffer size for pub/sub clients:  = 4294967296 Bytes = 4GBs,
        # when msgs in queue reach this limit, Redis will
        # close the client connection as soon as possible.

        # soft limit for pub/sub clients: 2147483648 Bytes = 2GB over 10 mins,
        # means if the client has an output buffer bigger than 2GB
        # for, continuously, 10 mins, the connection gets closed.
        # format is client hard_limit soft_limit
        client.config_set(
            "client-output-buffer-limit",
            "normal 0 0 0 "
            "slave 268435456 67108864 60 "
            "pubsub 4294967296 2147483648 600",
        )

    @classmethod
    def _set_slips_start_time(cls):
        """store the time slips started (datetime obj)"""
        now = time.time()
        cls.r.set(cls.constants.SLIPS_START_TIME, now)

    def publish(self, channel, msg):
        """Publish a msg in the given channel"""
        # keeps track of how many msgs were published in the given channel
        self.r.hincrby(self.constants.MSGS_PUBLISHED_AT_RUNTIME, channel, 1)
        self.r.publish(channel, msg)

    def get_msgs_published_in_channel(self, channel: str) -> int:
        """returns the number of msgs published in a channel"""
        return self.r.hget(self.constants.MSGS_PUBLISHED_AT_RUNTIME, channel)

    def subscribe(self, channel: str, ignore_subscribe_messages=True):
        """Subscribe to channel"""
        # For when a TW is modified
        if channel not in self.supported_channels:
            return False

        self.pubsub = self.r.pubsub()
        self.pubsub.subscribe(
            channel, ignore_subscribe_messages=ignore_subscribe_messages
        )
        return self.pubsub

    def publish_stop(self):
        """
        Publish stop command to terminate slips
        to shutdown slips gracefully, this function should only be used by slips.py
        """
        self.print("Sending the stop signal to all listeners", 0, 3)
        self.r.publish("control_channel", "stop_slips")

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

    def _keep_track_of_flows_analyzed_per_min(self, pipe):
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
        constant in the db. the goal of this is to keep track of the flow
        processing rate.
        - Only keep track of flows sent in specific channels(
        self.channels_that_recv_flows)
        - Works by keeping track of all uids and counting th eumber of
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
            self._keep_track_of_flows_analyzed_per_min(pipe)
            pipe.execute()
            return

    def get_message(self, channel_obj: redis.client.PubSub, timeout=0.0000001):
        """
        Wrapper for redis' get_message() to be able to handle
        redis.exceptions.ConnectionError
        notice: there has to be a timeout or the channel will wait forever
        and never receive a new msg
        :param channel_obj: PubSub obj of the channel
        """
        try:
            msg = channel_obj.get_message(timeout=timeout)
            self._track_flow_processing_rate(msg)
            return msg
        except redis.exceptions.ConnectionError as ex:
            # make sure we log the error only once
            if not self.is_connection_error_logged():
                self.mark_connection_error_as_logged()

            if self.connection_retry >= self.max_retries:
                self.publish_stop()
                self.print(
                    f"Stopping slips due to "
                    f"redis.exceptions.ConnectionError: {ex}",
                    1,
                    1,
                )
            else:
                # don't log this each retry
                if self.connection_retry % 10 == 0:
                    # retry to connect after backing off for a while
                    self.print(
                        f"redis.exceptions.ConnectionError: "
                        f"retrying to connect in {self.backoff}s. "
                        f"Retries to far: {self.connection_retry}",
                        0,
                        1,
                    )
                time.sleep(self.backoff)
                self.backoff = self.backoff * 2
                self.connection_retry += 1
                self.get_message(channel_obj, timeout)

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def get_ip_info(self, ip: str) -> Optional[dict]:
        """
        Return information about this IP from IPsInfo key
        :return: a dictionary or False if there is no IP in the database
        """
        data = self.rcache.hget(self.constants.IPS_INFO, ip)
        return json.loads(data) if data else None

    def _get_from_ip_info(self, ip: str, info_to_get: str):
        """
        :param ip: the key to get from the ip info hash
        :param info_to_get: the value to get from the ip info hash
        """
        if utils.is_ignored_ip(ip):
            return

        ip_info = self.get_ip_info(ip)
        if not ip_info:
            return

        info = ip_info.get(info_to_get)
        if not info:
            return
        return info

    def set_new_ip(self, ip: str):
        """
        1- Stores this new IP in the IPs hash
        2- Publishes in the channels that there is a new IP, and that we want
            data from the Threat Intelligence modules
        Sometimes it can happend that the ip comes as an IP object, but when
        accessed as str, it is automatically
        converted to str
        """
        data = self.get_ip_info(ip)
        if data is False:
            # If there is no data about this IP
            # Set this IP for the first time in the IPsInfo
            # Its VERY important that the data of the first time we see an IP
            # must be '{}', an empty dictionary! if not the logic breaks.
            # We use the empty dictionary to find if an IP exists or not
            self.rcache.hset(self.constants.IPS_INFO, ip, "{}")
            # Publish that there is a new IP ready in the channel
            self.publish("new_ip", ip)

    def ask_for_ip_info(
        self, ip, profileid, twid, flow, ip_state, daddr=False
    ):
        """
        is the ip param src or dst
        """
        # if the daddr key arg is not given, we know for sure that the ip
        # given is the daddr
        daddr = daddr or ip
        data_to_send = self.give_threat_intelligence(
            profileid,
            twid,
            ip_state,
            flow.starttime,
            flow.uid,
            daddr,
            proto=flow.proto.upper(),
            lookup=ip,
        )

        if ip in self.our_ips:
            # dont ask p2p about your own ip
            return

        # ask other peers their opinion about this IP
        cache_age = 1000
        # the p2p module is expecting these 2 keys
        data_to_send.update({"cache_age": cache_age, "ip": str(ip)})
        self.publish("p2p_data_request", json.dumps(data_to_send))

    def get_slips_internal_time(self):
        return self.r.get(self.constants.SLIPS_INTERNAL_TIME) or 0

    def get_redis_keys_len(self) -> int:
        """returns the length of all keys in the db"""
        return self.r.dbsize()

    def set_cyst_enabled(self):
        return self.r.set(self.constants.IS_CYST_ENABLED, "yes")

    def is_cyst_enabled(self):
        return self.r.get(self.constants.IS_CYST_ENABLED)

    def get_equivalent_tws(self, hrs: float) -> int:
        """
        How many tws correspond to the given hours?
        for example if the tw width is 1h, and hrs is 24, this function returns 24
        """
        return int(hrs * 3600 / self.width)

    def set_local_network(self, cidr):
        """
        set the local network used in the db
        """
        self.r.set(self.constants.LOCAL_NETWORK, cidr)

    def get_local_network(self):
        return self.r.get(self.constants.LOCAL_NETWORK)

    def get_used_port(self) -> int:
        return int(self.r.config_get(self.constants.REDIS_USED_PORT)["port"])

    def get_label_count(self, label):
        """
        :param label: malicious or normal
        """
        return self.r.zscore(self.constants.LABELS, label)

    def get_enabled_modules(self) -> List[str]:
        """
        Returns a list of the loaded/enabled modules
        """
        return self.r.hkeys(self.constants.PIDS)

    def get_disabled_modules(self) -> List[str]:
        if disabled_modules := self.r.hget(
            self.constants.ANALYSIS, "disabled_modules"
        ):
            return json.loads(disabled_modules)
        else:
            return {}

    def set_input_metadata(self, info: dict):
        """
        sets name, size, analysis dates, and zeek_dir in the db
        """
        for info, val in info.items():
            self.r.hset(self.constants.ANALYSIS, info, val)

    def get_zeek_output_dir(self):
        """
        gets zeek output dir from the db
        """
        return self.r.hget(self.constants.ANALYSIS, "zeek_dir")

    def get_input_file(self):
        """
        gets zeek output dir from the db
        """
        return self.r.hget(self.constants.ANALYSIS, "name")

    def get_commit(self):
        """
        gets the currently used commit from the db
        """
        return self.r.hget(self.constants.ANALYSIS, "commit")

    def get_zeek_version(self):
        """
        gets the currently used zeek_version from the db
        """
        return self.r.hget(self.constants.ANALYSIS, "zeek_version")

    def get_branch(self):
        """
        gets the currently used branch from the db
        """
        return self.r.hget(self.constants.ANALYSIS, "branch")

    def get_evidence_detection_threshold(self):
        """
        gets the currently used evidence_detection_threshold from the db
        """
        return self.r.hget(
            self.constants.ANALYSIS, "evidence_detection_threshold"
        )

    def get_input_type(self) -> str:
        """
        gets input type from the db
        returns one of the following "stdin", "pcap", "interface",
        "zeek_log_file", "zeek_folder", "stdin", "nfdump", "binetflow",
        "suricata"
        """
        return self.r.hget(self.constants.ANALYSIS, "input_type")

    def get_output_dir(self):
        """
        returns the currently used output dir
        """
        return self.r.hget(self.constants.ANALYSIS, "output_dir")

    def set_ip_info(self, ip: str, to_store: dict):
        """
        Store information for this IP
        We receive a dictionary, such as {
        'geocountry': 'rumania'} to
        store for this IP.
        If it was not there before we store it. If it was there before, we
        overwrite it
        """
        # Get the previous info already stored
        cached_ip_info = self.get_ip_info(ip)
        if not cached_ip_info:
            # This IP is not in the dictionary, add it first:
            self.set_new_ip(ip)
            cached_ip_info = {}

        # make sure we don't already have the same info about this IP in our db
        is_new_info = False
        for info_type, info_val in to_store.items():
            if info_type not in cached_ip_info and not is_new_info:
                is_new_info = True

            cached_ip_info[info_type] = info_val

        self.rcache.hset(
            self.constants.IPS_INFO, ip, json.dumps(cached_ip_info)
        )
        if is_new_info:
            self.r.publish("ip_info_change", ip)

    def get_redis_pid(self):
        """returns the pid of the current redis server"""
        return int(self.r.info()["process_id"])

    def get_p2p_reports_about_ip(self, ip) -> dict:
        """
        returns a dict of all p2p past reports about the given ip
        """
        # p2p_reports key is basically
        # { ip:  { reporter1: [report1, report2, report3]} }
        if reports := self.rcache.hget(self.constants.P2P_REPORTS, ip):
            return json.loads(reports)
        return {}

    def store_p2p_report(self, ip: str, report_data: dict):
        """
        stores answers about IPs slips asked other peers for.
        updates the p2p_reports key only
        """
        # reports in the db are sorted by reporter by default
        reporter = report_data["reporter"]
        del report_data["reporter"]

        # if we have old reports about this ip, append this one to them
        # cached_p2p_reports is a dict
        cached_p2p_reports: Dict[str, List[dict]] = (
            self.get_p2p_reports_about_ip(ip)
        )
        if cached_p2p_reports:
            # was this ip reported by the same peer before?
            if reporter in cached_p2p_reports:
                # ip was reported before, by the same peer
                # did the same peer report the same score and
                # confidence about the same ip twice in a row?
                last_report_about_this_ip = cached_p2p_reports[reporter][-1]
                score = report_data["score"]
                confidence = report_data["confidence"]
                if (
                    last_report_about_this_ip["score"] == score
                    and last_report_about_this_ip["confidence"] == confidence
                ):
                    report_time = report_data["report_time"]
                    # score and confidence are the same as the last report,
                    # only update the time
                    last_report_about_this_ip["report_time"] = report_time
                else:
                    # score and confidence are the different from the last
                    # report, add report to the list
                    cached_p2p_reports[reporter].append(report_data)
            else:
                # ip was reported before, but not by the same peer
                cached_p2p_reports[reporter] = [report_data]
            report_data = cached_p2p_reports
        else:
            # no old reports about this ip
            report_data = {reporter: [report_data]}

        self.rcache.hset(
            self.constants.P2P_REPORTS, ip, json.dumps(report_data)
        )

    def get_dns_resolution(self, ip: str):
        """
        IF this IP was resolved by slips
        returns a dict with {ts: .. ,
                            'domains': .. ,
                            'uid':...,
                            'resolved-by':.. }
        If not resolved, returns {}
        this function is called for every IP in the timeline of kalipso
        checks for the reolution in self.constants.DNS_RESOLUTION
        """
        if ip_info := self.r.hget(self.constants.DNS_RESOLUTION, ip):
            ip_info = json.loads(ip_info)
            # return a dict with 'ts' 'uid' 'domains' about this IP
            return ip_info
        return {}

    def is_ip_resolved(self, ip, hrs):
        """
        checks self.constants.DNS_RESOLUTION for the ip's resolutions
        :param hrs: float, how many hours to look back for resolutions
        """
        ip_info = self.get_dns_resolution(ip)
        if ip_info == {}:
            return False

        # these are the tws this ip was resolved in
        tws_where_ip_was_resolved = ip_info["timewindows"]

        # IP is resolved, was it resolved in the past x hrs?
        tws_to_search: int = self.get_equivalent_tws(hrs)

        for tw_number in range(tws_to_search):
            if f"timewindow{tw_number}" in tws_where_ip_was_resolved:
                return True
        return False

    def delete_dns_resolution(self, ip):
        self.r.hdel(self.constants.DNS_RESOLUTION, ip)

    def should_store_resolution(
        self, query: str, answers: list, qtype_name: str
    ) -> bool:
        """
        only stores queries of type A or AAAA
        """
        # don't store queries ending with arpa as dns resolutions,
        # they're reverse dns
        # only store type A and AAAA for ipv4 and ipv6
        if (
            qtype_name not in ["AAAA", "A"]
            or answers == "-"
            or query.endswith("arpa")
        ):
            return False

        # sometimes adservers are resolved to 0.0.0.0 or "127.0.0.1" to
        # block the domain.
        # don't store this as a valid dns resolution
        if query != "localhost":
            for answer in answers:
                if answer in ("127.0.0.1", "0.0.0.0"):
                    return False

        return True

    def is_cname(self, answer) -> bool:
        """checks if the given answer is a CNAME"""
        return (
            not validators.ipv6(answer)
            and not validators.ipv4(answer)
            and not self.is_txt_record(answer)
        )

    def is_txt_record(self, answer):
        return "TXT" in answer

    def set_dns_resolution(
        self,
        query: str,
        answers: list,
        ts: float,
        uid: str,
        qtype_name: str,
        srcip: str,
        twid: str,
    ):
        """
        Cache DNS answers of type A and AAAA
        1- For each ip in the answer, store the domain
           in DNSresolution as {ip: {ts: .. , 'domains': .. , 'uid':... }}
        2- For each CNAME, store the ip

        :param srcip: ip that performed the dns query
        """
        if not self.should_store_resolution(query, answers, qtype_name):
            return
        # List of IPs to associate with the given domain
        ips_to_add = []
        cnames = []

        for answer in answers:
            if self.is_txt_record(answer):
                continue

            if self.is_cname(answer):
                cnames.append(answer)
                continue

            # get stored DNS resolution from our db
            ip_info_from_db = self.get_dns_resolution(answer)
            if ip_info_from_db == {}:
                resolved_by = [srcip]
                # list of cached domains in the db, in this case theres none
                domains = []
                timewindows = [twid]
            else:
                # we have info about this domain in DNSresolution in the db
                # keep track of all srcips that resolved this domain
                resolved_by = ip_info_from_db.get("resolved-by", [])
                if srcip not in resolved_by:
                    resolved_by.append(srcip)

                # timewindows in which this odmain was resolved
                timewindows = ip_info_from_db.get("timewindows", [])
                if twid not in timewindows:
                    timewindows.append(twid)

                # we'll be appending the current answer
                # to these cached domains
                domains = ip_info_from_db.get("domains", [])
            # if the domain(query) we have isn't already in
            # DNSresolution in the db, add it
            if query not in domains:
                domains.append(query)

            # domains should be a list, not a string!,
            # so don't use json.dumps(domains) here
            ip_info = {
                "ts": ts,
                "uid": uid,
                "domains": domains,
                "resolved-by": resolved_by,
                "timewindows": timewindows,
            }
            ip_info = json.dumps(ip_info)
            # we store ALL dns resolutions seen since starting slips
            # store with the IP as the key
            self.r.hset(self.constants.DNS_RESOLUTION, answer, ip_info)
            self.set_ip_info(answer, {"DNS_resolution": domains})
            # these ips will be associated with the query in our db
            if not utils.is_ignored_ip(answer):
                ips_to_add.append(answer)

        # For each CNAME in the answer
        # store it in DomainsInfo in the cache db (used for kalipso)
        # and in CNAMEsInfo in the main db  (used for detecting dns
        # without resolution)
        if ips_to_add:
            domaindata = {"IPs": ips_to_add}
            # if an ip came in the DNS answer along with the last seen CNAME
            try:
                # store this CNAME in the db
                domaindata["CNAME"] = cnames
            except NameError:
                # no CNAME came with this query
                pass
            self.set_info_for_domains(query, domaindata, mode="add")
            self.set_domain_resolution(query, ips_to_add)

    def set_domain_resolution(self, domain, ips):
        """
        stores all the resolved domains with their ips in the db
        stored as {Domain: [IP, IP, IP]} in the db
        """
        self.r.hset(self.constants.DOMAINS_RESOLVED, domain, json.dumps(ips))

    @staticmethod
    def get_redis_server_pid(redis_port):
        """
        get the PID of the redis server started on the given redis_port
        retrns the pid
        """
        cmd = "ps aux | grep redis-server"
        cmd_output = os.popen(cmd).read()
        for line in cmd_output.splitlines():
            if str(redis_port) in line:
                pid = line.split()[1]
                return pid
        return False

    def set_slips_mode(self, slips_mode):
        """
        function to store the current mode (daemonized/interactive)
        in the db
        """
        self.r.set(self.constants.MODE, slips_mode)

    def get_slips_mode(self):
        """
        function to get the current mode (daemonized/interactive)
        in the db
        """
        self.r.get(self.constants.MODE)

    def get_modified_ips_in_the_last_tw(self):
        """
        this number is updated in the db every 5s by slips.py
        used for printing running stats in slips.py or outputprocess
        """
        if modified_ips := self.r.hget(
            self.constants.ANALYSIS, "modified_ips_in_the_last_tw"
        ):
            return modified_ips
        else:
            return 0

    def is_connection_error_logged(self):
        return bool(self.r.get(self.constants.LOGGED_CONNECTION_ERR))

    def mark_connection_error_as_logged(self):
        """
        When redis connection error occurs, to prevent
        every module from logging it to slips.log and the console,
        set this variable in the db
        """
        self.r.set(self.constants.LOGGED_CONNECTION_ERR, "True")

    def was_ip_seen_in_connlog_before(self, ip) -> bool:
        """
        returns true if this is not the first flow slip sees of the given ip
        """
        # we store every source address seen in a conn.log flow in this key
        # if the source address is not stored in this key, it means we may
        # have seen it but not in conn.log yet

        # if the ip's not in the following key, then its the first flow
        # seen of this ip
        return self.r.sismember(self.constants.SRCIPS_SEEN_IN_CONN_LOG, ip)

    def mark_srcip_as_seen_in_connlog(self, ip):
        """
        Marks the given ip as seen in conn.log
        keeps track of private ipv4 only.
        if an ip is not present in this set, it means we may
         have seen it but not in conn.log
        """
        self.r.sadd(self.constants.SRCIPS_SEEN_IN_CONN_LOG, ip)

    def _is_gw_mac(self, mac_addr: str) -> bool:
        """
        Detects the MAC of the gateway if 1 mac is seen
        assigned to 1 public destination IP
        :param ip: dst ip that should be associated with the given MAC info
        """

        if not validators.mac_address(mac_addr):
            return False

        if self._gateway_MAC_found:
            # gateway MAC already set using this function
            return self.get_gateway_mac() == mac_addr

    def _determine_gw_mac(self, ip, mac):
        """
        sets the gw mac if the given ip is public and is assigned a mc
        """
        if self._gateway_MAC_found:
            return False
        # since we don't have a mac gw in the db, see if
        # this given mac is the gw mac
        ip_obj = ipaddress.ip_address(ip)
        if not utils.is_private_ip(ip_obj):
            # now we're given a public ip and a MAC that's supposedly
            # belongs to it
            # we are sure this is the gw mac
            # set it if we don't already have it in the db
            self.set_default_gateway(self.constants.MAC, mac)

            # mark the gw mac as found so we don't look for it again
            self._gateway_MAC_found = True
            return True
        return False

    def get_ip_of_mac(self, MAC):
        """
        Returns the IP associated with the given MAC in our database
        """
        return self.r.hget(self.constants.MAC, MAC)

    def get_modified_tw(self):
        """Return all the list of modified tw"""
        data = self.r.zrange(
            self.constants.MODIFIED_TIMEWINDOWS, 0, -1, withscores=True
        )
        return data or []

    def get_field_separator(self):
        """Return the field separator"""
        return self.separator

    def store_tranco_whitelisted_domain(self, domain):
        """
        store whitelisted domain from tranco whitelist in the db
        """
        # the reason we store tranco whitelisted domains in the cache db
        # instead of the main db is, we don't want them cleared on every new
        # instance of slips
        self.rcache.sadd(self.constants.TRANCO_WHITELISTED_DOMAINS, domain)

    def is_whitelisted_tranco_domain(self, domain):
        return self.rcache.sismember(
            self.constants.TRANCO_WHITELISTED_DOMAINS, domain
        )

    def delete_tranco_whitelist(self):
        return self.rcache.delete(self.constants.TRANCO_WHITELISTED_DOMAINS)

    def set_growing_zeek_dir(self):
        """
        Mark a dir as growing so it can be treated like the zeek
         logs generated by an interface
        """
        self.r.set(self.constants.GROWING_ZEEK_DIR, "yes")

    def is_growing_zeek_dir(self):
        """Did slips mark the given dir as growing?"""
        return "yes" in str(self.r.get(self.constants.GROWING_ZEEK_DIR))

    def get_asn_info(self, ip: str) -> Optional[Dict[str, str]]:
        """
        returns asn info about the given IP
        returns a dict with "number" and "org" keys
        """
        return self._get_from_ip_info(ip, "asn")

    def get_rdns_info(self, ip: str) -> Optional[str]:
        """
        returns rdns info about the given IP
        returns a str with the rdns or none
        """
        return self._get_from_ip_info(ip, "reverse_dns")

    def get_sni_info(self, ip: str) -> Optional[str]:
        """
        returns sni info about the given IP
        returns the server name or none
        """
        sni = self._get_from_ip_info(ip, "SNI")
        if not sni:
            return
        sni = sni[0] if isinstance(sni, list) else sni
        return sni.get("server_name")

    def get_ip_identification(
        self, ip: str, get_ti_data=True
    ) -> Dict[str, str]:
        """
        Return the identification of this IP based
        on the AS, rDNS, and SNI of the IP.

        :param ip: The IP address to retrieve information for.
        :param get_ti_data: do we want to get info about this IP from out
        TI lists?
        :return: string containing AS, rDNS, and SNI of the IP.
        """
        cached_info: Optional[Dict[str, str]] = self.get_ip_info(ip)
        id = {}
        if not cached_info:
            return id

        sni = cached_info.get("SNI")
        if sni:
            sni = sni[0] if isinstance(sni, list) else sni
            sni = sni.get("server_name")

        id = {
            "AS": cached_info.get("asn"),
            "rDNS": cached_info.get("reverse_dns"),
            "SNI": sni,
        }

        if get_ti_data:
            id.update(
                {"TI": cached_info.get("threatintelligence", {}).get("source")}
            )

        if domains := cached_info.get("DNS_resolution", []):
            domains: List[str]
            id.update({"queries": domains})

        return id

    def get_multiaddr(self):
        """
        this is can only be called when p2p is enabled, this value is set by p2p pigeon
        """
        return self.r.get(self.constants.MULTICAST_ADDRESS)

    def get_labels(self):
        """
        Return the amount of each label so far in the DB
        Used to know how many labels are available during training
        """
        return self.r.zrange(self.constants.LABELS, 0, -1, withscores=True)

    def set_port_info(self, portproto: str, name):
        """
        Save in the DB a port with its description
        :param portproto: portnumber + / + protocol
        """
        self.rcache.hset(self.constants.PORT_INFO, portproto, name)

    def get_port_info(self, portproto: str):
        """
        Retrieve the name of a port
        :param portproto: portnumber + / + protocol
        """
        return self.rcache.hget(self.constants.PORT_INFO, portproto)

    def set_ftp_port(self, port):
        """
        Stores the used ftp port in our main db (not the cache like set_port_info)
        """
        self.r.lpush(self.constants.USED_FTP_PORTS, str(port))

    def is_ftp_port(self, port):
        # get all used ftp ports
        used_ftp_ports = self.r.lrange(self.constants.USED_FTP_PORTS, 0, -1)
        # check if the given port is used as ftp port
        return str(port) in used_ftp_ports

    def set_organization_of_port(self, organization, ip: str, portproto: str):
        """
        Save in the DB a port with its organization and the ip/
        range used by this organization
        :param portproto: portnumber + / + protocol.lower()
        :param ip: can be a single org ip, or a range or ''
        """
        if org_info := self.get_organization_of_port(portproto):
            # this port and proto was used with another
            # organization, append to it
            org_info = json.loads(org_info)
            org_info["ip"].append(ip)
            org_info["org_name"].append(organization)
        else:
            org_info = {"org_name": [organization], "ip": [ip]}

        org_info = json.dumps(org_info)
        self.rcache.hset(
            self.constants.ORGANIZATIONS_PORTS, portproto, org_info
        )

    def get_organization_of_port(self, portproto: str):
        """
        Retrieve the organization info that uses this port
        :param portproto: portnumber.lower() + / + protocol
        """
        # this key is used to store the ports the are known to be used
        #  by certain organizations
        return self.rcache.hget(
            self.constants.ORGANIZATIONS_PORTS, portproto.lower()
        )

    def add_zeek_file(self, filename):
        """Add an entry to the list of zeek files"""
        self.r.sadd(self.constants.ZEEK_FILES, filename)

    def get_all_zeek_files(self) -> set:
        """Return all entries from the list of zeek files"""
        return self.r.smembers(self.constants.ZEEK_FILES)

    def get_gateway_ip(self):
        return self.r.hget(self.constants.DEFAULT_GATEWAY, "IP")

    def get_gateway_mac(self):
        return self.r.hget(self.constants.DEFAULT_GATEWAY, self.constants.MAC)

    def get_gateway_mac_vendor(self):
        return self.r.hget(self.constants.DEFAULT_GATEWAY, "Vendor")

    def set_default_gateway(self, address_type: str, address: str):
        """
        :param address_type: can either be 'IP' or 'MAC'
        :param address: can be ip or mac, but always is a str
        """
        # make sure the IP or mac aren't already set before re-setting
        if (
            (address_type == "IP" and not self.get_gateway_ip())
            or (
                address_type == self.constants.MAC
                and not self.get_gateway_mac()
            )
            or (address_type == "Vendor" and not self.get_gateway_mac_vendor())
        ):
            self.r.hset(self.constants.DEFAULT_GATEWAY, address_type, address)

    def get_domain_resolution(self, domain) -> List[str]:
        """
        Returns the IPs resolved by this domain
        """
        ips = self.r.hget(self.constants.DOMAINS_RESOLVED, domain)
        return json.loads(ips) if ips else []

    def get_all_dns_resolutions(self):
        dns_resolutions = self.r.hgetall(self.constants.DNS_RESOLUTION)
        return dns_resolutions or []

    def is_running_non_stop(self) -> bool:
        """
        Slips runs non-stop in case of an interface or a growing zeek dir,
        in these 2 cases, it only stops on ctrl+c
        """
        return (
            self.get_input_type() == "interface" or self.is_growing_zeek_dir()
        )

    def set_passive_dns(self, ip, data):
        """
        Save in DB passive DNS from virus total
        """
        if data:
            data = json.dumps(data)
            self.rcache.hset(self.constants.PASSIVE_DNS, ip, data)

    def get_passive_dns(self, ip):
        """
        Gets passive DNS from the db
        """
        if data := self.rcache.hget(self.constants.PASSIVE_DNS, ip):
            return json.loads(data)
        else:
            return False

    def get_reconnections_for_tw(self, profileid, twid):
        """Get the reconnections for this TW for this Profile"""
        data = self.r.hget(f"{profileid}_{twid}", "Reconnections")
        data = json.loads(data) if data else {}
        return data

    def set_reconnections(self, profileid, twid, data):
        """Set the reconnections for this TW for this Profile"""
        data = json.dumps(data)
        self.r.hset(f"{profileid}_{twid}", "Reconnections", str(data))

    def get_host_ip(self) -> Optional[str]:
        """returns the latest added host ip"""
        host_ip: List[str] = self.r.zrevrange(
            "host_ip", 0, 0, withscores=False
        )
        return host_ip[0] if host_ip else None

    def set_host_ip(self, ip):
        """Store the IP address of the host in a db.
        There can be more than one"""
        # stored them in a sorted set to be able to retrieve the latest one
        # of them as the host ip
        host_ips_added = self.r.zcard("host_ip")
        self.r.zadd("host_ip", {ip: host_ips_added + 1})

    def set_asn_cache(self, org: str, asn_range: str, asn_number: str) -> None:
        """
        Stores the range of asn in cached_asn hash
        """

        range_info = {asn_range: {"org": org}}
        if asn_number:
            range_info[asn_range].update({"number": f"AS{asn_number}"})

        first_octet = utils.get_first_octet(asn_range)
        if not first_octet:
            return

        # this is how we store ASNs; sorted by first octet
        """
        {
            '192' : {
                '192.168.1.0/x': {'number': 'AS123', 'org':'Test'},
                '192.168.1.0/x': {'number': 'AS123', 'org':'Test'},
            },
            '10': {
                '10.0.0.0/x': {'number': 'AS123', 'org':'Test'},
            }

        }
        """
        if cached_asn := self.get_asn_cache(first_octet=first_octet):
            # we already have a cached asn of a range that
            # starts with the same first octet
            cached_asn: dict = json.loads(cached_asn)
            cached_asn.update(range_info)
            self.rcache.hset(
                self.constants.CACHED_ASN, first_octet, json.dumps(cached_asn)
            )
        else:
            # first time storing a range starting with the same first octet
            self.rcache.hset(
                self.constants.CACHED_ASN, first_octet, json.dumps(range_info)
            )

    def get_asn_cache(self, first_octet=False):
        """
         cached ASNs are sorted by first octet
        Returns cached asn of ip if present, or False.
        """
        if first_octet:
            return self.rcache.hget(self.constants.CACHED_ASN, first_octet)

        return self.rcache.hgetall(self.constants.CACHED_ASN)

    def store_pid(self, process: str, pid: int):
        """
        Stores each started process or module with it's PID
        :param pid: int
        :param process: module name, str
        """
        self.r.hset(self.constants.PIDS, process, pid)

    def get_pids(self) -> dict:
        """returns a dict with module names as keys and PIDs as values"""
        return self.r.hgetall(self.constants.PIDS)

    def get_pid_of(self, module_name: str):
        pid = self.r.hget(self.constants.PIDS, module_name)
        return int(pid) if pid else None

    def get_name_of_module_at(self, given_pid):
        """returns the name of the module that has the given pid"""
        for name, pid in self.get_pids().items():
            if int(given_pid) == int(pid):
                return name

    def set_org_info(self, org, org_info, info_type):
        """
        store ASN, IP and domains of an org in the db
        :param org: supported orgs are ('google', 'microsoft',
        'apple', 'facebook', 'twitter')
        : param org_info: a json serialized list of asns or ips or domains
        :param info_type: supported types are 'asn', 'domains', 'IPs'
        """
        # info will be stored in OrgInfo key {'facebook_asn': ..,
        # 'twitter_domains': ...}
        self.rcache.hset(
            self.constants.ORG_INFO, f"{org}_{info_type}", org_info
        )

    def get_org_info(self, org, info_type) -> str:
        """
        get the ASN, IP and domains of an org from the db
        :param org: supported orgs are ('google', 'microsoft', 'apple',
         'facebook', 'twitter')
        :param info_type: supported types are 'asn', 'domains'
        returns a json serialized dict with info
        PS: All ASNs returned by this function are uppercase
        """
        return (
            self.rcache.hget(self.constants.ORG_INFO, f"{org}_{info_type}")
            or "[]"
        )

    def get_org_ips(self, org):
        org_info = self.rcache.hget(self.constants.ORG_INFO, f"{org}_IPs")

        if not org_info:
            org_info = {}
            return org_info

        try:
            return json.loads(org_info)
        except TypeError:
            # it's a dict
            return org_info

    def set_whitelist(self, type_, whitelist_dict):
        """
        Store the whitelist_dict in the given key
        :param type_: supported types are IPs, domains, macs and organizations
        :param whitelist_dict: the dict of IPs,macs,  domains or orgs to store
        """
        self.r.hset(
            self.constants.WHITELIST, type_, json.dumps(whitelist_dict)
        )

    def get_all_whitelist(self) -> Optional[Dict[str, dict]]:
        """
        Returns a dict with the following keys from the whitelist
        'mac', 'organizations', 'IPs', 'domains'
        """
        whitelist: Optional[Dict[str, str]] = self.r.hgetall(
            self.constants.WHITELIST
        )
        if whitelist:
            whitelist = {k: json.loads(v) for k, v in whitelist.items()}
        return whitelist

    def get_whitelist(self, key: str) -> dict:
        """
        Whitelist supports different keys like : IPs domains
        and organizations
        this function is used to check if we have any of the
        above keys whitelisted
        """
        if whitelist := self.r.hget(self.constants.WHITELIST, key):
            return json.loads(whitelist)
        else:
            return {}

    def has_cached_whitelist(self) -> bool:
        return bool(self.r.exists(self.constants.WHITELIST))

    def is_dhcp_server(self, ip: str) -> bool:
        # make sure it's a valid ip
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            # not a valid ip skip
            return False
        dhcp_servers = self.r.lrange(self.constants.DHCP_SERVERS, 0, -1)
        return ip in dhcp_servers

    def store_dhcp_server(self, server_addr):
        """
        Store all seen DHCP servers in the database.
        """
        if self.is_dhcp_server(server_addr):
            # already in the db
            return

        self.r.lpush(self.constants.DHCP_SERVERS, server_addr)

    def save(self, backup_file):
        """
        Save the db to disk.
        backup_file should be the path+name of the file you want to save the db in
        If you -s the same file twice the old backup will be overwritten.
        """

        # use print statements in this function won't work because by the time this
        # function is executed, the redis database would have already stopped

        # saves to /var/lib/redis/dump.rdb
        # this path is only accessible by root
        self.r.save()

        # gets the db saved to dump.rdb in the cwd
        redis_db_path = os.path.join(os.getcwd(), "dump.rdb")

        if os.path.exists(redis_db_path):
            command = f"{self.sudo} cp {redis_db_path} {backup_file}.rdb"
            os.system(command)
            os.remove(redis_db_path)
            print(f"[Main] Database saved to {backup_file}.rdb")
            return True

        print(
            f"[DB] Error Saving: Cannot find the redis "
            f"database directory {redis_db_path}"
        )
        return False

    def load(self, backup_file: str) -> bool:
        """
        Load the db from disk to the db on port 32850
        backup_file should be the full path of the .rdb
        """

        # do not use self.print here! the output queue isn't initialized yet
        def is_valid_rdb_file():
            if not os.path.exists(backup_file):
                print("{} doesn't exist.".format(backup_file))
                return False

            # Check if valid .rdb file
            command = f"file {backup_file}"
            result = subprocess.run(command.split(), stdout=subprocess.PIPE)
            file_type = result.stdout.decode("utf-8")
            if "Redis" not in file_type:
                print(f"{backup_file} is not a valid redis database file.")
                return False
            return True

        if not is_valid_rdb_file():
            return False

        try:
            RedisDB._options.update(
                {
                    "dbfilename": os.path.basename(backup_file),
                    "dir": os.path.dirname(backup_file),
                    "port": 32850,
                }
            )

            with open(RedisDB._conf_file, "w") as f:
                for option, val in RedisDB._options.items():
                    f.write(f"{option} {val}\n")
            # Stop the server first in order for redis to load another db
            os.system(f"{self.sudo}service redis-server stop")

            # Start the server again, but make sure it's flushed
            # and doesnt have any keys
            os.system("redis-server redis.conf > /dev/null 2>&1")
            return True
        except Exception:
            self.print(f"Error loading the database {backup_file}.")
            return False

    def set_last_warden_poll_time(self, time):
        """
        :param time: epoch
        """
        self.r.hset(self.constants.WARDEN_INFO, "poll", time)

    def get_last_warden_poll_time(self):
        """
        returns epoch time of last poll
        """
        time = self.r.hget(self.constants.WARDEN_INFO, "poll")
        time = float(time) if time else float("-inf")
        return time

    @staticmethod
    def start_profiling():
        print("-" * 30 + " Started profiling")
        import cProfile

        profile = cProfile.Profile()
        profile.enable()
        return profile

    @staticmethod
    def end_profiling(profile):
        import pstats
        import io

        profile.disable()
        s = io.StringIO()
        sortby = pstats.SortKey.CUMULATIVE
        ps = pstats.Stats(profile, stream=s).sort_stats(sortby)
        ps.print_stats()
        print(s.getvalue())
        print("-" * 30 + " Done profiling")

    def store_blame_report(self, ip, network_evaluation):
        """
        :param network_evaluation: a dict with {'score': ..,
        'confidence':
        .., 'ts': ..} taken from a blame report
        """
        self.rcache.hset(
            self.constants.P2P_RECEIVED_BLAME_REPORTS, ip, network_evaluation
        )

    def store_zeek_path(self, path):
        """used to store the path of zeek log
        files slips is currently using"""
        self.r.set(self.constants.ZEEK_PATH, path)

    def get_zeek_path(self) -> str:
        """return the path of zeek log files slips is currently using"""
        return self.r.get(self.constants.ZEEK_PATH)

    def increment_processed_flows(self):
        """processed by the profiler only"""
        return self.r.incr(self.constants.PROCESSED_FLOWS, 1)

    def get_processed_flows_so_far(self) -> int:
        """processed by the profiler only"""
        processed_flows = self.r.get(self.constants.PROCESSED_FLOWS)
        if not processed_flows:
            return 0
        return int(processed_flows)

    def store_std_file(self, **kwargs):
        """
        available args are
            std_files = {
                    'stderr': ,
                    'stdout': ,
                    'stdin': ,
                    'pidfile': ,
                    'logsfile': ,
                }
        """
        for file_type, path in kwargs.items():
            self.r.set(file_type, path)

    def get_stdfile(self, file_type):
        return self.r.get(file_type)

    def incr_msgs_received_in_channel(self, module: str, channel: str):
        """increments the number of msgs received by a module in the given
        channel by 1"""
        self.r.hincrby(f"{module}_msgs_received_at_runtime", channel, 1)

    def get_msgs_received_at_runtime(self, module: str) -> Dict[str, int]:
        """
        returns a list of channels this module is subscribed to, and how
        many msgs were received on each one
        :returns: {channel_name: number_of_msgs, ...}
        """
        return self.r.hgetall(f"{module}_msgs_received_at_runtime")
