import configparser
import multiprocessing
import platform
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict

import modules.p2ptrust.trust.base_model as reputation_model
import modules.p2ptrust.trust.trustdb as trustdb
import modules.p2ptrust.utils.utils as utils
from modules.p2ptrust.utils.go_director import GoDirector
from modules.p2ptrust.utils.printer import Printer
from slips_files.common.abstracts import Module
from slips_files.core.database import __database__


def validate_slips_data(message_data: str) -> (str, int):
    """
    Check that message received from slips channel has correct format: ip, timeout

    The message should contain an IP address (string), followed by a space and an integer timeout. If the message is
    correct, the two values are returned as a tuple (str, int). If not, (None, None) is returned.
    :param message_data: data from slips request channel
    :return: parsed values or None tuple
    """

    try:
        ip_address, time_since_cached = message_data.split(" ", 1)
        time_since_cached = int(time_since_cached)

        if not utils.validate_ip_address(ip_address):
            return None, None

        return ip_address, time_since_cached

    except ValueError:
        # message has wrong format
        return None, None


class Trust(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'p2ptrust'
    description = 'Enables sharing detection data with other Slips instances'
    authors = ['Dita']

    def __init__(self,
                 output_queue: multiprocessing.Queue,
                 config: configparser.ConfigParser,
                 data_dir: str = "./p2ptrust_runtime/",
                 pigeon_port=6668,
                 rename_with_port=False,
                 slips_update_channel="ip_info_change",
                 p2p_data_request_channel="p2p_data_request",
                 gopy_channel="p2p_gopy",
                 pygo_channel="p2p_pygo",
                 start_pigeon=True,
                 pigeon_binary="p2p4slips",  # make sure the binary is in $PATH or put there full path
                 pigeon_logfile="pigeon_logs",
                 pigeon_key_file="pigeon.keys",
                 rename_redis_ip_info=False,
                 rename_sql_db_file=False,
                 override_p2p=False):
        multiprocessing.Process.__init__(self)

        # create data folder
        Path(data_dir).mkdir(parents=True, exist_ok=True)

        self.output_queue = output_queue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # To which channels do you want to subscribe? When a message arrives on the channel the module will wakeup
        # The options change, so the last list is on the slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added

        self.port = pigeon_port
        self.rename_with_port = rename_with_port
        self.gopy_channel_raw = gopy_channel
        self.pygo_channel_raw = pygo_channel
        self.pigeon_logfile_raw = pigeon_logfile
        self.start_pigeon = start_pigeon
        self.override_p2p = override_p2p
        self.data_dir = data_dir

        if self.rename_with_port:
            str_port = str(self.port)
        else:
            str_port = ""

        self.printer = Printer(output_queue, self.name + str_port)

        self.slips_update_channel = slips_update_channel
        self.p2p_data_request_channel = p2p_data_request_channel

        self.gopy_channel = self.gopy_channel_raw + str_port
        self.pygo_channel = self.pygo_channel_raw + str_port
        self.pigeon_logfile = data_dir + self.pigeon_logfile_raw + str_port
        self.pigeon_key_file = pigeon_key_file
        self.pigeon_binary = pigeon_binary

        self.storage_name = "IPsInfo"
        if rename_redis_ip_info:
            self.storage_name += str(self.port)

        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the
        # timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = -1
        else:
            # ??
            self.timeout = None

        # Start the db
        __database__.start(self.config)

        self.sql_db_name = self.data_dir + "trustdb.db"
        if rename_sql_db_file:
            self.sql_db_name += str(pigeon_port)

    def print(self, text: str, verbose: int = 1, debug: int = 0) -> None:
        self.printer.print(text, verbose, debug)

    def _configure(self):
        # TODO: do not drop tables on startup
        self.trust_db = trustdb.TrustDB(self.sql_db_name, self.printer, drop_tables_on_startup=True)
        self.reputation_model = reputation_model.BaseModel(self.printer, self.trust_db, self.config)

        self.go_director = GoDirector(self.printer,
                                      self.trust_db,
                                      self.config,
                                      self.storage_name,
                                      override_p2p=self.override_p2p,
                                      report_func=self.process_message_report,
                                      request_func=self.respond_to_message_request,
                                      gopy_channel=self.gopy_channel,
                                      pygo_channel=self.pygo_channel)

        self.pigeon = None
        if self.start_pigeon:
            if not shutil.which(self.pigeon_binary):
                self.print(f'P2p4slips binary not found in \"{self.pigeon_binary}\". '
                           f'Did you include it in PATH?. Exiting process.')
                return

            executable = [self.pigeon_binary]
            port_param = ["-port", str(self.port)]
            keyfile_param = ["-key-file", self.data_dir + self.pigeon_key_file]
            rename_with_port_param = ["-rename-with-port", str(self.rename_with_port).lower()]
            pygo_channel_param = ["-redis-channel-pygo", self.pygo_channel_raw]
            gopy_channel_param = ["-redis-channel-gopy", self.gopy_channel_raw]
            executable.extend(port_param)
            executable.extend(keyfile_param)
            executable.extend(rename_with_port_param)
            executable.extend(pygo_channel_param)
            executable.extend(gopy_channel_param)
            outfile = open(self.pigeon_logfile, "+w")
            self.pigeon = subprocess.Popen(executable, cwd=self.data_dir, stdout=outfile)

    def run(self):
        # configure process
        self._configure()

        # check if it was possible to start up pigeon
        if self.start_pigeon and self.pigeon is None:
            self.print("Module was supposed to start up pigeon but it was not possible to start pigeon! Exiting...")
            return

        pubsub = __database__.r.pubsub()

        # callbacks for subscribed channels
        callbacks = {
            self.p2p_data_request_channel: self.data_request_callback,
            self.slips_update_channel: self.update_callback,
            self.gopy_channel: self.gopy_callback,
        }

        pubsub.subscribe(**callbacks, ignore_subscribe_messages=True)
        try:
            while True:
                ret_code = self.pigeon.poll()
                if ret_code is not None:
                    self.print(f"Pigeon process suddenly terminated with return code {ret_code}. Stopping module.")
                    return

                # get_message() also let redis library to take execution time and call subscribed callbacks if needed
                message = pubsub.get_message()

                # listen to slips kill signal and quit
                if message and message['data'] == 'stop_process':
                    self.print("Received stop signal from slips, stopping")
                    if self.start_pigeon:
                        self.pigeon.send_signal(signal.SIGINT)

                    self.trust_db.__del__()
                    break

                time.sleep(0.1)

        except KeyboardInterrupt:
            pass

        except Exception as e:
            self.print(f"Exception {e}")

        return True

    def gopy_callback(self, msg: Dict):
        try:
            self.go_director.handle_gopy_data(msg["data"])
        except Exception as e:
            self.printer.err(f"Exception {e} in gopy_callback")

    def update_callback(self, msg: Dict):
        try:
            data = msg["data"]
            self.print(f"IP info was updated in slips for ip: {data}")
            self.handle_update(data)
        except Exception as e:
            self.printer.err(f"Exception {e} in update_callback")

    def data_request_callback(self, msg: Dict):
        try:
            self.handle_data_request(msg["data"])
        except Exception as e:
            self.printer.err(f"Exception {e} in data_request_callback")

    def handle_update(self, ip_address: str) -> None:
        """
        Handle IP scores changing in Slips received from the ip_info_change channel

        This method checks if new score differs from opinion known to the network, and if so, it means that it is worth
        sharing and it will be shared. Additionally, if the score is serious, the node will be blamed
        :param ip_address: The IP address sent through the ip_info_change channel (if it is not valid IP, it returns)
        """

        # abort if the IP is not valid
        if not utils.validate_ip_address(ip_address):
            self.print("IP validation failed")
            return

        score, confidence = utils.get_ip_info_from_slips(ip_address)
        if score is None:
            self.print("IP doesn't have any score/confidence values in DB")
            return

        # insert data from slips to database
        self.trust_db.insert_slips_score(ip_address, score, confidence)

        # TODO: discuss - only share score if confidence is high enough?
        # compare slips data with data in go
        data_already_reported = True
        try:
            cached_opinion = self.trust_db.get_cached_network_opinion("ip", ip_address)
            cached_score, cached_confidence, network_score, timestamp = cached_opinion
            if cached_score is None:
                data_already_reported = False
            elif abs(score - cached_score) < 0.1:
                data_already_reported = False
        except KeyError:
            data_already_reported = False
        except IndexError:
            # data saved in local db have wrong structure, this is an invalid state
            return

        # TODO: in the future, be smarter and share only when needed. For now, we will always share
        # if not data_already_reported:
        #     send_evaluation_to_go(ip_address, score, confidence, "*")
        utils.send_evaluation_to_go(ip_address, score, confidence, "*", self.pygo_channel)

        # TODO: discuss - based on what criteria should we start blaming?
        if score > 0.8 and confidence > 0.6:
            utils.send_blame_to_go(ip_address, score, confidence, self.pygo_channel)

    def handle_data_request(self, message_data: str) -> None:
        """
        Read data request from Slips and collect the data.

        Three `arguments` are expected in the redis channel:
            ip_address: str,
            cache_age: int [seconds]
        The return value is sent to the redis channel `p2p_data_response` in the format:
            ip_address: str,
            timestamp: int [time of assembling the response],
            network_opinion: float,
            network_confidence: float,
            network_competence: float,
            network_trust: float

        This method will check if any data not older than `cache_age` is saved in cache. If yes, this data is returned.
        If not, the database is checked. An ASK query is sent to the network and responses are collected and saved into
        the redis database.

        :param message_data: The data received from the redis channel `p2p_data_response`
        :return: None, the result is saved into the redis database under key `p2p4slips`
        """

        # make sure that IP address is valid and cache age is a valid timestamp from the past
        ip_address, cache_age = validate_slips_data(message_data)
        if ip_address is None:
            # IP address is not valid, aborting
            return

        # if data is in cache and is recent enough, nothing happens and Slips should just check the database
        score, confidence, network_score, timestamp = self.trust_db.get_cached_network_opinion("ip", ip_address)
        if score is not None and time.time() - timestamp < cache_age:
            # cached value is ok, do nothing
            return

        # if cached value is old, ask the peers

        # TODO: in some cases, it is not necessary to wait, specify that and implement it
        #       I do not remember writing this comment. I have no idea in which cases there is no need to wait? Maybe
        #       when everybody responds asap?
        utils.send_request_to_go(ip_address, self.pygo_channel)

        # go will send a reply in no longer than 10s (or whatever the timeout there is set to). The reply will be
        # processed by an independent process in this module and database will be updated accordingly
        # TODO: the timeout is lowered to allow fast experiments
        time.sleep(0.5)

        # get data from db, processed by the trust model
        combined_score, combined_confidence = self.reputation_model.get_opinion_on_ip(ip_address)

        # no data in db - this happens when testing, if there is not enough data on peers
        if combined_score is None:
            self.print("No data received from network :(")
        else:
            self.print("Network shared some data, saving it now!")
            self.print(
                "IP: " + ip_address + ", result: [" + str(combined_score) + ", " + str(combined_confidence) + "]")
            utils.save_ip_report_to_db(ip_address, combined_score, combined_confidence, network_score,
                                       self.storage_name)

    def respond_to_message_request(self, key, reporter):
        pass

    def process_message_report(self, reporter: str, report_time: int, data: dict):
        pass
