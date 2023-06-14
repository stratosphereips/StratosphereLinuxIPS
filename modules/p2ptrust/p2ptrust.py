
import modules.p2ptrust.trust.base_model as reputation_model
import modules.p2ptrust.trust.trustdb as trustdb
import modules.p2ptrust.utils.utils as p2p_utils
from modules.p2ptrust.utils.go_director import GoDirector
from slips_files.common.imports import *
import threading
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict
import json
import sys
import socket

def validate_slips_data(message_data: str) -> (str, int):
    """
    Check that message received from p2p_data_request channel has correct
    format:  json serialized {
                    'ip': str(saddr),
                    'profileid' : str(profileid),
                    'twid' :  str(twid),
                    'proto' : str(proto),
                    'ip_state' : 'srcip',
                    'stime': starttime,
                    'uid': uid,
                    'cache_age': cache_age
                }

    If the message is correct, the two values are returned as a tuple (str, int).
    If not, (None, None) is returned.
    :param message_data: data from slips request channel
    :return: the received msg or None tuple
    """

    try:
        message_data = json.loads(message_data)
        ip_address = message_data.get('ip')
        # time_since_cached = int(message_data.get('cache_age', 0))
        return message_data if p2p_utils.validate_ip_address(ip_address) else None
    except ValueError:
        # message has wrong format
        print(
            f'The message received from p2p_data_request channel has incorrect format: {message_data}'
        )
        return None


class Trust(Module, multiprocessing.Process):
    name = 'P2P Trust'
    description = 'Enables sharing detection data with other Slips instances'
    authors = ['Dita', 'Alya Gomaa']
    pigeon_port=6668
    rename_with_port=False
    slips_update_channel='ip_info_change'
    p2p_data_request_channel='p2p_data_request'
    gopy_channel_raw='p2p_gopy'
    pygo_channel_raw='p2p_pygo'
    start_pigeon=True
    pigeon_binary= os.path.join(os.getcwd(),'p2p4slips/p2p4slips')  # or make sure the binary is in $PATH
    pigeon_key_file='pigeon.keys'
    rename_redis_ip_info=False
    rename_sql_db_file=False
    override_p2p=False

    def init(self, *args, **kwargs):
        output_dir = self.db.get_output_dir()
        # flag to ensure slips prints multiaddress only once
        self.mutliaddress_printed = False
        self.pigeon_logfile_raw = os.path.join(output_dir, 'p2p.log')

        self.p2p_reports_logfile = os.path.join(output_dir, 'p2p_reports.log')
        # pigeon generate keys and stores them in the following dir, if this is placed in the <output> dir,
        # when restarting slips, it will look for the old keys in the new output dir! so it wont find them and will
        # generate new keys, and therefore new peerid!
        # store the keys in slips main dir so they don't change every run
        data_dir = os.path.join(os.getcwd(), 'p2ptrust_runtime/')
        # data_dir = f'./output/{used_interface}/p2ptrust_runtime/'
        # create data folder
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        self.data_dir = data_dir

        self.port = self.get_available_port()
        self.host = self.get_local_IP()

        str_port = str(self.port) if self.rename_with_port else ''

        self.gopy_channel = self.gopy_channel_raw + str_port
        self.pygo_channel = self.pygo_channel_raw + str_port

        self.read_configuration()
        if self.create_p2p_logfile:
            self.pigeon_logfile = self.pigeon_logfile_raw + str_port
            self.print(f"Storing p2p.log in {self.pigeon_logfile}")
            # create the thread that rotates the p2p.log every 1d
            self.rotator_thread = threading.Thread(
                target=self.rotate_p2p_logfile, daemon=True
            )

        self.storage_name = 'IPsInfo'
        if self.rename_redis_ip_info:
            self.storage_name += str(self.port)
        self.c1 = self.db.subscribe('report_to_peers')
        # channel to send msgs to whenever slips needs info from other peers about an ip
        self.c2 = self.db.subscribe(self.p2p_data_request_channel)
        # this channel receives peers requests/updates
        self.c3 = self.db.subscribe(self.gopy_channel)
        self.channels = {
            'report_to_peers': self.c1,
            self.p2p_data_request_channel: self.c2,
            self.gopy_channel: self.c3,
        }

        # they have to be defined here because the variable name utils is already taken
        # TODO rename one of them
        self.threat_levels = {
            'info': 0,
            'low': 0.2,
            'medium': 0.5,
            'high': 0.8,
            'critical': 1,
        }

        self.sql_db_name = f'{self.data_dir}trustdb.db'
        if self.rename_sql_db_file:
            self.sql_db_name += str(pigeon_port)
        # todo don't duplicate this dict, move it to slips_utils
        # all evidence slips detects has threat levels of strings
        # each string should have a corresponding int value to be able to calculate
        # the accumulated threat level and alert


    def read_configuration(self):
        conf = ConfigParser()
        self.create_p2p_logfile: bool = conf.create_p2p_logfile()


    def get_used_interface(self):
        return sys.argv[sys.argv.index('-i') + 1]

    def get_local_IP(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip


    def rotate_p2p_logfile(self):
        """
        Thread that rotates p2p.log file every 1 day
        """
        rotation_period = 86400    # 1d
        while True:
            time.sleep(rotation_period)
            lock = threading.Lock()
            lock.acquire()
            # erase contents of file instead of deleting it
            # because the pigeon has an open handle of it
            open(self.pigeon_logfile, "w").close()
            lock.release()


    def get_available_port(self):
        for port in range(32768, 65535):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(('0.0.0.0', port))
                sock.close()
                return port
            except Exception:
                # port is in use
                continue

    def _configure(self):
        # TODO: do not drop tables on startup
        self.trust_db = trustdb.TrustDB(
            self.sql_db_name, self.output_queue, drop_tables_on_startup=True
        )
        self.reputation_model = reputation_model.BaseModel(
            self.output_queue, self.trust_db
        )
        # print(f"[DEBUGGING] Starting godirector with pygo_channel: {self.pygo_channel}")
        self.go_director = GoDirector(
            self.trust_db,
            self.db,
            self.output_queue,
            self.storage_name,
            override_p2p=self.override_p2p,
            report_func=self.process_message_report,
            request_func=self.respond_to_message_request,
            gopy_channel=self.gopy_channel,
            pygo_channel=self.pygo_channel,
            p2p_reports_logfile=self.p2p_reports_logfile
        )

        self.pigeon = None
        if self.start_pigeon:
            if not shutil.which(self.pigeon_binary):
                self.print(
                    f'P2p4slips binary not found in "{self.pigeon_binary}". '
                    f'Did you include it in PATH?. Exiting process.'
                )
                return
            executable = [self.pigeon_binary]
            port_param = ['-port', str(self.port)]
            # if '-ip' in sys.argv:
            #     ip_to_listen_on = sys.argv[sys.argv.index('-ip')+1]
            #     host_param = ["-host", ip_to_listen_on ]
            #     print(f"P2P modules is listening on ip {ip_to_listen_on} port: {self.port}, using '-ip' parameter")
            # else:
            host_param = ['-host', self.host]
            self.print(
                f'P2p is listening on {self.host} port {self.port} determined by p2p module'
            )

            keyfile_param = ['-key-file', self.pigeon_key_file]
            # rename_with_port_param = ["-rename-with-port", str(self.rename_with_port).lower()]
            pygo_channel_param = ['-redis-channel-pygo', self.pygo_channel_raw]
            gopy_channel_param = ['-redis-channel-gopy', self.gopy_channel_raw]
            executable.extend(port_param)
            executable.extend(host_param)
            executable.extend(keyfile_param)
            # executable.extend(rename_with_port_param)
            executable.extend(pygo_channel_param)
            executable.extend(gopy_channel_param)
            if self.create_p2p_logfile:
                outfile = open(self.pigeon_logfile, '+w')
            else:
                outfile = open(os.devnull, "+w")

            self.pigeon = subprocess.Popen(
                executable, cwd=self.data_dir, stdout=outfile
            )


            # print(f"[debugging] runnning pigeon: {executable}")

    def new_evidence_callback(self, msg: Dict):
        """
        This function is called whenever a msg arrives to the report_to_peers channel,
        It compares the score and confidence of the given IP and decides whether or not to
        share it accordingly
        """
        try:
            data = json.loads(msg['data'])
        except json.decoder.JSONDecodeError:
            # not a valid json dict
            return

        # example: dstip srcip dport sport dstdomain
        attacker_direction = data.get('attacker_direction')
        if 'ip' not in attacker_direction:   # and not 'domain' in attacker_direction:
            # todo do we share domains too?
            # the detection is a srcport, dstport, etc. don't share
            return

        evidence_type = data.get('evidence_type')
        if 'P2PReport' in evidence_type:
            # we shouldn't re-share evidence reported by other peers
            return


        attacker = data.get('attacker')
        confidence = data.get('confidence', False)
        threat_level = data.get('threat_level', False)
        if not threat_level:
            self.print(
                f"IP {attacker} doesn't have a threat_level. not sharing to the network.", 0,2,
            )
            return
        if not confidence:
            self.print(
                f"IP {attacker} doesn't have a confidence. not sharing to the network.", 0, 2,
            )
            return

        # get the int representing this threat_level
        score = self.threat_levels[threat_level]
        # todo what we're currently sharing is the threat level(int) of the evidence caused by this ip

        # todo when we generate a new evidence,
        #  we give it a score and a tl, but we don't update the IP_Info and give this ip a score in th db!

        # TODO: discuss - only share score if confidence is high enough?
        # compare slips data with data in go
        data_already_reported = True
        try:
            cached_opinion = self.trust_db.get_cached_network_opinion(
                'ip', attacker
            )
            (
                cached_score,
                cached_confidence,
                network_score,
                timestamp,
            ) = cached_opinion
            # if we don't have info about this ip from the p2p network, report it to the p2p netwrok
            if not cached_score:
                data_already_reported = False
        except KeyError:
            data_already_reported = False
        except IndexError:
            # data saved in local db have wrong structure, this is an invalid state
            return

        # TODO: in the future, be smarter and share only when needed. For now, we will always share
        if not data_already_reported:
            # Take data and send it to a peer as report.
            p2p_utils.send_evaluation_to_go(
                attacker, score, confidence, '*', self.pygo_channel, self.db
            )

    def gopy_callback(self, msg: Dict):
        """
        this function is called whenever slips receives peers requests/updates
        happens when a msg is sent in the gopy_channel.
        """
        # try:
        data: str = msg['data']
        data: dict = json.loads(data)
        self.go_director.handle_gopy_data(data)
        # except Exception as e:
        #     self.printer.print(f'Exception in gopy_callback: {e} ', 0, 1)

    # def update_callback(self, msg: Dict):
    #     try:
    #         data = msg["data"]
    #         self.print(f"IP info was updated in slips for ip: {data}")
    #         self.handle_update(data)
    #     except Exception as e:
    #         self.printer.print(f"Exception {e} in update_callback")

    def data_request_callback(self, msg: Dict):
        try:
            # ignore subscribe msgs (first 2 msgs sent in redis channel)
            if msg and type(msg['data']) != int:
                self.handle_data_request(msg['data'])
        except Exception as e:
            self.print(f'Exception {e} in data_request_callback', 0, 1)

    # def handle_update(self, ip_address: str) -> None:
    #     """
    #     Handle IP scores changing in Slips received from the ip_info_change channel
    #
    #     This method checks if Slips has a new score that are different
    #     from the scores known to the network, and if so, it means that it is worth
    #     sharing and it will be shared.
    #     Additionally, if the score is serious, the node will be blamed(blocked)
    #     :param ip_address: The IP address sent through the ip_info_change channel (if it is not valid IP, it returns)
    #     """
    #
    #     # abort if the IP is not valid
    #     if not utils.validate_ip_address(ip_address):
    #         self.print("IP validation failed")
    #         return
    #
    #     score, confidence = utils.get_ip_info_from_slips(ip_address)
    #     if score is None:
    #         self.print("IP doesn't have any score/confidence values in DB")
    #         return
    #
    #     # insert data from slips to database
    #     self.trust_db.insert_slips_score(ip_address, score, confidence)
    #
    #     # TODO: discuss - only share score if confidence is high enough?
    #
    #     # compare slips data with data in go
    #     data_already_reported = True
    #     try:
    #         cached_opinion = self.trust_db.get_cached_network_opinion("ip", ip_address)
    #         cached_score, cached_confidence, network_score, timestamp = cached_opinion
    #         if cached_score is None:
    #             data_already_reported = False
    #         elif abs(score - cached_score) < 0.1:
    #             data_already_reported = False
    #     except KeyError:
    #         data_already_reported = False
    #     except IndexError:
    #         # data saved in local db have wrong structure, this is an invalid state
    #         return
    #
    #     # TODO: in the future, be smarter and share only when needed. For now, we will always share
    #     if not data_already_reported:
    #         utils.send_evaluation_to_go(ip_address, score, confidence, "*", self.pygo_channel)
    #
    #     # TODO: discuss - based on what criteria should we start blaming?
    #     # decide whether or not to block
    #     if score > 0.8 and confidence > 0.6:
    #         #todo finish the blocking logic and actually block the ip
    #
    #         # tell other peers that we're blocking this IP
    #         utils.send_blame_to_go(ip_address, score, confidence, self.pygo_channel)

    def set_evidence_malicious_ip(self, ip_info, threat_level, confidence):
        """
        Set an evidence for a malicious IP met in the timewindow
        ip_info format is json serialized {
        #             'ip': the source/dst ip
        #             'profileid' : profile where the alert was generated. It includes the src ip
        #             'twid' : name of the timewindow when it happened.
        #             'proto' : protocol
        #             'ip_state' : 'srcip/dstip',
        #             'stime': Exact time when the evidence happened
        #             'uid': Zeek uid of the flow that generated the evidence,
        #             'cache_age': How old is the info about this ip
        #         }
        :param threat_level: the threat level we learned form the network
        :param confidence: how confident the network opinion is about this opinion
        """

        attacker = ip_info.get('ip')
        ip_state = ip_info.get('ip_state')
        # proto = ip_info.get('proto', '').upper()
        uid = ip_info.get('uid')
        profileid = ip_info.get('profileid')
        twid = ip_info.get('twid')
        timestamp = str(ip_info.get('stime'))

        attacker_direction = ip_state
        evidence_type = 'Malicious-IP-from-P2P-network'

        category = 'Anomaly.Traffic'
        # dns_resolution = self.db.get_dns_resolution(ip)
        # dns_resolution = dns_resolution.get('domains', [])
        # dns_resolution = f' ({dns_resolution[0:3]}), ' if dns_resolution else ''
        victim = profileid.split("_")[-1]

        if 'src' in ip_state:
            direction = 'from'
            # we'll be using this to make the description more clear
            other_direction = 'to'
        else:
            direction = 'to'
            other_direction = 'from'

        ip_identification = self.db.get_ip_identification(attacker)
        description = (
            f'connection {direction} blacklisted IP {attacker} ({ip_identification}) '
            f'{other_direction} {profileid.split("_")[-1]}'
            f' Source: Slips P2P network.'
        )

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid, victim=victim)

        # add this ip to our MaliciousIPs hash in the database
        self.db.set_malicious_ip(attacker, profileid, twid)

    def handle_data_request(self, message_data: str) -> None:
        """
        Process the request from Slips, ask the network and process the network response.

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

        This method will check if any data not older than `cache_age`
        is saved in cache. If yes, this data is returned.
        If not, the database is checked.
        An ASK query is sent to the network and responses are collected and saved into
        the redis database.

        :param message_data: The data received from the redis channel `p2p_data_response`
        :return: None, the result is saved into the redis database under key `p2p4slips`
        """

        # make sure that IP address is valid
        # and cache age is a valid timestamp from the past
        ip_info = validate_slips_data(message_data)
        if ip_info is None:
            # IP address is not valid, aborting
            # print(f"DEBUGGING: IP address is not valid: {ip_info}, not asking the network")
            return
        # ip_info is {
        #             'ip': str(saddr),
        #             'profileid' : str(profileid),
        #             'twid' :  str(twid),
        #             'proto' : str(proto),
        #             'ip_state' : 'srcip',
        #             'stime': starttime,
        #             'uid': uid,
        #             'cache_age': cache_age
        #         }
        ip_address = ip_info.get('ip')
        cache_age = ip_info.get('cache_age')
        # if data is in cache and is recent enough,
        # nothing happens and Slips should just check the database
        (
            score,
            confidence,
            network_score,
            timestamp,
        ) = self.trust_db.get_cached_network_opinion('ip', ip_address)
        if score is not None and time.time() - timestamp < cache_age:
            # cached value is ok, do nothing
            # print("DEBUGGING:  cached value is ok, not asking the network.")
            return

        # if cached value is old, ask the peers

        # TODO: in some cases, it is not necessary to wait, specify that and implement it
        #       I do not remember writing this comment. I have no idea in which cases there is no need to wait? Maybe
        #       when everybody responds asap?
        p2p_utils.send_request_to_go(ip_address, self.pygo_channel, self.db)
        self.print(f'[Slips -> The Network] request about {ip_address}')

        # go will send a reply in no longer than 10s (or whatever the
        # timeout there is set to). The reply will be
        # processed by an independent process in this module and
        # database will be updated accordingly
        time.sleep(2)

        # get data from db, processed by the trust model
        (
            combined_score,
            combined_confidence,
        ) = self.reputation_model.get_opinion_on_ip(ip_address)

        # no data in db - this happens when testing, if there is not enough data on peers
        if combined_score is None:
            self.print(
                f'No data received from the network about {ip_address}\n', 0, 2
            )
            # print(f"[DEBUGGING] No data received from the network about {ip_address}\n")
        else:
            self.print(
                f'The Network shared some data about {ip_address}, '
                f'Shared data: score={combined_score}, confidence={combined_confidence} saving it to  now!\n',
                0,
                2,
            )

            # save it to IPsInfo hash in p2p4slips key in the db AND p2p_reports key
            p2p_utils.save_ip_report_to_db(
                ip_address,
                combined_score,
                combined_confidence,
                network_score,
                self.db,
                self.storage_name,
            )
            if int(combined_score) * int(confidence) > 0:
                self.set_evidence_malicious_ip(
                    ip_info, combined_score, confidence
                )

    def respond_to_message_request(self, key, reporter):
        # todo do you mean another peer is asking me about an ip? yes. in override mode
        """
        Handle data request from a peer (in overriding p2p mode) (set to false by defualt)
        :param key: The ip requested by the peer
        :param reporter: The peer that sent the request
        return a json response

        """
        pass

    def process_message_report(
        self, reporter: str, report_time: int, data: dict
    ):
        """
        Handle a report received from a peer
        :param reporter: The peer that sent the report
        :param report_time: Time of receiving the report, provided by the go part
        :param data: Report data
        """
        # All keys and data sent to this function is validated in go_director.py
        data = json.dumps(data)
        # give the report to evidenceProcess to decide whether to block or not
        self.db.publish('new_blame', data)


    def shutdown_gracefully(self):
        if hasattr(self, 'pigeon'):
            self.pigeon.send_signal(signal.SIGINT)
        if hasattr(self, 'trust_db'):
            self.trust_db.__del__()

    def pre_main(self):
        utils.drop_root_privs()
        # configure process
        self._configure()
        # check if it was possible to start up pigeon
        if self.start_pigeon and self.pigeon is None:
            self.print(
                'Module was supposed to start up pigeon but it was not possible to start pigeon! Exiting...'
            )
            return 1

        # create_p2p_logfile is taken from slips.conf
        if self.create_p2p_logfile:
            # rotates p2p.log file every 1 day
            self.rotator_thread.start()

        # should call self.update_callback
        # self.c4 = self.db.subscribe(self.slips_update_channel)

    def main(self):
        """main loop function"""
        if msg:= self.get_msg('report_to_peers'):
            self.new_evidence_callback(msg)

        if msg:= self.get_msg(self.p2p_data_request_channel):
            self.data_request_callback(msg)

        if msg:= self.get_msg(self.gopy_channel):
            self.gopy_callback(msg)

        ret_code = self.pigeon.poll()
        if ret_code is not None:
            self.print(
                f'Pigeon process suddenly terminated with return code {ret_code}. Stopping module.'
            )
            return 1

        try:
            if not self.mutliaddress_printed:
                # give the pigeon time to put the multiaddr in the db
                time.sleep(2)
                multiaddr = self.db.get_multiaddr()
                self.print(f"You Multiaddress is: {multiaddr}")
                self.mutliaddress_printed = True

        except Exception:
            pass
