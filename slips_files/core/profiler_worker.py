import json
from dataclasses import asdict
from multiprocessing import Process
import ipaddress
import pprint
import multiprocessing
from typing import (
    List,
    Union,
    Optional,
    Dict,
)

from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address
import netifaces
import validators

from slips_files.common.printer import Printer
from slips_files.common.slips_utils import utils
from slips_files.common.style import green
from slips_files.core.database.database_manager import DBManager
from slips_files.core.helpers.flow_handler import FlowHandler
from slips_files.core.helpers.symbols_handler import SymbolHandler
from slips_files.core.helpers.whitelist.whitelist import Whitelist
from slips_files.core.helpers.bloom_filters_manager import BFManager
from slips_files.core.input_profilers.argus import Argus
from slips_files.core.input_profilers.nfdump import Nfdump
from slips_files.core.input_profilers.suricata import Suricata
from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs


class ProfilerWorker(Process):
    def __init__(
        self,
        name,
        logger,
        output_dir,
        redis_port,
        conf,
        ppid: int,
        args,
        localnet_cache: Dict[str, str],
        profiler_queue: multiprocessing.Queue,
        stop_profiler_workers: multiprocessing.Event,
        handle_setting_local_net_lock: multiprocessing.Lock,
        flows_to_process_q: multiprocessing.Queue,
        input_handler: (
            ZeekTabs | ZeekJSON | Argus | Suricata | ZeekTabs | Nfdump
        ),
        bloom_filters: BFManager,
    ):
        super().__init__()
        self.name = name
        self.logger = logger
        self.output_dir = output_dir
        self.redis_port = redis_port
        self.conf = conf
        self.ppid = ppid
        self.args = args
        self.profiler_queue = profiler_queue
        self.flows_to_process_q = flows_to_process_q
        self.stop_profiler_workers = stop_profiler_workers
        self.bloom_filters = bloom_filters

        # this is an instance of that cls
        self.input_handler = input_handler
        self.handle_setting_local_net_lock = handle_setting_local_net_lock

        self.printer = Printer(self.logger, self.name)
        self.db = DBManager(
            self.logger, self.output_dir, self.redis_port, self.conf, self.ppid
        )

        self.read_configuration()
        self.received_lines = 0
        self.localnet_cache = localnet_cache
        self.whitelist = Whitelist(self.logger, self.db, self.bloom_filters)
        self.symbol = SymbolHandler(self.logger, self.db)
        # stores the MAC addresses of the gateway of each interface
        # will have interfaces as keys, and MACs as values
        self.gw_macs = {}
        self.gw_ips = {}
        # flag to know which flow is the start of the pcap/file
        self.first_flow = True

    def read_configuration(self):
        self.client_ips: List[
            Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]
        ]
        self.client_ips = self.conf.client_ips()
        self.local_whitelist_path = self.conf.local_whitelist_path()
        self.timeformat = self.conf.ts_format()
        self.analysis_direction = self.conf.analysis_direction()
        self.label = self.conf.label()
        self.width = self.conf.get_tw_width_as_float()

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def get_msg_from_queue(self, q: multiprocessing.Queue):
        """
        retrieves a msg from the given queue
        """
        try:
            return q.get(timeout=1, block=False)
        except multiprocessing.queues.Empty:
            return None
        except Exception:
            return None

    def should_stop_profiler_workers(self) -> bool:
        # cant use while self.flows_to_process_q.qsize() != 0 only here
        # because when the thread starts, this qsize is 0, so we need
        # another indicator that we are at the end of the flows. aka the
        # stop_profiler_workers event
        return (
            self.stop_profiler_workers.is_set()
            and not self.flows_to_process_q.qsize()
        )

    def get_private_client_ips(
        self,
    ) -> List[Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]]:
        """
        returns the private ips found in the client_ips param
        in the config file
        """
        private_clients = []
        for ip in self.client_ips:
            if utils.is_private_ip(ip):
                private_clients.append(ip)
        return private_clients

    def convert_starttime_to_epoch(self, starttime) -> str:
        try:
            return utils.convert_ts_format(starttime, "unixtimestamp")
        except ValueError:
            self.print(
                f"We can not recognize time format of "
                f"flow.starttime: {starttime}",
                0,
                1,
            )
            return starttime

    def store_first_seen_ts(self, ts):
        # set the pcap/file start time in the analysis key
        if self.first_flow:
            self.first_flow = False

            if self.db.get_first_flow_time():
                # already set by another worker
                return

            self.db.set_input_metadata({"file_start": ts})

    def store_features_going_in(self, profileid: str, twid: str, flow):
        """
        If we have the all direction set , slips creates profiles
        for each IP, the src and dst
        store features going our adds the conn in the profileA from
        IP A -> IP B in the db
        this function stores the reverse of this connection. adds
        the conn in the profileB from IP B <- IP A
        """
        # self.print(f'Storing features going in for profile
        # {profileid} and tw {twid}')
        supported_types = {"flow", "conn", "argus", "nfdump"}
        for type_ in supported_types:
            if type_ in flow.type_:
                break
        else:
            return

        symbol = self.symbol.compute(flow, twid, "InTuples")

        saddr_as_obj = ipaddress.ip_address(flow.saddr)
        # Add the src tuple using the src ip, and dst port
        tupleid = f"{saddr_as_obj}-{flow.dport}-{flow.proto}"
        role = "Server"
        # create the intuple
        self.db.add_tuple(profileid, twid, tupleid, symbol, role, flow)

        # Add the srcip and srcport
        self.db.add_ips(profileid, twid, flow, role)
        port_type = "Src"
        self.db.add_port(profileid, twid, flow, role, port_type)

        # Add the dstport
        port_type = "Dst"
        self.db.add_port(profileid, twid, flow, role, port_type)

        # Add the flow with all the fields interpreted
        self.db.add_flow(
            flow,
            profileid=profileid,
            twid=twid,
            label=self.label,
        )
        self.db.mark_profile_tw_as_modified(profileid, twid, "")

    def store_features_going_out(self, flow, flow_parser: FlowHandler):
        """
        function for adding the features going out of the profile
        """
        self.store_first_seen_ts(flow.starttime)

        cases = {
            "flow": flow_parser.handle_conn,
            "conn": flow_parser.handle_conn,
            "nfdump": flow_parser.handle_conn,
            "argus": flow_parser.handle_conn,
            "dns": flow_parser.handle_dns,
            "http": flow_parser.handle_http,
            "ssl": flow_parser.handle_ssl,
            "ssh": flow_parser.handle_ssh,
            "notice": flow_parser.handle_notice,
            "ftp": flow_parser.handle_ftp,
            "smtp": flow_parser.handle_smtp,
            "files": flow_parser.handle_files,
            "arp": flow_parser.handle_arp,
            "dhcp": flow_parser.handle_dhcp,
            "software": flow_parser.handle_software,
            "weird": flow_parser.handle_weird,
            "tunnel": flow_parser.handle_tunnel,
        }
        try:
            # call the function that handles this flow
            cases[flow.type_]()
        except KeyError:
            for supported_type in cases:
                if supported_type in flow.type_:
                    cases[supported_type]()
            return False

        # if the flow type matched any of the ifs above,
        # mark this profile as modified
        self.db.mark_profile_tw_as_modified(
            flow_parser.profileid, flow_parser.twid, ""
        )

    def get_rev_profile(self, flow):
        """
        get the profileid and twid of the daddr at the current starttime,
         not the source address
        """
        if not flow.daddr:
            # some flows don't have a daddr like software.log flows
            return False, False

        rev_profileid: str = self.db.get_profileid_from_ip(flow.daddr)
        if not rev_profileid:
            # the profileid is not present in the db, create it
            rev_profileid = f"profile_{flow.daddr}"
            self.db.add_profile(rev_profileid, flow.starttime)

        # in the database, Find and register the id of the tw where the flow
        # belongs.
        rev_twid: str = self.db.get_timewindow(flow.starttime, rev_profileid)
        return rev_profileid, rev_twid

    def get_localnet_of_given_interface(self) -> Dict[str, str]:
        """
        returns the local network of the given interface only if slips is
        running with -i
        """
        local_nets = {}
        for interface in utils.get_all_interfaces(self.args):
            addrs = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
            if not addrs:
                return local_nets

            for addr in addrs:
                ip = addr.get("addr")
                netmask = addr.get("netmask")
                if ip and netmask:
                    network = ipaddress.IPv4Network(
                        f"{ip}/{netmask}", strict=False
                    )
                    local_nets[interface] = str(network)
        return local_nets

    def get_local_net_of_flow(self, flow) -> Dict[str, str]:
        """
        gets the local network from client_ip
        param in the config file,
        or by using the localnetwork of the first private
        srcip seen in the traffic
        """
        local_net = {}
        # Reaching this func means slips is running on a file. we either
        # have a client ip or not
        private_client_ips: List[
            Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]
        ]
        # get_private_client_ips from the config file
        if private_client_ips := self.get_private_client_ips():
            # does the client ip from the config already have the localnet?
            for range_ in private_client_ips:
                if isinstance(range_, IPv4Network) or isinstance(
                    range_, IPv6Network
                ):
                    local_net["default"] = str(range_)
                    return local_net

        # For now the local network is only ipv4, but it
        # could be ipv6 in the future. Todo.
        ip: str = flow.saddr
        if cidr := utils.get_cidr_of_private_ip(ip):
            local_net["default"] = cidr
            return local_net

        return local_net

    def handle_setting_local_net(self, flow):
        """
        stores the local network if possible
        sets the self.localnet_cache dict
        """
        # this lock is to avoid running this func from the workers at the
        # same time.
        with self.handle_setting_local_net_lock:
            if not self.should_set_localnet(flow):
                return

            if self.db.is_running_non_stop():
                self.localnet_cache = self.get_localnet_of_given_interface()
            else:
                self.localnet_cache = self.get_local_net_of_flow(flow)

            for interface, local_net in self.localnet_cache.items():
                self.db.set_local_network(local_net, interface)

    def is_gw_info_detected(self, info_type: str, interface: str) -> bool:
        """
        checks own attributes and the db for the gw mac/ip
        :param info_type: can be 'mac' or 'ip'
        """
        info_mapping = {
            "mac": ("gw_macs", self.db.get_gateway_mac),
            "ip": ("gw_ips", self.db.get_gateway_ip),
        }

        if info_type not in info_mapping:
            raise ValueError(f"Unsupported info_type: {info_type}")

        attr, check_db_method = info_mapping[info_type]

        # did we get this interface's GW IP/MAC yet?
        if interface in getattr(self, attr, {}):
            # the reason we don't just check the db is we don't want a db
            # call per each flow
            return True

        # did some other module manage to get it?
        if info := check_db_method(interface):
            getattr(self, attr, {}).update({interface: info})
            return True

        return False

    def handle_in_flow(self, flow):
        """
        Adds a flow for the daddr <- saddr connection
        """
        # they are not actual flows to add in slips,
        # they are info about some ips derived by zeek from the flows
        execluded_flows = "software"
        if flow.type_ in execluded_flows:
            return
        rev_profileid, rev_twid = self.get_rev_profile(flow)
        self.store_features_going_in(rev_profileid, rev_twid, flow)

    def get_gw_ip_using_gw_mac(self, gw_mac) -> Optional[str]:
        """
        gets the ip of the given mac from the db
        prioritizes returning the ipv4. if not found, the function returns
        the ipv6. or none if both are not found.
        """
        # the db returns a serialized list of IPs belonging to this mac
        gw_ips: str = self.db.get_ip_of_mac(gw_mac)

        if not gw_ips:
            return

        gw_ips: List[str] = json.loads(gw_ips)
        # try to get the ipv4 if found in that list
        for ip in gw_ips:
            try:
                ipaddress.IPv4Address(ip)
                return ip
            except ipaddress.AddressValueError:
                continue

        # all of them are ipv6, return the first
        return gw_ips[0]

    def get_gateway_info(self, flow):
        """
        Gets the IP and MAC of the gateway and stores them in the db
        doesn't get the gateway ip if it's already in the db (for example
        detected by ip_info) module
        usually the mac of the flow going from a private ip -> a
        public ip is the mac of the GW
        """

        if not hasattr(flow, "dmac"):
            # some suricata flows dont have that, like SuricataFile objs
            return

        gw_mac_found: bool = self.is_gw_info_detected("mac", flow.interface)

        if not gw_mac_found:
            # we didnt get the MAC of the GW of this flow's interface
            # ok consider the GW MAC = any dst MAC of a flow
            # going from a private srcip -> a public ip
            if (
                utils.is_private_ip(flow.saddr)
                and not utils.is_ignored_ip(flow.daddr)
                and flow.dmac
            ):
                self.gw_macs.update({flow.interface: flow.dmac})
                self.db.set_default_gateway("MAC", flow.dmac, flow.interface)
                # self.print(
                #     f"MAC address of the gateway detected: "
                #     f"{green(self.gw_mac)}"
                # )
                gw_mac_found = True

        # we need the mac to be set to be able to find the ip using it
        if not self.is_gw_info_detected("ip", flow.interface) and gw_mac_found:
            gw_ip: Optional[str] = self.get_gw_ip_using_gw_mac(flow.dmac)
            if gw_ip:
                self.gw_ips[flow.interface] = gw_ip
                self.db.set_default_gateway("IP", gw_ip, flow.interface)
                self.print(
                    f"IP address of the gateway detected: " f"{green(gw_ip)}"
                )

    def is_ignored_ip(self, ip: str) -> bool:
        """
        This function checks if an IP is a special list of IPs that
        should not be alerted for different reasons
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return True

        # Is the IP multicast, private? (including localhost)
        # The broadcast address 255.255.255.255 is reserved.
        return (
            ip_obj.is_multicast
            or ip_obj.is_link_local
            or ip_obj.is_loopback
            or ip_obj.is_reserved
        )

    def should_set_localnet(self, flow) -> bool:
        """
        returns true only if the saddr of the current flow is ipv4, private
        and we don't have the local_net set already
        """
        if self.db.is_running_non_stop():
            if flow.interface in self.localnet_cache:
                return False
        elif "default" in self.localnet_cache:
            # running on a file, impossible to get the interface
            return False

        if flow.saddr == "0.0.0.0":
            return False

        if self.get_private_client_ips():
            # if we have private client ips, we're ready to set the
            # localnetwork
            return True

        if not validators.ipv4(flow.saddr):
            return False

        if self.is_ignored_ip(flow.saddr):
            return False

        saddr_obj = ipaddress.ip_address(flow.saddr)
        if not utils.is_private_ip(saddr_obj):
            return False

        return True

    def add_flow_to_profile(self, flow):
        """
        This is the main function that takes the columns of a flow
        and does all the magic to convert it into a working data in slips.
        It includes checking if the profile exists and how to put
        the flow correctly.
        """
        flow_parser = FlowHandler(self.db, self.symbol, flow)

        if not flow_parser.is_supported_flow_type():
            return False

        profileid = f"profile_{flow.saddr}"
        flow_parser.profileid = profileid

        try:
            ipaddress.ip_address(flow.saddr)
            ipaddress.ip_address(flow.daddr)
        except (ipaddress.AddressValueError, ValueError, AttributeError):
            # Its a mac
            if flow.type_ not in ("software", "weird"):
                # software and weird.log flows are allowed to not have a daddr
                return False

        self.get_gateway_info(flow)

        # Check if the flow is whitelisted and we should not process it
        if self.whitelist.is_whitelisted_flow(flow):
            self.print(f"{self.whitelist.get_bloom_filters_stats()}", 2, 0)
            return True

        # 5th. Store the data according to the paremeters
        # Now that we have the profileid and twid, add the data from the flow
        # in this tw for this profile
        self.print(f"Storing data in the profile: {profileid}", 3, 0)
        flow.starttime = self.convert_starttime_to_epoch(flow.starttime)
        # For this 'forward' profile, find the id in the
        # database of the tw where the flow belongs.
        twid = self.db.get_timewindow(flow.starttime, profileid)
        flow_parser.twid = twid

        # Create profiles for all ips we see
        self.db.add_profile(profileid, flow.starttime)
        self.store_features_going_out(flow, flow_parser)
        if self.analysis_direction == "all":
            self.handle_in_flow(flow)

        if self.db.is_cyst_enabled():
            # print the added flow as a form of debugging feedback for
            # the user to know that slips is working
            self.print(pprint.pp(asdict(flow)))
        return True

    def run(self):
        """
        This function runs in 3 different processes for faster processing of
        the flows
        """
        try:
            while not self.should_stop_profiler_workers():
                msg = self.get_msg_from_queue(self.flows_to_process_q)
                if not msg:
                    # wait for msgs
                    continue

                line: dict = msg["line"]
                # TODO who is putting this True here?
                if line is True:
                    continue

                # Received new input data
                self.print(f"< Received Line: {line}", 2, 0)
                self.received_lines += 1

                flow = self.input_handler.process_line(line)
                if not flow:
                    continue
                self.add_flow_to_profile(flow)
                self.handle_setting_local_net(flow)
                self.db.increment_processed_flows()
        except Exception as e:
            self.print(
                f"[{self.name}] Problem processing line {line}. "
                f"Line discarded. Error: {e}",
                0,
                1,
            )
        except KeyboardInterrupt:
            return
