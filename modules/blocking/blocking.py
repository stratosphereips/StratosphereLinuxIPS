# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import platform
import sys
import os
import shutil
import json
import subprocess
from typing import Dict
import time
from threading import Lock

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.slips_utils import utils
from .exec_iptables_cmd import exec_iptables_command
from modules.blocking.unblocker import Unblocker


OUTPUT_TO_DEV_NULL = ">/dev/null 2>&1"


class Blocking(IModule):
    """Data should be passed to this module as a json encoded python dict,
    by default this module flushes all slipsBlocking chains before it starts"""

    # Name: short name of the module. Do not use spaces
    name = "Blocking"
    description = "Block malicious IPs connecting to this device"
    authors = ["Sebastian Garcia, Alya Gomaa"]

    def init(self):
        self.c1 = self.db.subscribe("new_blocking")
        self.c2 = self.db.subscribe("tw_closed")
        self.read_configuration()
        self.channels = {
            "new_blocking": self.c1,
            "tw_closed": self.c2,
        }
        if platform.system() == "Darwin":
            self.print("Mac OS blocking is not supported yet.")
            sys.exit()

        self.firewall = self._determine_linux_firewall()
        self.sudo = utils.get_sudo_according_to_env()
        self._init_chains_in_firewall()
        self.blocking_log_path = os.path.join(self.output_dir, "blocking.log")
        self.blocking_logfile_lock = Lock()
        # clear it
        try:
            open(self.blocking_log_path, "w").close()
        except FileNotFoundError:
            pass
        self.last_closed_tw = None

        self.ap_info: None | Dict[str, str] = self.db.get_ap_info()
        self.is_running_in_ap_mode = True if self.ap_info else False

    def read_configuration(self):
        self.trust_local_network: bool = self.conf.get_trust_local_network()

    def log(self, text: str):
        """Logs the given text to the blocking log file"""
        with self.blocking_logfile_lock:
            with open(self.blocking_log_path, "a") as f:
                now = time.time()
                human_readable_datetime = utils.convert_ts_format(
                    now, utils.alerts_format
                )
                f.write(f"{human_readable_datetime} - {text}\n")

    def _determine_linux_firewall(self):
        """Returns the currently installed firewall and installs iptables if
        none was found"""

        if shutil.which("iptables"):
            # comes pre installed in docker
            return "iptables"
        else:
            # no firewall installed
            # user doesn't have a firewall
            self.print(
                "iptables is not installed. Blocking module is quitting."
            )
            sys.exit()

    def _get_cmd_output(self, command):
        """Executes a command and returns the output"""
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        return result.stdout.decode("utf-8")

    def _init_chains_in_firewall(self):
        """For linux: Adds a chain to iptables or a table to nftables called
        slipsBlocking where all the rules will reside"""

        if self.firewall != "iptables":
            return

        # delete any pre existing slipsBlocking rules that may conflict before
        # adding a new one
        # self.delete_iptables_chain()
        self.print('Executing "sudo iptables -N slipsBlocking"', 6, 0)
        # Add a new chain to iptables
        os.system(
            f"{self.sudo} iptables -N slipsBlocking {OUTPUT_TO_DEV_NULL}"
        )

        # Check if we're already redirecting to slipsBlocking chain
        input_chain_rules = self._get_cmd_output(
            f"{self.sudo} iptables -nvL INPUT"
        )
        output_chain_rules = self._get_cmd_output(
            f"{self.sudo} iptables -nvL OUTPUT"
        )
        forward_chain_rules = self._get_cmd_output(
            f"{self.sudo} iptables -nvL FORWARD"
        )
        # Redirect the traffic from all other chains to slipsBlocking so rules
        # in any pre-existing chains dont override it
        # -I to insert slipsBlocking at the top of the INPUT, OUTPUT and
        # FORWARD chains
        if "slipsBlocking" not in input_chain_rules:
            os.system(
                f"{self.sudo} iptables -I INPUT -j slipsBlocking "
                f"{OUTPUT_TO_DEV_NULL}"
            )
        if "slipsBlocking" not in output_chain_rules:
            os.system(
                f"{self.sudo} iptables -I OUTPUT -j slipsBlocking "
                f"{OUTPUT_TO_DEV_NULL}"
            )
        if "slipsBlocking" not in forward_chain_rules:
            os.system(
                f"{self.sudo} iptables -I FORWARD -j slipsBlocking"
                f" {OUTPUT_TO_DEV_NULL}"
            )

    def _is_ip_already_blocked(self, ip) -> bool:
        """Checks if ip is already blocked or not using iptables"""
        command = f"{self.sudo} iptables -L slipsBlocking -v -n"
        # Execute command
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        result = result.stdout.decode("utf-8")
        return ip in result

    def _block_ip(self, ip_to_block: str, flags: Dict[str, str]) -> bool:
        """
        This function determines the user's platform and firewall and calls
        the appropriate function to add the rules to the used firewall.
        By default this function blocks all traffic from and to the given ip.
        return strue if the ip is successfully blocked
        """

        if self.firewall != "iptables":
            return

        if not isinstance(ip_to_block, str):
            return False

        # Make sure ip isn't already blocked before blocking
        if self._is_ip_already_blocked(ip_to_block):
            return False

        from_ = flags.get("from_")
        to = flags.get("to")
        dport = flags.get("dport")
        sport = flags.get("sport")
        protocol = flags.get("protocol")
        # Set the default behaviour to block all traffic from and to an ip
        if from_ is None and to is None:
            from_, to = True, True
        # This dictionary will be used to construct the rule
        options = {
            "protocol": f" -p {protocol}" if protocol is not None else "",
            "dport": f" --dport {str(dport)}" if dport is not None else "",
            "sport": f" --sport {str(sport)}" if sport is not None else "",
        }
        blocked = False
        if from_:
            # Add rule to block traffic from source ip_to_block (-s)
            blocked = exec_iptables_command(
                self.sudo,
                action="insert",
                ip_to_block=ip_to_block,
                flag="-s",
                options=options,
            )
            if blocked:
                txt = f"Blocked all traffic from: {ip_to_block}"
                self.print(txt)
                self.log(txt)

        if to:
            # Add rule to block traffic to ip_to_block (-d)
            blocked = exec_iptables_command(
                self.sudo,
                action="insert",
                ip_to_block=ip_to_block,
                flag="-d",
                options=options,
            )
            if blocked:
                txt = f"Blocked all traffic to: {ip_to_block}"
                self.print(txt)
                self.log(f"Blocked all traffic to: {ip_to_block}")
                self.db.set_blocked_ip(ip_to_block)
        return blocked

    def protect_ap_clients(self):
        """
        If slips is running as an access point in bridged mode,
        https://stratospherelinuxips.readthedocs.io/en/develop/immune/installing_slips_in_the_rpi.html#protect-your-local-network-with-slips-on-the-rpi
        This func adds firewall rules to protect the AP clients from
        clients in the router's main network.
        The goal is to mimic NAT isolation without using NAT.
        why not just use NAT? to be able to monitor the traffic of the RPI
        to the router and back on eth0
        """
        if not self.is_running_in_ap_mode:
            return

        if self.trust_local_network:
            # then user trusts the local network, no need to add these
            # strict FW rules
            return

        self.print(
            f"Slips is running in AP bridged mode. Adding iptables "
            f"rules to protect AP clients on "
            f"{self.ap_info['wifi_interface']} from the router's "
            f"network users on {self.ap_info['ethernet_interface']}."
        )

        # Set the default policy for the FORWARD chain to DROP.
        os.system(
            self.sudo + f" iptables -P FORWARD DROP {OUTPUT_TO_DEV_NULL}"
        )
        # 1. Allow traffic originating from the Wi-Fi clients to go anywhere.
        os.system(
            self.sudo + f" iptables -P -A FORWARD -m physdev --physdev-in "
            f"{self.ap_info['wifi_interface']} "
            f"-j ACCEPT {OUTPUT_TO_DEV_NULL}"
        )

        # 2. Allow return traffic (ESTABLISHED, RELATED) back to the Wi-Fi clients.
        # when in AP bridge mode we excpect the users to always monitor
        # the physical interface with -i
        os.system(
            self.sudo + f" iptables -A FORWARD "
            f"-m physdev --physdev-in "
            f"{self.ap_info['ethernet_interface']} "
            f"-m state "
            f"--state RELATED,ESTA "
            f"{OUTPUT_TO_DEV_NULL}"
        )

    def shutdown_gracefully(self):
        self.unblocker.unblocker_thread.join(30)
        if self.unblocker.unblocker_thread.is_alive():
            self.print("Problem shutting down unblocker thread.")

    def pre_main(self):
        self.protect_ap_clients()
        self.unblocker = Unblocker(
            self.db, self.sudo, self.should_stop, self.logger, self.log
        )

    def main(self):
        if msg := self.get_msg("new_blocking"):
            # message['data'] in the new_blocking channel is a dictionary that contains
            # the ip and the blocking options
            # Example of the data dictionary to block or unblock an ip:
            # (notice you have to specify from,to,dport,sport,protocol or at
            # least 2 of them when unblocking)
            #   blocking_data = {
            #       "ip"       : "0.0.0.0"
            #       "tw"       : 1
            #       "block"    : True to block  - False to unblock
            #       "from"     : True to block traffic from ip (default) - False does nothing
            #       "to"       : True to block traffic to ip  (default)  - False does nothing
            #       "dport"    : Optional destination port number
            #       "sport"    : Optional source port number
            #       "protocol" : Optional protocol
            #   }
            # Example of passing blocking_data to this module:
            #   blocking_data = json.dumps(blocking_data)
            #   self.db.publish('new_blocking', blocking_data )

            data = json.loads(msg["data"])
            ip = data.get("ip")
            tw: int = data.get("tw")
            block = data.get("block")

            flags = {
                "from_": data.get("from"),
                "to": data.get("to"),
                "dport": data.get("dport"),
                "sport": data.get("sport"),
                "protocol": data.get("protocol"),
            }
            if block:
                self._block_ip(ip, flags)
            # whether this ip is blocked now, or was already blocked, make an
            # unblocking request to either extend its
            # blocking period, or block it until the next timewindow is over.
            self.unblocker.unblock_request(ip, tw, flags)

        if msg := self.get_msg("tw_closed"):
            # this channel receives requests for closed tws for every ip
            # slips sees.
            # if slips saw 3 ips, this channel will receive 3 msgs with tw1
            # as closed. we're not interested in the ips, we just wanna
            # know when slips advances to the next tw.
            profileid_tw = msg["data"].split("_")
            twid = profileid_tw[-1]
            if self.last_closed_tw != twid:
                self.last_closed_tw = twid
                self.unblocker.update_requests()
