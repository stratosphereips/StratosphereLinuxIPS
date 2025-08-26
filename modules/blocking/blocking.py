# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import platform
import sys
import os
import shutil
import json
import subprocess
from typing import Dict
import time

from slips_files.common.abstracts.iasync_module import IAsyncModule
from slips_files.common.slips_utils import utils
from .exec_iptables_cmd import exec_iptables_command
from modules.blocking.unblocker import Unblocker


class Blocking(IAsyncModule):
    """Data should be passed to this module as a json encoded python dict,
    by default this module flushes all slipsBlocking chains before it starts"""

    # Name: short name of the module. Do not use spaces
    name = "Blocking"
    description = "Block malicious IPs connecting to this device"
    authors = ["Sebastian Garcia, Alya Gomaa"]

    async def init(self):
        self.channels = {
            "new_blocking": self.new_blocking_msg_handler,
            "tw_closed": self.tw_closed_msg_handler,
        }
        await self.db.subscribe(self.pubsub, self.channels.keys())

        if platform.system() == "Darwin":
            self.print("Mac OS blocking is not supported yet.")
            sys.exit()

        self.firewall = self._determine_linux_firewall()
        self.sudo = utils.get_sudo_according_to_env()
        self._init_chains_in_firewall()
        self.blocking_log_path = os.path.join(self.output_dir, "blocking.log")
        self.blocking_logfile_lock = asyncio.Lock()
        # clear it
        try:
            open(self.blocking_log_path, "w").close()
        except FileNotFoundError:
            pass
        self.last_closed_tw = None

    async def new_blocking_msg_handler(self, msg):
        """Handler for new_blocking channel messages"""
        # message['data'] in the new_blocking channel is a dictionary
        # that contains the ip and the blocking options
        # Example of the data dictionary to block or unblock an ip:
        # (notice you have to specify from,to,dport,sport,protocol or at
        # least 2 of them when unblocking)
        #   blocking_data = {
        #       "ip"       : "0.0.0.0"
        #       "tw"       : 1
        #       "block"    : True to block  - False to unblock
        #       "from"     : True to block traffic from ip (default) -
        #                    False does nothing
        #       "to"       : True to block traffic to ip  (default)  -
        #                    False does nothing
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
            await self._block_ip(ip, flags)
        # whether this ip is blocked now, or was already blocked, make an
        # unblocking request to either extend its
        # blocking period, or block it until the next timewindow is over.
        await self.unblocker.unblock_request(ip, tw, flags)

    async def tw_closed_msg_handler(self, msg):
        """Handler for tw_closed channel messages"""
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
        os.system(f"{self.sudo} iptables -N slipsBlocking >/dev/null 2>&1")

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
                self.sudo
                + " iptables -I INPUT -j slipsBlocking >/dev/null 2>&1"
            )
        if "slipsBlocking" not in output_chain_rules:
            os.system(
                self.sudo
                + " iptables -I OUTPUT -j slipsBlocking >/dev/null 2>&1"
            )
        if "slipsBlocking" not in forward_chain_rules:
            os.system(
                self.sudo
                + " iptables -I FORWARD -j slipsBlocking >/dev/null 2>&1"
            )

    def _is_ip_already_blocked(self, ip) -> bool:
        """Checks if ip is already blocked or not using iptables"""
        command = f"{self.sudo} iptables -L slipsBlocking -v -n"
        # Execute command
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        result = result.stdout.decode("utf-8")
        return ip in result

    async def _block_ip(self, ip_to_block: str, flags: Dict[str, str]) -> bool:
        """
        This function determines the user's platform and firewall and calls
        the appropriate function to add the rules to the used firewall.
        By default this function blocks all traffic from and to the given ip.
        return strue if the ip is successfully blocked
        """

        if self.firewall != "iptables":
            return False

        if not isinstance(ip_to_block, str):
            return False

        # Make sure ip isn't already blocked before blocking
        if self._is_ip_already_blocked(ip_to_block):
            return False
        print(f"@@@@@@@@@@@@@@@@ wooohooo blocking _block_ip {ip_to_block}")
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
                await self.db.set_blocked_ip(ip_to_block)
        return blocked

    async def pre_main(self):
        self.unblocker = Unblocker(
            self.db,
            self.sudo,
            self.logger,
            self.log,
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
