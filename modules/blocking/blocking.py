# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import platform
import sys
import os
import shutil
import json
import subprocess
import time

from slips_files.common.abstracts.module import IModule
from .exec_iptables_cmd import exec_iptables_command
from modules.blocking.unblocker import Unblocker


class Blocking(IModule):
    """Data should be passed to this module as a json encoded python dict,
    by default this module flushes all slipsBlocking chains before it starts"""

    # Name: short name of the module. Do not use spaces
    name = "Blocking"
    description = "Block malicious IPs connecting to this device"
    authors = ["Sebastian Garcia, Alya Gomaa"]

    def init(self):
        self.c1 = self.db.subscribe("new_blocking")
        self.channels = {
            "new_blocking": self.c1,
        }
        if platform.system() == "Darwin":
            self.print("Mac OS blocking is not supported yet.")
            sys.exit()

        self.firewall = self.determine_linux_firewall()
        self.set_sudo_according_to_env()
        self.initialize_chains_in_firewall()
        self.unblocker = Unblocker(self.db)
        # self.test()

    def test(self):
        """For debugging purposes, once we're done with the module we'll
        delete it"""

        if not self.is_ip_blocked("2.2.0.0"):
            blocking_data = {
                "ip": "2.2.0.0",
                "block": True,
                "from": True,
                "to": True,
                "block_for": 5,
                # "dport"    : Optional destination port number
                # "sport"    : Optional source port number
                # "protocol" : Optional protocol
            }
            # Example of passing blocking_data to this module:
            blocking_data = json.dumps(blocking_data)
            self.db.publish("new_blocking", blocking_data)
            self.print("[test] Blocked ip.")
        else:
            self.print("[test] IP is already blocked")
        # self.unblock_ip("2.2.0.0",True,True)

    def set_sudo_according_to_env(self):
        """
        Check if running in host or in docker and sets sudo string accordingly.
        There's no sudo in docker so we need to execute all commands without it
        """
        # This env variable is defined in the Dockerfile
        self.running_in_docker = os.environ.get(
            "IS_IN_A_DOCKER_CONTAINER", False
        )
        self.sudo = "" if self.running_in_docker else "sudo "

    def determine_linux_firewall(self):
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

    def delete_slips_blocking_chain(self):
        """Flushes and deletes everything in slipsBlocking chain"""
        # check if slipsBlocking chain exists before flushing it and suppress
        # stderr and stdout while checking
        # 0 means it exists
        chain_exists = (
            os.system(
                f"{self.sudo}iptables -nvL slipsBlocking >/dev/null 2>&1"
            )
            == 0
        )
        if self.firewall == "iptables" and chain_exists:
            # Delete all references to slipsBlocking inserted in INPUT OUTPUT
            # and FORWARD before deleting the chain
            cmd = (
                f"{self.sudo}iptables -D INPUT -j slipsBlocking "
                f">/dev/null 2>&1 ; {self.sudo}iptables -D OUTPUT "
                f"-j slipsBlocking >/dev/null 2>&1 ; "
                f"{self.sudo}iptables -D FORWARD -j "
                f"slipsBlocking >/dev/null 2>&1"
            )
            os.system(cmd)
            # flush and delete all the rules in slipsBlocking
            cmd = (
                f"{self.sudo}iptables -F slipsBlocking >/dev/null 2>&1 ; "
                f"{self.sudo} iptables -X slipsBlocking >/dev/null 2>&1"
            )
            os.system(cmd)
            print("Successfully deleted slipsBlocking chain.")
            return True

        return False

    def get_cmd_output(self, command):
        """Executes a command and returns the output"""
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        return result.stdout.decode("utf-8")

    def initialize_chains_in_firewall(self):
        """For linux: Adds a chain to iptables or a table to nftables called
        slipsBlocking where all the rules will reside"""

        if self.firewall != "iptables":
            return

        # delete any pre existing slipsBlocking rules that may conflict before
        # adding a new one
        # self.delete_iptables_chain()
        self.print('Executing "sudo iptables -N slipsBlocking"', 6, 0)
        # Add a new chain to iptables
        os.system(f"{self.sudo}iptables -N slipsBlocking >/dev/null 2>&1")

        # Check if we're already redirecting to slipsBlocking chain
        input_chain_rules = self.get_cmd_output(
            f"{self.sudo} iptables -nvL INPUT"
        )
        output_chain_rules = self.get_cmd_output(
            f"{self.sudo} iptables -nvL OUTPUT"
        )
        forward_chain_rules = self.get_cmd_output(
            f"{self.sudo} iptables -nvL FORWARD"
        )
        # Redirect the traffic from all other chains to slipsBlocking so rules
        # in any pre-existing chains dont override it
        # -I to insert slipsBlocking at the top of the INPUT, OUTPUT and
        # FORWARD chains
        if "slipsBlocking" not in input_chain_rules:
            os.system(
                self.sudo
                + "iptables -I INPUT -j slipsBlocking >/dev/null 2>&1"
            )
        if "slipsBlocking" not in output_chain_rules:
            os.system(
                self.sudo
                + "iptables -I OUTPUT -j slipsBlocking >/dev/null 2>&1"
            )
        if "slipsBlocking" not in forward_chain_rules:
            os.system(
                self.sudo
                + "iptables -I FORWARD -j slipsBlocking >/dev/null 2>&1"
            )

    def is_ip_blocked(self, ip) -> bool:
        """Checks if ip is already blocked or not"""
        command = f"{self.sudo}iptables -L slipsBlocking -v -n"
        # Execute command
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        result = result.stdout.decode("utf-8")
        return ip in result

    def block_ip(
        self,
        ip_to_block=None,
        from_=True,
        to=True,
        dport=None,
        sport=None,
        protocol=None,
        block_for=False,
    ):
        """
        This function determines the user's platform and firewall and calls
        the appropriate function to add the rules to the used firewall.
        By default this function blocks all traffic from and to the given ip.
        """

        if not isinstance(ip_to_block, str):
            return False

        # Make sure ip isn't already blocked before blocking
        if self.is_ip_blocked(ip_to_block):
            return False

        if self.firewall == "iptables":
            # Blocking in iptables
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
                    self.print(f"Blocked all traffic from: {ip_to_block}")

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
                    self.print(f"Blocked all traffic to: {ip_to_block}")

            if block_for:
                time_of_blocking = time.time()
                #  unblock ip after block_for period passes
                self.unblock_ips.update(
                    {
                        ip_to_block: {
                            "block_for": block_for,
                            "time_of_blocking": time_of_blocking,
                            "blocking_details": {
                                "from": from_,
                                "to": to,
                                "dport": dport,
                                "sport": sport,
                                "protocol": protocol,
                            },
                        }
                    }
                )

            if blocked:
                # Successfully blocked an ip
                return True

        return False

    def main(self):
        # There's an IP that needs to be blocked
        if msg := self.get_msg("new_blocking"):
            # message['data'] in the new_blocking channel is a dictionary that contains
            # the ip and the blocking options
            # Example of the data dictionary to block or unblock an ip:
            # (notice you have to specify from,to,dport,sport,protocol or at least 2 of them when unblocking)
            #   blocking_data = {
            #       "ip"       : "0.0.0.0"
            #       "tw"       : 1
            #       "block"    : True to block  - False to unblock
            #       "from"     : True to block traffic from ip (default) - False does nothing
            #       "to"       : True to block traffic to ip  (default)  - False does nothing
            #       "dport"    : Optional destination port number
            #       "sport"    : Optional source port number
            #       "protocol" : Optional protocol
            #       'block_for': Optional, after this time (in seconds) this ip will be unblocked
            #   }
            # Example of passing blocking_data to this module:
            #   blocking_data = json.dumps(blocking_data)
            #   self.db.publish('new_blocking', blocking_data )

            # Decode(deserialize) the python dict into JSON formatted string
            data = json.loads(msg["data"])
            # Parse the data dictionary
            ip = data.get("ip")
            tw: int = data.get("tw")
            block = data.get("block")
            from_ = data.get("from")
            to = data.get("to")
            dport = data.get("dport")
            sport = data.get("sport")
            protocol = data.get("protocol")
            block_for = data.get("block_for")

            if block:
                self.block_ip(ip, from_, to, dport, sport, protocol, block_for)
            else:
                how_many_tws_to_block = 1
                flags = {
                    "from_": from_,
                    "to": to,
                    "dport": dport,
                    "sport": sport,
                    "protocol": protocol,
                }
                self.unblocker.unblock_request(
                    ip, how_many_tws_to_block, tw, flags
                )
