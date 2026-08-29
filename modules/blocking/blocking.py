# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import platform
import sys
import os
import shutil
import json
import subprocess
import math
from datetime import datetime, timezone
from typing import Any, Dict, List
import time
from threading import Lock

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.slips_utils import utils
from .exec_iptables_cmd import (
    LEGACY_SLIPS_COMMENT,
    exec_iptables_command,
    format_slips_rule_comment,
    list_slips_firewall_rules,
    sync_slips_rule_comment,
)
from modules.blocking.unblocker import Unblocker


OUTPUT_TO_DEV_NULL = ">/dev/null 2>&1"


class Blocking(IModule):
    """Data should be passed to this module as a json encoded python dict,
    by default this module flushes all slipsBlocking chains before it starts"""

    # Name: short name of the module. Do not use spaces
    name = "blocking"
    description = "Block malicious IPs connecting to this device"
    authors = ["Sebastian Garcia, Alya Gomaa"]

    def init(self):
        if platform.system() == "Darwin":
            self.print("Mac OS blocking is not supported yet.")
            sys.exit()

        self.firewall = self._determine_linux_firewall()
        self.sudo = utils.get_sudo_according_to_env()
        self._init_chains_in_firewall()
        self.blocking_log_path = self.get_module_specific_output_path(
            "blocking.log"
        )
        self.blocking_logfile_lock = Lock()
        # clear it
        utils.initialize_logfile(
            self.blocking_log_path,
            getattr(self.args, "is_slips_started_by_an_update", False),
        )
        self.last_closed_tw = None

        self.ap_info: None | Dict[str, str] = self.db.get_ap_info()
        self.is_running_in_ap_mode = True if self.ap_info else False

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("new_blocking")
        self.c2 = self.db.subscribe("tw_closed")
        self.channels = {
            "new_blocking": self.c1,
            "tw_closed": self.c2,
        }

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

    def _block_ip(self, ip_to_block: str, flags: Dict[str, Any]) -> bool:
        """
        This function determines the user's platform and firewall and calls
        the appropriate function to add the rules to the used firewall.
        By default this function blocks all traffic from and to the given ip.
        and it Blocks private IPs on the given interface, and block public
        IPs on all interfaces
        returns true if the ip is successfully blocked
        """

        if self.firewall != "iptables":
            return False

        if not isinstance(ip_to_block, str):
            return False

        # Make sure ip isn't already blocked before blocking
        if self._is_ip_already_blocked(ip_to_block):
            if self.db.get_blocking_timestamp(ip_to_block) is None:
                blocked_at = flags.get("_blocked_at")
                if blocked_at is None:
                    self.db.set_blocked_ip(ip_to_block)
                else:
                    self.db.set_blocked_ip(ip_to_block, blocked_at)
            comment = flags.get("rule_comment")
            if comment and not sync_slips_rule_comment(
                self.sudo, ip_to_block, comment
            ):
                self.print(
                    f"Unable to update firewall recovery metadata for "
                    f"{ip_to_block}.",
                    0,
                    1,
                )
            return True

        from_ = flags.get("from_")
        to = flags.get("to")
        dport = flags.get("dport")
        sport = flags.get("sport")
        protocol = flags.get("protocol")
        interface = flags.get("interface")
        # Set the default behaviour to block all traffic from and to an ip
        if from_ is None and to is None:
            from_, to = True, True
        # This dictionary will be used to construct the rule
        options = {
            "protocol": f"-p {protocol}" if protocol is not None else "",
            "dport": f"--dport {dport}" if dport is not None else "",
            "sport": f"--sport {sport}" if sport is not None else "",
        }
        source_options = dict(options)
        destination_options = dict(options)
        if utils.is_private_ip(ip_to_block) and interface:
            source_options["interface"] = f"-i {interface}"
            destination_options["interface"] = f"-o {interface}"

        requested_rules = []
        if from_:
            requested_rules.append(("-s", source_options, "from"))
        if to:
            requested_rules.append(("-d", destination_options, "to"))

        inserted_rules = []
        comment = flags.get("rule_comment", LEGACY_SLIPS_COMMENT)
        for rule_flag, rule_options, direction in requested_rules:
            if exec_iptables_command(
                self.sudo,
                action="insert",
                ip_to_block=ip_to_block,
                flag=rule_flag,
                options=rule_options,
                comment=comment,
            ):
                inserted_rules.append((rule_flag, rule_options))
                continue

            rollback_success = True
            for inserted_flag, inserted_options in reversed(inserted_rules):
                deleted = exec_iptables_command(
                    self.sudo,
                    action="delete",
                    ip_to_block=ip_to_block,
                    flag=inserted_flag,
                    options=inserted_options,
                    comment=comment,
                )
                rollback_success = deleted and rollback_success
            message = f"Unable to block traffic {direction} {ip_to_block}."
            if inserted_rules:
                rollback_result = (
                    "Inserted rules were rolled back."
                    if rollback_success
                    else "Unable to roll back every inserted rule."
                )
                message = f"{message} {rollback_result}"
            self.print(message, 0, 1)
            self.log(message)
            return False

        if not inserted_rules:
            return False
        blocked_at = flags.get("_blocked_at")
        if blocked_at is None:
            self.db.set_blocked_ip(ip_to_block)
        else:
            self.db.set_blocked_ip(ip_to_block, blocked_at)
        for _, _, direction in requested_rules:
            message = f"Blocked all traffic {direction}: {ip_to_block}"
            self.print(message)
            self.log(message)
        return True

    def _recovered_rule_flags(
        self, rules: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Combine source, destination and transport state from saved rules.

        Parameters:
            rules: Existing managed iptables rules for one address.

        Returns:
            Flags suitable for later exact firewall removal.
        """
        flags: Dict[str, Any] = {
            "from_": any(rule["from_"] for rule in rules),
            "to": any(rule["to"] for rule in rules),
        }
        for key in ("dport", "sport", "protocol", "interface"):
            values = {rule.get(key) for rule in rules if rule.get(key)}
            flags[key] = values.pop() if len(values) == 1 else None
        return flags

    def _recovery_state(
        self,
        rules: List[Dict[str, Any]],
        now: float,
    ) -> Dict[str, Any]:
        """Build Redis state from one address's persisted firewall rules.

        Parameters:
            rules: Managed source and destination rules for one address.
            now: Current Unix time used to classify expiration.

        Returns:
            Serializable state including recovery and probation information.
        """
        valid_rules = [rule for rule in rules if rule["metadata_valid"]]
        flags = self._recovered_rule_flags(rules)
        if not valid_rules:
            recovery_status = (
                "legacy metadata"
                if any(rule["legacy"] for rule in rules)
                else "invalid metadata"
            )
            flags.update(
                {
                    "_recovered": True,
                    "_recovery_status": recovery_status,
                    "_origin_run": "unknown",
                    "rule_comment": rules[0]["comment"],
                }
            )
            return {
                "unblock_at": None,
                "remaining_timewindows": None,
                "flags": flags,
                "recovered": True,
                "recovery_status": recovery_status,
                "origin_run": "unknown",
                "rule_comment": rules[0]["comment"],
                "updated_at": now,
            }

        blocked_at = min(float(rule["blocked_at"]) for rule in valid_rules)
        deadline = max(float(rule["unblock_at"]) for rule in valid_rules)
        origin_runs = sorted({str(rule["run_id"]) for rule in valid_rules})
        origin_run = ", ".join(origin_runs)
        metadata_conflict = len({rule["comment"] for rule in rules}) > 1
        if metadata_conflict:
            recovery_status = "metadata conflict"
        elif deadline <= now:
            recovery_status = "expired; removal pending"
        else:
            recovery_status = "recovered"
        width = max(1, int(self.conf.get_tw_width_in_seconds()))
        remaining = max(0, math.ceil(max(0, deadline - now) / width) - 1)
        unblock_at = datetime.fromtimestamp(deadline, timezone.utc).isoformat()
        comment = max(valid_rules, key=lambda rule: float(rule["unblock_at"]))[
            "comment"
        ]
        flags.update(
            {
                "_recovered": True,
                "_recovery_status": recovery_status,
                "_origin_run": origin_run,
                "rule_comment": comment,
            }
        )
        return {
            "unblock_at": unblock_at,
            "remaining_timewindows": remaining,
            "flags": flags,
            "recovered": True,
            "recovery_status": recovery_status,
            "origin_run": origin_run,
            "rule_comment": comment,
            "blocked_at": blocked_at,
            "updated_at": now,
        }

    def _recover_firewall_rules(self) -> int:
        """Import pre-existing Slips firewall rules into the current run.

        Returns:
            Number of distinct addresses recovered from iptables.
        """
        rules_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for rule in list_slips_firewall_rules(self.sudo):
            rules_by_ip.setdefault(rule["ip"], []).append(rule)
        if not rules_by_ip:
            return 0

        now = time.time()
        self.print(
            f"WARNING: Found {len(rules_by_ip)} IPs in the existing "
            "slipsBlocking chain. Recovering their firewall state.",
            0,
            1,
        )
        self.log(
            f"Recovered {len(rules_by_ip)} pre-existing firewall records "
            "from iptables comments."
        )
        for ip, rules in rules_by_ip.items():
            state = self._recovery_state(rules, now)
            blocked_at = state.get("blocked_at", now)
            self.db.set_blocked_ip(ip, blocked_at)
            self.db.set_firewall_block_state(ip, state)
            status = state["recovery_status"]
            self.print(
                f"Recovered firewall rule for {ip}: {status}.",
                0,
                1,
            )
        return len(rules_by_ip)

    def shutdown_gracefully(self):
        self.unblocker.unblocker_thread.join(30)
        if self.unblocker.unblocker_thread.is_alive():
            self.print("Problem shutting down unblocker thread.")

    def pre_main(self):
        self._recover_firewall_rules()
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
                "interface": data.get("interface"),
            }
            request = self.unblocker.prepare_unblock_request(ip, tw, flags)
            blocking_timestamp = self.db.get_blocking_timestamp(ip)
            blocked_at = blocking_timestamp or time.time()
            run_id = os.path.basename(os.path.normpath(self.parent_output_dir))
            request_flags = request["flags"]
            request_flags["_blocked_at"] = blocked_at
            request_flags["_origin_run"] = run_id
            request_flags["rule_comment"] = format_slips_rule_comment(
                blocked_at,
                request["tw_to_unblock"].end_time,
                run_id,
            )
            if block:
                if not self._block_ip(ip, request_flags):
                    self.print(
                        f"Firewall rule insertion failed for {ip}; "
                        "no unblock request was registered.",
                        0,
                        1,
                    )
                    return
            # Whether this IP was newly blocked or already present, retain its
            # latest deletion deadline and update the iptables comments.
            self.unblocker.register_unblock_request(ip, request)

        if msg := self.get_msg("tw_closed"):
            # this channel receives requests for closed tws for every ip
            # slips sees.
            # if slips saw 3 ips, this channel will receive 3 msgs with tw1
            # as closed. we're not interested in the ips, we just wanna
            # know when slips advances to the next tw.
            profileid_tw = utils.get_msg_payload(msg).split("_")
            twid = profileid_tw[-1]
            if self.last_closed_tw != twid:
                self.last_closed_tw = twid
                self.unblocker.update_requests()
