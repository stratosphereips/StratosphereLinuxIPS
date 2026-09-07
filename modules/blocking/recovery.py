# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import math
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from .exec_iptables_cmd import list_slips_firewall_rules


def clear_firewall_recovery_state(db) -> None:
    """
    Delete every persisted firewall block state and blocked-IP record.

    Called after the managed iptables chain itself has been deleted, so
    a future run's _recover_firewall_rules() doesn't recover stale
    state for rules that no longer exist.

    Parameters:
        db: Database manager used to read and clear the block states.
    """
    states = db.get_firewall_block_states()
    if not isinstance(states, dict):
        return
    for ip in states:
        db.del_firewall_block_state(ip)
        db.del_blocked_ip(ip)


class RecoveryMixin:
    """
    Recovers pre-existing Slips firewall rules into a fresh run.

    Mixed into the Blocking module; relies on self.conf, self.db,
    self.sudo, self.print and self.log being provided by it.
    """

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

    def _recovery_state_without_valid_rules(
        self,
        rules: List[Dict[str, Any]],
        flags: Dict[str, Any],
        now: float,
    ) -> Dict[str, Any]:
        """Build recovery state for rules whose metadata can't be trusted.

        Parameters:
            rules: Existing managed iptables rules for one address.
            flags: Flags already combined from those rules.
            now: Current Unix time used to timestamp the state.

        Returns:
            Serializable state with no unblock deadline or timewindow count.
        """
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

    def _recovery_status_for_valid_rules(
        self,
        rules: List[Dict[str, Any]],
        deadline: float,
        now: float,
    ) -> str:
        """Classify recovered rules as conflicting, expired, or recovered.

        Parameters:
            rules: All managed rules for the address, valid or not.
            deadline: Latest unblock time among the valid rules.
            now: Current Unix time used to classify expiration.

        Returns:
            One of "metadata conflict", "expired; removal pending",
            or "recovered".
        """
        metadata_conflict = len({rule["comment"] for rule in rules}) > 1
        if metadata_conflict:
            return "metadata conflict"
        if deadline <= now:
            return "expired; removal pending"
        return "recovered"

    def _recovery_state_with_valid_rules(
        self,
        rules: List[Dict[str, Any]],
        valid_rules: List[Dict[str, Any]],
        flags: Dict[str, Any],
        now: float,
    ) -> Dict[str, Any]:
        """Build recovery state from rules with trustworthy metadata.

        Parameters:
            rules: All managed rules for the address, valid or not.
            valid_rules: The subset of rules with usable metadata.
            flags: Flags already combined from all rules.
            now: Current Unix time used to classify expiration.

        Returns:
            Serializable state including recovery and probation information.
        """
        blocked_at = min(float(rule["blocked_at"]) for rule in valid_rules)
        deadline = max(float(rule["unblock_at"]) for rule in valid_rules)
        origin_run = ", ".join(
            sorted({str(rule["run_id"]) for rule in valid_rules})
        )
        recovery_status = self._recovery_status_for_valid_rules(
            rules, deadline, now
        )
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

    def _recovery_state(
        self,
        rules: List[Dict[str, Any]],
        now: float,
    ) -> Dict[str, Any]:
        """Build Redis state from one ip's persisted firewall rules.

        Parameters:
            rules: Managed source and destination rules for one address.
            now: Current Unix time used to classify expiration.

        Returns:
            Serializable state including recovery and probation information.
        """
        valid_rules = [rule for rule in rules if rule["metadata_valid"]]
        flags = self._recovered_rule_flags(rules)
        if not valid_rules:
            return self._recovery_state_without_valid_rules(rules, flags, now)

        return self._recovery_state_with_valid_rules(
            rules, valid_rules, flags, now
        )

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
            f"Found {len(rules_by_ip)} pre-existing firewall records "
            "from iptables comments."
        )
        for ip, rules in rules_by_ip.items():
            state = self._recovery_state(rules, now)
            self.db.set_firewall_block_state(ip, state)

            blocked_at = state.get("blocked_at", now)
            self.db.set_blocked_ip(ip, blocked_at)

            status = state["recovery_status"]
            self.print(
                f"Recovered firewall rule for {ip}: {status}.",
                0,
                1,
            )
        return len(rules_by_ip)
