"""Manage Slips block rules in a dedicated macOS Packet Filter anchor."""

import ipaddress
import re
import shlex
import subprocess
from typing import Any

PF_ANCHOR = "com.apple/slips"


class MacOSPF:
    """Apply Slips-owned PF rules without replacing the system ruleset."""

    def __init__(self, sudo: str, db: Any) -> None:
        """Keep the privilege command and persistent block-state database.

        Parameters:
            sudo: Privilege escalation prefix when Slips is not root.
            db: Slips database facade holding scheduled block states.
        """
        self.command = [*shlex.split(sudo), "pfctl"]
        self.db = db
        self.rules: dict[str, dict[str, Any]] = {}

    def _run(self, *args: str, input_text: str | None = None) -> bool:
        """Run one PF command and report whether it succeeded.

        Parameters:
            args: Arguments passed to pfctl.
            input_text: Optional ruleset sent on standard input.

        Returns:
            True when pfctl exits successfully.
        """
        result = subprocess.run(
            [*self.command, *args],
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return result.returncode == 0

    @staticmethod
    def _rule_lines(ip: str, flags: dict[str, Any]) -> list[str]:
        """Render a validated address and its requested PF selectors.

        Parameters:
            ip: Address to block.
            flags: Direction, interface, protocol and port selectors.

        Returns:
            PF rule lines for the requested directions.
        """
        address = str(ipaddress.ip_address(ip))
        interface = flags.get("interface")
        if interface and not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_.-]*", interface
        ):
            raise ValueError("Invalid PF interface")
        protocol = flags.get("protocol")
        if protocol and protocol not in {"tcp", "udp", "icmp", "icmp6"}:
            raise ValueError("Invalid PF protocol")
        ports: dict[str, str] = {}
        for key in ("sport", "dport"):
            value = flags.get(key)
            if value is not None:
                port = int(value)
                if port < 1 or port > 65535:
                    raise ValueError("Invalid PF port")
                ports[key] = str(port)
        if ports and protocol not in {"tcp", "udp"}:
            raise ValueError("PF ports require TCP or UDP")
        from_ip = flags.get("from_")
        to_ip = flags.get("to")
        if from_ip is None and to_ip is None:
            from_ip = to_ip = True
        prefix = "block drop quick"
        if interface:
            prefix += f" on {interface}"
        if protocol:
            prefix += f" proto {protocol}"
        lines = []
        if from_ip:
            line = f"{prefix} from {address}"
            if "sport" in ports:
                line += f" port {ports['sport']}"
            line += " to any"
            if "dport" in ports:
                line += f" port {ports['dport']}"
            lines.append(line)
        if to_ip:
            line = f"{prefix} from any"
            if "sport" in ports:
                line += f" port {ports['sport']}"
            line += f" to {address}"
            if "dport" in ports:
                line += f" port {ports['dport']}"
            lines.append(line)
        return lines

    def _apply(self, rules: dict[str, dict[str, Any]]) -> bool:
        """Syntax-check and atomically replace only the Slips anchor.

        Parameters:
            rules: Complete set of desired Slips blocks.

        Returns:
            True when the PF anchor was loaded and PF is enabled.
        """
        try:
            rendered = (
                "\n".join(
                    line
                    for ip, flags in rules.items()
                    for line in self._rule_lines(ip, flags)
                )
                + "\n"
            )
        except (TypeError, ValueError):
            return False
        if not self._run(
            "-n", "-a", PF_ANCHOR, "-f", "-", input_text=rendered
        ):
            return False
        if rules and not self._run("-e"):
            return False
        if not self._run("-a", PF_ANCHOR, "-f", "-", input_text=rendered):
            return False
        self.rules = rules
        return True

    def restore(self) -> bool:
        """Reinstall blocks with durable unblocking schedules after restart.

        Returns:
            True when all saved rules were installed.
        """
        states = self.db.get_firewall_block_states()
        if not isinstance(states, dict):
            return True
        rules = {
            ip: state["flags"]
            for ip, state in states.items()
            if isinstance(state, dict) and isinstance(state.get("flags"), dict)
        }
        return self._apply(rules) if rules else True

    def block(self, ip: str, flags: dict[str, Any]) -> bool:
        """Install or replace one address block.

        Parameters:
            ip: Address to block.
            flags: Requested PF selectors.

        Returns:
            True when the complete anchor was updated.
        """
        return self._apply({**self.rules, ip: flags})

    def unblock(self, ip: str) -> bool:
        """Remove one address while preserving other Slips blocks.

        Parameters:
            ip: Address whose block should be removed.

        Returns:
            True when the complete anchor was updated.
        """
        return self._apply(
            {
                blocked: flags
                for blocked, flags in self.rules.items()
                if blocked != ip
            }
        )
