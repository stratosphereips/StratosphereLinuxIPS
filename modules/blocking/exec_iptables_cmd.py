import ipaddress
import re
import shlex
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from slips_files.common.slips_utils import utils


SLIPS_COMMENT_PREFIX = "Slips"
LEGACY_SLIPS_COMMENT = "Slips rule"


def _iptables_command(sudo: str, arguments: List[str]) -> List[str]:
    """Build an argv list for an iptables invocation.

    Parameters:
        sudo: Optional privilege-escalation command.
        arguments: Arguments following the iptables executable.

    Returns:
        Complete command argument vector.
    """
    return [*shlex.split(sudo), "iptables", *arguments]


def _token_value(tokens: List[str], option: str) -> Optional[str]:
    """Read the value following an iptables rule option.

    Parameters:
        tokens: Tokenized iptables rule.
        option: Option whose value should be returned.

    Returns:
        Option value, or None when the option is absent or incomplete.
    """
    try:
        return tokens[tokens.index(option) + 1]
    except (ValueError, IndexError):
        return None


def _rule_ip(value: Optional[str]) -> Optional[str]:
    """Normalize a non-wildcard address from an iptables rule.

    Parameters:
        value: Address or network expression from iptables.

    Returns:
        Canonical IP address, or None for wildcard and invalid values.
    """
    if not value:
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if network.prefixlen == 0:
        return None
    return str(network.network_address)


def _metadata_timestamp(value: Optional[str]) -> Optional[float]:
    """Convert one firewall-comment timestamp to Unix time.

    Parameters:
        value: ISO-formatted timestamp from a managed-rule comment.

    Returns:
        Unix timestamp, or None when the value cannot be parsed.
    """
    if not value:
        return None
    try:
        return float(utils.convert_ts_format(value, "unixtimestamp"))
    except (TypeError, ValueError):
        return None


def format_slips_rule_comment(
    blocked_at: float,
    unblock_at: str,
    run_id: str,
) -> str:
    """Create recoverable metadata for a Slips firewall rule.

    Parameters:
        blocked_at: Unix time when enforcement originally began.
        unblock_at: Scheduled removal time in a Slips-supported format.
        run_id: Short identifier of the run that owns the rule.

    Returns:
        Compact human-readable iptables comment.
    """
    unblock_timestamp = _metadata_timestamp(unblock_at)
    if unblock_timestamp is None:
        raise ValueError(f"Invalid firewall unblock timestamp: {unblock_at}")
    safe_run_id = re.sub(r"[^A-Za-z0-9_.:-]", "_", run_id)[:80] or "unknown"
    blocked_text = datetime.fromtimestamp(
        float(blocked_at), timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    unblock_text = datetime.fromtimestamp(
        unblock_timestamp, timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        f"{SLIPS_COMMENT_PREFIX} run={safe_run_id} "
        f"blocked={blocked_text} delete={unblock_text}"
    )


def parse_slips_rule_comment(comment: str) -> Dict[str, Any]:
    """Parse recovery metadata from one managed iptables comment.

    Parameters:
        comment: Text stored by the iptables comment extension.

    Returns:
        Parsed ownership and scheduling metadata.
    """
    result: Dict[str, Any] = {
        "managed": comment.startswith(SLIPS_COMMENT_PREFIX),
        "metadata_valid": False,
        "legacy": comment == LEGACY_SLIPS_COMMENT,
        "run_id": None,
        "blocked_at": None,
        "unblock_at": None,
    }
    if not result["managed"]:
        return result
    fields = {}
    for token in comment.split()[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    blocked_at = _metadata_timestamp(fields.get("blocked"))
    unblock_at = _metadata_timestamp(fields.get("delete"))
    if blocked_at is None or unblock_at is None or unblock_at < blocked_at:
        return result
    result.update(
        {
            "metadata_valid": True,
            "run_id": fields.get("run") or "unknown",
            "blocked_at": blocked_at,
            "unblock_at": unblock_at,
        }
    )
    return result


def list_slips_firewall_rules(sudo: str) -> List[Dict[str, Any]]:
    """Return structured Slips-owned rules from the firewall chain.

    Parameters:
        sudo: Optional privilege-escalation command.

    Returns:
        Managed rules with addresses, direction, options and comment metadata.
    """
    result = subprocess.run(
        _iptables_command(sudo, ["-S", "slipsBlocking"]),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    rules: List[Dict[str, Any]] = []
    rule_number = 0
    for line in result.stdout.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        if len(tokens) < 3 or tokens[:2] != ["-A", "slipsBlocking"]:
            continue
        rule_number += 1
        comment = _token_value(tokens, "--comment") or ""
        if not comment.startswith(SLIPS_COMMENT_PREFIX):
            continue
        source_ip = _rule_ip(_token_value(tokens, "-s"))
        destination_ip = _rule_ip(_token_value(tokens, "-d"))
        ip = source_ip or destination_ip
        if not ip:
            continue
        protocol = _token_value(tokens, "-p")
        rules.append(
            {
                "rule_number": rule_number,
                "tokens": tokens,
                "ip": ip,
                "from_": source_ip == ip,
                "to": destination_ip == ip,
                "protocol": (
                    None if protocol in (None, "all", "0") else protocol
                ),
                "sport": _token_value(tokens, "--sport"),
                "dport": _token_value(tokens, "--dport"),
                "interface": _token_value(tokens, "-i")
                or _token_value(tokens, "-o"),
                "comment": comment,
                **parse_slips_rule_comment(comment),
            }
        )
    return rules


def sync_slips_rule_comment(sudo: str, ip: str, comment: str) -> bool:
    """Replace metadata comments on every managed rule for one IP.

    Parameters:
        sudo: Optional privilege-escalation command.
        ip: Address whose source and destination rules should be updated.
        comment: New recoverable comment.

    Returns:
        True when every discovered rule was updated, or no rule exists.
    """
    matching = [
        rule for rule in list_slips_firewall_rules(sudo) if rule["ip"] == ip
    ]
    success = True
    for rule in matching:
        specification = list(rule["tokens"][2:])
        try:
            specification[specification.index("--comment") + 1] = comment
        except (ValueError, IndexError):
            success = False
            continue
        result = subprocess.run(
            _iptables_command(
                sudo,
                [
                    "-R",
                    "slipsBlocking",
                    str(rule["rule_number"]),
                    *specification,
                ],
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        success = result.returncode == 0 and success
    return success


def delete_slips_rules_for_ip(
    sudo: str,
    ip: str,
    flags: Dict[str, Any],
) -> bool:
    """Delete managed rules for one IP regardless of their metadata comment.

    Parameters:
        sudo: Optional privilege-escalation command.
        ip: Address whose rules should be removed.
        flags: Requested source and destination rule directions.

    Returns:
        True when matching rules are absent after deletion.
    """
    from_requested = flags.get("from_")
    to_requested = flags.get("to")
    if from_requested is None and to_requested is None:
        from_requested, to_requested = True, True
    matching = [
        rule
        for rule in list_slips_firewall_rules(sudo)
        if rule["ip"] == ip
        and (
            (bool(from_requested) and rule["from_"])
            or (bool(to_requested) and rule["to"])
        )
    ]
    success = True
    for rule in sorted(
        matching, key=lambda item: item["rule_number"], reverse=True
    ):
        result = subprocess.run(
            _iptables_command(
                sudo,
                ["-D", "slipsBlocking", str(rule["rule_number"])],
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        success = result.returncode == 0 and success
    remaining = [
        rule
        for rule in list_slips_firewall_rules(sudo)
        if rule["ip"] == ip
        and (
            (bool(from_requested) and rule["from_"])
            or (bool(to_requested) and rule["to"])
        )
    ]
    return success and not remaining


def exec_iptables_command(
    sudo: str,
    action: str,
    ip_to_block: str,
    flag: str,
    options: Dict[str, str],
    comment: str = LEGACY_SLIPS_COMMENT,
) -> bool:
    """Construct and execute one exact managed iptables rule operation.

    Parameters:
        sudo: Optional privilege-escalation command.
        action: One of insert, delete, or check.
        ip_to_block: Address selected by the rule.
        flag: Source or destination selector.
        options: Optional protocol, port and interface fragments.
        comment: Managed-rule ownership and recovery metadata.

    Returns:
        True when iptables reports success.
    """
    if action not in ("insert", "delete", "check"):
        return False
    if flag not in ("-s", "-d"):
        return False
    try:
        ipaddress.ip_address(ip_to_block)
    except ValueError:
        return False

    arguments = [
        f"--{action}",
        "slipsBlocking",
        flag,
        ip_to_block,
        "-m",
        "comment",
        "--comment",
        comment,
    ]
    for cmd_parameter in options.values():
        try:
            arguments.extend(shlex.split(utils.sanitize(cmd_parameter)))
        except (TypeError, ValueError):
            return False
    arguments.extend(("-j", "DROP"))
    result = subprocess.run(
        _iptables_command(sudo, arguments),
        stdout=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0
