import ipaddress
import os
from typing import Dict

from slips_files.common.slips_utils import utils


def exec_iptables_command(
    sudo: str,
    action: str,
    ip_to_block: str,
    flag: str,
    options: Dict[str, str],
):
    """
    Constructs the iptables rule/command based on the options sent

    flag options:
      -s : to block traffic from source ip
      -d : to block to destination ip
    action options:
      insert : to insert a new rule at the top of slipsBlocking list
      delete : to delete an existing rule
    """
    # sanitize cmd params
    if action not in ("insert", "delete"):
        return 1

    if flag not in ("-s", "-d"):
        return 1

    if not ipaddress.ip_address(ip_to_block):
        return 1

    command = (
        f"{sudo} iptables --{action} slipsBlocking {flag} {ip_to_block} "
        f'-m comment --comment "Slips rule" >/dev/null 2>&1'
    )
    # Add the options constructed in block_ip or unblock_ip to the
    # iptables command
    for cmd_parameter in options.values():
        command += utils.sanitize(cmd_parameter)
    command += " -j DROP"

    exit_status = os.system(command)

    # 0 is the success value
    return exit_status == 0
