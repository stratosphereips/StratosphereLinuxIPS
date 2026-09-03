from slips_files.common.slips_utils import utils
import os

from modules.blocking.exec_iptables_cmd import list_slips_firewall_rules


def _chain_exists() -> bool:
    """
    Check if the slipsBlocking chain exists
    :return: True if it exists, False otherwise
    """
    sudo = utils.get_sudo_according_to_env()
    # check if slipsBlocking chain exists before flushing it and suppress
    # stderr and stdout while checking
    # 0 means it exists
    return (
        os.system(f"{sudo} iptables -nvL slipsBlocking >/dev/null 2>&1") == 0
    )


def del_slips_blocking_chain() -> bool:
    """Flushes and deletes everything in slipsBlocking chain"""
    if not _chain_exists():
        return False

    sudo = utils.get_sudo_according_to_env()

    # Delete all references to slipsBlocking inserted in INPUT OUTPUT
    # and FORWARD before deleting the chain
    cmd = (
        f"{sudo} iptables -D INPUT -j slipsBlocking >/dev/null 2>&1 ;"
        f" {sudo} iptables -D OUTPUT -j slipsBlocking >/dev/null 2>&1 ; "
        f"{sudo} iptables -D FORWARD -j slipsBlocking >/dev/null 2>&1"
    )
    os.system(cmd)

    # flush and delete all the rules in slipsBlocking
    cmd = (
        f"{sudo} iptables -F slipsBlocking >/dev/null 2>&1 ; "
        f"{sudo} iptables -X slipsBlocking >/dev/null 2>&1"
    )
    os.system(cmd)

    print("Successfully deleted slipsBlocking chain.")
    return True


def has_slips_firewall_rules() -> bool:
    """Check whether the Slips chain contains managed firewall rules.

    Returns:
        True when at least one Slips-commented rule is installed.
    """
    sudo = utils.get_sudo_according_to_env()
    return bool(list_slips_firewall_rules(sudo))
