import os


def exec_iptables_command(sudo: str, action, ip_to_block, flag, options):
    """
    Constructs the iptables rule/command based on the options sent

    flag options:
      -s : to block traffic from source ip
      -d : to block to destination ip
    action options:
      insert : to insert a new rule at the top of slipsBlocking list
      delete : to delete an existing rule
    """
    command = (
        f"{sudo} iptables --{action} slipsBlocking {flag} {ip_to_block} "
        f'-m comment --comment "Slips rule" >/dev/null 2>&1'
    )
    # Add the options constructed in block_ip or unblock_ip to the
    # iptables command
    for key in options.keys():
        command += options[key]
    command += " -j DROP"

    exit_status = os.system(command)

    # 0 is the success value
    return exit_status == 0
