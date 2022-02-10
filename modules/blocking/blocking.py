# Must imports
from slips_files.common.abstracts import Module
from slips_files.common.slips_utils import utils
import multiprocessing
from slips_files.core.database import __database__
import platform
import sys

# Your imports
import os
import shutil
import json
import subprocess

class Module(Module, multiprocessing.Process):
    """Data should be passed to this module as a json encoded python dict,
    by default this module flushes all slipsBlocking chains before it starts """
    # Name: short name of the module. Do not use spaces
    name = 'Blocking'
    description = 'Block malicious IPs connecting to this device'
    authors = ['Sebastian Garcia, Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        self.c1 = __database__.subscribe('new_blocking')
        self.os = platform.system()
        if self.os == 'Darwin':
            # blocking isn't supported, exit module
            self.print('Mac OS blocking is not supported yet.')
            sys.exit()
        self.timeout = 0.0000001
        self.firewall = self.determine_linux_firewall()
        self.set_sudo_according_to_env()
        self.initialize_chains_in_firewall()
        # self.test()


    def test(self):
        """ For debugging purposes, once we're done with the module we'll delete it """

        if not self.is_ip_blocked('2.2.0.0'):
            blocking_data = {
                          "ip"       : "2.2.0.0",
                          "block"    : True ,
                          "from"     : True ,
                          "to"       : True ,
                          # "dport"    : Optional destination port number
                          # "sport"    : Optional source port number
                          # "protocol" : Optional protocol
                      }
            # Example of passing blocking_data to this module:
            blocking_data = json.dumps(blocking_data)
            __database__.publish('new_blocking', blocking_data )
            self.print("Blocked ip.")
        else:
            self.print("IP is already blocked")
        # self.unblock_ip("2.2.0.0",True,True)

    def set_sudo_according_to_env(self):
        """ Check if running in host or in docker and sets sudo string accordingly.
            There's no sudo in docker so we need to execute all commands without it
         """
        # This env variable is defined in the Dockerfile
        self.running_in_docker = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)
        if self.running_in_docker:
            self.sudo = ''
        else:
            self.sudo = 'sudo '

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    def determine_linux_firewall(self):
        """ Returns the currently installed firewall and installs iptables if none was found """

        if shutil.which('iptables'):
            # comes pre installed in docker
            return 'iptables'
        elif shutil.which('nftables'):
            return 'nftables'
        else:
            # no firewall installed
            # user doesn't have a firewall
            self.print("iptables is not installed. Blocking module is quitting.")
            sys.exit()

    def delete_slipsBlocking_chain(self):
        """ Flushes and deletes everything in slipsBlocking chain """
        # check if slipsBlocking chain exists before flushing it and suppress stderr and stdout while checking
        # 0 means it exists
        chain_exists = os.system(self.sudo + "iptables -nvL slipsBlocking >/dev/null 2>&1")  == 0
        if self.firewall == 'iptables' and chain_exists:
            # Delete all references to slipsBlocking inserted in INPUT OUTPUT and FORWARD before deleting the chain
            cmd = f'{self.sudo}iptables -D INPUT -j slipsBlocking >/dev/null 2>&1 ; {self.sudo}iptables -D OUTPUT -j slipsBlocking >/dev/null 2>&1 ; {self.sudo}iptables -D FORWARD -j slipsBlocking >/dev/null 2>&1'
            os.system(cmd)
            # flush and delete all the rules in slipsBlocking
            cmd = f'{self.sudo}iptables -F slipsBlocking >/dev/null 2>&1 ; {self.sudo} iptables -X slipsBlocking >/dev/null 2>&1'
            os.system(cmd)
            print('Successfully deleted slipsBlocking chain.')
            return True
        elif self.firewall == 'nftables':
            # TODO: handle the creation of the slipsBlocking chain in nftables
            # Flush rules in slipsBlocking chain because you can't delete a chain without flushing first
            os.system(self.sudo + "nft flush chain inet slipsBlocking")
            # Delete slipsBlocking chain from nftables
            os.system(self.sudo + "nft delete chain inet slipsBlocking")
            return True
        return False

    def get_cmd_output(self,command):
        """ Executes a command and returns the output """

        # Execute command
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        # Get command output
        return result.stdout.decode('utf-8')

    def initialize_chains_in_firewall(self):
        """ For linux: Adds a chain to iptables or a table to nftables called
            slipsBlocking where all the rules will reside """

        if self.firewall == 'iptables':
            # delete any pre existing slipsBlocking rules that may conflict before adding a new one
            # self.delete_iptables_chain()
            self.print('Executing "sudo iptables -N slipsBlocking"',6,0)
            # Add a new chain to iptables
            os.system(self.sudo + 'iptables -N slipsBlocking >/dev/null 2>&1')

            # Check if we're already redirecting to slipsBlocking chain
            INPUT_chain_rules = self.get_cmd_output(self.sudo + " iptables -nvL INPUT")
            OUTPUT_chain_rules = self.get_cmd_output(self.sudo + " iptables -nvL OUTPUT")
            FORWARD_chain_rules = self.get_cmd_output(self.sudo + " iptables -nvL FORWARD")
            # Redirect the traffic from all other chains to slipsBlocking so rules
            # in any pre-existing chains dont override it
            # -I to insert slipsBlocking at the top of the INPUT, OUTPUT and FORWARD chains
            if 'slipsBlocking' not in INPUT_chain_rules :
                os.system(self.sudo + 'iptables -I INPUT -j slipsBlocking >/dev/null 2>&1')
            if 'slipsBlocking' not in OUTPUT_chain_rules :
                os.system(self.sudo + 'iptables -I OUTPUT -j slipsBlocking >/dev/null 2>&1')
            if 'slipsBlocking' not in FORWARD_chain_rules :
                os.system(self.sudo + 'iptables -I FORWARD -j slipsBlocking >/dev/null 2>&1')

        elif self.firewall == 'nftables':
            self.print('Executing "sudo nft add table inet slipsBlocking"',6,0)
            # Add a new nft table that uses the inet family (ipv4,ipv6)
            os.system(self.sudo + "nft add table inet slipsBlocking")
            # TODO: HANDLE NFT TABLE

    def exec_iptables_command(self,
                              action, ip_to_block,
                              flag, options):
        """
        Constructs the iptables rule/command based on the options sent in the message
        flag options:
          -s : to block traffic from source ip
          -d : to block to destination ip
        action options:
          insert : to insert a new rule at the top of slipsBlocking list
          delete : to delete an existing rule
        """

        command = f'{self.sudo}iptables --{action} slipsBlocking {flag} {ip_to_block} -m comment --comment "Slips rule" >/dev/null 2>&1'
        # Add the options constructed in block_ip or unblock_ip to the iptables command
        for key in options.keys():
            command += options[key]
        command += " -j DROP"
        # Execute
        exit_status = os.system(command)
        # 0 is the success value
        success = False if exit_status != 0 else True
        return success

    def is_ip_blocked(self, ip) -> bool:
        """ Checks if ip is already blocked or not """

        command = self.sudo + 'iptables -L slipsBlocking -v -n'
        # Execute command
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        result = result.stdout.decode('utf-8')
        return ip in result

    def block_ip(self, ip_to_block=None, from_=True, to=True,
                 dport=None, sport=None, protocol=None):
        """
            This function determines the user's platform and firewall and calls
            the appropriate function to add the rules to the used firewall.
            By default this function blocks all traffic from and to the given ip.
        """

        # Make sure ip isn't already blocked before blocking
        if type(ip_to_block) == str and not self.is_ip_blocked(ip_to_block) and self.firewall == 'iptables':
            # Blocking in iptables
            # Set the default behaviour to block all traffic from and to an ip
            if from_ is None and to is None:
                from_, to = True, True
            # This dictionary will be used to construct the rule
            options = {
                "protocol" : " -p " + protocol if protocol is not None else '' ,
                "dport"    : " --dport " + str(dport)  if dport is not None else '',
                "sport"    : " --sport " + str(sport)  if sport is not None else '',
            }

            if from_:
                # Add rule to block traffic from source ip_to_block (-s)
                blocked = self.exec_iptables_command(action='insert',
                                                         ip_to_block=ip_to_block,
                                                         flag='-s',
                                                         options=options)
            if to:
                # Add rule to block traffic to ip_to_block (-d)
                blocked = self.exec_iptables_command(action='insert',
                                                         ip_to_block=ip_to_block,
                                                         flag='-d',
                                                         options=options)

            if blocked:
                # Successfully blocked an ip
                self.print("Blocked: " + ip_to_block)
                return True

        return type(ip_to_block) == str , self.is_ip_blocked(ip_to_block), self.firewall

    def unblock_ip(self, ip_to_unblock, from_=None, to=None, dport=None,
                   sport=None,
                   protocol=None):
        """ Unblocks an ip based on the flags passed in the message """
        # This dictionary will be used to construct the rule
        options = {
            "protocol" : f" -p {protocol}"   if protocol  else '' ,
            "dport"    : f" --dport {dport}" if dport else '',
            "sport"    : f" --sport {sport}" if sport  else '',
        }
        # Set the default behaviour to unblock all traffic from and to an ip
        if from_ is None and to is None:
            from_, to = True, True
        # Set the appropriate iptables flag to use in the command
        # The module sending the message HAS TO specify either 'from_' or 'to' or both
        # so that this function knows which rule to delete
        # if both or none were specified we'll be executing 2 commands/deleting 2 rules

        # Block traffic from source ip
        if from_:
            unblocked = self.exec_iptables_command(action='delete',
                                                     ip_to_block=ip_to_unblock,
                                                     flag='-s',
                                                     options=options)
        # Block traffic from distination ip
        if to:
            unblocked = self.exec_iptables_command(action='delete',
                                                     ip_to_block=ip_to_unblock,
                                                     flag='-d',
                                                     options=options)

        if unblocked:
            # Successfully blocked an ip
            self.print("Unblocked: " + ip_to_unblock)
            return True
        return False

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                # There's an IP that needs to be blocked
                if message and message['channel'] == 'new_blocking' \
                    and message['type'] == 'message':
                    # message['data'] in the new_blocking channel is a dictionary that contains
                    # the ip and the blocking options
                    # Example of the data dictionary to block or unblock an ip:
                    # (notice you have to specify from,to,dport,sport,protocol or at least 2 of them when unblocking)
                    #   blocking_data = {
                    #       "ip"       : "0.0.0.0"
                    #       "block"    : True to block  - False to unblock
                    #       "from"     : True to block traffic from ip (default) - False does nothing
                    #       "to"       : True to block traffic to ip  (default)  - False does nothing
                    #       "dport"    : Optional destination port number
                    #       "sport"    : Optional source port number
                    #       "protocol" : Optional protocol
                    #   }
                    # Example of passing blocking_data to this module:
                    #   blocking_data = json.dumps(blocking_data)
                    #   __database__.publish('new_blocking', blocking_data )

                    # Decode(deserialize) the python dict into JSON formatted string
                    data = json.loads(message['data'])
                    # Parse the data dictionary
                    ip    = data.get("ip")
                    block = data.get("block")
                    from_ = data.get("from")
                    to    = data.get("to")
                    dport = data.get("dport")
                    sport = data.get("sport")
                    protocol = data.get("protocol")
                    if block:
                        self.block_ip(ip, from_, to, dport, sport, protocol)
                    else:
                        self.unblock_ip(ip, from_, to, dport, sport, protocol)

            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
