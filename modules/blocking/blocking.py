# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables
# 5. The file name of the python module (template.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to ignore the module
# 7. The name of the class MUST be 'Module', do not change it.

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import os
import shutil
import json


class Module(Module, multiprocessing.Process):
    """Data should be passed to this module as a json encoded python dict,
    by default this module flushes all slipsBlocking chains before it starts """
    # Name: short name of the module. Do not use spaces
    name = 'Blocking'
    description = 'Module to block IPs connecting to this device'
    authors = ['Kamila Babayeva, Sebastian Garcia, Alya Gomaa']

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

        self.set_sudo_according_to_env()
        # Set the timeout based on the platform. This is because the
        # pyredis lib does not have officially recognized the
        # timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            self.platform_system = 'Darwin'
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            self.platform_system = 'Linux'
            # linux
            self.timeout = None
        else:
            # Other systems
            self.timeout = None

        # self.test()

    def test(self):
        """ For debugging purposes, once we're done with the module we'll delete it """

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
        print("Blocked ip")

    def set_sudo_according_to_env(self):
        """ Check if running in host or in docker and sets sudo string accordingly.
            There's no sudo in docker so we need to execute all commands without it
         """
        # This env variable is defined in the Dockerfile
        running_in_docker = os.environ.get('AM_I_IN_A_DOCKER_CONTAINER', False)
        global sudo
        if running_in_docker:
            sudo = ''
        else:
            sudo = 'sudo '

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by
        taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to
         be printed
         debug: is the minimum debugging level required for this text to be
         printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the
        minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def determine_linux_firewall(self):
        """ Returns the currently installed firewall and installs iptables if none was found """

        if shutil.which('iptables'):
            return 'iptables'
        elif shutil.which('nftables'):
            return 'nftables'
        else:
            # If no firewall is found download and use iptables
            os.system(sudo + "apt install iptables")
            return 'iptables'

    def delete_iptables_chain(self):
        """ Flushes and deletes everything in slipsBlocking chain """

        # check if slipsBlocking chain exists before flushing it and suppress stderr and stdout while checking
        # 0 means it exists
        if os.system(sudo + " iptables -nvL slipsBlocking >/dev/null 2>&1") == 0:
            # Delete all references to slipsBlocking inserted in INPUT OUTPUT and FORWARD before deleting the chain
            os.system(sudo + 'iptables -D INPUT -j slipsBlocking')
            os.system(sudo + 'iptables -D OUTPUT -j slipsBlocking')
            os.system(sudo + 'iptables -D FORWARD -j slipsBlocking')

            # flush all the rules in slipsBlocking 
            os.system(sudo + 'iptables -F slipsBlocking')
            # Delete slipsBlocking chain from iptables
            os.system(sudo + 'iptables -X slipsBlocking')

    def initialize_chains_in_firewall(self):
        """ For linux: Adds a chain to iptables or a table to nftables called
            slipsBlocking where all the rules will reside """

        if self.platform_system == 'Linux':
            # Get the user's currently installed firewall
            self.firewall = self.determine_linux_firewall()
            if self.firewall == 'iptables':
                # delete any pre existing slipsBlocking rules that may conflict before adding a new one
                self.delete_iptables_chain()
                self.print('Executing "sudo iptables -N slipsBlocking"')
                # Add a new chain to iptables
                os.system(sudo + 'iptables -N slipsBlocking')
                # TODO: use python iptc
                # TODO: determine which one to use OUTPUT INPUT or FORWARD or is it safer to use the three of them?
                # Redirect the traffic from all other chains to slipsBlocking so rules
                # in any pre-existing chains dont override it
                # -I to insert slipsBlocking at the top of the INPUT, OUTPUT and FORWARD chains
                os.system(sudo + 'iptables -I INPUT -j slipsBlocking')
                os.system(sudo + 'iptables -I OUTPUT -j slipsBlocking')
                os.system(sudo + 'iptables -I FORWARD -j slipsBlocking')
            elif self.firewall == 'nftables':
                self.print('Executing "sudo nft add table inet slipsBlocking"')
                # Add a new nft table that uses the inet family (ipv4,ipv6)
                os.system(sudo + "nft add table inet slipsBlocking")
                # TODO: HANDLE NFT TABLE
        elif self.platform_system == 'Darwin':
            self.print('Mac OS blocking is not supported yet.')

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

        command = sudo + "iptables --" + action + " slipsBlocking " + flag + " " + ip_to_block
        # Add the options constructed in block_ip or unblock_ip to the iptables command
        for key in options.keys():
            command += options[key]
        command += " -j DROP"
        self.print("Executing: '" + command +" '")
        # Execute
        exit_status = os.system(command)
        # 0 is the success value
        if exit_status != 0:
            self.print("Error executing " + command, verbose=1, debug=1)
            return 1  # failed to execute command
        else:
            return 0  # success


    def block_ip(self, ip_to_block=None, from_=True, to=True,
                 dport=None, sport=None, protocol=None):
        """
            This function determines the user's platform and firewall and calls
            the appropriate function to add the rules to the used firewall.
            By default this function blocks all traffic from or to the given ip.
        """
        if type(ip_to_block) == str:
            # Block this ip in iptables
            if self.platform_system == 'Linux':
                # Blocking in iptables
                if self.firewall == 'iptables':
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
                        exit_status = self.exec_iptables_command(action='insert',
                                                                 ip_to_block=ip_to_block,
                                                                 flag='-s',
                                                                 options=options)
                    if to:
                        # Add rule to block traffic to ip_to_block (-d)
                        exit_status = self.exec_iptables_command(action='insert',
                                                                 ip_to_block=ip_to_block,
                                                                 flag='-d',
                                                                 options=options)
                    if exit_status:
                            # Successfully blocked an ip
                            self.print("Blocked: " + ip_to_block)
            elif self.platform_system == 'Darwin':
                # Blocking in MacOS
                self.print('Mac OS blocking is not supported yet.')

        
    def handle_stop_process_message(self, message):
        """ Deletes slipsBlocking chain and rules based on the user's platform and firewall """
        if self.platform_system == 'Linux':
            if self.firewall == 'iptables':
                # Delete rules in slipsBlocking chain
                self.delete_iptables_chain()
            elif self.firewall == 'nftables':
                # TODO: handle the creation of the slipsBlocking chain in nftables
                # Flush rules in slipsBlocking chain because you can't delete a chain without flushing first
                os.system(sudo + "nft flush chain inet slipsBlocking")
                # Delete slipsBlocking chain from nftables
                os.system(sudo + "nft delete chain inet slipsBlocking")
        elif self.platform_system == 'Darwin':
            self.print('Mac OS blocking is not supported yet.')

    def unblock_ip(self,
                   ip_to_unblock,
                   from_, to,
                   dport=None,
                   sport=None,
                   protocol=None):
        """ Unblocks an ip based on the flags passed in the message """
        # This dictionary will be used to construct the rule
        options = {
            "protocol" : " -p " + protocol if protocol is not None else '' ,
            "dport"    : " --dport " + str(dport)  if dport is not None else '',
            "sport"    : " --sport " + str(sport)  if sport is not None else '',
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
            flag = '-s'
            exit_status = self.exec_iptables_command(action='delete',
                                                     ip_to_block=ip_to_unblock,
                                                     flag=flag,
                                                     options=options)
        # Block traffic from distination ip
        if to:
            flag = '-d'
            exit_status = self.exec_iptables_command(action='delete',
                                                     ip_to_block=ip_to_unblock,
                                                     flag=flag,
                                                     options=options)

        if exit_status == 0:
            # Successfully blocked an ip
            self.print("Unblocked: " + ip_to_unblock)

    def run(self):
        #TODO: handle MacOS
        self.initialize_chains_in_firewall()
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message['data'] == 'stop_process':
                    self.handle_stop_process_message(message)
                    return True

                # There's an IP that needs to be blocked
                if message['channel'] == 'new_blocking' \
                    and message['type'] == 'message':
                    # message['data'] in the new_blocking channel is a dictionary that contains
                    # the ip and the blocking options
                    # Example of the data dictionary to block or unblock an ip:
                    #   (notice you have to specify from,to,dport,sport,protocol or at least 2 of them when unblocking)
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
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
