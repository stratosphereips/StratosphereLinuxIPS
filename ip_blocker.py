import sys, subprocess
from subprocess import Popen, PIPE

def add_reject_rule(address='192.168.1.123'):
    #command = 'ipset add blacklist '+ address
    command_test = 'iptables -v -S FORWARD'
    results = Popen(command_test, shell=True, stdin=PIPE, stdout=PIPE).communicate()
    for line in results:
        if address in line and 'REJECT' in line:
            # We are already blocking
            print 'already blocked'
            return True
        else:
            print 'block!'
            command = 'iptables -I FORWARD 3 -s {} -j REJECT'.format(address)
            subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
            return True

def remove_reject_rule(address):
    #command = 'ipset del blacklist '+ address
    command = 'iptables -D FORWARD -s {} -j REJECT'.format(address)
    res = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()

if __name__ == '__main__':
    #remove_reject_rule(sys.argv[1])
    add_reject_rule(sys.argv[1])
