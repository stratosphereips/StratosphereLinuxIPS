import sys, subprocess


def add_reject_rule(address):
	command = 'ipset add blacklist '+ address
	subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()

def remove_reject_rule(address):
	command = 'ipset del blacklist '+ address
	subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()

if __name__ == '__main__':
	#remove_reject_rule(sys.argv[1])
	add_reject_rule(sys.argv[1])
