# Customize --help in argparse.

import os
import sys
import argparse
import textwrap


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super(ArgumentParser, self).__init__(*args, **kwargs)
        self.program = {key: kwargs[key] for key in kwargs}
        self.options = []
        self.alerts_default_path = 'output/'


    def add_argument(self, *args, **kwargs):
        super(ArgumentParser, self).add_argument(*args, **kwargs)
        option = {}
        option['flags'] = [item for item in args]
        for key in kwargs:
            option[key] = kwargs[key]
        self.options.append(option)

    def print_help(self):
        wrapper = textwrap.TextWrapper(width=160)

        # Print description
        if 'description' in self.program:
            print(self.program['description'])
            print()

        # Print usage
        if 'usage' in self.program:
            print('Usage: %s' % self.program['usage'])
        else:
            usage = []
            for option in self.options:
                usage += [
                    '[%s|%s]' % (item, option['metavar'])
                    if 'metavar' in option
                    else '[%s|%s]' % (item, option['dest'].upper())
                    if 'dest' in option
                    else '[%s]' % item
                    for item in option['flags']
                ]
            wrapper.initial_indent = 'Usage: %s ' % os.path.basename(
                sys.argv[0]
            )
            wrapper.subsequent_indent = len(wrapper.initial_indent) * ' '
            output = str.join(' ', usage)
            output = wrapper.fill(output)
            print(output)
        print()

        # Print options
        print('Options:')
        maxlen = 0
        for option in self.options:
            option['flags2'] = ' '.join(
                [
                    '|'.join([item for item in option['flags']]),
                    option['metavar'] if 'metavar' in option else '',
                ]
            )

            if len(option['flags2']) > maxlen:
                maxlen = len(option['flags2'])
        for option in self.options:
            template = ' %-' + str(maxlen) + 's  | '
            wrapper.initial_indent = template % option['flags2']
            wrapper.subsequent_indent = len(wrapper.initial_indent) * ' '
            if 'help' in option and 'default' in option:
                output = option['help']
                output += (
                    " (default: '%s')" % option['default']
                    if isinstance(option['default'], str)
                    else ' (default: %s)' % str(option['default'])
                )
                output = wrapper.fill(output)
            elif 'help' in option:
                output = option['help']
                output = wrapper.fill(output)
            elif 'default' in option:
                output = (
                    "Default: '%s'" % option['default']
                    if isinstance(option['default'], str)
                    else 'Default: %s' % str(option['default'])
                )
                output = wrapper.fill(output)
            else:
                output = wrapper.initial_indent
            print(output)

    def get_configfile(self):
        slips_conf_path = os.path.join(os.getcwd(), 'slips.conf')
        self.add_argument(
            '-c',
            '--config',
            metavar='<configfile>',
            action='store',
            required=False,
            default=slips_conf_path,
            help='Path to the Slips config file.',
        )
        return self.parse_known_args()[0].config

    def parse_arguments(self):
        # Parse the parameters
        slips_conf_path = os.path.join(os.getcwd() ,'slips.conf')
        self.add_argument(
            '-c',
            '--config',
            metavar='<configfile>',
            action='store',
            required=False,
            default=slips_conf_path,
            help='Path to the Slips config file.',
        )
        self.add_argument(
            '-v',
            '--verbose',
            metavar='<verbositylevel>',
            action='store',
            required=False,
            type=int,
            help='Verbosity level. This logs more info about Slips.',
        )
        self.add_argument(
            '-e',
            '--debug',
            metavar='<debuglevel>',
            action='store',
            required=False,
            type=int,
            help='Debugging level. This shows more detailed errors.',
        )
        self.add_argument(
            '-f',
            '--filepath',
            metavar='<file>',
            action='store',
            required=False,
            help='Read a Zeek dir, Argus binetflow, pcapfile or nfdump.',
        )
        self.add_argument(
            '-i',
            '--interface',
            metavar='<interface>',
            action='store',
            required=False,
            help='Read packets from an interface.',
        )
        self.add_argument(
            '-l',
            '--createlogfiles',
            action='store_true',
            required=False,
            help='Create log files with all the traffic info and detections.',
        )
        self.add_argument(
            '-F',
            '--pcapfilter',
            action='store',
            required=False,
            type=str,
            help="Packet filter for Zeek. BPF style.",
        )
        self.add_argument(
            '-cc',
            '--clearcache',
            action='store_true',
            required=False,
            help='Clear the cache database.',
        )
        self.add_argument(
            '-p',
            '--blocking',
            help='Allow Slips to block malicious IPs. Requires root access. Supported only on Linux.',
            required=False,
            default=False,
            action='store_true',
        )
        self.add_argument(
            '-cb',
            '--clearblocking',
            help='Flush and delete slipsBlocking iptables chain',
            required=False,
            default=False,
            action='store_true',
        )
        self.add_argument(
            '-o',
            '--output',
            action='store',
            required=False,
            default=self.alerts_default_path,
            help='Store alerts.json and alerts.txt in the given folder.',
        )
        self.add_argument(
            '-s',
            '--save',
            action='store_true',
            required=False,
            help='Save the analysed file db to disk.',
        )
        self.add_argument(
            '-d',
            '--db',
            action='store',
            required=False,
            help='Read an analysed file (rdb) from disk.',
        )
        self.add_argument(
            '-D',
            '--daemon',
            required=False,
            default=False,
            action='store_true',
            help='Run slips in daemon mode',
        )
        self.add_argument(
            '-S',
            '--stopdaemon',
            required=False,
            default=False,
            action='store_true',
            help='Stop slips daemon',
        )
        self.add_argument(
            '-k',
            '--killall',
            action='store_true',
            required=False,
            help='Kill all unused redis servers',
        )
        self.add_argument(
            '-m',
            '--multiinstance',
            action='store_true',
            required=False,
            help='Run multiple instances of slips, don\'t overwrite the old one',
        )
        self.add_argument(
            '-P',
            '--port',
            action='store',
            required=False,
            help='The redis-server port to use',
        )
        self.add_argument(
            '-V',
            '--version',
            action='store_true',
            required=False,
            help='Print Slips Version',
        )
        self.add_argument(
            '-h', '--help', action='help', help='command line help'
        )
        return self.parse_args()
