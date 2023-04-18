import shutil
import psutil
import sys
import os
import subprocess

class Checker:
    def __init__(self, main):
        self.main = main

    def check_input_type(self) -> tuple:
        """
        returns line_type, input_type, input_information
        supported input types are:
            interface, argus, suricata, zeek, nfdump, db
        supported self.input_information:
            given filepath, interface or type of line given in stdin
        """
        # only defined in stdin lines
        line_type = False
        # -I
        if self.main.args.interface:
            input_information = self.main.args.interface
            input_type = 'interface'
            # return input_type, self.main.input_information
            return input_type, input_information, line_type

        if self.main.args.db:
            self.main.load_db()
            return

        if not self.main.args.filepath:
            print('[Main] You need to define an input source.')
            sys.exit(-1)
        # -f file/stdin-type
        input_information = self.main.args.filepath
        if os.path.exists(input_information):
            input_type = self.main.get_input_file_type(input_information)
        else:
            input_type, line_type = self.main.handle_flows_from_stdin(
                input_information
            )

        return input_type, input_information, line_type

    def check_given_flags(self):
        """
        check the flags that don't require starting slips
        for ex: clear db, clearing the blocking chain, killing all servers, stopping the daemon, etc.
        """

        if self.main.args.help:
            self.main.print_version()
            arg_parser = self.main.conf.get_parser(help=True)
            arg_parser.parse_arguments()
            arg_parser.print_help()
            self.main.terminate_slips()

        if self.main.args.interface and self.main.args.filepath:
            print('Only -i or -f is allowed. Stopping slips.')
            self.main.terminate_slips()


        if (self.main.args.save or self.main.args.db) and os.getuid() != 0:
            print('Saving and loading the database requires root privileges.')
            self.main.terminate_slips()

        if (self.main.args.verbose and int(self.main.args.verbose) > 3) or (
            self.main.args.debug and int(self.main.args.debug) > 3
        ):
            print('Debug and verbose values range from 0 to 3.')
            self.main.terminate_slips()

        # Check if redis server running
        if not self.main.args.killall and self.main.redis_man.check_redis_database() is False:
            print('Redis database is not running. Stopping Slips')
            self.main.terminate_slips()

        if self.main.args.config and not os.path.exists(self.main.args.config):
            print(f"{self.main.args.config} doesn't exist. Stopping Slips")
            self.main.terminate_slips()

        if self.main.args.interface:
            interfaces = psutil.net_if_addrs().keys()
            if self.main.args.interface not in interfaces:
                print(f"{self.main.args.interface} is not a valid interface. Stopping Slips")
                self.main.terminate_slips()


        # Clear cache if the parameter was included
        if self.main.args.clearcache:
            self.clear_redis_cache()
        # Clear cache if the parameter was included
        if self.main.args.blocking and not self.main.args.interface:
            print('Blocking is only allowed when running slips using an interface.')
            self.main.terminate_slips()

        # kill all open unused redis servers if the parameter was included
        if self.main.args.killall:
            self.main.redis_man.close_open_redis_id()
            self.main.terminate_slips()

        if self.main.args.version:
            self.main.print_version()
            self.main.terminate_slips()

        if (
            self.main.args.interface
            and self.main.args.blocking
            and os.geteuid() != 0
        ):
            # If the user wants to blocks, we need permission to modify iptables
            print(
                'Run Slips with sudo to enable the blocking module.'
            )
            self.main.terminate_slips()

        if self.main.args.clearblocking:
            if os.geteuid() != 0:
                print(
                    'Slips needs to be run as root to clear the slipsBlocking chain. Stopping.'
                )
            else:
                self.delete_blocking_chain()
            self.main.terminate_slips()
        # Check if user want to save and load a db at the same time
        if self.main.args.save and self.main.args.db:
            print("Can't use -s and -d together")
            self.main.terminate_slips()

    def delete_blocking_chain(self):
        # start only the blocking module process and the db
        from slips_files.core.database.database import __database__
        from multiprocessing import Queue, active_children
        from modules.blocking.blocking import Module

        blocking = Module(Queue())
        blocking.start()
        blocking.delete_slipsBlocking_chain()
        # kill the blocking module manually because we can't
        # run shutdown_gracefully here (not all modules has started)
        for child in active_children():
            child.kill()

    def clear_redis_cache(self):
        print('Deleting Cache DB in Redis.')
        self.main.redis_man.clear_redis_cache_database()
        self.main.input_information = ''
        self.main.zeek_folder = ''
        # self.main.log_redis_server_PID(6379, self.main.redis_man.get_pid_of_redis_server(6379))
        self.main.terminate_slips()
    
    def check_output_redirection(self) -> tuple:
        """
        Determine where slips will place stdout,
         stderr and logfile based on slips mode
         @return (current_stdout, stderr, slips_logfile)
         current_stdout will be '' if it's not redirected to a file
        """
        # lsof will provide a list of all open fds belonging to slips
        command = f'lsof -p {self.main.pid}'
        result = subprocess.run(command.split(), capture_output=True)
        # Get command output
        output = result.stdout.decode('utf-8')
        # if stdout is being redirected we'll find '1w' in one of the lines
        # 1 means stdout, w means write mode
        # by default, stdout is not redirected
        current_stdout = ''
        for line in output.splitlines():
            if '1w' in line:
                # stdout is redirected, get the file
                current_stdout = line.split(' ')[-1]
                break

        if self.main.mode == 'daemonized':
            stderr = self.main.daemon.stderr
            slips_logfile = self.main.daemon.stdout
        else:
            stderr = os.path.join(self.main.args.output, 'errors.log')
            slips_logfile = os.path.join(self.main.args.output, 'slips.log')
        return (current_stdout, stderr, slips_logfile)
