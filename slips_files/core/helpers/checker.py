# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import sys

import psutil


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
            input_type = "interface"
            # return input_type, self.main.input_information
            return input_type, input_information, line_type

        if self.main.args.db:
            self.main.redis_man.load_db()
            return

        if self.main.args.input_module:
            input_information = "input_module"
            input_type = self.main.args.input_module
            # this is the default value of the type of flows slips reads from
            # a module
            line_type = "zeek"
            return input_type, input_information, line_type

        if not self.main.args.filepath:
            print("[Main] You need to define an input source.")
            sys.exit(-1)

        # -f file/dir/stdin-type
        input_information = self.main.args.filepath
        if os.path.isfile(input_information) or os.path.isdir(
            input_information
        ):
            input_type = self.main.get_input_file_type(input_information)
        else:
            input_type, line_type = self.main.handle_flows_from_stdin(
                input_information
            )

        return input_type, input_information, line_type

    def check_given_flags(self):
        """
        check the flags that don't require starting slips
        for example: clear db, clearing the blocking chain, killing all
        servers, etc.
        """

        if self.main.args.help:
            self.main.print_version()
            arg_parser = self.main.conf.get_parser(help=True)
            arg_parser.parse_arguments()
            arg_parser.print_help()
            self.main.terminate_slips()
        if self.main.args.interface and self.main.args.filepath:
            print("Only -i or -f is allowed. Stopping slips.")
            self.main.terminate_slips()

        if (
            self.main.args.interface or self.main.args.filepath
        ) and self.main.args.input_module:
            print(
                "You can't use --input-module with -f or -i. Stopping slips."
            )
            self.main.terminate_slips()

        if (self.main.args.save or self.main.args.db) and os.getuid() != 0:
            print("Saving and loading the database requires root privileges.")
            self.main.terminate_slips()

        if (self.main.args.verbose and int(self.main.args.verbose) > 3) or (
            self.main.args.debug and int(self.main.args.debug) > 3
        ):
            print("Debug and verbose values range from 0 to 3.")
            self.main.terminate_slips()

        # Check if redis server running
        if (
            not self.main.args.killall
            and self.main.redis_man.check_redis_database() is False
        ):
            print("Redis database is not running. Stopping Slips")
            self.main.terminate_slips()

        if self.main.args.config and not os.path.exists(self.main.args.config):
            print(f"{self.main.args.config} doesn't exist. Stopping Slips")
            self.main.terminate_slips()

        if self.main.conf.use_local_p2p() and not self.main.args.interface:
            print(
                "Warning: P2P is only supported using "
                "an interface. P2P Disabled."
            )

        if self.main.conf.use_global_p2p() and not (
            self.main.args.interface or self.main.args.growing
        ):
            print(
                "Warning: Global P2P (Fides Module + Iris Module) is only supported using "
                "an interface. Global P2P (Fides Module + Iris Module) Disabled."
            )

        if self.main.args.interface:
            interfaces = psutil.net_if_addrs().keys()
            if self.main.args.interface not in interfaces:
                print(
                    f"{self.main.args.interface} is not a valid interface. "
                    f"Stopping Slips"
                )
                self.main.terminate_slips()

        # if we're reading flows from some module other than the input
        # process, make sure it exists
        if self.main.args.input_module and not self.input_module_exists(
            self.main.args.input_module
        ):
            self.main.terminate_slips()

        # Clear cache if the parameter was included
        if self.main.args.clearcache:
            self.clear_redis_cache()
        # Clear cache if the parameter was included
        if self.main.args.blocking and not self.main.args.interface:
            print(
                "Blocking is only allowed when running slips using an interface."
            )
            self.main.terminate_slips()

        # kill all open unused redis servers if the parameter was included
        if self.main.args.killall:
            self.main.redis_man.close_open_redis_servers()
            self.main.terminate_slips()

        if self.main.args.version:
            self.main.print_version()
            self.main.terminate_slips()

        if (
            self.main.args.interface
            and self.main.args.blocking
            and os.geteuid() != 0
        ):
            # If the user wants to blocks, we need permission to modify
            # iptables
            print("Run Slips with sudo to enable the blocking module.")
            self.main.terminate_slips()

        if self.main.args.clearblocking:
            if os.geteuid() != 0:
                print(
                    "Slips needs to be run as root to clear the slipsBlocking "
                    "chain. Stopping."
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
        from multiprocessing import Queue, active_children
        from modules.blocking.blocking import Blocking

        blocking = Blocking(Queue())
        blocking.start()
        blocking.delete_slipsBlocking_chain()
        # kill the blocking module manually because we can't
        # run shutdown_gracefully here (not all modules has started)
        for child in active_children():
            child.kill()

    def clear_redis_cache(self):
        redis_cache_default_server_port = 6379
        redis_cache_server_pid = self.main.redis_man.get_pid_of_redis_server(
            redis_cache_default_server_port
        )
        print("Deleting Cache DB in Redis.")
        self.main.redis_man.clear_redis_cache_database()
        self.main.input_information = ""
        self.main.zeek_dir = ""
        self.main.redis_man.log_redis_server_pid(
            redis_cache_default_server_port, redis_cache_server_pid
        )
        self.main.terminate_slips()

    def input_module_exists(self, module):
        """
        :param module: this is the one given to slips via --input-module
        check if the module was created in modules/ dir
        """
        available_modules = os.listdir("modules")

        if module not in available_modules:
            print(f"{module} module is not available. Stopping slips")
            return False

        # this function assumes that the module is created in module/name/name.py
        if f"{module}.py" not in os.listdir(f"modules/{module}/"):
            print(
                f"{module} is not available in modules/{module}/{module}.py. "
                f"Stopping Slips."
            )
            return False
        return True
