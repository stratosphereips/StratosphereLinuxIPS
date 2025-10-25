# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import sys

import psutil


class Checker:
    def __init__(self, main):
        self.main = main

    def get_input_type(self) -> tuple:
        """
        returns line_type, input_type, input_information
        supported input_type values are:
            interface, argus, suricata, zeek, nfdump, db
        supported input_information:
            given filepath, interface or type of line given in stdin,
            comma separated access point interfaces like wlan0,eth0
        """
        # only defined in stdin lines
        line_type = False
        # -i or -ap
        if self.main.args.interface or self.main.args.access_point:
            input_information = (
                self.main.args.interface or self.main.args.access_point
            )
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

    def _print_help_and_exit(self):
        """prints the help msg and shutd down slips"""
        self.main.print_version()
        arg_parser = self.main.conf.get_parser(help=True)
        arg_parser.parse_arguments()
        arg_parser.print_help()
        self.main.terminate_slips()

    def _check_mutually_exclusive_flags(self):
        """checks if the user provided args that shouldnt be used together"""
        mutually_exclusive_flags = [
            self.main.args.interface,  # -i
            self.main.args.access_point,  # -ap
            self.main.args.save,  # -s
            self.main.args.db,  # -d
            self.main.args.filepath,  # -f
            self.main.args.input_module,  # -im
        ]

        # Count how many of the flags are set (True)
        mutually_exclusive_flag_count = sum(
            bool(flag) for flag in mutually_exclusive_flags
        )

        if mutually_exclusive_flag_count > 1:
            print(
                "Only one of the flags -i, -ap, -s, -d, or -f is allowed. "
                "Stopping slips."
            )
            self.main.terminate_slips()
            return

    def _check_if_root_is_required(self):
        if (self.main.args.save or self.main.args.db) and os.getuid() != 0:
            print("Saving and loading the database requires root privileges.")
            self.main.terminate_slips()
            return
        if (
            self.main.args.interface
            and self.main.args.blocking
            and os.geteuid() != 0
        ):
            # If the user wants to blocks, we need permission to modify
            # iptables
            print("Run Slips with sudo to use the blocking modules.")
            self.main.terminate_slips()
            return

        if self.main.args.clearblocking:
            if os.geteuid() != 0:
                print(
                    "Slips needs to be run as root to clear the slipsBlocking "
                    "chain. Stopping."
                )
            else:
                self.delete_blocking_chain()
            self.main.terminate_slips()
            return

    def _check_interface_validity(self):
        """checks if the given interface/s are valid"""
        interfaces = psutil.net_if_addrs().keys()
        if self.main.args.interface:
            if self.main.args.interface not in interfaces:
                print(
                    f"{self.main.args.interface} is not a valid interface. "
                    f"Stopping Slips"
                )
                self.main.terminate_slips()
                return

        if self.main.args.access_point:
            for interface in self.main.args.access_point.split(","):
                if interface not in interfaces:
                    print(
                        f"{interface} is not a valid interface."
                        f" Stopping Slips"
                    )
                    self.main.terminate_slips()
                    return

    def _is_slips_running_non_stop(self) -> bool:
        """determines if slips is monitoring real time traffic based oin
        the giving params"""
        return (
            self.main.args.interface
            or self.main.args.access_point
            or self.main.args.growing
            or self.main.args.input_module
        )

    def verify_given_flags(self):
        """
        Checks the validity of the given flags.
        """
        if self.main.args.help:
            self._print_help_and_exit()

        if self.main.args.version:
            self.main.print_version()
            self.main.terminate_slips()
            return

        self._check_mutually_exclusive_flags()
        self._check_if_root_is_required()
        self._check_interface_validity()

        if (self.main.args.verbose and int(self.main.args.verbose) > 3) or (
            self.main.args.debug and int(self.main.args.debug) > 3
        ):
            print("Debug and verbose values range from 0 to 3.")
            self.main.terminate_slips()
            return

        # Check if redis server running
        if (
            not self.main.args.killall
            and self.main.redis_man.check_redis_database() is False
        ):
            print("Redis database is not running. Stopping Slips")
            self.main.terminate_slips()
            return

        if self.main.args.config and not os.path.exists(self.main.args.config):
            print(f"{self.main.args.config} doesn't exist. Stopping Slips")
            self.main.terminate_slips()

        if self.main.conf.use_local_p2p() and not self.main.args.interface:
            print(
                "Warning: P2P is only supported using "
                "an interface. P2P Disabled."
            )
            return

        if self.main.conf.use_global_p2p() and not (
            self.main.args.interface or self.main.args.growing
        ):
            print(
                "Warning: Global P2P (Fides Module + Iris Module) is only supported using "
                "an interface. Global P2P (Fides Module + Iris Module) Disabled."
            )
            return

        # if we're reading flows from some module other than the input
        # process, make sure it exists
        if self.main.args.input_module and not self.input_module_exists(
            self.main.args.input_module
        ):
            self.main.terminate_slips()
            return

        # Clear cache if the parameter was included
        if self.main.args.clearcache:
            self.clear_redis_cache()
            return

        # Clear cache if the parameter was included
        if self.main.args.blocking and not self._is_slips_running_non_stop():
            print(
                "Blocking is only allowed when running slips on real time "
                "traffic. (running with -i, -ap, -im, or -g)"
            )
            self.main.terminate_slips()
            return

        # kill all open unused redis servers if the parameter was included
        if self.main.args.killall:
            self.main.redis_man.close_open_redis_servers()
            self.main.terminate_slips()
            return

    def delete_blocking_chain(self):
        from modules.blocking.slips_chain_manager import (
            del_slips_blocking_chain,
        )

        del_slips_blocking_chain()

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
