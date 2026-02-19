# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import os

from slips_files.common.abstracts.iinput_handler import IInputHandler
from slips_files.common.slips_utils import utils
from slips_files.common.style import yellow
from slips_files.core.input.observer_manager import InputObserver
from slips_files.core.input.zeek.utils.zeek_file_remover import ZeekFileRemover


class InterfaceInput(IInputHandler):
    def __init__(self, input_process):
        super().__init__(input_process)
        self.db = self.input.db
        self.observer = InputObserver(self.input)
        self.file_remover = ZeekFileRemover(self.input, self.input.zeek_utils)

    def run(self):
        """
        runs when slips is given an interface with -i or 2 interfaces with -ap
        """
        self.input.zeek_utils.ensure_zeek_dir()
        self.input.print(f"Storing zeek log files in {self.input.zeek_dir}")
        if self.input.is_running_non_stop:
            self.file_remover.start()

        # slips is running with -i or -ap
        # We don't want to stop bro if we read from an interface
        self.input.bro_timeout = float("inf")
        # format is {interface: zeek_dir_path}
        interfaces_to_monitor = {}
        if self.input.args.interface:
            interfaces_to_monitor.update(
                {
                    self.input.args.interface: {
                        "dir": self.input.zeek_dir,
                        "type": "main_interface",
                    }
                }
            )

        elif self.input.args.access_point:
            # slips is running in AP mode, we need to monitor the 2
            # interfaces, wifi and eth.
            for _type, interface in self.db.get_ap_info().items():
                # _type can be 'wifi_interface' or "ethernet_interface"
                dir_to_store_interface_logs = os.path.join(
                    self.input.zeek_dir, interface
                )
                interfaces_to_monitor.update(
                    {
                        interface: {
                            "dir": dir_to_store_interface_logs,
                            "type": _type,
                        }
                    }
                )
        for interface, interface_info in interfaces_to_monitor.items():
            interface_dir = interface_info["dir"]
            if not os.path.exists(interface_dir):
                os.makedirs(interface_dir)

            if interface_info["type"] == "ethernet_interface":
                cidr = utils.get_cidr_of_interface(interface)
                tcpdump_filter = f"dst net {cidr}"
                logline = yellow(
                    f"Zeek is logging incoming traffic only "
                    f"for interface: {interface}."
                )
                self.input.print(logline)
            else:
                tcpdump_filter = None
                logline = yellow(
                    f"Zeek is logging all traffic on interface:"
                    f" {interface}."
                )
                self.input.print(logline)

            self.input.zeek_utils.init_zeek(
                self.observer,
                interface_dir,
                interface,
                tcpdump_filter=tcpdump_filter,
            )

        self.input.lines = self.input.zeek_utils.read_zeek_files()
        self.input.print_lines_read()
        self.input.mark_self_as_done_processing()
        return True

    def shutdown_gracefully(self):
        self.observer.stop()
        self.file_remover.shutdown_gracefully()
        self.input.zeek_utils.shutdown_zeek_runtime()
        self.input.zeek_utils.close_all_handles()
        self.input.mark_self_as_done_processing()
        return True
