# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.slips_utils import utils
from slips_files.common.style import green

import subprocess
import os
import threading
from multiprocessing import Queue


class UIManager:
    def __init__(self, main):
        self.main = main
        self.web_interface_port = self.main.conf.web_interface_port

    def check_if_webinterface_started(self):
        if not hasattr(self, "webinterface_return_value"):
            return

        # now that the web interface had enough time to start,
        # check if it successfully started or not
        if self.webinterface_return_value.empty():
            # to make sure this function is only executed once
            delattr(self, "webinterface_return_value")
            return

        if not self.webinterface_return_value.get():
            # to make sure this function is only executed once
            delattr(self, "webinterface_return_value")
            return

        self.main.print(
            f"Slips {green('web interface')} running on "
            f"http://localhost:{self.web_interface_port}/ "
            f"[PID {green(self.web_interface_pid)}]\n"
            f"The port will stay open after slips is done with the "
            f"analysis unless you manually kill it.\n"
            f"You need to kill it to be able to start the web interface "
            f"again."
        )
        delattr(self, "webinterface_return_value")

    def start_webinterface(self):
        """
        Starts the web interface shell script if -w is given
        """

        def detach_child():
            """
            Detach the web interface from the parent process group(slips.py),
             the child(web interface)
             will no longer receive signals and should be manually killed in
             shutdown_gracefully()
            """
            os.setpgrp()

        def run_webinterface():
            # starting the wbeinterface using the shell script results
            # in slips not being able to
            # get the PID of the python proc started by the .sh script
            # so we'll start it with python instead
            command = ["python3", "-m", "webinterface.app"]

            webinterface = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                preexec_fn=detach_child,
                cwd=os.getcwd(),
            )

            self.main.db.store_pid("Web Interface", webinterface.pid)
            self.web_interface_pid = webinterface.pid
            # we'll assume that it started, and if not, the return value will
            # immediately change and this thread will
            # print an error
            self.webinterface_return_value.put(True)

            # waits for process to terminate, so if no errors occur
            # we will never get the return value of this thread
            error = webinterface.communicate()[1]
            if error:
                # pop the return value we just added
                self.webinterface_return_value.get()
                # set false as the return value of this thread
                self.webinterface_return_value.put(False)

                self.main.print("Web interface error:", verbose=1, debug=3)
                for line in error.strip().decode().splitlines():
                    self.main.print(f"{line}")

        if utils.is_port_in_use(self.web_interface_port):
            pid = self.main.metadata_man.get_pid_using_port(
                self.web_interface_port
            )
            self.main.print(
                f"Failed to start web interface. "
                f"Port {self.web_interface_port} is used by PID {pid}",
                verbose=1,
                debug=3,
            )
            return

        # if there's an error, this webinterface_return_value will be set
        # to false, and the error will be printed
        self.webinterface_return_value = Queue()
        self.webinterface_thread = threading.Thread(
            target=run_webinterface,
            daemon=True,
        )
        self.webinterface_thread.start()
        # we'll be checking the return value of this thread later
