from style import green

import subprocess
import os
import threading
from multiprocessing import Queue

class UIManager:
    def __init__(self, main):
        self.main = main

    def check_if_webinterface_started(self):
        if not hasattr(self, 'webinterface_return_value'):
            return

        # now that the web interface had enough time to start,
        # check if it successfully started or not
        if self.webinterface_return_value.empty():
            # to make sure this function is only executed once
            delattr(self, 'webinterface_return_value')
            return
        if self.webinterface_return_value.get() != True:
            # to make sure this function is only executed once
            delattr(self, 'webinterface_return_value')
            return

        self.main.print(f"Slips {green('web interface')} running on "
                   f"http://localhost:55000/")
        delattr(self, 'webinterface_return_value')
    
    def start_webinterface(self):
        """
        Starts the web interface shell script if -w is given
        """
        def detach_child():
            """
            Detach the web interface from the parent process group(slips.py), the child(web interface)
             will no longer receive signals and should be manually killed in shutdown_gracefully()
            """
            os.setpgrp()

        def run_webinterface():
            # starting the wbeinterface using the shell script results in slips not being able to
            # get the PID of the python proc started by the .sh script
            command = ['python3', 'webinterface/app.py']
            webinterface = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                preexec_fn=detach_child
            )
            # self.webinterface_pid = webinterface.pid
            self.main.db.store_process_PID('Web Interface', webinterface.pid)
            # we'll assume that it started, and if not, the return value will immediately change and this thread will
            # print an error
            self.webinterface_return_value.put(True)

            # waits for process to terminate, so if no errors occur
            # we will never get the return value of this thread
            error = webinterface.communicate()[1]
            if error:
                # pop the True we just added
                self.webinterface_return_value.get()
                # set false as the return value of this thread
                self.webinterface_return_value.put(False)

                pid = self.main.metadata_man.get_pid_using_port(55000)
                # pid = self.get_pid_using_port(55000)
                self.main.print (f"Web interface error:\n"
                            f"{error.strip().decode()}\n"
                            f"Port 55000 is used by PID {pid}")

        # if there's an error, this will be set to false, and the error will be printed
        # otherwise we assume that the interface started
        # self.webinterface_started = True
        self.webinterface_return_value = Queue()
        self.webinterface_thread = threading.Thread(
            target=run_webinterface,
            daemon=True,
        )
        self.webinterface_thread.start()
        # we'll be checking the return value of this thread later

