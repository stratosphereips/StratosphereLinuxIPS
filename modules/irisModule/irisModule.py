import platform
import signal
import time
from logging import debug
from pathlib import Path

import psutil

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.abstracts.module import IModule
import json
import os
import subprocess
import yaml

def _iris_configurator(config_path : str, redis_port : int):
    # Read the YAML configuration
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)

    # Ensure the Redis section exists and update the port
    if "Redis" in config:
        config["Redis"]["Port"] = redis_port
        config["Redis"]["Host"] = "127.0.0.1"
        config["Redis"]["Tl2NlChannel"] = "iris_internal"
    else:
        config["Redis"] = {
            "Host": "127.0.0.1",
            "Port": redis_port,
            "Tl2NlChannel": "iris_internal"
        }

    # Write the updated configuration back to the file
    with open(config_path, "w") as file:
        yaml.dump(config, file, default_flow_style=False, sort_keys=False)
    return config["Server"]["port"]

class IrisModule(IModule):
    # Name: short name of the module. Do not use spaces
    name = "Iris"
    description = "Global P2P module cooperating with Fides"
    authors = ["David Otta"]
    process = None

    def init(self):
        # To which channels do you want to subscribe? When a message
        # arrives on the channel the module will receive a msg

        # You can find the full list of channels at
        # slips_files/core/database/redis_db/database.py
        self.f2n = self.db.subscribe("fides2network")
        self.n2f = self.db.subscribe("network2fides")
        self.fi = self.db.subscribe("iris_internal")
        self.channels = {
            "network2fides": self.n2f,
            "fides2network": self.f2n,
            "iris_internal": self.fi,
        }

    def make_relative_path(self, executable_path, config_file_path):
        # Get the directory of the executable
        executable_dir = os.path.dirname(executable_path)

        # Calculate the relative path from executable directory to the config file
        relative_path = os.path.relpath(config_file_path, executable_dir)

        return relative_path

    def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """

        iris_exe_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "iris"
        )
        conf = ConfigParser()
        iris_conf_path = self.make_relative_path(
            iris_exe_path, conf.get_iris_config_location()
        )

        self.irip = _iris_configurator(conf.get_iris_config_location(), self.redis_port)

        command = [
            iris_exe_path,
            "--conf",
            iris_conf_path,
        ]
        # self.log_line(f'Initializing IRIS module with {command}')

        command_str = " ".join(
            f'"{arg}"' if " " in arg or '"' in arg else arg for arg in command
        )

        self.print(f"Running Iris using command: {command_str}")

        log_dir = os.path.join(self.output_dir, "iris")
        os.makedirs(log_dir, exist_ok=True)
        # Open the log file
        log_file_path = os.path.join(log_dir, "iris_logs.txt")
        self.log_file = open(log_file_path, "w")
        self.log_file.write(f"Running Iris using command: {command_str}")

        full_cwd = Path.cwd() / "modules" / "irisModule"

        try:
            # Start the subprocess, redirecting stdout and stderr to the same file
            self.process = subprocess.Popen(
                command,  # Replace with your command
                stdout=self.log_file,
                stderr=self.log_file,
                cwd=full_cwd,
            )
            self.print(f"Running Iris with PID: {self.process.pid}")
        except OSError as e:
            error_message = {"from": self.name, "txt": str(e)}
            #self . logger.log_error(error_message)
            self.print(f"Iris Module failed to start Iris (peercli/iris) using command: {command_str}, generating: {str(e)}", verbose=1, debug=3)

    def __sigterminantor(self, port):
        # Get the current operating system
        current_os = platform.system()

        try:
            # Find the process ID by port number
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                # Check if the process has a connection listening on the given port
                for conn in proc.info['connections']:
                    if conn.laddr.port == port:
                        pid = proc.info['pid']
                        self.print(f"Process found: {proc.info['name']} (PID: {pid}) is listening on port {port}")

                        if current_os == "Windows":
                            # Windows doesn't support SIGTERM directly, use terminate() method
                            proc.terminate()
                            self.print(f"Terminated process with PID {pid} on Windows.")
                        else:
                            # On Linux/macOS, send SIGTERM
                            os.kill(pid, signal.SIGTERM)
                            self.print(f"Sent SIGTERM to process with PID {pid}.")
                        return
            self.print(f"No process found listening on port {port}.")

        except Exception as e:
            print(f"Error occurred: {e}")

    def simplex_duplex_translator(self):
        if msg := self.get_msg("fides2network"):
            # Fides send something to the network (Iris)
            # FORWARD to Iris
            self.db.publish("iris_internal", msg["data"])
            self.print(f"fides2network: {msg}")

        if msg := self.get_msg("iris_internal"):
            # Message on Iris duplex channel
            # Get the message
            type = json.loads(msg["data"])["type"]
            if "nl2tl" in type:
                # Message is from Iris addressed to Fides Module
                # FORWARD to Fides Module
                self.db.publish("network2fides", msg["data"])
                self.print(f"iris_internal: {msg}")
            # else: pass, message was just an echo from F -> I forwarding

    def main(self):
        """Main loop function"""
        try:
            self.simplex_duplex_translator()
        except KeyboardInterrupt:
            return True

    def shutdown_gracefully(self):
        self.print("Iris Module terminating gracefully")
        #self.__sigterminantor()
        self.send_sigterm(self.process.pid)
        os.kill(self.process.pid, signal.SIGTERM)
        self.log_file.close()
        self.print("Iris Module terminating wait")
        if self.process.poll() is None:
            self.process.wait()
        self.print("Iris Module terminated gracefully")

    def send_sigterm(self, pid):
        current_platform = platform.system()

        if current_platform == 'Windows':
            # Windows: Using taskkill to terminate a process
            try:
                subprocess.run(['taskkill', '/PID', str(pid)], check=True)
                self.print(f"Sent SIGTERM to process {pid} on Windows")
            except subprocess.CalledProcessError as e:
                self.print(f"Failed to kill process {pid}: {e}")
        else:
            # Unix-like systems: Sending SIGTERM signal
            try:
                os.kill(pid, signal.SIGTERM)
                self.print(f"Sent SIGTERM to process {pid} on {current_platform}")
            except ProcessLookupError:
                self.print(f"Process {pid} not found.")
            except PermissionError:
                self.print(f"Permission denied when trying to kill process {pid}.")
            except Exception as e:
                self.print(f"An error occurred: {e}")
