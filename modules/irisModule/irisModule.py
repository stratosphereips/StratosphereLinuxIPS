import platform
import signal
from pathlib import Path


from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.abstracts.module import IModule
import json
import os
import subprocess
import yaml


class IrisModule(IModule):
    # Name: short name of the module. Do not use spaces
    name = "Iris"
    description = "Global P2P module cooperating with Fides"
    authors = ["David Otta"]
    process = None
    stopFlag = False

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

    def _iris_configurator(self, config_path: str, redis_port: int):
        try:
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
                    "Tl2NlChannel": "iris_internal",
                }
            if "Server" in config:
                #config["Server"]["Port"] = 9010
                config["Server"]["Host"] = self.db.get_host_ip()
                config["Server"]["DhtServerMode"] = "true"
            else:
                config["Redis"] = {
                    "Port": 6644,
                    "Host": self.db.get_host_ip(),
                    "DhtServerMode": "true",
                }

            # Write the updated configuration back to the file
            with open(config_path, "w") as file:
                yaml.dump(
                    config, file, default_flow_style=False, sort_keys=False
                )

        except FileNotFoundError:
            # Handle the case when the file doesn't exist
            self.print("The file was not found.")
            return None
        except IOError:
            # Handle other I/O related errors (e.g., permissions issues)
            self.print("An error occurred while reading the file.")
            return None
        except Exception as e:
            # Catch any other unexpected errors
            self.print(f"An unexpected error occurred: {e}")
            return None
        return config["Server"]["Port"]

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

        self.irip = self._iris_configurator(
            conf.get_iris_config_location(), self.redis_port
        )
        if self.irip is None:
            self.stopFlag = True
            return

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
        self.log_file_path = os.path.join(log_dir, "iris_logs.txt")
        self.log_file = open(self.log_file_path, "w")
        self.log_file.write(f"Running Iris using command: {command_str}")

        full_cwd = Path.cwd() / "modules" / "irisModule"

        try:
            # Start the subprocess, redirecting stdout and stderr to the same file
            self.process = subprocess.Popen(
                command,
                stdout=self.log_file,
                stderr=self.log_file,
                cwd=full_cwd,
            )
            self.print(f"Running Iris with PID: {self.process.pid}")
        except OSError as e:
            self.print(
                f"Iris Module failed to start Iris "
                f"(peercli/iris) using command: {command_str}, "
                f"generating: {e}",
                verbose=1,
                debug=3,
            )
            self.stopFlag = True
            return

    def _simplex_duplex_translator(self):
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

    def _check_iris_status(self):
        if self.process.poll() is None:
            return True
        self.log_file.close()
        self.iris_log_reader = open(self.log_file_path, "r")
        keywords = {"ERROR", "FATAL", "PANIC"}
        for line in self.iris_log_reader:
            if any(keyword in line for keyword in keywords):
                self.print(f"Iris says: {line}", verbose=0, debug=1)
        return False

    def main(self):
        """Main loop function"""
        if self.stopFlag:
            return True
        try:
            self._simplex_duplex_translator()
            if (
                not self._check_iris_status()
            ):  # Iris needs attention, canceled, crashing, ...
                self.print(
                    f"Iris in a critical state, stopping! \n\t "
                    f"For more info than above, please access the "
                    f"logs in {self.log_file_path}",
                    verbose=1,
                    debug=3,
                )
                return True
        except KeyboardInterrupt:
            # the only way to stop this module is by using the ctrl+c
            # so we're returning true so that Imodule wouold to call
            # shutdown_gracefully()
            return True

    def shutdown_gracefully(self):
        self.print("Iris Module terminating gracefully")
        if self.process and self.process.poll() is None:
            # process is running, killit
            self.send_sigterm(self.process.pid)

            if self.process.poll() is None:
                self.print("Iris Module terminating. wait")
                self.process.wait()

        if self.log_file is not None:
            self.log_file.close()

        self.print("Iris Module terminated gracefully")

    def send_sigterm(self, pid):
        current_platform = platform.system()

        if current_platform == "Windows":
            # Windows: Using taskkill to terminate a process
            try:
                subprocess.run(["taskkill", "/PID", str(pid)], check=True)
                self.print(f"Sent SIGTERM to process {pid} on Windows")
            except subprocess.CalledProcessError as e:
                self.print(f"Failed to kill process {pid}: {e}")
        else:
            # Unix-like systems: Sending SIGTERM signal
            try:
                os.kill(pid, signal.SIGTERM)
                self.print(
                    f"Sent SIGTERM to process {pid} on {current_platform}"
                )
            except ProcessLookupError:
                self.print(f"Process {pid} not found.")
            except PermissionError:
                self.print(
                    f"Permission denied when trying to kill process {pid}."
                )
            except Exception as e:
                self.print(f"An error occurred: {e}")
