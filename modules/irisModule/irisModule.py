import signal
from pathlib import Path

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.abstracts.module import IModule
import json
import os
import subprocess


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

    def log_line(self, txt: str):
        self.logger.log_line({"from": self.name, "txt": txt})

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
        except OSError as e:
            error_message = {"from": self.name, "txt": str(e)}
            self.logger.log_error(error_message)

    def simplex_duplex_translator(self):
        if msg := self.get_msg("fides2network"):
            # Fides send something to the network (Iris)
            # FORWARD to Iris
            self.db.publish("iris_internal", msg["data"])

        if msg := self.get_msg("iris_internal"):
            # Message on Iris duplex channel
            # Get the message
            type = json.loads(msg["data"])["type"]
            if "nl2tl" in type:
                # Message is from Iris addressed to Fides Module
                # FORWARD to Fides Module
                self.db.publish("network2fides", msg["data"])
            # else: pass, message was just an echo from F -> I forwarding

    def main(self):
        """Main loop function"""
        self.simplex_duplex_translator()

    def shutdown_gracefully(self):
        self.print("Iris Module terminating gracefully")
        self.process.terminate()
        try:
            # Wait for the process to finish with a timeout of 5 seconds
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.print(
                "Iris (peercli) process did not terminate gracefully within the timeout, killing it.",
                verbose=1, debug=1
            )
            self.process.kill()
            os.kill(self.process.pid, signal.SIGTERM)
        self.log_file.close()
        self.print("Iris Module terminating wait")
        if self.process.poll() is None:
            self.process.wait()
        self.print("Iris Module terminated gracefully")
