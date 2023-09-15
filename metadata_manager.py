from slips_files.common.imports import *
import socket
import psutil
import sys
import redis
import time
import os
import shutil
import json
from datetime import datetime

class MetadataManager:
    def __init__(self, main):
        self.main = main
    
    def get_host_ip(self):
        """
        Recognize the IP address of the machine
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('1.1.1.1', 80))
            ipaddr_check = s.getsockname()[0]
            s.close()
        except (socket.error):
            # not connected to the internet
            return None
        return ipaddr_check

    def get_pid_using_port(self, port):
        """
        Returns the PID of the process using the given port or False if no process is using it
        """
        port = int(port)
        for conn in psutil.net_connections():
            if conn.laddr.port == port:
                return psutil.Process(conn.pid).pid #.name()
        return None
    
    def store_host_ip(self):
        """
        Store the host IP address if input type is interface
        """
        running_on_interface = '-i' in sys.argv or self.main.db.is_growing_zeek_dir()
        if not running_on_interface:
            return

        hostIP = self.get_host_ip()
        while True:
            try:
                self.main.db.set_host_ip(hostIP)
                break
            except redis.exceptions.DataError:
                self.main.print(
                    'Not Connected to the internet. Reconnecting in 10s.'
                )
                time.sleep(10)
                hostIP = self.get_host_ip()
        return hostIP

    def add_metadata(self):
        """
        Create a metadata dir output/metadata/ that has a copy of slips.conf, whitelist.conf, current commit and date
        """
        if not self.enable_metadata:
            return

        metadata_dir = os.path.join(self.main.args.output, 'metadata')
        try:
            os.mkdir(metadata_dir)
        except FileExistsError:
            # if the file exists it will be overwritten
            pass

        # Add a copy of slips.conf
        config_file = self.main.args.config or 'config/slips.conf'
        shutil.copy(config_file, metadata_dir)

        # Add a copy of whitelist.conf
        whitelist = self.main.conf.whitelist_path()
        shutil.copy(whitelist, metadata_dir)

        now = datetime.now()
        now = utils.convert_format(now, utils.alerts_format)

        self.info_path = os.path.join(metadata_dir, 'info.txt')
        with open(self.info_path, 'w') as f:
            f.write(f'Slips version: {self.main.version}\n'
                    f'File: {self.main.input_information}\n'
                    f'Branch: {self.main.db.get_branch()}\n'
                    f'Commit: {self.main.db.get_commit()}\n'
                    f'Slips start date: {now}\n'
                    )

        print(f'[Main] Metadata added to {metadata_dir}')
        return self.info_path

    def set_analysis_end_date(self):
        """
        Add the analysis end date to the metadata file and
        the db for the web interface to display
        """
        self.enable_metadata = self.main.conf.enable_metadata()
        end_date = utils.convert_format(datetime.now(), utils.alerts_format)
        self.main.db.set_input_metadata({'analysis_end': end_date})
        if self.enable_metadata:
            # add slips end date in the metadata dir
            try:
                with open(self.info_path, 'a') as f:
                    f.write(f'Slips end date: {end_date}\n')
            except (NameError, AttributeError):
                pass
        return end_date

    def set_input_metadata(self):
        """
        save info about name, size, analysis start date in the db
        """
        now = utils.convert_format(datetime.now(), utils.alerts_format)
        to_ignore = self.main.conf.get_disabled_modules(self.main.input_type)
        info = {
            'slips_version': self.main.version,
            'name': self.main.input_information,
            'analysis_start': now,
            'disabled_modules': json.dumps(to_ignore),
            'output_dir': self.main.args.output,
            'input_type': self.main.input_type,
            'evidence_detection_threshold': self.main.conf.evidence_detection_threshold(),
        }

        if hasattr(self.main, 'zeek_dir'):
            info.update({
                'zeek_dir': self.main.zeek_dir
            })

        size_in_mb = '-'
        if self.main.args.filepath not in (False, None) and os.path.exists(self.main.args.filepath):
            size = os.stat(self.main.args.filepath).st_size
            size_in_mb = float(size) / (1024 * 1024)
            size_in_mb = format(float(size_in_mb), '.2f')

        info.update({
            'size_in_MB': size_in_mb,
        })
        # analysis end date will be set in shutdown_gracefully
        # file(pcap,netflow, etc.) start date will be set in
        self.main.db.set_input_metadata(info)

    def check_if_port_is_in_use(self, port):
        if port == 6379:
            # even if it's already in use, slips should override it
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("localhost", port))
            return False
        except OSError as e:
            print(f"[Main] Port {port} is already in use by another process."
                  f" Choose another port using -P <portnumber> \n"
                  f"Or kill your open redis ports using: ./slips.py -k ")
            self.main.terminate_slips()

    def update_slips_running_stats(self):
        """
        updates the number of processed ips, slips internal time, and modified tws so far in the db
        """
        slips_internal_time = float(self.main.db.getSlipsInternalTime()) + 1

        # Get the amount of modified profiles since we last checked
        modified_profiles, last_modified_tw_time = self.main.db.getModifiedProfilesSince(
            slips_internal_time
        )
        modified_ips_in_the_last_tw = len(modified_profiles)
        self.main.db.set_input_metadata({'modified_ips_in_the_last_tw': modified_ips_in_the_last_tw})
        # Get the time of last modified timewindow and set it as a new
        if last_modified_tw_time != 0:
            self.main.db.set_slips_internal_time(
                last_modified_tw_time
            )
        return modified_ips_in_the_last_tw, modified_profiles

    def enable_metadata(self):
        self.enable_metadata = self.main.conf.enable_metadata()

        if self.enable_metadata:
            self.info_path = self.add_metadata()