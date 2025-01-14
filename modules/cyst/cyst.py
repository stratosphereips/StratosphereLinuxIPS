# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.abstracts.module import IModule
import socket
import json
import os
import errno
import sys
from pprint import pp
import contextlib

from slips_files.core.structures.alerts import (
    Alert,
    dict_to_alert,
)


class Module(IModule):
    # Name: short name of the module. Do not use spaces
    name = "CYST"
    description = "Communicates with CYST simulation framework"
    authors = ["Alya Gomaa"]

    def init(self):
        self.port = None
        self.c1 = self.db.subscribe("new_alert")
        self.channels = {"new_alert": self.c1}
        self.cyst_UDS = "/run/slips.sock"
        self.conn_closed = False

    def initialize_unix_socket(self):
        """
        If the socket is there, slips will connect to itm if not, slips will create it
        """
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if os.path.exists(self.cyst_UDS):
            os.unlink(self.cyst_UDS)
        # Create a UDS socket
        sock.bind(self.cyst_UDS)
        failure = sock.listen(2)
        if not failure:
            self.print("Slips is now listening. waiting for CYST to connect.")
        else:
            error = f"Failed to initialize sips socket. Error code: {failure}"
            return False, error

        connection, client_address = sock.accept()
        return sock, connection

    def get_flow(self):
        """
        reads 1 flow from the CYST socket and converts it to dict
        returns a dict if the flow was received or False if there was an error
        """
        try:
            self.cyst_conn.settimeout(5)
            # get the number of bytes cyst is going to send, it is exactly 5 bytes
            flow_len = self.cyst_conn.recv(5).decode()
            try:
                flow_len: int = int(flow_len)
            except ValueError:
                self.print(
                    f"Received invalid flow length from cyst: {flow_len}"
                )
                self.conn_closed = True
                return False

            flow: bytes = self.cyst_conn.recv(flow_len).decode()

        except socket.timeout:
            self.print("timeout but still listening for flows.")
            return False
        except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                # cyst didn't send anything
                return False
            else:
                self.print(f"An error occurred: {e}")
                self.conn_closed = True
                return False

        # When a recv returns 0 bytes, it means the other side has closed
        # (or is in the process of closing) the connection.
        if not flow:
            self.print("CYST closed the connection.")
            self.conn_closed = True
            return False
        try:
            flow = json.loads(flow)
            return flow
        except json.decoder.JSONDecodeError:
            self.print(f"Invalid json line received from CYST. {flow}", 0, 1)
            return False

    def send_length(self, msg: bytes):
        """
        takes care of sending the msg length with padding before the actual msg
        """
        # self.print("Sending evidence length to cyst.")

        # send the length of the msg to cyst first
        msg_len = str(len(msg)).encode()
        # pad the length, so it takes exactly 5 bytes, this is what cyst expects
        msg_len += (5 - len(msg_len)) * b" "

        self.cyst_conn.sendall(msg_len)

    def send_alert(self, alert_ID: str, ip_to_block: str):
        """
        Sends the alert ID and the IDs of the evidence causing this alert to cyst
        """
        alert_to_send = {
            "slips_msg_type": "alert",
            "alert_ID": alert_ID,
            "ip_to_block": ip_to_block,
        }

        self.print("Sending alert to CYST: ")
        self.print(pp(alert_to_send))

        alert_to_send: bytes = json.dumps(alert_to_send).encode()
        self.send_length(alert_to_send)

        try:
            self.cyst_conn.sendall(alert_to_send)
        except BrokenPipeError:
            self.conn_closed = True
            return

    def close_connection(self):
        print("Closing connection", 0, 1)
        if hasattr(self, "sock"):
            self.sock.close()
        # delete the socket
        os.unlink(self.cyst_UDS)

    def is_cyst_enabled(self):
        # are the flows being read from the default inputprocess or from a custom module? like this one
        custom_flows = "-im" in sys.argv or "--input-module" in sys.argv
        if not custom_flows:
            return False

        with contextlib.suppress(ValueError):
            # are we reading custom flows from this module?
            if self.name in sys.argv[sys.argv.index("--input-module") + 1]:
                return True

            if self.name in sys.argv[sys.argv.index("--im") + 1]:
                return True

        return True

    def shutdown_gracefully(self):
        self.close_connection()
        # if slips is done, slips shouldn't expect more flows or send evidence
        # it should terminate
        self.db.publish_stop()
        return

    def pre_main(self):
        # are the flows being read from the default inputprocess or from a custom module? like this one
        if not self.db.is_cyst_enabled():
            return 1
        self.db.set_cyst_enabled()
        # connect to cyst
        self.print("Initializing socket", 0, 1)
        self.sock, self.cyst_conn = self.initialize_unix_socket()
        if not self.sock:
            return 1
        self.print("Done initializing socket", 0, 1)

    def main(self):
        """
        returning non-zero will cause shutdown_gracefully to be called
        """
        # check for connection before sending
        if self.conn_closed:
            self.print("Connection closed by CYST.", 0, 1)
            return 1

        # RECEIVE FLOWS FROM CYST
        if flow := self.get_flow():
            # send the flow to inputprocess so slips can process it normally
            to_send = {
                "flow": flow,
                "module": self.name,  # to know where this flow is coming from aka what's the input module
            }

            self.print("Received flow from cyst")
            self.print(pp(to_send))

            self.db.publish("new_module_flow", json.dumps(to_send))

        # check for connection before receiving
        if self.conn_closed:
            self.print("Connection closed by CYST.", 0, 1)
            return 1

        if msg := self.get_msg("new_alert"):
            alert: dict = json.loads(msg["data"])
            alert: Alert = dict_to_alert(alert)
            self.print(
                "Cyst module received a new blocking request . "
                "sending to CYST ... "
            )
            self.send_alert(alert.id, alert.profile.ip)
