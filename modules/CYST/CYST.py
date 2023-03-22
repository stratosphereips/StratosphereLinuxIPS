from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
import sys
import traceback
import socket
import json
import os
import errno

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'CYST'
    description = 'Communicates with CYST simulation framework'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        self.port = None
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        self.c1 = __database__.subscribe('new_json_evidence')
        self.c2 = __database__.subscribe('new_alert')
        self.cyst_UDS = '/tmp/slips.sock'
        self.conn_closed = False



    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f'{levels}|{self.name}|{text}')


    def initialize_unix_socket(self):
        """
        Slips will be the server, so it has to run before cyst to create the socket
        """
        unix_socket = '/tmp/slips.sock'

        # Make sure the socket does not already exist
        if os.path.exists(unix_socket):
            os.unlink(unix_socket)

        # Create a UDS socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(unix_socket)


        failure = sock.listen(2)
        if not failure:
            self.print(f"Slips is now listening. waiting for CYST to connect.")
        else:
            self.print(f" failed to initialize sips socket. Error code: {failure}")

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
                self.print(f"Received invalid flow length from cyst: {flow_len}")
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
            self.print(f"CYST closed the connection.")
            return False
        try:
            flow = json.loads(flow)
            return flow
        except json.decoder.JSONDecodeError:
            self.print(f'Invalid json line received from CYST. {flow}', 0, 1)
            return False

    def send_length(self, msg: bytes):
        """
        takes care of sending the msg length with padding before the actual msg
        """
        # self.print("Sending evidence length to cyst.")

        # send the length of the msg to cyst first
        msg_len = str(len(msg)).encode()
        # pad the length so it takes exactly 5 bytes, this is what cyst expects
        msg_len += (5- len(msg_len) ) *b' '

        self.cyst_conn.sendall(msg_len)


    def send_evidence(self, evidence: str):
        """
        :param evidence: json serialized dict
        """
        self.print(f"Sending evidence back to CYST.", 0, 1)
        # add the slips_msg_type
        evidence: dict = json.loads(evidence)


        # this field helps cyst see what slips is sending, an evidence or a blocking request
        evidence.update(
            {'slips_msg_type': 'evidence'}
        )
        evidence = json.dumps(evidence)

        # slips takes around 8s from the second it receives the flow to respond to cyst
        evidence: bytes = evidence.encode()
        self.send_length(evidence)
        try:
            self.cyst_conn.sendall(evidence)
        except BrokenPipeError:
            self.conn_closed = True
            return

    def send_blocking_request(self, ip):
        """
        for now when slips generates a blocking request, it blocks everything from and to this srcip
        -p doesn't have to be present for slips to send blocking requests to cyst
        the blocking module won't start and it's ok. the goal is to have cyst take care of the blocking not slips

        """
        #todo handle this slips_msg_type in cyst
        blocking_request = {
            'slips_msg_type': 'blocking',
            'to_block_type': 'ip', # can be anything in the future i.e domain url etc
            'value': ip
        }
        blocking_request: bytes = json.dumps(blocking_request).encode()
        self.send_length(blocking_request)

        try:
            self.cyst_conn.sendall(blocking_request)
        except BrokenPipeError:
            self.conn_closed = True
            return

    def send_alert(self, alert_ID: str, evidence: list):
        """
        Sends the alert ID and the IDs of the evidence causing this alert to cyst
        """
        alert_to_send = {
            'slips_msg_type': 'alert',
            'alert_ID': alert_ID,
            'evidence': evidence
        }
        alert_to_send: bytes = json.dumps(alert_to_send).encode()
        self.send_length(alert_to_send)

        try:
            self.cyst_conn.sendall(alert_to_send)
        except BrokenPipeError:
            self.conn_closed = True
            return



    def close_connection(self):
        self.sock.close()

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)
        # if slips is done, slips shouldn't expect more flows or send evidence
        # it should terminate
        __database__.publish('finished_modules', 'stop_slips')
        return

    def run(self):
        if not ('-C' in sys.argv or '--CYST' in sys.argv):
            return

        # connect to cyst
        self.sock, self.cyst_conn = self.initialize_unix_socket()

        while True:
            try:
                #check for connection before sending
                if self.conn_closed :
                    self.print( 'Connection closed by CYST.', 0, 1)
                    self.shutdown_gracefully()
                    return True

                # RECEIVE FLOWS FROM CYST
                if flow := self.get_flow():
                    # send the flow to inputprocess so slips can process it normally
                    __database__.publish('new_cyst_flow', json.dumps(flow))

                #check for connection before receiving
                if self.conn_closed:
                    self.print( 'Connection closed by CYST.', 0, 1)
                    self.shutdown_gracefully()
                    return True

                # SEND EVIDENCE TO CYST
                msg = __database__.get_message(self.c1)
                if (msg and msg['data'] == 'stop_process'):
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(msg, 'new_json_evidence'):
                    print(f"@@@@@@@@@@@@@@@@@@ cyst module received a new evidence . sending ... ")
                    evidence: str = msg['data']
                    self.send_evidence(evidence)

                msg = __database__.get_message(self.c2)
                if (msg and msg['data'] == 'stop_process'):
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(msg, 'new_alert'):
                    print(f"@@@@@@@@@@@@@@@@@@ cyst module received a new blocking request . sending ... ")
                    alert_info: dict = json.loads(msg['data'])
                    profileid = alert_info['profileid']
                    twid = alert_info['twid']
                    # alert_ID is {profileid}_{twid}_{ID}
                    alert_ID = alert_info['alert_ID']
                    evidence: list = __database__.get_evidence_causing_alert(profileid, twid, alert_ID)
                    if evidence:
                        self.send_alert(alert_ID, evidence)



            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True


