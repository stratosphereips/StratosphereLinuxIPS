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
        #todo handle multiple flows received at once i.e. split by \n
        try:
            self.cyst_conn.settimeout(5)
            flow: bytes = self.cyst_conn.recv(10000).decode()
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



    def send_evidence(self, evidence: str):
        """
        :param evidence: json serialized dict
        """
        self.print(f"Sending evidence back to CYST.", 0, 1)
        # todo test how long will it take slips to respond to cyst
        # todo explicitly sending message length before the message itself.
        try:
            self.cyst_conn.sendall(evidence.encode())
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
                    # todo slips doesn't stop when connection is closed by cyst.
                    #  it keeps running forever
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

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True


