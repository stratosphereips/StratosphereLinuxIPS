# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables
# 5. The file name of the python module (template.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to ignore the module
# 7. The name of the class MUST be 'Module', do not change it.


# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
import sys
import traceback

# Your imports
import signal
import subprocess
import time
import os
import json
import psutil

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'elk'
    description = 'Setup Elk for visualisation(kibana), as well as to recieve messages from different machines'
    authors = ['Prakhar Gupta']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        # To which channels do you want to subscribe? When a message
        # arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('new_service')
        # Your variables
        self.elasticsearch_host = 'localhost'
        self.elasticsearch_port = '9200'
        self.kibana_port = '5601'

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

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)

    class ELKStart:
        def elk_restart(services):
            """Restarts the ELK stack services"""
            print("Restarting services...")
            for service in services:
                subprocess.run(['sudo', 'systemctl', 'restart', service])
                time.sleep(2)

        def temp_start_elk():
            """Starts the ELK stack services temporarily"""

            def stop_services(signum, frame):
                """Stops the ELK stack services"""
                print("\nStopping services...")
                subprocess.run(['sudo', 'systemctl', 'stop', 'kibana'])
                time.sleep(2)
                subprocess.run(['sudo', 'systemctl', 'stop', 'elasticsearch'])
                time.sleep(2)
                subprocess.run(['sudo', 'systemctl', 'stop', 'logstash'])
                exit()

            # Register the signal handler
            signal.signal(signal.SIGINT, stop_services)

            # Start the services
            print("Starting services...")
            subprocess.run(['sudo', 'systemctl', 'start', 'logstash'])
            time.sleep(5)
            subprocess.run(['sudo', 'systemctl', 'start', 'elasticsearch'])
            time.sleep(5)
            subprocess.run(['sudo', 'systemctl', 'start', 'kibana'])

            # Wait for a SIGINT signal (Ctrl+C)
            print("Press Ctrl+C to stop the services...")
            signal.pause()

        def permanent_start_elk():
            """Starts the ELK stack services permanently"""

            # Start the services
            print("Starting services...")
            subprocess.run(['sudo', 'systemctl', 'start', 'logstash'])
            subprocess.run(['sudo', 'systemctl', 'start', 'elasticsearch'])
            subprocess.run(['sudo', 'systemctl', 'start', 'kibana'])

        def auto_startup_elk():
            """Starts the ELK stack services automatically on   boot"""

            # Enable the services
            print("Enabling services for auto_start...")
            subprocess.run(['sudo', 'systemctl', 'enable', 'logstash'])
            subprocess.run(['sudo', 'systemctl', 'enable', 'elasticsearch'])
            subprocess.run(['sudo', 'systemctl', 'enable', 'kibana'])

        def elk_ram_check():
            """Checks if system has atleast 8GB of free RAM for ELK stack"""
            mem = psutil.virtual_memory().available / (1024 ** 3)
            if mem < 6:
                print("\033[1m\033[37mIt seems that Ram is not sufficient please freeup the ram...\033[0m")
                return False
            else:
                return True
        def elk_config():
            curr=os.getcwd()
            CONFIG=curr + '/config/elk_config.json'
            if os.path.exists(CONFIG):
                with open(CONFIG) as f:
                    data = json.load(f)
            else:
                data = {}
                #ADD comment to the config file
                data['comment'] = 'Choose number from 1,2,3,4 to start elk services, where 1 stands for temporary, 2 for permanent, 3 for permanent and auto start on boot, 4 for not to start elk services'
                data['other_configuration']='You can check other configurations inside /modules/elk'
                data['choice'] = 4
                with open(CONFIG, 'w') as f:
                    json.dump(data, f, indent=4)

            return data['choice']
                

        def ask_elk():
            """Asks the user how to start the ELK stack     services"""

            print("\033[1m\033[37mELK Stack uses atleast 8GB of RAM, so please  ensure that you have atleast 8GB of free RAM before starting the services.\033[0m")

            if not(Module.ELKStart().elk_ram_check()):
                return

            choice = Module.ELKStart().elk_config()

            if not(choice =='4'):
                print("#############################################")
                print("Please follow below instructions to be able to show results on   Kibana:")
                print("")
                print("1. Open your web browser and type 'localhost:5601' in the address bar to go to Kibana home page.")
                print("2. Click on 3 bars on top left side of the page")
                print("3. Inside Management Click on 'Stack Management' in the left-hand navigation menu.")
                print("4. In the left hand navigation menu, Click on 'Index Patterns' in 'Kibana' section and then click the 'Create index pattern' button.")
                print("5. Click on create index pattern hyperlink. (not neccessary if this option is available)")
                print("6. Enter 'myindex-*' as the index pattern name in 'Name' field.")
                print("7. Choose '@timestamp' as the Time Filter field name and click   'Create index pattern'.")
                print()
                print("Now you can see the visualizations on Kibana under 'Discover' section in 'Analytics' subsection when clicked on 3 bars on top left side of the page.")
                print("Don't forget to change the timeperiod on top right , to get the results you are searching for.")
                print()
                print()
                print("Logstach is also listening on port 5000, for recieving logs from other machines. You can send logs to it by using the following command as examples:")
                print("cat ./alerts.log | nc localhost 5000")
                print()
                print("Please ensure to configure configure.sh in modules/elk/ to use appropiate network adapter ip.")
                print("#################################################")




            # Start the services
            if choice == '1':
                Module.ELKStart().temp_start_elk()
            elif choice == '2':
                Module.ELKStart().permanent_start_elk()
            elif choice == '3':
                Module.ELKStart().permanent_start_elk()
                Module.ELKStart().auto_startup_elk()
            elif choice == '4':
                print("Skipping elk services...")
            else:
                print("\033[1m\033[37mInvalid Choice, Skipping elk services\033[0m")

    class ELK_config:
        def elk_alert_config():
            """Copies the alerts.log file"""

            # Update the alert.conf file
            Module.ELK_config().update_alert_conf()

            print("Configuring elk services...")
            curr_dir = os.getcwd()
            alert_conf = curr_dir + '/modules/elk/alert.conf'
            subprocess.run(['sudo', 'cp', alert_conf, '/etc/logstash/conf.d/alert.conf'])

            # Ask the user how to start the services
            Module.ELKStart().ask_elk()

        def elk_service_config():
            curr_dir = os.getcwd()
            elk_conf_script = curr_dir + '/modules/elk/configure.sh'
            print("Configuring alerts.log file...")
            subprocess.run(['sudo','bash', elk_conf_script])

            Module.ELK_config().elk_alert_config()

        def elk_service_check():
            """Configures the ELK stack services"""
            #Check if elk services are installed
            services = ['logstash', 'elasticsearch', 'kibana']
            for service in services:
                result = subprocess.run(['systemctl', 'status', service], capture_output=True, text=True)
                if "could not be found" in result.stderr:
                    print(f"{service} is not installed.")
                    return
                else:
                    print(f"->{service} is installed.")
                    

            print()
            Module.ELK_config().elk_service_config()


    def run(self):
        # Subscribe to the new_evidence channel and listen for incoming messages
        Module.ELK_config().elk_service_check()
        self.c1 = __database__.subscribe('new_evidence')
        self.print('Subscribed to new_evidence channel. Listening for incoming messages...', 1, 0)

        while True:
            try:
                # Get message from Redis
                message = __database__.get_message(self.c1)

                if message and message['data'] == 'stop_process':
                    # If the message is to stop the process, then stop gracefully
                    self.shutdown_gracefully()
                    return True

                if message and message['channel'] == 'new_evidence':
                    # Get the evidence from Redis
                    evidence = message['data']
                    self.print('Received new evidence: {}'.format(evidence), 1, 0)

                    ###The module is intended to send new evidences when the output is completely generated
                        # # Send the evidence to Elasticsearch
                        # is_sent, response = Module.ELKStart().elk_restart(['logstash'])
                        # if is_sent:
                        #     self.print('Successfully sent evidence to Elasticsearch', 1, 0)
                        # else:
                        #     self.print('Error sending evidence to Elasticsearch. Response: {}'.format(response), 0, 1)

            except KeyboardInterrupt:
                # If keyboard interrupt, then stop gracefully
                self.shutdown_gracefully()
                return True
            except Exception as e:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print('Problem on the run() line {}. Details: {}'.format(exception_line, e), 0, 1)
                return True



        



