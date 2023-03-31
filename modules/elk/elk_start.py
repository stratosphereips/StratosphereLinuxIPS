import signal
import subprocess
import time
import os
import psutil

class ELKStart:
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

    def ask_elk():
        """Asks the user how to start the ELK stack     services"""

        print("\033[1m\033[37mELK Stack uses atleast 8GB of RAM, so please  ensure that you have atleast 8GB of free RAM before starting the services.\033[0m")

        if not(ELKStart.elk_ram_check()):
            return
        # Ask the user how to start the services
        print("How do you want to start elk services?")
        print("1. Temporarily")
        print("2. Permanently")
        print("3. Permanently and Automatically on boot")
        print("4. Do not start elk services")
        choice = input("Enter your choice: ")

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
            ELKStart.temp_start_elk()
        elif choice == '2':
            ELKStart.permanent_start_elk()
        elif choice == '3':
            ELKStart.permanent_start_elk()
            ELKStart.auto_startup_elk()
        elif choice == '4':
            print("Skipping elk services...")
        else:
            print("\033[1m\033[37mInvalid Choice, Skipping elk services\033[0m")

class ELK_config:
    def update_alert_conf():
        """Updates the alert.conf file with the curr path"""
        curr_dir = os.getcwd()
        alert_conf = curr_dir + '/modules/elk/alert.conf'
        with open(alert_conf, 'r') as f:
            lines = f.readlines()
            content = f.read()
            new_content = content.replace("dir/StratosphereLinuxIPS", f"{curr_dir}/output/**/alerts.log")
            with open(alert_conf, 'w') as f:
                f.write(new_content)

    def elk_alert_config():
        """Copies the alerts.log file"""

        # Update the alert.conf file
        ELK_config.update_alert_conf()

        print("Configuring elk services...")
        curr_dir = os.getcwd()
        alert_conf = curr_dir + '/modules/elk/alert.conf'
        subprocess.run(['sudo', 'cp', alert_conf, '/etc/logstash/conf.d/alert.conf'])

        # Ask the user how to start the services
        ELKStart.ask_elk()

    def elk_service_config():
        curr_dir = os.getcwd()
        elk_conf_script = curr_dir + '/modules/elk/configure.sh'
        print("Configuring alerts.log file...")
        subprocess.run(['sudo','bash', elk_conf_script])

        ELK_config.elk_alert_config()

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
        ELK_config.elk_service_config()

if __name__ == '__main__':
    ELK_config.elk_service_check()
