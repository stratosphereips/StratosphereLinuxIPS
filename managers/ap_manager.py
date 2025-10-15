import subprocess


class APManager:
    """
    Gets AP info when slips is running as an AP in the RPI
    https://stratospherelinuxips.readthedocs.io/en/develop/immune/installing_slips_in_the_rpi.html#protect-your-local-network-with-slips-on-the-rpi
    """

    def __init__(self, main, input_information: str):
        self.main = main
        # can be the filepath given to slips, interface or
        #     comma separated access point interfaces like wlan0,eth0
        if self.main.args.access_point:
            self.ap_interfaces = input_information

    def store_ap_interfaces(self, input_information):
        """
        stores the interfaces given with -ap to slips in the db
        """
        self.wifi_interface, self.eth_interface = input_information.split(",")
        interfaces = {
            "wifi_interface": self.wifi_interface,
            "ethernet_interface": self.eth_interface,
        }
        self.main.db.set_ap_info(interfaces)

    def is_ap_running(self):
        """returns true if a running AP is detected"""
        command = ["iw", "dev"]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=True
            )
            lines = result.stdout.splitlines()
            for line in lines:
                if "type AP" in line:
                    return True
            return False
        except subprocess.CalledProcessError:
            return False
        except FileNotFoundError:
            return False
