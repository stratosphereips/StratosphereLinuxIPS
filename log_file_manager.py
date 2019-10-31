import configparser

"""
By loading "__log_file_manager__" variable you can read, set and add new data to slips's log file from every 
class.
The reason to have a log file is to store information about last runs of slips. For example last updating of modules, etc.
"""


class LogFileManager:

    def __init__(self):
        self.slips_log_file = 'slips_log.conf'
        slips_log = configparser.ConfigParser()
        founded = self.__read_log_file(slips_log)
        if not founded:
            # Try to create new slips_log.conf file.
            self.__create_logfile()

    def __create_logfile(self):
        slips_log = configparser.ConfigParser()
        with open(self.slips_log_file, 'w') as configfile:
            configfile.writelines('# GENERATED FILE BY SLIPS. DO NOT CHANGE THE CONTENT.\n\n')
            slips_log.write(configfile)

    def __read_log_file(self, config) -> bool:
        try:
            with open(self.slips_log_file) as log:
                config.read_file(log)
            founded = True
        except (IOError, TypeError):
            # No conf file provided.
            founded = False
        return founded

    def __update_log_file(self, config_update):
        try:
            with open(self.slips_log_file, 'w') as f:
                f.writelines('# GENERATED FILE BY SLIPS. DO NOT CHANGE THE CONTENT.\n\n')
                config_update.write(f)
        except FileNotFoundError:
            self.__create_logfile()

    def set_data(self, section_name: str, variable_name: str, value):
        """
        Set data in our slips_log.conf file. If the section does not exist, create it.
        """
        config_update = configparser.RawConfigParser()
        self.__read_log_file(config_update)
        try:
            config_update.set(section_name, variable_name, str(value))
        except configparser.NoSectionError:
            config_update.add_section(section_name)
            config_update.set(section_name, variable_name, str(value))
        self.__update_log_file(config_update)

    def read_data(self, section: str, name: str) -> str:
        """ Read the configuration file for what we need """
        # Get the time of log report.
        slips_log = configparser.ConfigParser()
        self.__read_log_file(slips_log)
        try:
             conf_variable = slips_log.get(section, name)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            conf_variable = None
        except FileNotFoundError:
            self.__create_logfile()
            conf_variable = None
        return conf_variable

__log_file_manager__ = LogFileManager()
