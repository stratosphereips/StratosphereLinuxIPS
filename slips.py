#!/usr/bin/env python3
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz

import configparser
import signal
import sys
import redis
import os
import time
import shutil
from datetime import datetime
import socket
import warnings
from modules.update_manager.update_file_manager import UpdateFileManager
import json
import pkgutil
import inspect
import modules
import importlib
from slips_files.common.abstracts import Module
from slips_files.common.argparse import ArgumentParser
import errno
import subprocess
import re
from collections import OrderedDict
from distutils.dir_util import copy_tree
import asyncio

version = '0.8.4'

# Ignore warnings on CPU from tensorflow
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
# Ignore warnings in general
warnings.filterwarnings('ignore')


def read_configuration(config, section, name):
    """ Read the configuration file for what slips.py needs. Other processes also access the configuration """
    try:
        return config.get(section, name)
    except (configparser.NoOptionError, configparser.NoSectionError, NameError):
        # There is a conf, but there is no option, or no section or no configuration file specified
        return False


def recognize_host_ip():
    """
    Recognize the IP address of the machine
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ipaddr_check = s.getsockname()[0]
        s.close()
    except (socket.error):
        # not connected to the internet
        return None
    return ipaddr_check


def create_folder_for_logs():
    """
    Create a folder for logs if logs are enabled
    """
    logs_folder = datetime.now().strftime('%Y-%m-%d--%H-%M-%S')
    try:
        os.makedirs(logs_folder)
    except OSError as e:
        if e.errno != errno.EEXIST:
            # doesn't exist and can't create
            return False
    return logs_folder


async def update_ti_files(outputqueue, config):
    """
    Update malicious files and store them in database before slips start
    """
    update_manager = UpdateFileManager(outputqueue, config)
    # create_task is used to run update() function concurrently instead of serially
    update_finished = asyncio.create_task(update_manager.update())
    # wait for UpdateFileManager to finish before starting all the modules
    await update_finished


def check_redis_database(redis_host='localhost', redis_port=6379) -> bool:
    """
    Check if we have redis-server running
    """
    try:
        r = redis.StrictRedis(host=redis_host, port=redis_port, db=0, charset="utf-8",
                                   decode_responses=True)
        r.ping()
    except Exception as ex:
        print('[DB] Error: Is redis database running? You can run it as: "redis-server --daemonize yes"')
        return False
    return True


def clear_redis_cache_database(redis_host='localhost', redis_port=6379) -> bool:
    """
    Clear cache database
    """
    rcache = redis.StrictRedis(host=redis_host, port=redis_port, db=1, charset="utf-8",
                               decode_responses=True)
    rcache.flushdb()
    return True


def check_zeek_or_bro():
    """
    Check if we have zeek or bro
    """
    if shutil.which('zeek'):
        return 'zeek'
    elif shutil.which('bro'):
        return 'bro'
    return False


def terminate_slips():
    """
    Do all necessary stuff to stop process any clear any files.
    """
    sys.exit(-1)


def load_modules(to_ignore):
    """
    Import modules and loads the modules from the 'modules' folder. Is very relative to the starting position of slips
    """

    plugins = {}
    failed_to_load_modules = 0
    # Walk recursively through all modules and packages found on the . folder.
    # __path__ is the current path of this python program
    for loader, module_name, ispkg in pkgutil.walk_packages(modules.__path__, modules.__name__ + '.'):
        if any(module_name.__contains__(mod) for mod in to_ignore):
            continue
        # If current item is a package, skip.
        if ispkg:
            continue
        # to avoid loading everything in the dir,
        # only load modules that have the same name as the dir name
        dir_name = module_name.split('.')[1]
        file_name = module_name.split('.')[2]
        if dir_name != file_name:
            continue

        # Try to import the module, otherwise skip.
        try:
            # "level specifies whether to use absolute or relative imports. The default is -1 which
            # indicates both absolute and relative imports will be attempted. 0 means only perform 
            # absolute imports. Positive values for level indicate the number of parent 
            # directories to search relative to the directory of the module calling __import__()."
            module = importlib.import_module(module_name)
        except ImportError as e:
            print("Something wrong happened while importing the module {0}: {1}".format(module_name, e))
            continue

        # Walk through all members of currently imported modules.
        for member_name, member_object in inspect.getmembers(module):
            # Check if current member is a class.
            if inspect.isclass(member_object):
                if issubclass(member_object, Module) and member_object is not Module:
                    plugins[member_object.name] = dict(obj=member_object, description=member_object.description)

    # Change the order of the blocking module(load it first) so it can receive msgs sent from other modules
    if 'Blocking' in plugins:
        plugins = OrderedDict(plugins)
        # last=False to move to the beginning of the dict
        plugins.move_to_end('Blocking', last=False)

    return plugins, failed_to_load_modules


def get_cwd():
    # Can't use os.getcwd() because slips directory name won't always be Slips plus this way requires less parsing
    for arg in sys.argv:
        if 'slips.py' in arg:
            # get the path preceeding slips.py
            # (may be ../ or  ../../ or '' if slips.py is in the cwd),
            # this path is where slips.conf will be
            cwd = arg[:arg.index('slips.py')]
            return cwd


def prepare_zeek_scripts():
    """
    Adds local network to slips-conf.zeek
    """

    # get home network from slips.conf
    try:
        home_network = config.get('parameters', 'home_network')
    except (configparser.NoOptionError, configparser.NoSectionError, NameError):
        # There is a conf, but there is no option, or no section or no configuration file specified
        from slips_files.common.slips_utils import utils
        home_network = utils.home_network_ranges

    zeek_scripts_dir = os.getcwd() + '/zeek-scripts'
    # add local sites if not there
    is_local_nets_defined = False
    with open(zeek_scripts_dir + '/slips-conf.zeek', 'r') as slips_conf:
        if 'local_nets' in slips_conf.read():
            is_local_nets_defined = True
        
    if not is_local_nets_defined:
        with open(zeek_scripts_dir + '/slips-conf.zeek', 'a') as slips_conf:
            # update home network
            slips_conf.write('\nredef Site::local_nets += { '+home_network+' };\n')

    # # load all scripts in zeek-script dir
    # with open(zeek_scripts_dir + '/__load__.zeek','r') as f:
    #     loaded_scripts = f.read()
    # with open(zeek_scripts_dir + '/__load__.zeek','a') as f:
    #     for file_name in os.listdir(zeek_scripts_dir):
    #         # ignore the load file
    #         if file_name == '__load__.zeek':
    #             continue
    #         if file_name not in loaded_scripts:
    #             # found a file in the dir that isn't in __load__.zeek, add it
    #             f.write(f'\n@load ./{file_name}')


def add_metadata():
    """
    Create a metadata dir output/metadata/ that has a copy of slips.conf, whitelist.conf, current commit and date
    """
    metadata_dir = os.path.join(args.output, 'metadata')
    try:
        os.mkdir(metadata_dir)
    except FileExistsError:
        # if the file exists it will be overwritten
        pass

    # Add a copy of slips.conf
    config_file = args.config or 'slips.conf'
    shutil.copy(config_file, metadata_dir)
    # Add a copy of whitelist.conf
    whitelist = config.get('parameters', 'whitelist_path')
    shutil.copy(whitelist, metadata_dir)

    branch_info = utils.get_branch_info()
    commit, branch = None, None
    if branch_info != False:
        # it's false when we're in docker because there's no .git/ there
        commit, branch = branch_info[0], branch_info[1]
    now = datetime.now()

    info_path = os.path.join(metadata_dir, 'info.txt')
    with open(info_path, 'w') as f:
        f.write(f'Slips version: {version}\n')
        f.write(f'Branch: {branch}\n')
        f.write(f'Commit: {commit}\n')
        f.write(f'Date: {now}\n')

    print(f'[Main] Metadata added to {metadata_dir}')


def shutdown_gracefully(input_information):
    """ Wait for all modules to confirm that they're done processing and then shutdown
    :param input_information: the interface/pcap/nfdump/binetflow used. we need it to save the db
    """

    try:
        print('\n'+'-'*27)
        print('Stopping Slips')
        # Stop the modules that are subscribed to channels
        __database__.publish_stop()

        finished_modules = []
        # get dict of PIDs spawned by slips
        PIDs = __database__.get_PIDs()
        slips_processes = len(list(PIDs.keys()))

        # Send manual stops to the processes not using channels
        for process in ('OutputProcess', 'ProfilerProcess', 'EvidenceProcess', 'InputProcess', 'logsProcess'):
            try:
                os.kill(int(PIDs[process]), signal.SIGINT)
            except KeyError:
                # process hasn't started (for example logsProcess) so we can't send sigint,
                continue

        # only print that modules are still running once
        warning_printed = False

        # timeout variable so we don't loop forever
        # give slips enough time to close all modules - make sure all modules aren't considered 'busy' when slips stops
        max_loops = 430
        # loop until all loaded modules are finished
        try:
            while len(finished_modules) < slips_processes and max_loops != 0:
                # print(f"Modules not finished yet {set(loaded_modules) - set(finished_modules)}")
                try:
                    message = c1.get_message(timeout=0.01)
                except NameError:
                    # Sometimes the c1 variable does not exist yet. So just force the shutdown
                    message = {
                        'data': 'dummy_value_not_stopprocess',
                        'channel': 'finished_modules'}

                if message and message['data'] == 'stop_process':
                    continue
                if message and message['channel'] == 'finished_modules' and type(message['data']) == str:
                    # all modules must reply with their names in this channel after
                    # receiving the stop_process msg
                    # to confirm that all processing is done and we can safely exit now
                    module_name = message['data']

                    if module_name not in finished_modules:
                        finished_modules.append(module_name)
                        try:
                            # remove module from the list of opened pids
                            PIDs.pop(module_name)
                        except KeyError:
                            # reaching this block means a module that belongs to slips
                            # is publishing in  finished_modules
                            # but slips doesn't know of it's PID!!
                            print(f"[Main] Module{module_name} just published in "
                                  f"finished_modules channel and Slips doesn't know about it's PID!", 0, 1)
                            # pass insead of continue because
                            # this module is finished and we need to print that it has stopped
                            pass
                        modules_left = len(list(PIDs.keys()))
                        # to vertically align them when printing
                        module_name = module_name + ' '*(20-len(module_name))
                        print(f"\t\033[1;32;40m{module_name}\033[00m \tStopped. \033[1;32;40m{modules_left}\033[00m left.")
                max_loops -= 1
                # after reaching the max_loops and before killing the modules that aren't finished,
                # make sure we're not in the middle of processing
                if len(PIDs) > 0 and max_loops < 2:
                    if not warning_printed:
                        # some modules publish in finished_modules channel before slips.py starts listening,
                        # but they finished gracefully.
                        # remove already stopped modules from PIDs dict
                        for module, pid in PIDs.items():
                            try:
                                # signal 0 is used to check if the pid exists
                                os.kill(int(pid), 0)
                            except ProcessLookupError:
                                # pid doesn't exist because module already stopped
                                finished_modules.append(module)

                        # exclude the module that are already stopped from the pending modules
                        pending_modules = [module for module in list(PIDs.keys()) if module not in finished_modules]
                        if len(pending_modules) > 0:
                            print(f"\n[Main] The following modules are busy working on your data."
                                  f"\n\n{pending_modules}\n\n"
                                  "You can wait for them to finish, or you can press CTRL-C again to force-kill.\n")
                            warning_printed = True
                    # delay killing unstopped modules
                    max_loops += 1
                    continue
        except KeyboardInterrupt:
            # either the user wants to kill the remaining modules (pressed ctrl +c again)
            # or slips was stuck looping for too long that the os sent an automatic sigint to kill slips
            # pass to kill the remaining modules
            pass


        # modules that aren't subscribed to any channel will always be killed and not stopped
        # comes here if the user pressed ctrl+c again
        for unstopped_proc, pid in PIDs.items():
            unstopped_proc = unstopped_proc+' '*(20-len(unstopped_proc))
            try:
                os.kill(int(pid), 9)
                print(f'\t\033[1;32;40m{unstopped_proc}\033[00m \tKilled.')
            except ProcessLookupError:
                print(f'\t\033[1;32;40m{unstopped_proc}\033[00m \tAlready stopped.')


        # save redis database if '-s' is specified
        if args.save:
            # Create a new dir to store backups
            backups_dir = get_cwd() + 'redis_backups' + '/'
            try:
                os.mkdir(backups_dir)
            except FileExistsError:
                pass
            # The name of the interface/pcap/nfdump/binetflow used is in input_information
            # if the input is a zeek dir, remove the / at the end
            if input_information.endswith('/'):
                input_information = input_information[:-1]
            # We need to seperate it from the path
            input_information = os.path.basename(input_information)
            # Remove the extension from the filename
            try:
                input_information = input_information[:input_information.index('.')]
            except ValueError:
                # it's a zeek dir
                pass
            # Give the exact path to save(), this is where the .rdb backup will be
            __database__.save(backups_dir + input_information)
            # info will be lost only if you're out of space and redis can't write to dump.rdb, otherwise you're fine
            print("[Main] [Warning] stop-writes-on-bgsave-error is set to no, information may be lost in the redis backup file.")
            print(f"[Main] Database saved to {backups_dir}{input_information}")

        # if store_a_copy_of_zeek_files is set to yes in slips.conf, copy the whole zeek_files dir to the output dir
        try:
            store_a_copy_of_zeek_files = config.get('parameters', 'store_a_copy_of_zeek_files')
            store_a_copy_of_zeek_files = False if 'no' in store_a_copy_of_zeek_files.lower() else True
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            store_a_copy_of_zeek_files = False

        if store_a_copy_of_zeek_files:
            # this is where the copy will be stores
            zeek_files_path = os.path.join(args.output, 'zeek_files')
            copy_tree("zeek_files", zeek_files_path)
            print(f"[Main] Stored a copy of zeek files to {zeek_files_path}.")

        # if delete_zeek_files is set to yes in slips.conf,
        # delete the whole zeek_files
        try:
            delete_zeek_files = config.get('parameters', 'delete_zeek_files')
            delete_zeek_files = False if 'no' in delete_zeek_files.lower() else True
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            delete_zeek_files = True

        if delete_zeek_files:
            shutil.rmtree('zeek_files')

        os._exit(-1)
        return True
    except KeyboardInterrupt:
        return False


def is_debugger_active() -> bool:
    """Return if the debugger is currently active"""
    gettrace = getattr(sys, 'gettrace', lambda: None)
    return gettrace() is not None

####################
# Main
####################


if __name__ == '__main__':
    try:
        # Before the argparse, we need to set up the default path fr alerts.log
        # and alerts.json. In our case, it is output folder.
        slips_version =  f'Slips. Version {version}'

        from slips_files.common.slips_utils import utils
        branch_info = utils.get_branch_info()
        commit, branch = None, None
        if branch_info != False:
            # it's false when we're in docker because there's no .git/ there
            commit = branch_info[0]
            slips_version += f' ({commit[:8]})'

        print(slips_version)
        print('https://stratosphereips.org')
        print('-'*27)

        alerts_default_path = 'output/'
        # Parse the parameters
        slips_conf_path = get_cwd() + 'slips.conf'
        parser = ArgumentParser(usage="./slips.py -c <configfile> [options] [file ...]",
                                add_help=False)
        parser.add_argument('-c', '--config', metavar='<configfile>',
                            action='store', required=False, default=slips_conf_path,
                            help='path to the Slips config file.')
        parser.add_argument('-v', '--verbose', metavar='<verbositylevel>', action='store', required=False, type=int,
                            help='amount of verbosity. This shows more info about the results.')
        parser.add_argument('-e', '--debug', metavar='<debuglevel>', action='store', required=False, type=int,
                            help='amount of debugging. This shows inner information about the program.')
        parser.add_argument('-f', '--filepath', metavar='<file>', action='store', required=False,
                            help='read a Zeek folder, Argus binetflow, pcapfile or nfdump.')
        parser.add_argument('-i', '--interface', metavar='<interface>', action='store', required=False,
                            help='read packets from an interface.')
        parser.add_argument('-l', '--createlogfiles', action='store_true', required=False,
                            help='create log files with all the traffic info and detections.')
        parser.add_argument('-F', '--pcapfilter', action='store', required=False, type=str,
                            help='packet filter for Zeek. BPF style.')
        parser.add_argument('-G',  '--gui', help='Use the nodejs GUI interface.',
                            required=False, default=False, action='store_true')
        parser.add_argument('-cc', '--clearcache', action='store_true',
                            required=False, help='clear a cache database.')
        parser.add_argument('-p', '--blocking',
                            help='Allow Slips to block malicious IPs. Requires root access. Supported only on Linux.',
                            required=False, default=False, action='store_true')
        parser.add_argument('-cb', '--clearblocking', help='Flush and delete slipsBlocking iptables chain',
                            required=False, default=False, action='store_true')
        parser.add_argument('-o', '--output', action='store', required=False, default=alerts_default_path,
                            help='store alerts.json and alerts.txt in the provided folder.')
        parser.add_argument('-s', '--save', action='store_true', required=False,
                            help='To Save redis db to disk. Requires root access.')
        parser.add_argument('-d', '--db', action='store', required=False,
                            help='To read a redis (rdb) saved file. Requires root access.')
        parser.add_argument("-h", "--help", action="help", help="command line help")

        args = parser.parse_args()

        # Read the config file name given from the parameters
        # don't use '%' for interpolation.
        # comment_prefixes are the characters that if found at the beginning
        # of the line, the line is completely ignored by configparses, by default they are # and ;
        # set them to # only to support removing commented ti files from the cache db
        config = configparser.ConfigParser(interpolation=None, comment_prefixes="#")
        try:
            with open(args.config) as source:
                config.read_file(source)
        except IOError:
            pass
        except TypeError:
            # No conf file provided
            pass

        if (args.verbose and int(args.verbose) > 3) or (args.debug and int(args.debug) > 3):
            print("Debug and verbose values range from 0 to 3.")
            terminate_slips()

        # Check if redis server running
        if check_redis_database() is False:
            print("Redis database is not running. Stopping Slips")
            terminate_slips()

        # Clear cache if the parameter was included
        if args.clearcache:
            print('Deleting Cache DB in Redis.')
            clear_redis_cache_database()
            terminate_slips()

        if args.clearblocking:
            if os.geteuid() != 0:
                print("Slips needs to be run as root to clear the slipsBlocking chain. Stopping.")
                terminate_slips()
            else:
                # start only the blocking module process and the db
                from slips_files.core.database import __database__
                from multiprocessing import Queue
                from modules.blocking.blocking import Module
                blocking = Module(Queue(), config)
                blocking.start()
                blocking.delete_slipsBlocking_chain()
                # Tell the blocking module to clear the slips chain
                shutdown_gracefully('')

        if args.db:
            from slips_files.core.database import __database__
            __database__.start(config)
            if not __database__.load(args.db):
                print(f"[Main] Failed to {args.db}")
            else:
                print(f"{args.db.split('/')[-1]} loaded successfully. Run ./kalipso.sh")
            terminate_slips()

        # Check if user want to save and load a db at the same time
        if args.save:
            # make sure slips is running as root
            if os.geteuid() != 0:
                print("Slips needs to be run as root to save the database. Stopping.")
                terminate_slips()
            if args.db:
                print("Can't use -s and -b together")
                terminate_slips()

        # Check the type of input
        if args.interface:
            input_information = args.interface
            input_type = 'interface'
        elif args.filepath:
            input_information = args.filepath
            # check invalid file path
            if not os.path.exists(input_information):
                print(f'[Main] Invalid file path {input_information}. Stopping.')
                os._exit(-1)

            # default value
            input_type = 'file'
            # Get the type of file
            cmd_result = subprocess.run(['file', input_information], stdout=subprocess.PIPE)
            # Get command output
            cmd_result = cmd_result.stdout.decode('utf-8')

            if 'pcap' in cmd_result:
                input_type = 'pcap'
            elif 'dBase' in cmd_result:
                input_type = 'nfdump'
            elif 'CSV' in cmd_result:
                input_type = 'binetflow'
            elif 'directory' in cmd_result:
                input_type = 'zeek_folder'
            else:
                # is it a zeek log file or suricata, binetflow tabs , or binetflow comma separated file?
                # use first line to determine
                with open(input_information, 'r') as f:
                    while True:
                        # get the first line that isn't a comment
                        first_line = f.readline().replace('\n', '')
                        if not first_line.startswith('#'):
                            break
                if 'flow_id' in first_line:
                    input_type = 'suricata'
                else:
                    # this is a text file , it can be binetflow or zeek_log_file
                    try:
                        # is it a json log file
                        json.loads(first_line)
                        input_type = 'zeek_log_file'
                    except json.decoder.JSONDecodeError:
                        # this is a tab separated file
                        # is it zeek log file or binetflow file?
                        # line = re.split(r'\s{2,}', first_line)[0]
                        tabs_found = re.search('\s{1,}-\s{1,}', first_line)
                        if '->' in first_line or 'StartTime' in first_line:
                            # tab separated files are usually binetflow tab files
                            input_type = 'binetflow-tabs'
                        elif tabs_found:
                            input_type = 'zeek_log_file'
        elif args.db:
            input_type = 'database'
            input_information = 'database'
        else:
            print('[Main] You need to define an input source.')
            sys.exit(-1)

        # If we need zeek (bro), test if we can run it.
        # Need to be assign to something because we pass it to inputProcess later
        zeek_bro = None
        if input_type not in ('pcap' , 'interface'):
            zeek_bro = check_zeek_or_bro()
            if zeek_bro is False:
                # If we do not have bro or zeek, terminate Slips.
                print('Error. No zeek or bro binary found.')
                terminate_slips()
            else:
                prepare_zeek_scripts()

        # See if we have the nfdump, if we need it according to the input type
        if input_type == 'nfdump' and shutil.which('nfdump') is None:
            # If we do not have nfdump, terminate Slips.
            print("[Main] nfdump is not installed. Stopping Slips.")
            terminate_slips()

        # Remove default folder for alerts, if exists
        if os.path.exists(args.output):
            try:
                os.remove(args.output + 'alerts.log')
                os.remove(args.output + 'alerts.json')
            except OSError:
                # Directory not empty (may contain hidden non-deletable files), don't delete dir
                pass

        # Create output folder for alerts.txt and alerts.json if they do not exist
        if not args.output.endswith('/'):
            args.output = args.output + '/'
        if not os.path.exists(args.output):
            os.makedirs(args.output)

        # Also check if the user blocks on interface, does not make sense to block on files
        if args.interface and args.blocking and os.geteuid() != 0:
            # If the user wants to blocks,we need permission to modify iptables
            print('Run slips with sudo to enable the blocking module.')
            shutdown_gracefully(input_information)

        """
        Import modules here because if user wants to run "./slips.py --help" it should never throw error. 
        """
        from multiprocessing import Queue
        from slips_files.core.inputProcess import InputProcess
        from slips_files.core.outputProcess import OutputProcess
        from slips_files.core.profilerProcess import ProfilerProcess
        from slips_files.core.guiProcess import GuiProcess
        from slips_files.core.logsProcess import LogsProcess
        from slips_files.core.evidenceProcess import EvidenceProcess

        # Any verbosity passed as parameter overrides the configuration. Only check its value
        if args.verbose is None:
            # Read the verbosity from the config
            try:
                args.verbose = int(config.get('parameters', 'verbose'))
            except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError):
                # There is a conf, but there is no option, or no section or no configuration file specified
                # By default, 1
                args.verbose = 1

        # Limit any verbosity to > 0
        if args.verbose < 1:
            args.verbose = 1

        # Any debuggsity passed as parameter overrides the configuration. Only check its value
        if args.debug is None:
            # Read the debug from the config
            try:
                args.debug = int(config.get('parameters', 'debug'))
            except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError):
                # There is a conf, but there is no option, or no section or no configuration file specified
                # By default, 0
                args.debug = 0

        # Limit any debuggisity to > 0
        if args.debug < 0:
            args.debug = 0

        ##########################
        # Creation of the threads
        ##########################
        from slips_files.core.database import __database__

        # Output thread. This thread should be created first because it handles
        # the output of the rest of the threads.
        # Create the queue
        outputProcessQueue = Queue()
        # if stdout it redirected to a file, tell outputProcess.py to redirect it's output as well
        # lsof will provide a list of all open fds belonging to slips
        command = f'lsof -p {os.getpid()}'
        result = subprocess.run(command.split(), capture_output=True)
        # Get command output
        output = result.stdout.decode('utf-8')
        # if stdout is being redirected we'll find '1w' in one of the lines 1 means stdout, w means write mode
        for line in output.splitlines():
            if '1w' in line:
                # stdout is redirected, get the file
                current_stdout = line.split(' ')[-1]
                break
        else:
            # stdout is not redirected
            current_stdout = ''

        # Create the output thread and start it
        outputProcessThread = OutputProcess(outputProcessQueue, args.verbose, args.debug, config, stdout=current_stdout)
        # this process starts the db
        outputProcessThread.start()

        # Before starting update malicious file
        # create an event loop and allow it to run the update_file_manager asynchronously
        asyncio.run(update_ti_files(outputProcessQueue, config))

        # Print the PID of the main slips process. We do it here because we needed the queue to the output process
        outputProcessQueue.put('10|main|Started main program [PID {}]'.format(os.getpid()))
        # Output pid
        __database__.store_process_PID('OutputProcess', int(outputProcessThread.pid))

        outputProcessQueue.put('10|main|Started output thread [PID {}]'.format(outputProcessThread.pid))

        # Start each module in the folder modules
        outputProcessQueue.put('01|main|Starting modules')
        to_ignore = read_configuration(config, 'modules', 'disable')

        # This plugins import will automatically load the modules and put them in the __modules__ variable
        # if slips is given a .rdb file, don't load the modules as we don't need them
        if to_ignore and not args.db:
            # Convert string to list
            to_ignore = to_ignore.replace("[", "").replace("]", "").replace(" ", "").split(",")
            # Ignore exporting alerts module if export_to is empty
            export_to = config.get('ExportingAlerts', 'export_to').rstrip("][").replace(" ", "").lower()
            if 'stix' not in export_to and 'slack' not in export_to and 'json' not in export_to:
                to_ignore.append('exporting_alerts')
            # ignore CESNET sharing module if send and receive are are disabled in slips.conf
            send_to_warden = config.get('CESNET', 'send_alerts').lower()
            receive_from_warden = config.get('CESNET', 'receive_alerts').lower()
            if 'no' in send_to_warden and 'no' in receive_from_warden:
                to_ignore.append('CESNET')
            # don't run blocking module unless specified
            if not args.clearblocking and not args.blocking \
                    or (args.blocking and not args.interface):  # ignore module if not using interface
                to_ignore.append('blocking')

            # leak detector only works on pcap files
            if input_type != 'pcap':
                to_ignore.append('leak_detector')
            try:
                # This 'imports' all the modules somehow, but then we ignore some
                modules_to_call = load_modules(to_ignore)[0]
                for module_name in modules_to_call:
                    if module_name not in to_ignore:
                        module_class = modules_to_call[module_name]['obj']
                        ModuleProcess = module_class(outputProcessQueue, config)
                        ModuleProcess.start()
                        __database__.store_process_PID(module_name, int(ModuleProcess.pid))
                        description = modules_to_call[module_name]['description']
                        outputProcessQueue.put(
                            f'10|main|\t\tStarting the module {module_name} '
                            f'({description}) '
                            f'[PID {ModuleProcess.pid}]')
            except TypeError:
                # There are not modules in the configuration to ignore?
                print('No modules are ignored')

        # Get the type of output from the parameters
        # Several combinations of outputs should be able to be used
        if args.gui:
            # Create the curses thread
            guiProcessQueue = Queue()
            guiProcessThread = GuiProcess(guiProcessQueue, outputProcessQueue, args.verbose, args.debug, config)
            guiProcessThread.start()
            outputProcessQueue.put('quiet')

        do_logs = read_configuration(config, 'parameters', 'create_log_files')
        # if -l is provided or create_log_files is yes then we will create log files
        if args.createlogfiles or do_logs == 'yes':
            # Create a folder for logs
            logs_folder = create_folder_for_logs()
            # Create the logsfile thread if by parameter we were told, or if it is specified in the configuration
            logsProcessQueue = Queue()
            logsProcessThread = LogsProcess(logsProcessQueue, outputProcessQueue,
                                            args.verbose, args.debug, config, logs_folder)
            logsProcessThread.start()
            outputProcessQueue.put('10|main|Started logsfiles thread [PID {}]'.format(logsProcessThread.pid))
            __database__.store_process_PID('logsProcess', int(logsProcessThread.pid))
        else:
            logs_folder = False

        # Evidence thread
        # Create the queue for the evidence thread
        evidenceProcessQueue = Queue()
        # Create the thread and start it
        evidenceProcessThread = EvidenceProcess(evidenceProcessQueue, outputProcessQueue,
                                                config, args.output, logs_folder)
        evidenceProcessThread.start()
        outputProcessQueue.put('10|main|Started Evidence thread [PID {}]'.format(evidenceProcessThread.pid))
        __database__.store_process_PID('EvidenceProcess', int(evidenceProcessThread.pid))

        # Profile thread
        # Create the queue for the profile thread
        profilerProcessQueue = Queue()
        # Create the profile thread and start it
        profilerProcessThread = ProfilerProcess(profilerProcessQueue,
                                                outputProcessQueue, args.verbose, args.debug, config)
        profilerProcessThread.start()
        outputProcessQueue.put('10|main|Started Profiler thread [PID {}]'.format(profilerProcessThread.pid))
        __database__.store_process_PID('ProfilerProcess', int(profilerProcessThread.pid))

        c1 = __database__.subscribe('finished_modules')

        # Input process
        # Create the input process and start it
        inputProcess = InputProcess(outputProcessQueue, profilerProcessQueue,
                                    input_type, input_information, config, args.pcapfilter, zeek_bro)
        inputProcess.start()
        outputProcessQueue.put('10|main|Started input thread [PID {}]'.format(inputProcess.pid))
        time.sleep(0.5)
        print()
        __database__.store_process_PID('InputProcess', int(inputProcess.pid))

        enable_metadata = read_configuration(config, 'parameters', 'metadata_dir')
        if 'yes' in enable_metadata.lower():
            add_metadata()

        # Store the host IP address if input type is interface
        if input_type == 'interface':
            hostIP = recognize_host_ip()
            while True:
                try:
                    __database__.set_host_ip(hostIP)
                    break
                except redis.exceptions.DataError:
                    print("Not Connected to the internet. Reconnecting in 10s.")
                    time.sleep(10)
                    hostIP = recognize_host_ip()

        # As the main program, keep checking if we should stop slips or not
        # This is not easy since we need to be sure all the modules are stopped
        # Each interval of checking is every 5 seconds
        check_time_sleep = 5
        # In each interval we check if there has been any modifications to the database by any module.
        # If not, wait this amount of intervals and then stop slips.
        # We choose 6 to wait 30 seconds.
        limit_minimum_intervals_to_wait = 4
        minimum_intervals_to_wait = limit_minimum_intervals_to_wait
        fieldseparator = __database__.getFieldSeparator()
        slips_internal_time = 0
        try:
            while True:
                # Sleep some time to do rutine checks
                time.sleep(check_time_sleep)
                slips_internal_time = float(__database__.getSlipsInternalTime())+1
                # Get the amount of modified profiles since we last checked
                modified_profiles, last_modified_tw_time = __database__.getModifiedProfilesSince(slips_internal_time)
                amount_of_modified = len(modified_profiles)
                # Get the time of last modified timewindow and set it as a new
                if last_modified_tw_time != 0:
                    __database__.setSlipsInternalTime(last_modified_tw_time)
                # How many profiles we have?
                profilesLen = str(__database__.getProfilesLen())
                print(f'Total Number of Profiles in DB so far: {profilesLen}. '
                      f'Modified Profiles in the last TW: {amount_of_modified}. '
                      f'({datetime.now().strftime("%Y-%m-%d--%H:%M:%S")})', end='\r')

                # Check if we need to close some TW
                __database__.check_TW_to_close()

                # In interface we keep track of the host IP. If there was no
                # modified TWs in the host NotIP, we check if the network was changed.
                # Dont try to stop slips if its catpurting from an interface
                if args.interface:
                    # To check of there was a modified TW in the host IP. If not,
                    # count down.
                    modifiedTW_hostIP = False
                    for profileIP in modified_profiles:
                        # True if there was a modified TW in the host IP
                        if hostIP == profileIP:
                            modifiedTW_hostIP = True

                    # If there was no modified TW in the host IP
                    # then start counting down
                    # After count down we update the host IP, to check if the
                    # network was changed
                    if not modifiedTW_hostIP and args.interface:
                        if minimum_intervals_to_wait == 0:
                            hostIP = recognize_host_ip()
                            if hostIP:
                                __database__.set_host_ip(hostIP)
                            minimum_intervals_to_wait = limit_minimum_intervals_to_wait
                        minimum_intervals_to_wait -= 1
                    else:
                        minimum_intervals_to_wait = limit_minimum_intervals_to_wait

                # ---------------------------------------- Stopping slips

                # When running Slips in the file.
                # If there were no modified TW in the last timewindow time,
                # then start counting down
                else:
                    # don't shutdown slips if it's being debugged
                    if amount_of_modified == 0 and not is_debugger_active():
                        # print('Counter to stop Slips. Amount of modified
                        # timewindows: {}. Stop counter: {}'.format(amount_of_modified, minimum_intervals_to_wait))
                        if minimum_intervals_to_wait == 0:
                            # If the user specified -s, save the database before stopping
                            shutdown_gracefully(input_information)
                            break
                        minimum_intervals_to_wait -= 1
                    else:
                        minimum_intervals_to_wait = limit_minimum_intervals_to_wait

                __database__.pubsub.check_health()

        except KeyboardInterrupt:
            shutdown_gracefully(input_information)

    except KeyboardInterrupt:
        shutdown_gracefully(input_information)
