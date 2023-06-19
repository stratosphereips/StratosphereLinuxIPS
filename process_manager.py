from slips_files.common.imports import *
from style import green
import signal
import os
import time
import pkgutil
import inspect
import modules
import importlib
from datetime import datetime
from collections import OrderedDict

class ProcessManager:
    def __init__(self, main):
        self.main = main
        self.module_objects = {}

    def kill(self, module_name, INT=False):
        sig = signal.SIGINT if INT else signal.SIGKILL
        try:
            pid = int(self.PIDs[module_name])
            self.module_objects[module_name].shutdown_gracefully()
            os.kill(pid, sig)
        except (KeyError, ProcessLookupError):
            # process hasn't started yet
            pass

    def kill_all(self, PIDs):
        for module in PIDs:
            if module not in self.PIDs:
                # modules the are last to kill aren't always started and there in self.PIDs
                # ignore them
                continue
            self.kill(module)
            self.print_stopped_module(module)

    def stop_core_processes(self):
        self.kill('Input')

        if self.main.mode == 'daemonized':
            # when using -D, we kill the processes because
            # the queues are not there yet to send stop msgs
            for process in (
                        'ProfilerProcess',
                        'OutputProcess'

            ):
                self.kill(process, INT=True)

        else:
            # Send manual stops to the processes using queues
            stop_msg = 'stop_process'
            self.main.profilerProcessQueue.put(stop_msg)
            self.main.output_queue.put(stop_msg)

    def get_modules(self, to_ignore):
        """
        Get modules from the 'modules' folder.
        """
        # This plugins import will automatically load the modules and put them in
        # the __modules__ variable

        plugins = {}
        failed_to_load_modules = 0
        # Walk recursively through all modules and packages found on the . folder.
        # __path__ is the current path of this python program
        for loader, module_name, ispkg in pkgutil.walk_packages(
                modules.__path__, f'{modules.__name__}.'
        ):
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
                print(
                    'Something wrong happened while importing the module {0}: {1}'.format(
                        module_name, e
                    )
                )
                failed_to_load_modules += 1
                continue

            # Walk through all members of currently imported modules.
            for member_name, member_object in inspect.getmembers(module):
                # Check if current member is a class.
                if inspect.isclass(member_object) and (issubclass(
                        member_object, Module
                ) and member_object is not Module):
                    plugins[member_object.name] = dict(
                        obj=member_object,
                        description=member_object.description,
                    )

        # Change the order of the blocking module(load it first)
        # so it can receive msgs sent from other modules
        if 'Blocking' in plugins:
            plugins = OrderedDict(plugins)
            # last=False to move to the beginning of the dict
            plugins.move_to_end('Blocking', last=False)

        # when cyst starts first, as soon as slips connects to cyst, cyst sends slips the flows,
        # but the inputprocess didn't even start yet so the flows are lost
        # to fix this, change the order of the CYST module(load it last)
        if 'CYST' in plugins:
            plugins = OrderedDict(plugins)
            # last=False to move to the beginning of the dict
            plugins.move_to_end('CYST', last=True)

        return plugins, failed_to_load_modules

    def load_modules(self):
        to_ignore = self.main.conf.get_disabled_modules(self.main.input_type)
        # Import all the modules
        modules_to_call = self.get_modules(to_ignore)[0]
        loaded_modules = []
        for module_name in modules_to_call:
            # delete later
            # if module_name != 'CPU Profiler':
            #     continue
            # end
            if module_name in to_ignore:
                continue

            module_class = modules_to_call[module_name]['obj']
            module = module_class(
                self.main.output_queue,
                self.main.db,
            )
            module.start()
            self.main.db.store_process_PID(
                module_name, int(module.pid)
            )
            self.module_objects[module_name] = module # maps name -> object
            description = modules_to_call[module_name]['description']
            self.main.print(
                f'\t\tStarting the module {green(module_name)} '
                f'({description}) '
                f'[PID {green(module.pid)}]', 1, 0
                )
            loaded_modules.append(module_name)
        # give outputprocess time to print all the started modules
        time.sleep(0.5)
        print('-' * 27)
        self.main.print(f"Disabled Modules: {to_ignore}", 1, 0)
        return loaded_modules
    
    def print_stopped_module(self, module):
        self.PIDs.pop(module, None)
        # all text printed in green should be wrapped in the following

        modules_left = len(list(self.PIDs.keys()))
        # to vertically align them when printing
        module += ' ' * (20 - len(module))
        print(
            f'\t{green(module)} \tStopped. '
            f'{green(modules_left)} left.'
        )

    def get_already_stopped_modules(self):
        already_stopped_modules = []
        for module, pid in self.PIDs.items():
            try:
                # signal 0 is used to check if the pid exists
                os.kill(int(pid), 0)
            except ProcessLookupError:
                # pid doesn't exist because module already stopped
                # to be able to remove it's pid from the dict
                already_stopped_modules.append(module)
        return already_stopped_modules

    def warn_about_pending_modules(self, finished_modules):
        # exclude the module that are already stopped from the pending modules
        pending_modules = [
            module
            for module in list(self.PIDs.keys())
            if module not in finished_modules
        ]
        if not len(pending_modules):
            return
        print(
            f'\n[Main] The following modules are busy working on your data.'
            f'\n\n{pending_modules}\n\n'
            'You can wait for them to finish, or you can '
            'press CTRL-C again to force-kill.\n'
        )
        return True

    def should_kill_all_modules(self,
                                function_start_time,
                                wait_for_modules_to_finish) -> bool:
        """
        checks if x minutes has passed since the start of the function
        :param wait_for_modules_to_finish: time in mins to wait before force killing all modules
                                            defined by wait_for_modules_to_finish in slips.conf
        """
        now = datetime.now()
        diff = utils.get_time_diff(function_start_time, now, return_type='minutes')
        return  diff >= wait_for_modules_to_finish

    def get_modules_to_be_killed_last(self) -> list:
        """
        based on what modules were started in this instance of slips return the list of processes that we want to kill last
        @return: list of modules to be kileld last
        """
        modules_to_be_killed_last = [
            'Evidence',
            # 'Blocking',
            # 'Exporting Alerts',
        ]
        if self.main.args.blocking:
            modules_to_be_killed_last.append('Blocking')
        if 'exporting_alerts' not in self.main.db.get_disabled_modules():
            modules_to_be_killed_last.append('Exporting Alerts')
        return modules_to_be_killed_last

    def shutdown_gracefully(self):
        """
        Wait for all modules to confirm that they're done processing
        or kill them after 15 mins
        """
        # 15 mins from this time, all modules should be killed
        function_start_time = datetime.now()
        try:
            if not self.main.args.stopdaemon:
                print('\n' + '-' * 27)
            print('Stopping Slips')

            wait_for_modules_to_finish  = self.main.conf.wait_for_modules_to_finish()
            # close all tws
            self.main.db.check_TW_to_close(close_all=True)

            # set analysis end date
            end_date = self.main.metadata_man.set_analysis_end_date()

            start_time = self.main.db.get_slips_start_time()
            analysis_time = utils.get_time_diff(start_time, end_date, return_type='minutes')
            print(f'[Main] Analysis finished in {analysis_time:.2f} minutes')

            # Stop the modules that are subscribed to channels
            self.main.db.publish_stop()

            # get dict of PIDs spawned by slips
            self.PIDs = self.main.db.get_pids()
            # we don't want to kill this process
            self.PIDs.pop('slips.py', None)

            if self.main.mode == 'daemonized':
                profilesLen = self.main.db.get_profiles_len()
                self.main.daemon.print(f'Total analyzed IPs: {profilesLen}.')

            modules_to_be_killed_last: list = self.get_modules_to_be_killed_last()

            self.stop_core_processes()
            # only print that modules are still running once
            warning_printed = False

            # loop until all loaded modules are finished
            # in the case of -S, slips doesn't even start the modules,
            # so they don't publish in finished_modules. we don't need to wait for them we have to kill them
            if not self.main.args.stopdaemon:
                #  modules_to_be_killed_last are ignored when they publish a msg in finished modules channel,
                # we will kill them later, so we shouldn't be waiting for them to get outta the loop
                slips_processes = len(list(self.PIDs.keys())) - len(modules_to_be_killed_last)

                try:
                    finished_modules = []
                    # timeout variable so we don't loop forever
                    # give slips enough time to close all modules - make sure
                    # all modules aren't considered 'busy' when slips stops
                    max_loops = 430
                    while (
                        len(finished_modules) < slips_processes and max_loops != 0
                    ):
                        # print(f"Modules not finished yet {set(loaded_modules) - set(finished_modules)}")
                        try:
                            message = self.main.c1.get_message(timeout=0.00000001)
                        except NameError:
                            continue

                        if message and message['data'] in ('stop_process', 'stop_slips'):
                            continue

                        if utils.is_msg_intended_for(message, 'finished_modules'):
                            # all modules must reply with their names in this channel after
                            # receiving the stop_process msg
                            # to confirm that all processing is done and we can safely exit now
                            module_name = message['data']
                            if module_name in modules_to_be_killed_last:
                                # we should kill these modules the very last, or else we'll miss evidence generated
                                # right before slips stops
                                continue

                            if module_name not in finished_modules:
                                finished_modules.append(module_name)
                                self.kill(module_name)
                                self.print_stopped_module(module_name)

                                # some modules publish in finished_modules channel before slips.py starts listening,
                                # but they finished gracefully.
                                # remove already stopped modules from PIDs dict
                                for module in self.get_already_stopped_modules():
                                    finished_modules.append(module)
                                    self.print_stopped_module(module)

                        max_loops -= 1
                        # after reaching the max_loops and before killing the modules that aren't finished,
                        # make sure we're not processing
                        # the logical flow is self.pids should be empty by now as all modules
                        # are closed, the only ones left are the ones we want to kill last
                        modules_running = len(self.PIDs)
                        modules_that_should_be_running = len(modules_to_be_killed_last)
                        if modules_running > modules_that_should_be_running and max_loops < 2:
                            if not warning_printed and self.warn_about_pending_modules(finished_modules):
                                if 'Update Manager' not in finished_modules:
                                    print(
                                        f"[Main] Update Manager may take several minutes "
                                        f"to finish updating 45+ TI files."
                                    )
                                warning_printed = True

                            # -t flag is only used in integration tests,
                            # so we don't care about the modules finishing their job when testing
                            # instead, kill them
                            # if self.main.args.testing:
                            #     pass
                            #     break

                            # delay killing unstopped modules until all of them
                            # are done processing
                            max_loops += 1

                            # checks if 15 minutes has passed since the start of the function
                            if self.should_kill_all_modules(function_start_time, wait_for_modules_to_finish):
                                print(f"Killing modules that took more than "
                                      f"{wait_for_modules_to_finish} mins to finish.")
                                break

                except KeyboardInterrupt:
                    # either the user wants to kill the remaining modules (pressed ctrl +c again)
                    # or slips was stuck looping for too long that the os sent an automatic sigint to kill slips
                    # pass to kill the remaining modules
                    pass
            # modules that aren't subscribed to any channel will always be killed and not stopped
            # comes here if the user pressed ctrl+c again
            self.kill_all(self.PIDs.copy())
            self.kill_all(modules_to_be_killed_last)

            # save redis database if '-s' is specified
            if self.main.args.save:
                self.main.save_the_db()

            if self.main.conf.export_labeled_flows():
                format = self.main.conf.export_labeled_flows_to().lower()
                self.main.db.export_labeled_flows(format)

            # if store_a_copy_of_zeek_files is set to yes in slips.conf,
            # copy the whole zeek_files dir to the output dir
            self.main.store_zeek_dir_copy()

            # if delete_zeek_files is set to yes in slips.conf,
            # delete zeek_files/ dir
            self.main.delete_zeek_files()
            self.main.db.close()

            if self.main.mode == 'daemonized':
                # if slips finished normally without stopping the daemon with -S
                # then we need to delete the pidfile
                self.main.daemon.delete_pidfile()
            return True
        except KeyboardInterrupt:
            self.kill_all(self.PIDs.copy())
            self.kill_all(modules_to_be_killed_last)
            return False
