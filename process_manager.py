from slips_files.common.imports import *
from slips_files.core.outputProcess import OutputProcess
from slips_files.core.profilerProcess import ProfilerProcess
from slips_files.core.evidenceProcess import EvidenceProcess
from slips_files.core.inputProcess import InputProcess
from multiprocessing import Queue, Event, Process
from collections import OrderedDict
from typing import List, Tuple
from style import green
import signal
import time
import pkgutil
import inspect
import modules
import importlib
import os
from sys import exit


class ProcessManager:
    def __init__(self, main):
        self.main = main
        self.module_objects = {}
        # this is the queue that will be used by the input proces to pass flows
        # to the profiler
        self.profiler_queue = Queue()
        self.termination_event: Event = multiprocessing.Event()
        self.stopped_modules = []

    def start_output_process(self, current_stdout, stderr, slips_logfile):
        output_process = OutputProcess(
            self.main.output_queue,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
            verbose=self.main.args.verbose,
            debug=self.main.args.debug,
            stdout=current_stdout,
            stderr=stderr,
            slips_logfile=slips_logfile,
        )
        output_process.start()
        self.main.db.store_process_PID('Output', int(output_process.pid))
        self.slips_logfile = output_process.slips_logfile
        return output_process

    def start_profiler_process(self):
        profiler_process = ProfilerProcess(
            self.main.output_queue,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
            profiler_queue=self.profiler_queue,
        )
        profiler_process.start()
        self.main.print(
            f'Started {green("Profiler Process")} '
            f"[PID {green(profiler_process.pid)}]",
            1,
            0,
        )
        self.main.db.store_process_PID("Profiler", int(profiler_process.pid))
        return profiler_process

    def start_evidence_process(self):
        evidence_process = EvidenceProcess(
            self.main.output_queue,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
        )
        evidence_process.start()
        self.main.print(
            f'Started {green("Evidence Process")} '
            f"[PID {green(evidence_process.pid)}]",
            1,
            0,
        )
        self.main.db.store_process_PID("Evidence", int(evidence_process.pid))
        return evidence_process

    def start_input_process(self):
        input_process = InputProcess(
            self.main.output_queue,
            self.main.args.output,
            self.main.redis_port,
            self.termination_event,
            profiler_queue=self.profiler_queue,
            input_type=self.main.input_type,
            input_information=self.main.input_information,
            cli_packet_filter=self.main.args.pcapfilter,
            zeek_or_bro=self.main.zeek_bro,
            zeek_dir=self.main.zeek_dir,
            line_type=self.main.line_type,
        )
        input_process.start()
        self.main.print(
            f'Started {green("Input Process")} ' f"[PID {green(input_process.pid)}]",
            1,
            0,
        )
        self.main.db.store_process_PID("Input", int(input_process.pid))
        return input_process


    def kill_process_tree(self, pid: int):
        try:
            # Send SIGKILL signal to the process
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass  # Ignore if the process doesn't exist or cannot be killed

        # Get the child processes of the current process
        try:
            process_list = os.popen('pgrep -P {}'.format(pid)).read().splitlines()
        except:
            process_list = []

        # Recursively kill the child processes
        for child_pid in process_list:
            self.kill_process_tree(int(child_pid))

    def kill_all_children(self):
        for process in self.processes:
            module_name: str = self.main.db.get_name_of_module_at(process.pid)
            if not module_name:
                # if it's a thread started by one of the modules or
                # by slips.py, we don't have it stored in the db so just skip it
                continue
            if module_name in self.stopped_modules:
                # already stopped
                continue

            process.join(3)
            self.kill_process_tree(process.pid)
            self.print_stopped_module(module_name)

    def get_modules(self, to_ignore: list):
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
            modules.__path__, f"{modules.__name__}."
        ):
            ignore_module = False
            for ignored_module in to_ignore:
                ignored_module = ignored_module.replace(' ','').replace('_','').replace('-','').lower()
                # this version of the module name wont contain _ or spaces so we can
                # easily match it with the ignored module name
                curr_module_name = module_name.replace('_','').replace('-','').lower()
                if curr_module_name.__contains__(ignored_module):
                    ignore_module = True
                    break

            if ignore_module:
                continue


            # If current item is a package, skip.
            if ispkg:
                continue
            # to avoid loading everything in the dir,
            # only load modules that have the same name as the dir name
            dir_name = module_name.split(".")[1]
            file_name = module_name.split(".")[2]
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
                    "Something wrong happened while importing the module {0}: {1}".format(
                        module_name, e
                    )
                )
                failed_to_load_modules += 1
                continue

            # Walk through all members of currently imported modules.
            for member_name, member_object in inspect.getmembers(module):
                # Check if current member is a class.
                if inspect.isclass(member_object) and (
                    issubclass(member_object, Module) and member_object is not Module
                ):
                    plugins[member_object.name] = dict(
                        obj=member_object,
                        description=member_object.description,
                    )

        # Change the order of the blocking module(load it first)
        # so it can receive msgs sent from other modules
        if "Blocking" in plugins:
            plugins = OrderedDict(plugins)
            # last=False to move to the beginning of the dict
            plugins.move_to_end("Blocking", last=False)

        # when cyst starts first, as soon as slips connects to cyst, cyst sends slips the flows,
        # but the inputprocess didn't even start yet so the flows are lost
        # to fix this, change the order of the CYST module(load it last)
        if "CYST" in plugins:
            plugins = OrderedDict(plugins)
            # last=False to move to the beginning of the dict
            plugins.move_to_end("CYST", last=True)

        return plugins, failed_to_load_modules

    def load_modules(self):
        to_ignore = self.main.conf.get_disabled_modules(self.main.input_type)
        # Import all the modules
        modules_to_call = self.get_modules(to_ignore)[0]
        loaded_modules = []
        for module_name in modules_to_call:
            if module_name in to_ignore:
                continue

            module_class = modules_to_call[module_name]["obj"]
            module = module_class(
                self.main.output_queue,
                self.main.args.output,
                self.main.redis_port,
                self.termination_event,
            )
            module.start()
            self.main.db.store_process_PID(module_name, int(module.pid))
            self.module_objects[module_name] = module  # maps name -> object
            description = modules_to_call[module_name]["description"]
            self.main.print(
                f"\t\tStarting the module {green(module_name)} "
                f"({description}) "
                f"[PID {green(module.pid)}]",
                1,
                0,
            )
            loaded_modules.append(module_name)
        # give outputprocess time to print all the started modules
        time.sleep(0.5)
        print("-" * 27)
        self.main.print(f"Disabled Modules: {to_ignore}", 1, 0)
        return loaded_modules

    def print_stopped_module(self, module):
        self.stopped_modules.append(module)

        modules_left = len(self.processes) - len(self.stopped_modules)

        # to vertically align them when printing
        module += " " * (20 - len(module))
        print(f"\t{green(module)} \tStopped. " f"{green(modules_left)} left.")

    def warn_about_pending_modules(self, pending_modules: List[Process]):
        """
        Prints the names of the modules that are not finished yet.
        :param pending_modules: List of active/pending process that aren't killed or stopped yet
        """
        if self.warning_printed_once:
            return

        pending_module_names: List[str] = [proc.name for proc in pending_modules]
        print(
            f"\n[Main] The following modules are busy working on your data."
            f"\n\n{pending_module_names}\n\n"
            "You can wait for them to finish, or you can "
            "press CTRL-C again to force-kill.\n"
        )

        # check if update manager is still alive
        if "Update Manager" in pending_module_names:
            print(
                f"[Main] Update Manager may take several minutes "
                f"to finish updating 45+ TI files."
            )

        self.warning_printed_once = True
        return True


    def get_hitlist_in_order(self) -> Tuple[List[Process], List[Process]]:
        """
        returns a list of PIDs that slips should terminate first, and pids that should be killed last
        """
        # all modules that deal with evidence, blocking and alerts should be killed last
        # so we don't miss reporting, exporting or blocking any malicious IoC
        pids_to_kill_last = [
            self.main.db.get_pid_of("Evidence"),
            self.main.db.get_pid_of("Input"),
            self.main.db.get_pid_of("Output"),
            self.main.db.get_pid_of("Profiler"),
        ]

        if self.main.args.blocking:
            pids_to_kill_last.append(self.main.db.get_pid_of("Blocking"))

        if "exporting_alerts" not in self.main.db.get_disabled_modules():
            pids_to_kill_last.append(self.main.db.get_pid_of("Exporting Alerts"))

        # remove all None PIDs
        pids_to_kill_last: List[int] = [
            pid for pid in pids_to_kill_last if pid is not None
        ]

        to_kill_first: List[Process] = []
        to_kill_last: List[Process] = []
        for process in self.processes:
            # if it's not to kill be killed last, then we need to kill it first :'D
            if process.pid in pids_to_kill_last:
                to_kill_last.append(process)
            else:
                to_kill_first.append(process)

        return to_kill_first, to_kill_last

    def wait_for_processes_to_finish(
        self, pids_to_kill: List[Process]
    ) -> List[Process]:
        """
        :param pids_to_kill: list of PIDs to wait for
        :return: list of PIDs that still are not done yet
        """
        alive_processes: List[Process] = []
        # go through all processes to kill and see which
        # of them still need time
        for process in pids_to_kill:
            if 'output' in process.name.lower():
                self.main.output_queue.put('stop')
            # wait 3s for it to stop
            process.join(3)

            if process.is_alive():
                # reached timeout
                alive_processes.append(process)
            else:
                self.print_stopped_module(process.name)

        return alive_processes

    def get_analysis_time(self):
        """
        Returns how long slips tool to analyze the given file
        """
        # set analysis end date
        end_date = self.main.metadata_man.set_analysis_end_date()

        start_time = self.main.db.get_slips_start_time()
        return utils.get_time_diff(
            start_time, end_date, return_type="minutes"
        )


    def shutdown_interactive(self, to_kill_first, to_kill_last):
        """
        Shuts down modules in interactive mode only.
        it won't work with the daemon's -S because the
        processes aren't technically the children of the daemon
        returns 2 lists of alive children
        """
        # wait for the processes to be killed first as long as they want
        # maximum time to wait is timeout_seconds
        alive_processes = self.wait_for_processes_to_finish(to_kill_first)
        if alive_processes:
            # update the list of processes to kill first with only the ones that are still alive
            to_kill_first: List[Process] = alive_processes

            # the 2 lists combined are all the children that are still alive
            # here to_kill_last are considered alive because we haven't tried to join() em yet
            self.warn_about_pending_modules(alive_processes + to_kill_last)
            return to_kill_first, to_kill_last
        else:
            # all of them are killed
            to_kill_first = []

        alive_processes = self.wait_for_processes_to_finish(to_kill_last)
        if alive_processes:
            # update the list of processes to kill last with only the ones that are still alive
            to_kill_last: List[Process] = alive_processes

            # the 2 lists combined are all the children that are still alive
            self.warn_about_pending_modules(alive_processes)
            return to_kill_first, to_kill_last
        # all of them are killed
        return None, None

    def shutdown_daemon(self):
        """
        Shutdown slips modules in daemon mode
        using the daemon's -s
        """
        # this method doesn't deal with self.processes bc they aren't the daemon's children,
        # they are the children of the slips.py that ran using -D
        # (so they started on a previous run)
        # and we only have access to the PIDs
        for module_name, pid in self.processes.items():
            self.kill_process_tree(int(pid))
            self.print_stopped_module(module_name)

    def shutdown_gracefully(self):
        """
        Wait for all modules to confirm that they're done processing
        or kill them after 15 mins
        """
        try:
            if not self.main.args.stopdaemon:
                print("\n" + "-" * 27)
            print("Stopping Slips")

            # by default, 15 mins from this time, all modules should be killed
            method_start_time = time.time()

            # how long to wait for modules to finish in minutes
            timeout: float = self.main.conf.wait_for_modules_to_finish()
            timeout_seconds: float = timeout * 60

            # close all tws
            self.main.db.check_TW_to_close(close_all=True)

            analysis_time = self.get_analysis_time()
            print(f"\n[Main] Analysis of {self.main.input_information} finished in {analysis_time:.2f} minutes")

            graceful_shutdown = True
            if self.main.mode == 'daemonized':
                self.processes: dict = self.main.db.get_pids()
                self.shutdown_daemon()

                profilesLen = self.main.db.get_profiles_len()
                self.main.daemon.print(f"Total analyzed IPs: {profilesLen}.")

                # if slips finished normally without stopping the daemon with -S
                # then we need to delete the pidfile here
                self.main.daemon.delete_pidfile()

            else:
                hitlist: Tuple[List[Process], List[Process]] = self.get_hitlist_in_order()
                to_kill_first: List[Process] = hitlist[0]
                to_kill_last: List[Process] = hitlist[1]

                self.termination_event.set()

                # to make sure we only warn the user once about hte pending modules
                self.warning_printed_once = False
                try:
                    # Wait timeout_seconds for all the processes to finish
                    while time.time() - method_start_time < timeout_seconds:
                        to_kill_first, to_kill_last = self.shutdown_interactive(to_kill_first, to_kill_last)
                        if not to_kill_first and not to_kill_last:
                            # all modules are done
                            break
                except KeyboardInterrupt:
                    # either the user wants to kill the remaining modules (pressed ctrl +c again)
                    # or slips was stuck looping for too long that the OS sent an automatic sigint to kill slips
                    # pass to kill the remaining modules
                    reason = "User pressed ctr+c or slips was killed by the OS"
                    graceful_shutdown = False
                    pass

                if time.time() - method_start_time >= timeout_seconds:
                    # getting here means we're killing them bc of the timeout
                    # not getting here means we're killing them bc of double
                    # ctr+c OR they terminated successfully
                    reason = f"Killing modules that took more than {timeout} mins to finish."
                    print(reason)
                    graceful_shutdown = False

                self.kill_all_children()

            # save redis database if '-s' is specified
            if self.main.args.save:
                self.main.save_the_db()

            if self.main.conf.export_labeled_flows():
                format_ = self.main.conf.export_labeled_flows_to().lower()
                self.main.db.export_labeled_flows(format_)

            # if store_a_copy_of_zeek_files is set to yes in slips.conf,
            # copy the whole zeek_files dir to the output dir
            self.main.store_zeek_dir_copy()

            # if delete_zeek_files is set to yes in slips.conf,
            # delete zeek_files/ dir
            self.main.delete_zeek_files()
            self.main.db.close()

            # when using -S, the main has no output_queue
            if hasattr(self.main, 'output_queue'):
                self.main.output_queue.close()
                self.main.output_queue.cancel_join_thread()

            with open(self.slips_logfile, 'a') as f:
                if graceful_shutdown:
                    f.write("[Process Manager] Slips shutdown gracefully\n")
                else:
                    f.write(f"[Process Manager] Slips didn't shutdown gracefully - {reason}\n")

        except KeyboardInterrupt:
            return False
