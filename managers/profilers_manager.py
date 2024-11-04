import os
import subprocess
import sys


class ProfilersManager:
    def __init__(self, main):
        self.main = main
        self.read_configurations()

    def read_configurations(self):
        self.cpu_profiler_enabled = self.main.conf.get_cpu_profiler_enable()
        self.cpu_profiler_mode = self.main.conf.get_cpu_profiler_mode()
        self.cpu_profiler_multiprocess = (
            self.main.conf.get_cpu_profiler_multiprocess()
        )
        self.cpu_profiler_dev_mode_entries = (
            self.main.conf.get_cpu_profiler_dev_mode_entries()
        )
        self.cpu_profiler_output_limit = (
            self.main.conf.get_cpu_profiler_output_limit(),
        )
        self.cpu_profiler_sampling_interval = (
            self.main.conf.get_cpu_profiler_sampling_interval()
        )

        self.memory_profiler_mode = self.main.conf.get_memory_profiler_mode()
        self.memory_profiler_enabled = (
            self.main.conf.get_memory_profiler_enable()
        )
        self.memory_profiler_multiprocess = (
            self.main.conf.get_memory_profiler_multiprocess()
        )

    def cpu_profiler_init(self):
        if not self.cpu_profiler_enabled:
            return

        from slips_files.common.performance_profilers.cpu_profiler import (
            CPUProfiler,
        )

        try:
            if (
                self.cpu_profiler_multiprocess
                and self.cpu_profiler_mode == "dev"
            ):
                args = sys.argv
                if args[-1] != "--no-recurse":
                    tracer_entries = str(self.cpu_profiler_dev_mode_entries)
                    viz_args = [
                        "viztracer",
                        "--tracer_entries",
                        tracer_entries,
                        "--max_stack_depth",
                        "10",
                        "-o",
                        str(
                            os.path.join(
                                self.args.output,
                                "cpu_profiling_result.json",
                            )
                        ),
                    ]
                    viz_args.extend(args)
                    viz_args.append("--no-recurse")
                    print(
                        "Starting multiprocess profiling recursive subprocess"
                    )
                    subprocess.run(viz_args)
                    exit(0)
            else:
                self.cpu_profiler = CPUProfiler(
                    db=self.main.db,
                    output=self.args.output,
                    mode=self.cpu_profiler_mode,
                    limit=self.cpu_profiler_output_limit,
                    interval=self.cpu_profiler_sampling_interval,
                )
                self.cpu_profiler.start()
        except Exception as e:
            print(e)
            self.cpu_profiler_enabled = False

    def cpu_profiler_release(self):
        if not hasattr(self, "cpu_profiler_enabled"):
            return

        if self.cpu_profiler_enabled and not self.cpu_profiler_multiprocess:
            self.cpu_profiler.stop()
            self.cpu_profiler.print()

    def memory_profiler_init(self):
        if not self.memory_profiler_enabled:
            return

        from slips_files.common.performance_profilers.memory_profiler import (
            MemoryProfiler,
        )

        output_dir = os.path.join(self.args.output, "memoryprofile/")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        output_file = os.path.join(output_dir, "memory_profile.bin")
        self.memory_profiler = MemoryProfiler(
            output_file,
            db=self.main.db,
            mode=self.memory_profiler_mode,
            multiprocess=self.memory_profiler_multiprocess,
        )
        self.memory_profiler.start()

    def memory_profiler_release(self):
        if (
            hasattr(self, "memory_profiler_enabled")
            and self.memory_profiler_enabled
        ):
            self.memory_profiler.stop()
