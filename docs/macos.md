# Native macOS: diagnosis, implementation, and verification

The native startup failures involve Python packaging, semaphore limits, and
process ownership. Changing the multiprocessing start method alone does not
address them.

## Findings and fixes

| Failure | Cause | Change |
| --- | --- | --- |
| `slips.py -h` fails with `No module named 'distutils'` on the host's Python 3.14 | `slips/main.py` imports a removed standard-library package | Use `shutil.copytree(..., dirs_exist_ok=True)`; use Python 3.11 for the current dependency pins |
| `OSError: [Errno 22] Invalid argument` while constructing the profiler queue | Requested queue capacity is 1,321,528; the host's `SEM_VALUE_MAX` is 32,767. Other queues request 30,000,000 | Cap bounded multiprocessing queues at `SEM_VALUE_MAX`; retain the existing capacities on systems supporting them |
| Process startup cannot serialize live locks, database clients, threads, or running process objects | Core constructors execute in the parent; the detection target is a bound method capturing the main coordinator | `ModuleProcess` transfers construction arguments and initializes each module in its own process |
| Profiler grandchildren receive live database and process state | Input parsers contain database connections; AID clients reference a running process | Transfer parser data without its database; reconnect parsers in workers; give workers queue-only AID clients |
| Logging locks and startup progress are independent in spawned children | Synchronization objects were class globals recreated on import | Store synchronization objects on the logger instance passed to each child |
| DNS checks raise `NotImplementedError` from `qsize()` | Multiprocessing queue size inspection depends on a semaphore operation unavailable on macOS | Use `queue.Queue` for the DNS analyzer's thread-only communication; remove multiprocessing-only shutdown calls |
| New child connections can reset the analysis clock | Each spawned process initializes its own Redis singleton | Initialize the internal clock only when the analysis has no start time |
| The AID child can be terminated before queued flows reach SQLite | Python terminates daemon children when their parent exits | Send one stop sentinel and join the AID child before marking profiling complete |
| YARA cannot replace old compiled rules | Compiled rules in the source tree may belong to a previous installation or use an incompatible YARA version | Compile rules beneath the current run's module output directory |
| Stdin is mistaken for a directory, loses its input under spawn, or crashes parsing | The `zeek` token collides with a repository directory; stdin is replaced by multiprocessing; parsers assume an interface and use inconsistent Argus names | Recognize stdin tokens first, transfer a duplicated descriptor, supply flow interface metadata, map Argus to its parser, and infer networks without a capture interface |
| EOF on stdin is treated as a core failure | All continuously running inputs were assumed never to finish | Allow normal input/profiler completion after stdin signals EOF; retain failure checks before EOF |
| Startup errors disappear when workers never finish starting | Diagnostics remain in the startup queue until the final worker announcement | Flush buffered startup diagnostics before shutdown |
| nfdump crashes parsing the CSV header or uses the wrong columns | The installed nfdump's default CSV schema differs from the legacy schema Slips expects | Request explicit legacy column order, trim padded fields, normalize numeric protocol IDs, and parse packet/byte counts as numbers |
| Iris cannot execute on macOS | The bundled executable is Linux ELF | Build the Iris submodule natively and select it with `global_p2p.iris_binary` |
| Native Iris peers start but no alerts cross the adapter | Internal Slips message versioning overwrites Iris's numeric wire-protocol version, and incoming Iris messages fail the internal version check | Translate versions at the Iris adapter; preserve the external version when publishing to Iris |

The semaphore and `qsize()` failures were reproduced directly on macOS.
The serialization boundaries were identified from the source and are exercised
with real spawned subprocesses in regression tests. The original default
Python failed before it could reach those boundaries.

Queue capacities count **items**, not bytes. Capping them preserves bounded
backpressure but changes the maximum number of buffered items on macOS.

## Implementation plan

1. Establish an isolated Python 3.11 environment using the existing requirements.
2. Fix import and queue-construction failures so the CLI can start.
3. Move resource ownership into children across detection, core, evidence-worker,
   profiler-worker, and AID process boundaries.
4. Explicitly share logging and worker-count state; preserve child-local database
   connections and complete queued storage before exit.
5. Exercise real `spawn` and `forkserver` processes, affected unit tests, and a
   native PCAP analysis through Zeek, SQLite, evidence logging, and shutdown.

## Validation scope

The investigation used an Apple Silicon Mac running macOS 26.6.2, Python
3.11.13, Zeek 8.0.3, and Redis 8.0.3. The existing
requirements installed successfully, including TensorFlow 2.19.1 and NumPy
1.26.4. CLI help works without selecting `fork`.

The initial affected regression set passed 498 tests. The expanded full unit
suite subsequently passed **2,627 tests, with two skipped**. The skipped
VirusTotal tests require a usable API key and quota. Real `spawn` and
`forkserver` subprocess tests verify that constructors run in the child,
unpicklable thread locks stay local, logger state and worker counters remain
shared, bloom filters reconnect without flushing Redis, and AID shutdown waits
for storage. Full-suite failures also exposed Linux-only assumptions in test
fixtures and configuration-singleton contamination between tests. Linux firewall
and privilege-drop tests now explicitly mock Linux; parser state is isolated
between tests. Passing those tests does not imply native firewall support.

The full unit invocation used the Python 3.11 environment:

```bash
python -m pytest tests/unit/ --ignore=tests/integration_tests -n 7 -p no:warnings -vvvv -s
```

Runtime tests and the unit command ran under an OS network policy allowing
local TCP/UDP and Unix sockets while denying outbound connections to external
hosts. This permits Redis, multiprocessing descriptor transfer, and local
peers without submitting analyzed indicators to external services.

Native runs of `dataset/test7-malicious.pcap` reached detection, saved flow and
alert databases, and completed shutdown. The first runs exposed the YARA cache
permission issue and DNS queue cleanup issue described above. A final run with
those corrections used local detectors and an OS-enforced loopback-only outbound
network policy, allowing local Redis while preventing external indicator queries.
It exited successfully in 1.49 minutes with no tracebacks or logged errors.
SQLite contained all 377 connections present in Zeek's `conn.log`, plus 57
alternative flows. The evidence output contained 537 valid JSON records, and
the run's YARA rule compiled successfully. The log confirmed graceful shutdown.

Additional native end-to-end checks verified stored flow counts, absence of
tracebacks, successful exit, and the graceful-shutdown log:

| Input / mode | Verified result |
| --- | --- |
| PCAPNG | Converted from the tested PCAP; 377 connections and 57 alternative flows stored; clean shutdown in 89.7 seconds |
| Zeek JSON file and directory | 30 supplied connections stored in each run |
| Zeek tab-separated file and directory | 30 supplied connections stored in each run |
| Argus CSV and tab-separated files | 30 supplied flows stored in each run |
| Suricata JSON file | 30 supplied flow events stored |
| Zeek, Argus, and Suricata stdin | 30 supplied flows stored for each format; normal completion at EOF |
| Binary nfdump | All 2,398 decoded bidirectional records stored |
| Growing Zeek directory | Read by both Slips instances during the Iris test; terminated by SIGTERM |
| Global P2P / Iris | Native ARM64 Go build; synthetic message crossed Slips 1 → Iris 1 → Iris 2 → Slips 2's `network2fides` channel; both instances shut down gracefully |

The Iris check used separate Redis servers and QUIC ports on loopback, disabled
external bootstrapping, and enabled the Iris/Fides modules. It validates the
adapter and peer transport, not Fides reputation decisions or public-network
discovery. Its executable was built with Go 1.25.1. The bundled local-P2P
executable (`p2p4slips`) is also Linux ELF; building its checked-out source with
that Go version fails with `invalid reference to syscall.recvmsg` in the old
`golang.org/x/net/internal/socket` dependency.

The installation instructions are in [installation.md](installation.md#macos-hosts).
Live capture, daemon mode, Intel macOS, sustained-load behavior, and optional
integrations still need separate validation. In particular, daemon mode retains
its legacy double-fork implementation; the foreground spawn tests do not validate
that daemonization path. Linux firewall blocking and access-point management are
outside native macOS support.

## Remaining validation and implementation

This is **not** a claim that every option or every integration test passes.

1. Modernize the local-P2P submodule's networking dependencies, build a native
   `p2p4slips`, then test two peers exchanging reputation requests and responses.
   The current build fails before this backend can be exercised.
2. Test actual live capture with access to macOS BPF devices. The test account
   cannot open `/dev/bpf0`; growing-log tests do not prove capture works.
3. Make CYST's hardcoded `/run/slips.sock` configurable and test socket input.
   CYST input was not exercised end to end.
4. Validate daemonization and its system lock/log paths separately, plus explicit
   database load/save CLI modes, the web UI, sustained load, and Intel macOS.
5. Port and run the complete integration suite. The canonical shell runner uses
   Bash's `mapfile` (absent from macOS's bundled Bash 3.2) and repeatedly clears
   the cache. Existing peer fixtures also use Linux-only `/proc/net/route` or
   `ip route`. The unit suite was run directly; the complete canonical runner
   was not executed. Add isolated cache fixtures and native macOS CI before
   declaring all options supported.

## References

Python documents the [start methods, macOS fork warning, shared state, and queue
limitations](https://docs.python.org/3/library/multiprocessing.html). Homebrew
provides [Python 3.11](https://formulae.brew.sh/formula/python@3.11),
[Zeek](https://formulae.brew.sh/formula/zeek), and
[YARA](https://formulae.brew.sh/formula/yara).
The nfdump project documents its [explicit output formats and field
tokens](https://github.com/phaag/nfdump/blob/master/man/nfdump.1).
