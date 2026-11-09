# FAQ

## General and Docker

### Slips starting too slow in docker

Make sure you're not running many containers at the same time because they share kernel resources
even though they're isolated.


### Getting "Illegal instruction" error when running slips

If the tensorflow version you're using isn't compatible with your architecture,
you will get the "Illegal instruction" error and slips will terminate.

To fix this you can disable the modules that use tensorflow by adding
```rnn-cc-detection``` to the ```disable``` key in ```config/slips.yaml```


### Docker time is not in sync with that of the host

You can add your local /etc/localtime as volume in Slips Docker container by using:

```
docker run -it --rm --net=host --cap-add=NET_ADMIN -v /etc/localtime:/etc/localtime:ro --name slips stratosphereips/slips:latest
```

### Redis WARNING Memory overcommit must be enabled! in docker

This is a redis known issue, you can find the fix here
https://redis.io/docs/latest/operate/oss_and_stack/management/admin/#:~:text=Redis%20setup%20tips-,Linux,-Deploy%20Redis%20using

## Development and Architecture

### How does slips work?

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/slips_workflow.png" title="Slips Workflow">

* slips.py is the entry point, it’s responsible for starting all modules, and keeping slips up until the analysis is finished.

* slips.py starts the input process, which is the one responsible for reading the flows from the files given to slips using -f it detects the type of file, reads it and passes the flows to the profiler process. if slips was given a PCAP or is running on an interface , the input process starts a zeek thread that analyzes the pcap/interface using slips’ own zeek configuration and sends the generated zeek flows to the profiler process.

* slips.py also starts the update manager, it updates slips local TI files, like the ones stored in slips_files/organizations_info and slips_files/ports_info. later, when slips is starting all the modules, slips also starts the update manager but to update remote TI files in the background in this case.

* Once the profiler process receives the flows read by the input process, it starts to convert them to a structure that slips can deal with. it creates profiles and time windows for each IP it encounters.

* Profiler process gives each flow to the appropriate module to deal with it. for example flows from http.log will be sent to http_analyzer.py to analyze them.

* Profiler process stores the flows, profiles, etc. in slips databases for later processing. the info stored in the dbs will be used by all modules later. Slips has 2 databases, Redis and SQLite. it uses the sqlite db to store all the flows read and labeled. and uses redis for all other operations. the sqlite db is created in the output directory, meanwhite the redis database is in-memory. 7-8. using the flows stored in the db in step 6 and with the help of the timeline module, slips puts the given flows in a human-readable form which is then used by the web UI.

* when a module finds a detection, it sends the detection to the evidence process to deal with it (step 10) but first, this evidence is checked by the whitelist to see if it’s whitelisted in our config/whitelist.conf or not. if the evidence is whitelisted, it will be discarded and won’t go through the next steps

* now that we’re sure that the evidence isn’t whitelisted, the evidence process logs it to slips log files and gives the evidence to all modules responsible for exporting evidence. so, if CEST, Exporting modules, or CYST is enabled, the evidence process notifies them through redis channels that it found an evidence and it’s time to share the evidence.

* if the blocking module is enabled using -p, the evidence process shares all detected alerts to the blocking module. and the blocking module handles the blocking of the attacker IP through the linux firewall (supported in linux only)

* if p2p is enabled in config/slips.yaml, the p2p module shares the IP of the attacker, its’ score and blocking requests sent by the evidence process with other peers in the network so they can block the attackers before they reach them.

* The output process is slips custom logging framework. all alerts, warnings and info printed are sent here first for proper formatting and printing.



### What is the recommended development environment?

For minimum hassle when developing it's recommended to use ubuntu, install slips natively, and use your favorite IDE

### While developing, my module is not working and there's no errors shown to the CLI or printed to errors.log

Always make sure to run slips with -e 1, for example
    ./slips.py -e 1 -f <some_pcap> -o some_output_dir

The goal of suppressing errors by default is the most errors should be handled by the developers and modules should recover and continue working normally afterwards (if possible), so no need to show minor errorrs to users by default.

### What are all these Databases? Redis cache db, redis main database, SQLite, and Database manager?

- We use SQLite for storing all the flows and altflows, so if you want to store or retreive something you will most probably find the function you need already implemented there ( in slips_files/core/database/sqlite_db/database.py)
- Any other info goes in Redis.
- The DB manager is a Facade which acts as a proxy to both the sqlite and the redis databases. The goal of this is to add an abstraction layer between the developers and the dbs. To avoid the confusion of "i need to do X, is it in redis or sqlite?"
- The point above means that for each function you add to Redis or SQLite, you need to add a wrapper for it in the database_manager.py to be accessible to all modules.

### How does Redis communication work?
- If you run slips without any special arguments, Slips starts redis cache db ( redis server port 6379 db 1) and Redis main db (redis port 6379 db 1)
- You can start Slips with -m, which starts redis on a random available redis port in the range (32768 to 10000), or -P if you want to start redis on a specific port.
- Slips starts the redis server if it's not started by default.
- Slips uses its own redis.conf, it doesn't use the default one. you can find it in config/redis.conf.template.
- The cache db is shared among all running slips instances, and is persistent, meaning it is not deleted on each run unlike the main redis db (redis port 6379 db 1), which is overwritten every run.
- If you're gonna add a new redis channel to slips, remember to add it to the list of supported_channels in slips_files/core/database/redis_db/database.py


### How are the modules loaded?

- All modules in the modules/ directory that implement the IModule interface are automatically imported by slips, for more technical details check the load_modules() function in managers/process_manager.py
- Module names must use snake_case and follow the `x_y_doer` style used by names such as `http_analyzer`.
- Set the module class `name` to the same snake_case identifier as the module directory and main file.
- Keep the module directory name, the main module file, the config section name, and any module references in docs aligned with that same snake_case name.


### There's some missing code in all modules, what's happening?

- All modules implement the IModule interface in slips_files/common/abstracts/module.py, it ensures that all modules behave the same, for example they all shutdown the same, they all keep track of the redis channels they're using, they all have a common __init__(), they all forward msgs to the printer in the same way, etc.
- Any logic that will be duplicated accross all modules should be in this interface


### How does slips stop?

It all begins when input.py realizes there's no more flows arriving from the zeek files/suricata/nfdump file it's reading.

It's a good idea to read the code before checking this graph

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/how_slips_stops.jpg">

Evidence Handler is the only process that stops but keeps waiting in memory for new msgs to arrive until all other modules are done. because if any of the modules added an evidence, EvidenceHandler should be up to report and handle it or else it will be discarded.
Once all modules are done processing, EvidenceHandler is killed by the Process manager.


### How does the tests work?

- Running the tests locally should be done using ./tests/run_all_tests.sh
- It runs the unit tests first, then the integration tests.
- Please get familiar with pytest first https://docs.pytest.org/en/stable/how-to/output.html

### What does `generate_performance_plots` do?

- `Debug.generate_performance_plots` in [config/slips.yaml](config/slips.yaml) is a developer-only debugging switch for performance investigations.
- When it is `true`, Slips writes extra CSVs under `output/performance_plots/csv/`, including alert latency (`latency.csv`), profiler worker latency (`profiler_worker_*_latency.csv`), and throughput (`flows_per_minute.csv`).
- On shutdown, the process manager turns those CSVs into plots and metrics under `output/performance_plots/` and `output/metrics.txt`.
- Leave it `false` for normal development and production-style runs. Enabling it adds Redis bookkeeping, file writes, and plot-generation work that are only useful when diagnosing throughput or latency behavior.
- The plots shown in [docs/immune/stress_testing.md](docs/immune/stress_testing.md) were generated with this parameter enabled.

### Where and how do we get the GW info?

Using one of these 3 ways

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/gw_info.jpg">
