# Usage

Slips can read the packets directly from the **network interface** of the host machine, and packets and flows from different types of files, including

- Pcap files (internally using Zeek)
- Packets directly from an interface (internally using Zeek)
- Suricata flows (from JSON files created by Suricata, such as eve.json)
- Argus flows (CSV file separated by commas or TABs)
- Zeek/Bro flows from a Zeek folder with log files
- Nfdump flows from a binary nfdump file
- Text flows from stdin in zeek, argus or suricata form

It's recommended to use PCAPs.

All the input flows are converted to an internal format. So once read, Slips works the same with all of them.

After Slips runs on the given traffic, the output can be analyzed with the web interface. If the `modules/kalipso` submodule is checked out and installed separately, you can also use the Kalipso terminal interface.

In this section, we will explain how to execute each type of file in Slips.

Either you are [running Slips in docker](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#slips-in-docker) or [locally](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-slips-natively), you can run Slips using the same below commands and configurations.


## Reading the input

The table below shows the different parameter Slips uses for different inputs.


<style>
table {
  font-family: arial, sans-serif;
  border-collapse: collapse;
  width: 100%;
}

td, th {
  border: 1px solid #dddddd;
  text-align: left;
  padding: 8px;
}

tr:nth-child(even) {
  background-color: #dddddd;
}
</style>



<table>
	<tr>
		<th>File/interface</th>
		<th>Argument</th>
		<th>Example command</th>
	</tr>
	<tr>
		<td>Network interface (*)</td>
		<td>-i</td>
		<td>./slips.py -i en0</td>
	</tr>
	<tr>
		<td>pcap</td>
		<td>-f</td>
		<td>./slips.py -f test.pcap</td>
	</tr>
	<tr>
		<td>Argus binetflow</td>
		<td>-f</td>
		<td>./slips.py -f test.binetflow</td>
	</tr>
	<tr>
		<td>Zeek/Bro folder/log</td>
		<td>-f</td>
		<td>./slips.py -f zeek_files</td>
	</tr>
	<tr>
		<td>Nfdump flow</td>
		<td>-f</td>
		<td>./slips.py -f test.nfdump </td>
	</tr>
    <tr>
		<td>Suricata flows</td>
		<td>-f</td>
		<td>./slips.py -f suricata.json </td>
	</tr>
    <tr>
		<td>stdin</td>
		<td>-f</td>
		<td>./slips.py -f zeek </td>
	</tr>
    <tr>
		<td>Access Point</td>
		<td>-ap</td>
		<td>./slips.py -ap wifi_interface,eth_interface </td>
	</tr>

</table>

(*) To find the interface in Linux, you can use the command ```ifconfig```.

There is also a configuration file **config/slips.yaml** where the user can set up parameters for Slips execution and models
separately. Configuration of the **config/slips.yaml** is described [here](#modifying-the-configuration-file).

## Daemonized vs interactive mode

Slips can run in two modes:

| Mode | How to start it | What happens |
| --- | --- | --- |
| **Interactive** (default) | `./slips.py -i eth0` | Slips stays in your terminal. Press Ctrl-C to stop it. |
| **Daemon** | `./slips.py -i eth0 -D` | Slips runs in the background and gives you your terminal back. |

Output files go to `output/<some_dir>` unless you pass `-o`. Slips prints the
output directory when it starts.

By default you don't need root to run Slips. If you point the output directory
to a folder owned by root, run Slips with sudo or give your user write access
to that folder.

### Running Slips as a daemon

```bash
./slips.py -i eth0 -o output/my-network -w -D
```

What to expect:

- **Startup:** the command waits up to 30 seconds, then prints the daemon's
  PID and log file. If startup takes longer, it returns anyway and Slips keeps
  starting in the background. Startup errors are printed in the terminal.
- **Follow progress:** `tail -f output/my-network/slips.log`. The line
  `Slips daemon core workers started` means Slips is up.
- **Logs:** written to the output directory, same as interactive mode:
  `slips.log` for messages and `errors.log` for errors. Old logs are not
  erased when a daemon starts.
- **One daemon at a time:** only one daemon can run. Other non-daemon Slips
  runs can run next to it.
- **No sudo needed for the PID file:** Slips stores it in
  `permanent/slips_daemon.lock` (inside `parameters.permanent_dir`). You still
  need the usual permissions to capture on an interface.

### Find, stop and restart running instances

Run these from the Slips folder, using the same Python environment you used to
start Slips:

| Command | What it does |
| --- | --- |
| `./slips.py --list-instances` | Shows every running Slips instance started from this folder. |
| `./slips.py --stop` | Stops Slips if only one instance is running. |
| `./slips.py --stop 12345` | Stops the instance with PID `12345`. |
| `./slips.py --stop all` | Stops every running instance from this folder. |
| `./slips.py --restart` | Restarts the running daemon. |
| `./slips.py --restart 12345` | Restarts the daemon with PID `12345`. |

These commands work on their own. Do not combine them with `-i`, `-f`, `-c` or
other analysis options.

#### Listing instances

`--list-instances` shows a table with each instance's PID, how it was started,
its web interface port, its interface or input file, and its output folder.

- It finds daemons, normal terminal runs, and runs started with `&` or `nohup`.
- It does not list Slips' internal worker processes, or Slips runs started from
  a different Slips folder.
- A `-` in the **WEB PORT** column means no web interface was found for that
  run (disabled, still starting, or stopped).
- Listing is read-only: it does not start anything or touch any database.

#### Stopping

- If more than one instance is running, `--stop` lists them and asks you to pick
  a PID. It never guesses.
- Stopping is the same as pressing Ctrl-C: Slips saves what it learned, stops
  its workers and Zeek, and closes its web interface.
- The command waits up to 45 seconds. If something is still running after that,
  it prints the remaining PIDs and exits with an error instead of force-killing
  them. Check that run's `errors.log` to see why.
- Stopping a PCAP analysis early means the rest of the PCAP is not analyzed.
- Stopping never deletes your saved history or alerts.
- `-S`/`--stopdaemon` has been replaced by `--stop`.

#### Restarting

`--restart` stops the running daemon, then starts it again with exactly the
same command, Python interpreter and working folder.

- It only restarts **daemons**. It cannot restart an interactive run, or a
  daemon that already stopped, because it needs the running daemon to know how
  it was started.
- It waits up to 5 minutes for Slips to finish saving, and prints progress every
  10 seconds. If the stop fails, nothing new is started.
- The new daemon reads your configuration files again, so config changes take
  effect after a restart.
- Your original options (`-i`, `-o`, `-c`, `-w`, `--web-port`, `--keep-history`)
  are kept as they were. Restart does not add `--keep-history` for you.

On macOS, use the Python from your virtual environment, for example:

```bash
.venv-macos/bin/python slips.py --restart
```

## Running Several slips instances

Each Slips run needs Redis. By default Slips starts and uses Redis on port 6379:

| Redis database | What it holds | Shared between runs? | Cleared on startup? |
| --- | --- | --- | --- |
| Port 6379, DB 0 | The current run's profiles, time windows and alerts | No | Yes (set `deletePrevdb: false` to skip) |
| Port 6379, DB 1 | Cache, such as threat intelligence | Yes, by all runs | No |

To run several instances at the same time, use `-m`. Each instance then gets
its own Redis server on a free port between 32768 and 32850 (or the port you
choose with `-P <port>`). Slips picks the port in `get_redis_port()`:

| How Slips runs | Redis port for DB 0 |
| --- | --- |
| Live traffic (`-i`, `-g`) or any run without `-m` | 6379 |
| `-m` (for example `-m -f file.pcap`) | First free port from 32768 to 32850 |
| `-P <port>` | The port you give |

All instances still share the cache in port 6379,
DB 1. Each run's output goes to `output/<filename>_<timestamp>/`.

- Slips starts the Redis servers it needs automatically.
- On macOS, you may get a popup asking to allow the new port. Click **Allow**.
- Running Slips twice on the same file or interface creates a new output folder
  each time, named after the input and the start time.
- Each web interface only shows the run that started it. If you use `-w` on
  several runs, give each one its own `--web-port`.
- When you are done, close the Redis servers Slips started with
  `./slips.py --killall`.

### Analyze a PCAP while a live capture is running

You can analyze a PCAP (or a finished Zeek log folder) without disturbing a
live capture that is already running. Use `-m`, `-f` and `-o` together:

```bash
nice -n 15 ./slips.py -m -w \
  -c config/slips.yaml \
  --web-port 55002 \
  -f dataset/test7-malicious.pcap -o output/pcap-analysis-01
```

- Use your normal config file with `-c`. You do not need to copy or edit it.
- Pick a web port that is not already used by the live capture, then open
  `http://127.0.0.1:55002/`.
- Use a new `-o` folder for every analysis you want to keep. Reusing a folder
  replaces the older analysis.
- `nice` lowers the PCAP run's CPU priority so the live capture comes first. It
  does not limit memory, so on a machine with little RAM, analyze PCAPs
  somewhere else.
- When the analysis finishes, answer `n` (or press Enter) to keep its web
  interface open. Keep that terminal open while you browse.
- Do not use `--keep-history`, `--clearcache` or `-P 6379` with this run. Slips
  refuses them.

Slips keeps this analysis separate from the live one automatically:

| What | Live capture | PCAP analysis |
| --- | --- | --- |
| Redis | Port 6379, DB 0 | Its own Redis port (32768-32850) |
| Host identity DB | `permanent/host_profiles/hosts.sqlite` | `<output>/host_profiles/hosts.sqlite` |
| Regex generator store | `permanent/databases/regex_store/` | `<output>/regex_generator/` |
| T Cell store | `<output>/t_cell/` (or `permanent/` if you set `persistent_store_dir`) | `<output>/t_cell/` |
| Threat intelligence feed downloads | `permanent/remote_data_files/` | The same folder |
| Whitelist | Your whitelist | The same whitelist (a copy is kept in `<output>/metadata/`) |
| Redis and web passwords | Yours | The same files in `permanent/`, so the same login works |
| Zeek files | As configured | Kept inside the analysis output |
| Web interface | As configured | Only reachable from this machine (localhost) |
| Automatic Slips updates | As configured | Turned off |
| Threat intelligence cache | Port 6379, DB 1 | Shared with the live capture |

Your config file is never changed. The analysis' **Configuration** tab in the
web interface shows the settings it actually used.

To open the web interface of a remote machine, forward the port over SSH from
your own computer:

```bash
ssh -N -L 127.0.0.1:55002:127.0.0.1:55002 user@remote-host
```

### Keep detections across a live-interface restart

Use `--keep-history` with the same interface and output folder every time you
start Slips:

```bash
./slips.py -i eth0 -o output/my-network --keep-history -w
```

- **First start:** if the output folder has no `databases/flows.sqlite` yet,
  Slips starts fresh. You don't need any setup step.
- **Later starts:** Slips keeps the old alerts, evidence and web history, so the
  web interface shows detections from before the restart.
- Temporary run state in Redis DB 0 is still cleared, so the old run can't
  affect new detections. The shared cache (DB 1) is kept.
- Stop the previous Slips run first. Slips refuses to start two runs that write
  to the same output folder or use the same web port.
- `--keep-history` cannot be used with `-m` or with a `-P` port other than 6379.
  A separate PCAP analysis (see above) can still run next to it.
- To start over with an empty history, run without `--keep-history`.

Slips does not keep everything forever: old flows, alerts and logs are removed
or archived so long runs don't fill your disk. See
[How Slips forgets the past](data_retention.md) for the limits and how to
change them.


## Closing redis servers

Slips uses a random unused port in the range in the range (32768 to 32850).

When running slips, it will warn you if you have more than 1 redis serve open using the following msg

    [Main] Warning: You have 2 redis servers running. Run Slips with --killall to stop them.

you can use the -k flag to kill 1 open redis server, or all of them using the following command

    ./slips.py -k

You will be prompted with the following options

    Choose which one to kill [0,1,2 etc..]

    [0] Close all servers
    [1] dataset/sample_zeek_files - port 32768
    [2] dataset/sample_zeek_files - port 32769
    [3] dataset/sample_zeek_files - port 32770

you can select the number you want to kill or 0 to close all the servers.

Note that if all ports from (32768 to 32850) are unavailable, slips won't be able to start, and you will
be asked to close all all of them using the following warning

    All ports from 32768 to 32769 are used. Unable to start slips.

    Press Enter to close all ports.

You can press enter to close all ports, then start slips again.


## Growing zeek directories

Due to issues running Slips on an interface on MacOS, we added the option ```-g```
to run slips on a growing zeek directory

so you can run Slips in docker, mount a <zeekdir> into the container
then start zeek inside it using the following command

``` bro -C -i <interface> tcp_inactivity_timeout=60mins tcp_attempt_delay=1min <path_to>/slips/zeek-scripts```

Then start Slips on your zeek dir using -g <dir> and specify the interface you're monitoring with -i.

```./slips.py -e 1 -g <zeek_dir> -i <interface>```

By using the -g parameter, slips will treat your given zeek directory as growing (the same way it treats zeek
directories generated by using slips with -i) and will keep waiting for flows unless stopped by the user.

NOTE: When using -g, it is mandatory to give Slips the same interface zeek is running on with -i.


## Reading the output
The output process collects output from the modules and handles the display of information on screen. Currently, Slips'
analysis and detected malicious behaviour can be analyzed as following:

- **alerts.json and alerts.txt in the output folder** - collects all evidences and detections generated by Slips in a .txt and .json formats.
- **alerts_summary.log in `output/alerts/`** - when the `alert_summary` module is enabled, stores one analyst-facing paragraph per alert based on grouped correlated evidence and, when needed, recursive reduction summaries from the shared LLM reply path.
- **`llm-summary/alert_summary.log` in the output folder** - when the `alert_summary` module is enabled, stores operational logs for alert queueing, prompt-budget checks, recursive reduction layers, LLM requests, responses, failures, and shutdown handling according to `alert_summary.log_verbosity`.
- **`LLM/llm.log` in the output folder** - when the shared `LLM` module is enabled, stores backend readiness, per-request queueing, dispatch, success or failure, and response publication details for the run.
- **log files in a folder _current-date-time_** - separates the traffic into files according to a profile and timewindow and summarize the traffic according to each profile and timewindow.
- **Web interface** - browser based GUI for viewing slips detections, incoming and outgoing traffic, and an organized timeline of flows.


### The Web Interface

Enable the run-specific local interface with `-w`:

```bash
./slips.py -e 1 -f dataset/test7-malicious.pcap -w
```

Then open `http://localhost:55000/`. You can also enable it with `web_interface.enabled: true` in `config/slips.yaml` and change `web_interface.port`.

The interface is read-only, binds only to `127.0.0.1`, and shows exactly the run that launched it. It is not a receiver for remote Slips systems and is not a multi-instance database selector. It reads this run's Redis database, `output/<run>/databases/flows.sqlite`, `output/<run>/error.log`, and current process metrics. Its own operational log is `output/<run>/web_interface/server.log`.

The Overview, Alerts, Evidence, and Hosts tabs provide sorting, search, filters, module health, alert-to-evidence-to-flow drill-down, all evidence including records outside alerts, and host identity/DNS/TI/traffic context. See [Local web interface](web_interface.md) for exact data sources and behavior.

On Linux, a Docker container must use `--net=host` to reach the intentionally loopback-only listener. Ordinary Docker port publishing cannot forward to a service bound to the container's own loopback address.

## Saving the database

Slips uses redis to store analysis information. you can save your analysis for later use by running slips with ```-s```,

For example:

```sudo ./slips.py -f dataset/test7-malicious.pcap -s```

Your .rdb saved database will be stored in the default output dir.

Note: If you try to save the same file twice using ```-s``` the old backup will be overwritten.

You can load it again using ```-d```, For example:

```sudo ./slips.py -d redis_backups/hide-and-seek-short.rdb```

The local interface does not upload, browse, or switch saved Redis databases; loading an `.rdb` remains a separate Slips operation.

Note: saving and loading the database requires **root privileges** and is only supported in linux.

This feature isn't supported in docker due to problems with redis in docker.


_DISCLAIMER_: When saving the database you will see the following
warning

    stop-writes-on-bgsave-error is set to no, information may be lost in the redis backup file

This configuration is set by slips so that redis will continue working even if redis
can't write to dump.rdb.

Your information will be lost only if you're out of space and redis can't write to dump.rdb or if you
don't have permissions to write to /var/lib/redis/dump.rdb, otherwise you're fine and
the saved database will contain all analyzed flows.


## Whitelisting

Slips allows you to whitelist some pieces of data in order to avoid its processing.
In particular, you can whitelist an IP address, a domain, a MAC address or a complete organization.
You can choose to whitelist what is going __to__ them, what is coming __from__ them, or both directions.
You can also choose to whitelist the flows, so they are not processed, or alerts, so
you see the flows but don't receive alerts on them. The idea of whitelisting is to avoid
processing any communication to or from these iocs, not to avoid any packet that
contains that ioc. For example, if you whitelist the flow of the domain slack.com, then a DNS
request to the DNS server 1.2.3.4 asking for slack.com will still be shown.


This whitelist can be enabled or disabled by changing the ```enable_local_whitelist``` key in `config/slips.yaml`.

When monitoring a live interface, Slips also excludes its own information
lookup connections from profiling. Python lookup sockets, including update
checks, are matched by their full source and destination IPs, ports, and
protocol. The external `whois` command is covered by a ten-second allowance
for TCP port 43 from the current
local interface addresses. These automatic exclusions apply only to the
current Slips run and do not affect imported captures. Redis marks expire
automatically, including when run history is retained. The database import
also reads local interface addresses without making a public-IP request;
public-IP lookups made by running modules use the same socket tracking.

Do not modify the default ```config/whitelist.conf``` in place. Create a copy, update your copy, and set ```whitelists.local_whitelist_path``` in the Slips config file you are using to point to that copy.

Example:

```bash
cp config/whitelist.conf config/my_whitelist.conf
cp config/slips.yaml config/my_slips.yaml
```

Then set ```local_whitelist_path: config/my_whitelist.conf``` in ```config/my_slips.yaml``` and run Slips with:

```bash
./slips.py -c config/my_slips.yaml -f dataset/test7-malicious.pcap
```

The attacker and victim of every evidence are checked against the whitelist. In addition to all the related IPs, DNS resolutions, SNI, and CNAMEs of the attacker and teh victim. If any of them are whitelisted, the flow/evidence is discarded.

Whitelists now use bloom filters to speed up the process of checking if an IoC is whitelisted or not.

### Flows Whitelist
If you whitelist an IP address, Slips will check all flows and see if you are whitelisting to them or from them.

If you whitelist a domain, Slips will check:
- Domains in HTTP Host header
- Domains in the SNI field of TLS flows
- All the Domains in the DNS resolution of IPs (there can be many) (be careful that the resolution takes time, which means that some flows may not be whitelisted because Slips doesn't know they belong to a domain).
- Domains in the CN of the certificates in TLS

If you whitelist an organization, then:
- Every IP is checked against all the known IP ranges of that organization
- Every domain (SNI/HTTP Host/IP Resolution/TLS CN certs) is checked against all the known domains of that organization
- ASNs of every IP are verified against the known ASN of that organization

If you whitelist a MAC address, then:
- The source and destination MAC addresses of all flows are checked against the whitelisted mac address.


### Blocking Whitelist

To keep flows, evidence and alerts while preventing firewall blocking and ARP
poisoning, put this rule in your copied whitelist file:

```csv
ip,192.168.1.128,both,blocking
```

### Alerts Whitelist

To suppress one evidence type only when a specific source IP connects to a
specific **destination port**, add this line to your copied whitelist file:

```csv
ip,192.168.1.163->*:902,src,alerts,UNKNOWN_PORT
```

All three conditions must match: the source is `192.168.1.163`, the destination
port is `902`, and the evidence type is `UNKNOWN_PORT`. `*` means any destination
IP. The source port can be anything. Other sources, destination ports and evidence
types remain eligible for alerts. The rule keeps flow processing enabled and
excludes matching future evidence from alert scoring; it does not remove old
evidence or alerts. Existing broader whitelist rules still apply independently.

Use `[2001:db8::10]->*:902` for an IPv6 source. The source must be one IP,
and the destination port must be an integer from 1 to 65535. This syntax requires
`src,alerts`; ICMP cannot match because it has no ports. Omit the fifth column
to apply to every evidence type for that source and destination port. The source
must be recorded directly in the evidence, rather than inferred from a domain.

This differs from `ip,192.168.1.163:902,src,alerts,UNKNOWN_PORT`, which matches
**source port** 902. Restart Slips once after upgrading to load the new code.
After that, edits use the normal whitelist refresh; the web editor also supports
the destination-port condition.

If you whitelist some piece of data not to generate alerts, the process is the following:

- If you whitelisted an IP
    - We check if the source or destination IP of the flow that generated that alert is whitelisted.
    - We check if the content of the alert is related to the IP that is whitelisted.

- If you whitelisted a domain
    - We check if any domain in alerts related to DNS/HTTP Host/SNI is whitelisted.
    - We check also if any domain in the traffic is a subdomain of your whitelisted domain. So if you whitelist 'test.com', we also match 'one.test.com'

- If you whitelisted an organization
    - We check that the ASN of the IP in the alert belongs to that organization.
    - We check that the range of the IP in the alert belongs to that organization.

- If you whitelist a MAC address, then:
  - The source and destination MAC addresses of all flows are checked against the whitelisted mac address.

### Tranco whitelist

In order to reduce the number of false positive alerts,
Slips uses Tranco whitelist which contains a research-oriented top sites
ranking hardened against manipulation here https://tranco-list.eu/

Slips download the top 10k domains from this list and by default and
whitelists all evidence and alerts from and to these domains.
Slips still shows the flows to and from these IoC.

Redis storage detail:

- Slips stores the full downloaded Tranco whitelist in Redis under
  `tranco_whitelisted_domains` while preserving download order.
- Other modules, such as `RegexGenerator`, read the first
  `whitelists.tranco_top_benign_limit` entries from that ordered whitelist
  cache as benign data without losing ranking order.

The tranco list is updated daily by default in Slips, but you can change how often to update it using the
```online_whitelist_update_period``` key in config/slips.yaml.

Tranco whitelist can be enabled or disabled by changing the ```enable_online_whitelist``` key in `config/slips.yaml`.

### Whitelisting Example
Do not edit the default ```config/whitelist.conf``` directly. Copy it, set ```local_whitelist_path``` in your copied Slips config file to the copied whitelist file, and modify that copied whitelist instead.

For example, your copied whitelist file can contain:


    "IoCType","IoCValue","Direction","IgnoreType","EvidenceType"
    ip,1.2.3.4,both,alerts
    ip,192.168.1.163:5353,dst,alerts
    ip,[fe80::1]:5353,dst,alerts
    ip,192.168.1.10->*:902,src,alerts,UNKNOWN_PORT
    ip,192.168.1.128,both,blocking
    domain,google.com,src,flows
    domain,apple.com,both,both
    ip,94.23.253.72,both,alerts
    ip,91.121.83.118,both,alerts
    mac,b1:b1:b1:c1:c2:c3,both,alerts
    organization,microsoft,both,both
    organization,facebook,both,both
    organization,google,both,both
    organization,apple,both,both
    organization,twitter,both,both
    uri,/health,both,flows

### Whitelist columns

Write one rule per line, with four required columns and an optional fifth:

```text
IoCType,IoCValue,Direction,IgnoreType,EvidenceType
```

Use commas between columns and do not quote rule values. Use lowercase names
for the type, direction and mode. Start explanation lines with `;`; start a
disabled rule with `#` so Slips removes that matching rule from its whitelist
cache. Do not put a comment after a rule on the same line.

| Column | What it does and why |
| --- | --- |
| `IoCType` | Chooses what to match: `ip`, `domain`, `organization`, `mac` or `uri`. IoC is the item being whitelisted. |
| `IoCValue` | The actual address, name or request path. For example, `192.168.1.10`, `example.com`, `apple`, `a1:a2:a3:a4:a5:a6` or `/health`. IP values can also include port conditions, described below. |
| `Direction` | `src` matches the source; `dst` matches the destination; `both` accepts either side. These are the roles in the flow or evidence, regardless of which host profile you opened. An evidence's attacker is not necessarily its source. |
| `IgnoreType` | Chooses whether to skip flow processing, exclude evidence from scoring and alerts, or prevent enforcement while keeping detections. See the modes below. |
| `EvidenceType` (optional) | Limits an `ip` rule with mode `alerts` to one detection type, such as `UNKNOWN_PORT` or `ARP_SCAN`. Use the internal name from `EvidenceType` in `slips_files/core/structures/evidence.py`, not a display label such as "Unknown port". Omit it or leave it empty to match all types. Other item types and modes do not support this column. |

The four `IgnoreType` modes have different effects:

| Mode | Effect |
| --- | --- |
| `alerts` | Keep processing flows. Exclude matching evidence from host scoring and alert generation. Retained evidence is marked whitelisted/excluded and can be inspected with **Show excluded** in the web. This suppresses the detection's contribution, not just a notification. |
| `flows` | Skip matching flow records before detection. Those records cannot produce detections. Use `alerts` instead when you still want the flows analyzed. |
| `both` | Skip matching flows and also exclude matching evidence from scoring and alerts. |
| `blocking` | Keep flows, evidence, host scores and alerts, but prevent firewall blocking and ARP poisoning of the specified IP. Requires one individual IP, `Direction=both`, and no port or evidence type. It protects that IP, not every host communicating with it. |

Supported values and their limits:

- **IP address:** one IPv4 or IPv6 address. Without a port condition it applies
  on every port. Subnets and address ranges, such as `192.168.1.0/24`, are not
  supported.
- **IP and its own port:** `192.168.1.10:902` or `[2001:db8::10]:902` requires
  both the address and its port to match on the same side. With `src`, this is
  the **source port**; with `dst`, it is the **destination port**. With `both`,
  either endpoint can match, but its IP and port must match together.
- **Any IP on a port:** `*:902` matches that port on the side selected by
  `Direction`. These port forms accept a single number from 0 to 65535 without
  leading zeros. They have no TCP/UDP selector. Use separate lines for additional
  ports.
- **Source IP connecting to a destination port:** `192.168.1.10->*:902` matches
  that source connecting to port 902 on any destination IP, regardless of source
  port. Use `[2001:db8::10]->*:902` for IPv6. Requires `src,alerts` and a port
  from 1 to 65535. The evidence must record the source IP and destination port;
  ICMP cannot match because it has no ports.
- **Domain:** a domain and its subdomains, without a URL scheme or path. Slips
  must know the domain's relationship to the host through DNS or protocol data;
  a missing relationship can prevent a match.
- **Organization:** one of `google`, `microsoft`, `apple`, `facebook` or `twitter`.
  Matches known IP ranges, domains and ASNs of that organization; arbitrary
  organization names are not accepted.
- **MAC address:** six pairs separated by colons. Slips must have recorded the
  host's MAC address to match it.
- **URI:** an exact HTTP request path, including the query string if present,
  with a maximum of 256 characters and no commas. `/health` does not match
  `/health?check=1`; this is not a prefix or regular expression. Use `both,flows`
  or `both,both`. URI matching ignores direction and IP/port, and skips matching
  request records, not necessarily their parent connections.

For example, this rule keeps flows but excludes only `UNKNOWN_PORT` evidence
for one source connecting to destination port 902:

```text
ip,192.168.1.10->*:902,src,alerts,UNKNOWN_PORT
```

All conditions on that line must match. Other whitelist rules still apply
independently, so a broader rule can suppress the same traffic regardless of
this evidence-type restriction. For the same type, value and evidence type,
the last rule replaces earlier entries even if their directions or modes differ.
Adding a rule does not delete old evidence or alerts.

## Popup notifications

Slips can display a desktop notification when a host crosses the alert threshold.
The banner shows the host IP and name, the latest finding, and the host score
with its alert threshold. Detailed evidence remains available in the web interface.

This feature is disabled by default. You can enable it by changing ```popup_alerts``` to ```yes``` in ```config/slips.yaml```

This feature is supported in Linux and it requires root privileges.

On macOS, Slips prepares a small native **Slips** notification app with its logo
in `~/Applications/Slips Notifications.app`. This happens in the background,
outside alert processing, and requires Apple's command-line developer tools
(`swiftc`, `sips` and `codesign`). The signed app is reused across runs.
Allow notifications for **Slips** in **System Settings → Notifications**.
Check Focus settings if banners are hidden. Notification permission is specific
to this app and is separate from Script Editor's permission.

If the native app cannot be built, Slips logs a warning and falls back to the
built-in `osascript` command. That fallback uses Script Editor's notification
permission and icon. Neither macOS backend requires root. Restart Slips after
enabling `popup_alerts` or updating the notification code.

This feature is not supported in Docker

## Slips permissions

Slips doesn't need root permissions unless you

1. use the blocking modules (Firewall and ARP poisoner) ( with -p )
2. are saving the database ( with -d )

If you can't listen to an interface without sudo, you can run the following command to let any user use zeek to listen to an interface not just root.

```
sudo setcap cap_net_raw,cap_net_admin=eip /<path-to-zeek-bin/zeek
```

Even when Slips is run using sudo, it drops root privileges  in modules that don't need them.


## Modifying the configuration file

Slips has a ```config/slips.yaml``` the contains user configurations for different modules and general execution. Below are some of Slips features that can be modifie with respect to the user preferences.

Do not modify the default ```config/slips.yaml``` in place. Keep it as the shipped baseline, create a copy for your local changes, and run Slips with that copy using ```-c```.

Example:

```bash
cp config/slips.yaml config/my_slips.yaml
./slips.py -c config/my_slips.yaml -f dataset/test7-malicious.pcap
```

### Generic configuration

**Time window width.**

Each IP address that appears in the network traffic of the input is represented as a profile in Slips. Each profile is divided into time windows. Each time window is 1 hour long by default, and it gathers the network traffic and its behaviour for the period of 1 hour. The duration of the timewindow can be changed in the the config/slips.yaml using

```time_window_width```


**Analysis Direction**

```analysis_direction``` can either be ```out``` or ```all```

The ```analysis_direction``` parameter controls which traffic flows are processed and analyzed by SLIPS. It determines whether SLIPS should focus on outbound traffic (potential data exfiltration), inbound traffic (incoming attacks), or analyze traffic in both directions.
In ```all``` mode, SLIPS creates profiles for both internal (A) and external (B) IP addresses, and analyzes traffic in both directions (inbound and outbound).

In ```out``` mode, SLIPS still creates profiles for internal (A) and external (B) IP addresses, but only analyzes the outgoing traffic from the internal (A) profiles to external (B) destinations.

This parameter allows you to tailor SLIPS's analysis focus based on your specific monitoring requirements, such as detecting potential data exfiltration attempts (```out``` mode) or performing comprehensive network monitoring in both directions (```all``` mode).

**Persistent runtime data**

Use ```permanent_dir``` to choose where Slips stores databases and runtime-generated files that must persist across different Slips runs and should not be overwritten.

This includes persistent artifacts such as ```p2p_trust_runtime/```,
```databases/regex_store/```, and shared module databases like the Fides cache
under ```databases/```.

**Live Slips auto update**

Use ```update.auto_update_slips``` to enable or disable automatic live updates of the installed Slips version.

```yaml
update:
  auto_update_slips: false
```

This setting is separate from the runtime ```feeds_update_manager``` module, which only updates TI feeds and related files.
When a remote TI feed responds with an empty or whitespace-only body, Slips keeps the last valid
entries for that feed and records the skipped update in `slips.log`. A later
nonempty version is loaded at the next scheduled check. Invalid individual
entries are skipped and noted in `slips.log`; they do not stop the rest of a
valid feed from loading.

Automatic Slips updates may overwrite the default config files shipped with Slips. If you want to keep local config changes safe, do not modify the default config files. Create and use your own config files with different names instead.

Use ```update.channel_to_update_slips_from``` in slips.yaml to choose the update channel:

- ```stable``` -> ```origin/master```
- ```unstable``` -> ```origin/develop```
- ```testing``` -> uses the branch specified in ```update.testing_branch_to_update_slips_from```



<div class="zoom">
<img style="max-width:500px;max-height:500px;" src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/directions.png" title="Figure 1. Out and all directions">
</div>


### Disabling a module

You can disable modules easily by appending the module name to the ```disable``` list.

The module name to disable should be the same as the name of it's directory name inside modules/ directory

### ML Detection

The ```mode=train``` should be used to tell the MLdetection1 module that the flows received are all for training.

The ```mode=test``` should be used after training the models, to test unknown data.

You should have trained at least once with 'Normal' data and once with 'Malicious' data in order for the test to work.

### Blocking

This module is enabled only using the ```-p``` parameter and needs an interface to run.

Usage example:

```sudo ./slips.py -i wlp3s0 -p```

Slips needs to be run as root so it can execute iptables commands.

In Docker, since there's no root, the environment variable ```IS_IN_A_DOCKER_CONTAINER``` should be set to ```True``` to use 'sudo' properly.

If you use the latest Dockerfile, it will be set by default. If not, you can set it manually by running this command in the docker container

```export IS_IN_A_DOCKER_CONTAINER=True```



### VirusTotal

In order for virustotal module to work, you need to add your VirusTotal API key to the file
```config/vt_api_key```.

You can specify the path to the file with VirusTotal API key in the ```api_key_file``` variable.

The file should contain the key at the start of the first line, and nothing more.

If no key is found, virustotal module will not start.


### Exporting Alerts

Slips can export alerts to different systems.

Refer to the [exporting section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html) for detailed instructions on how to export.


## Logging

To enable the creation of log files, there are two options:

1. Running Slips with ```verbose``` and ```debug``` flags
2. Using errors.log and running.log

#### Zeek log files

You can enable or disable deleting zeek log files after stopping slips by setting ```delete_zeek_files``` to  yes or no.

DISCLAIMER: zeek generates log files that grow every second until they reach GBs, to save disk space,
Slips deletes all zeek log files after 1 day when running on an
interface. this is called zeek rotation and is enabled by default.

You can disable rotation by setting ```rotation``` to ```no``` in ```config/slips.yaml```

Check [rotation section](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#rotation) for more info

But you can also enable storing a copy of zeek log files in the output
directory after the analysis is done by setting ```store_a_copy_of_zeek_files``` to yes,
or while zeek is still generating log files by setting ```store_zeek_files_in_the_output_dir``` to yes.
When both settings are enabled, shutdown keeps the logs already in the output
directory without copying that directory onto itself.
this option stores a copy of the zeek files present in ```zeek_files/``` the moment slips stops.
so this doesn't include deleted zeek logs.

Once slips is done, you will find a copy of your zeek files in ```<output_dir>/zeek_files/```

DISCLAIMER: Once slips knows you do not want a copy of zeek log files after slips is done by enabling
 ```delete_zeek_files``` and disabling ```store_a_copy_of_zeek_files``` parameters,
it deletes large log files periodically (like arp.log).


#### Rotation of zeek logs

Rotation is done in zeek files to avoid growing zeek log files and save disk space.

Rotating is only enabled when running on an interface.

By default, Slips rotates zeek files every 1 day. this can be changed in ```config/slips.yaml```
by changing the value of ```rotation_period```

```rotation_period``` value can be written as a numeric constant followed by a time unit where
the time unit is one of usec, msec, sec, min, hr, or day which respectively
represent microseconds, milliseconds, seconds, minutes, hours, and days.
Whitespace between the numeric constant and time unit is optional. Appending the letter s to the
time unit in order to pluralize it is also optional.
Check [Zeek rotation interval](https://docs.zeek.org/en/master/script-reference/types.html#type-interval) for more details

Slips has an option to not delete the rotated zeek files immediately by setting the
```keep_rotated_files_for``` parameter.

This is equivalent to telling slips, Delete all logs that happened before the last  ```keep_rotated_files_for``` days.

```keep_rotated_files_for``` value supports days only.


####  Running Slips with verbose and debug flags

We use two variables for logging, ```verbose``` and ```debug```, they both range from 0 to 3.

Default value for debug is 0. so no errors are printed by default.

Default value for verbose is 1. so basic operations and proof of work are printed by default.

To change them, We use ```-v``` for verbosity and ```-e``` for debugging

For example:

```./slips.py -c config/slips.yaml -v 2 -e 1 -f zeek_dir ```

Verbosity is about less or more information on the normal work of slips.

For example: "Done writing logs to file x."

Debug is only about errors.

For example: "Error reading threat intelligence file, line 4, column 2"

To more verbosity level, the more detailed info is printed.

The more debug level, the more errors are logged.

Below is a table showing each level of both.

<table>
<tbody>
<tr style="height: 22px;">
<td style="height: 22px;">&nbsp;</td>
<td style="height: 22px;">&nbsp;Verbosity</td>
<td style="height: 22px;">&nbsp;Debugging</td>
</tr>
<tr style="height: 22px;">
<td style="height: 22px;">&nbsp;0</td>
<td style="height: 22px;">&nbsp;Don't&nbsp;print</td>
<td style="height: 22px;">&nbsp;Don't print</td>
</tr>
<tr style="height: 22px;">
<td style="height: 22px;">1&nbsp;</td>
<td style="height: 22px;">&nbsp;Show basic operation, proof of work&nbsp;</td>
<td style="height: 22px;">&nbsp;Print exceptions</td>
</tr>
<tr style="height: 22px;">
<td style="height: 22px;">2&nbsp;</td>
<td style="height: 22px;">&nbsp;Log I/O operations and filenames</td>
<td style="height: 22px;">&nbsp;Unsupported and unhandled types (cases that may cause errors)</td>
</tr>
<tr style="height: 22px;">
<td style="height: 22px;">3&nbsp;</td>
<td style="height: 22px;">&nbsp;Log database/profile/timewindow changes</td>
<td style="height: 22px;">&nbsp;Red warnings that need examination - developer warnings</td>
</tr>
</tbody>
</table>

#### Using errors.log and running.log

Slips logs errors to `errors.log` in the selected output directory in both
interactive and daemon mode, whether or not `-e` is used.
See [Daemonized vs interactive](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#daemonized-vs-interactive-mode)
for more information about the 2 modes

General Slips messages are written to `slips.log` in that directory. The
`output` configuration section can change these filenames.

## Reading Input from stdin

Slips supports reading input flows in text format from stdin in interactive mode.

Supported flow from stdin are zeek conn.log files (json form), suricata and argus.

For example, you can run slips using:

```./slips.py -f zeek```

or

```./slips.py -f suricata```

and you once you see the following line:

```[InputProcess] Receiving flows from stdin.```

you can start giving slips flows in you desired format.

All zeek lines taken from stdin should be in json form and are treated as conn.log lines.

This feature is specifically designed to allow slips to interact with network simulators and scripts.


## Slips as an access point

Slips supports monitoring two interface with Zeek when it's running as an access point.

To use this feature, simply pass the `--access-point` or `-ap` argument followed by a comma-separated list of interfaces
to monitor when running slips.

The wifi interface should be listed first, followed by the ethernet interface.

```./slips.py --access-point  wlan0,eth0```

or

```./slips.py -ap wlan0,eth0```


Slips will produce zeek logs in two separate directories inside your output directory:
`zeek_files/eth0/` and `zeek_files/wlan0/`.
and will be able to detect the host IP, gateway IP and zeek logs of each interface separately.


## Plug in a zeek script

Slips supports automatically running a custom zeek script by adding it to ```zeek-scripts``` dir and adding the file
name in ```zeek-scripts/__load__.zeek```.

For example, if you want to add a zeek script called ```arp.zeek``` you should add it to ```__load__.zeek``` like this:

	@load ./arp.zeek

Zeek output is suppressed by default, so if your script has errors, Slips will fail silently.

## Exporting strato letters

Exporting the strato letters can be done by enabling the `export_strato_letters` option in
`config/slips.yaml` . once enabled, Slips will export the strato letters to `strato_letters.tsv` in the output directory.
this file can be used for training Slips RNN module.



## Slips parameters

- ```-c``` or  ```--config``` Used for changing then path to the Slips config file. default is config/slips.yaml. It is recommended to copy ```config/slips.yaml``` and pass your copy with ```-c``` instead of editing the default file.
- ```-v``` or  ```--verbose``` Verbosity level. This logs more info about Slips.
- ```-e``` or  ```--debug``` Debugging level. This shows more detailed errors.
- ```-f``` or  ```--filepath``` Read and automatically recognize a Zeek dir, a Zeek conn.log file, a Suricata JSON file, Argus, PCAP.
- ```-i``` or  ```--interface``` Read packets from an interface.
- ```-l``` or  ```--createlogfiles``` Create log files with all the traffic info and detections.
- ```-F``` or  ```--pcapfilter``` Packet filter for Zeek. BPF style.
- ```-cc``` or  ```--clearcache``` Clear the cache database.
- ```-p``` or  ```--blocking``` Allow Slips to block malicious IPs. Requires root access. Linux uses iptables; macOS uses a dedicated Packet Filter anchor (`com.apple/slips`).
- ```-cb``` or  ```--clearblocking``` Remove Slips-owned iptables or macOS Packet Filter rules.
- ```-o``` or  ```--output``` Store alerts.json and alerts.txt in the given folder.
- ```-s``` or  ```--save``` Save the analysed file db to disk.
- ```-d``` or  ```--db``` Read an analysed file (rdb) from disk.
- ```-D``` or  ```--daemon``` Run slips in daemon mode
- ```-k``` or  ```--killall``` Kill all unused redis servers
- `--list-instances` List accessible running Slips instances from this checkout.
- `--stop [PID|all]` Gracefully stop the sole running instance, a selected PID, or all instances from this checkout.
- `--restart [PID]` Stop a running daemon and start it again with its original arguments and working directory, using the Python environment invoking this command.
- ```-m``` or  ```--multiinstance``` Run multiple instances of slips, don't overwrite the old one
- ```-P``` or  ```--port``` The redis-server port to use
- ```--keep-history``` Keep the previous live run's SQLite detections and web history in the same `-o` directory, or start fresh if no database exists; start with a clean Redis database 0.
- ```-g``` or  ```--growing``` Treat the given zeek directory as growing. eg. zeek dirs generated when running onan interface
- ```-w``` or  ```--webinterface``` Enable the local web interface for this Slips run
- ```-V``` or  ```--version``` Used for checking your running Slips version flags.
- ```-im``` or  ```--input-module``` Used for reading flows from a module other than input process.
- ```-ap``` or  ```--access-point``` Used for reading packets from two interfaces when Slips is running as an access point.


## Disk and RAM usage on long runs

When Slips monitors an interface for days or weeks, it removes old data on its own so it does not fill your RAM or disk:

- Old time windows are deleted from RAM.
- Old flows are deleted from the flow database.
- Old alerts and evidence are moved to archive files, which are deleted later.
- Slips logs and Zeek logs are rotated.

All limits have safe defaults and can be changed in the ```flow_retention``` and ```detection_history``` sections of ```config/slips.yaml```

Check [How Slips forgets the past](data_retention.md) for what is kept, for how long, and how to change it.

## Limiting Slips resource consumption

When given a very a large pcap, slips may use more memory/CPU than it should. to fix that you can reduce the niceness of
Slips by running:

    renice -n 6 -p <Slips-PID>

## Running Slips from python

You can run Slips from python using the following script

```py
import subprocess
command = './slips.py -f dataset/test3-mixed.binetflow -o /data/test'
args = command.split()
process = subprocess.run(args, stdout=subprocess.PIPE)
```
