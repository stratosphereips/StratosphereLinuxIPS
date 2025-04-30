1.1.9 (April 30, 2025)
- Add bootstrapping node mode for the global P2P. Thanks to @d-strat
- Add support for ARM64 architecture in Docker images.
- Fix issues getting domain registrants.
- Fix the "Database is locked" SQLite error.
- Fix the issue of Slips hanging when shutting down.
- Ignore URLs when found in threat intelligence feeds.
- Improve handling of Zeek tab-separated log files. Logs from Zeek old versions are now read correctly.
- Optimize IP Info module.
- Print flows processed per minute in the stats printed to the CLI.
- Support reading labeled Zeek logs and using their labels in Slips modules.

1.1.8 (Mar 31st, 2025)
- Fix SQLite database errors.
- Fix CPU and RAM profilers.
- Fix issue with AsyncModules not shutting down gracefully.


1.1.7 (Feb 28th, 2025)
- Add global P2P support. Thanks to @d-strat
- Add new "GRE tunnel scan" detections.
- Add the option to enable/disable local and online whitelists from slips.yaml.
- Fix false positive "Connection to a private IP outside of local network" detection. Slips now doesn't alert on DNS servers outside of local network.
- Fix false positive "Connection to a private IP" detection when the connection is DHCP.
- Fix false positive "Device changing IP" detection alerting about special IPs.
- Fix false positive "Invalid DNS answer" detection alerting about .arpa domains.
- Fix false positive "non-HTTP established connection on port 80".
- Fix false positive "non-SSL established connection on port 443".
- Improve "Connection to unknown port" detections. Now the threat level depends on the flow state.
- Improve "DNS without connection" evidence. Slips now only detects when the query type is A or AAAA.
- Improve the description of malicious flow by MLflowdetection module.
- Improve the detections of the MLflowdetection module.
- Improve the existing "GRE tunnel" detections.
- Improve whitelists: Slips is now whitelisting CNAME, SNI, related queries, and DNS resolutions of attackers and victims.

1.1.6 (Jan 31st, 2025)
* 3x speedup of the profiler process responsible for analyzing the given flows.
* Fix false positive "connection without DNS" detection.
* Fix false positive "DNS without connection" detection.
* Fix problem parsing Suricata DNS flows.
* Fix problem using threat intelligence feeds from cache even if they are not present in the given config file.
* Fix regex warning when starting Slips. Special thanks to @Sekhar-Kumar-Dash.
* Fix Tranco whitelists.
* Improve "Incompatible CN" detection.
* Improve "Invalid DNS answer" detection.
* Improve unit tests. Special thanks to @Sekhar-Kumar-Dash.
* Improve whitelisting by checking if the SNI of each evidence is whitelisted or not.
* Update the license used.

1.1.5 (Jan 3rd, 2025)
- 200x times speedup of domain lookups in the threat intelligence module.
- Add a threat level and confidence to each alert.
- Add evidence for CN and hostname mismatch in SSL flows.
- Add multiple telnet reconnection attempts detection.
- Add support to IP ranges as the client_ip in slips.yaml
- Alert "invalid DNS answer" on all private DNS answers.
- Don't alert "high entropy TXT answers" for flows from multicast IPs.
- Fix multiple reconnection attempts detection.
- Fix problem downloading the latest MAC database from macvendors.com
- Improve the detection of the Gateway IP and MAC when running on files and PCAPs.
- Improve unit tests. Special thanks to @Sekhar-Kumar-Dash.
- Split the "connection to/from blacklisted IPs" detection into two different evidence with different threat levels.
- Update Slips internal list of Apple known ports.

1.1.4.1 (Dec 3rd, 2024)
- Fix abstract class starting with the rest of the modules.
- Fix the updating of the MAC vendors database used in slips.
- Improve MAC vendor offline lookups.

1.1.4 (Nov 29th, 2024)
- Fix changing the used database in the web interface.
- Reduce false positive evidence about malicious downloaded files.
- Fix datetime errors when running on interface
- Improve the detection of "DNS without connection".
- Add support for a light Slips docker image.

1.1.3 (October 30th, 2024)
- Enhanced Slips shutdown process for smoother operations.
- Optimized resource management in Slips, resolving issues with lingering threads in memory.
- Remove the progress bar; Slips now provides regular statistical updates.
- Improve unit testing—special thanks to @Sekhar-Kumar-Dash.
- Drop support for macOS, P2P, and platform-specific Docker images. A unified Docker image is now available for all platforms.
- Correct the number of evidence reported in statistics.
- Fix incorrect end date reported in metadata/info.txt upon analysis completion.
- Print more information to CLI on Slips startup, including network details, client IP, thresholds used, and more.
- Reduce false positives from Spamhaus by looking up inbound traffic only.
- Speed up horizontal port scan detections.
- Enhance logging of IDMEF errors.
- Resolve issues with the accumulated threat level reported in alerts.json.

1.1.2 (September 30th, 2024)
- Add a relation between related evidence in alerts.json
- Better unit tests. Thanks to @Sekhar-Kumar-Dash
- Discontinued MacOS m1 docker images, P2p images, and slips dependencies image.
- Fix the problem of the progress bar stopping before analysis is done, causing Slips to freeze when analyzing large PCAPs.
- Improve how Slips recognizes the current host IP.
- Increase the speed of the Flowalerts module by changing how Slips checks for DNS servers.
- Major code improvements.
- Remove redundant keys from the Redis database.
- Remove unused keys from the Redis database.
- Use IDMEFv2 format in alerts.json instead of IDEA0.
- Wait for modules to finish 1 week by default.

1.1.1 (September 4th, 2024)
- Better unit tests. thanks to @Sekhar-Kumar-Dash.
- Fix Zeek warning caused by one of the loaded zeek scripts.
- Fix Slips installation scripts at install/install.sh
- Improve how Slips validates domains taken from TI feeds.
- Improve whitelists.
- Fix the issue of flowalerts module not analyzing all given conn.log flows.
- Update python dependencies.
- Better handling of problems connecting to Redis database.

1.1 (July 2024)
- Update Python version to 3.10.12 and all python libraries used by Slips.
- Update nodejs and zeek.
- Improve the stopping of Slips. Modules now have more time to process flows.
- Fix database unit tests overwriting config/redis.conf.
- New config file format, Slips is now using yaml thanks to @patel-lay.
- Better unit tests. thanks to @Sekhar-Kumar-Dash.
- Github workflow improvements.
- Fix RNN module and add a new model.
- Horizontal port scan detection improvements.


1.0.15 (June 2024)
- Add a Parameter to export strato letters to re-train the RNN model.
- Better organization of flowalerts module by splitting it into many specialized files.
- Better unit tests. thanks to @Sekhar-Kumar-Dash
- Disable "Connection without DNS resolution" evidence to DNS servers.
- Fix displaying "Failed" as the protocol name in the web interface when reading Suricata flows.
- Fix problem reversing source and destination addresses in JA3 evidence description.
- Improve CI by using more parallelization.
- Improve non-SSL and non-HTTP detections by making sure that the sum of bytes sent and received is zero.
- Improve RNN evidence description, now it's more clear which IP is the botnet, and which is the C&C server.
- Improve some threat levels of evidence to reduce false positives.
- Improve whitelists. Better matching, more domains added, reduced false positives.
- More minimal Slips notifications, now Slips displays the alert description instead of all evidence in the alert.
- The port of the web interface is now configurable in slips.conf


1.0.14 (May 2024)
- Improve whitelists. better matching of ASNs, domains, and organizations.
- Whitelist Microsoft, Apple, Twitter, Facebook and Google alerts by default to reduce false positives.
- Better unit tests. thanks to @Sekhar-Kumar-Dash
- Speed up portscan detections.
- Fix the issue of overwriting redis config file every run.
- Add more info to metadata/info.txt for each run.


1.0.13 (April 2024)
- Whitelist alerts to all organizations by default to reduce false positives.
- Improve and compress Slips Docker images. thanks to @verovaleros
- Improve CI and add pre-commit hooks.
- Fix problem reporting victims in alerts.json.
- Better docs for the threat intelligence module. thanks to @zeyadtmi
- Improve whitelists.
- Better detection threshold to reduce false positive.
- Better unit tests. thanks to @Sekhar-Kumar-Dash
- Fix problems stopping the daemon.

1.0.12 (March 2024)
- Add an option to specify the current client IP in slips.conf to help avoid false positives.
- Better handling of URLhaus threat intelligence.
- Change how slips determines the local network of the current client IP.
- Fix issues with the progress bar.
- Fix problem logging alerts and errors to alerts.log and erros.log.
- Fix problem reporting evidence to other peers.
- Fix problem starting the web interface.
- Fix whitelists.
- Improve how the evidence for young domain detections is set.
- Remove the description of blacklisted IPs from the evidence description and add the source TI feed instead.
- Set evidence to all young domain IPs when a connection to a young domain is found.
- Set two evidence in some detections e.g. when the source address connects to a blacklisted IP, evidence is set for both.
- Use blacklist name instead of IP description in all evidence.
- Use the latest Redis and NodeJS version in all docker images.


1.0.11 (February 2024)
- Improve the logging of evidence in alerts.json and alerts.log.
- Optimize the storing of evidence in the Redis database.
- Fix problem of missing evidence, now all evidence is logged correctly.
- Fix problem adding flows to incorrect time windows.
- Fix problem setting SSH version changing evidence.
- Fix problem closing Redis ports using -k.
- Fix problem closing the progress bar.
- Fix problem releasing the terminal when Slips is done.

1.0.10 (January 2024)
- Faster ensembling of evidence.
- Log accumulated threat levels of each evidence in alerts.json.
- Better handling of the termination of the progress bar.
- Re-add support for tensorflow to the dockers for macOS M1 and macOS M1 P2P.
- Fix problem setting 'vertical portscan' evidence detected by Zeek.
- Fix unable to do RDAP lookups
- Fix stopping Slips daemon.

-1.0.9 (December 2023)
- Fix using -k to kill opened redis servers.
- Better README and docs.
- Improve URLhaus detections.
- Improve the detection of vertical and horizontal portscans
- Unify disabled modules names printed in the CLI.
- Set the threat level reported to other peers to the max of threat levels seen in any time window.
- Faster detections of devices changing IPs
- Remove the home_network feature from Slips.
- Faster detection of alerts.
- Fix problem not using 'command and control channel' evidence in the alert of each profile.

-1.0.8 (November 2023)
- Use All-ID hash to fingerprint flows stored in the flows database
- Increase the weight of port scan alerts by increasing its threat level
- Fix False positive port scan alerts
- Add an option in slips.conf to wait for the update manager to update all TI feeds before starting the rest of Slips to avoid missing any blacklisted IPs.
- Fix error detecting password guessing.
- Fix issues reading all flows when running on a low-spec device.
- Improved the stopping of slips and termination of processes.
- Improved progress bar.
- Fix reading flows from stdin.
- Better code, logs, and unit tests.

-1.0.7 (September 2023):
- CPU and memory profilers thanks to @danieltherealyang
- Check dns queries and answers for whitelisted IPs and domains
- Add AID flow hash to all conn.log flows, which is a combination of community_id and the flow's timestamp
- Sqlite database improvements and better error handling
- Add support for exporting Slips alerts to a sqlite db


-1.0.6 (June 2023):
- Store flows in SQLite database in the output directory instead of redis.
- 55% RAM usage decrease.
- Support the labeling of flows based on Slips detections.
- Add support for exporting labeled flows in json and tsv formats.
- Code improvements. Change the structure of all modules.
- Graceful shutdown of all modules thanks to @danieltherealyang
- Print the number of evidence generated by Slips when running on PCAPs and interface.
- Improved the detection of ports that belong to a specific organization.
- Fix bugs in CYST module.
- Fix URLhaus evidence desciption.
- Fix the freezing progress bar issue.
- Fix problem starting Slips in docker in linux.
- Ignore ICMP scans if the flow has ICMP type 3
- Improve our whitelist. Slips now checks for whitelisted attackers and victims in the generated evidence.
- Add embedded documentation in the web interface thanks to @shubhangi013
- Improved the choosing of random redis ports using the -m parameter.

-1.0.5 (May 2023):
- Fix missing flows due to modules stopping before the processing is done.
- Code improvements. Change the structure of all modules.
- Fix how we detect vertical and horizontal port scans.
- Update whitelist by adding all the IPs of whitelisted domains.
- Fixed error whitelisting Unencrypted HTTP traffic.
- Remove the feature of creating log directories using -l, now the only logs Slips generates are store in the output/ directory.
- added support for reading flows from any module, not just inputprocess, using --input-module.
- CYST module improvements.
- Detect invalid DNS answers when querying adservers. thanks to @ganesh-dagadi .
- Update Slips known ports.
- Prevent model.bin and scaler.bin from changing in test mode. thanks to @haleelsada.
- Use either 'ip neigh show' or 'arp -an' to get gateway MAC from the hosts ARP table. thanks to @naturalnetworks.

-1.0.4 (April 2023)
- Add more descriptive titles to VT scores in the web UI thanks to @shubhangi.
- Add stratoletters documentation, thanks to @haleelsada.
- Add the detection of GRE tunnels.
- Auto publish our MacOS Docker image when there's a new release, thanks to @pjflux2001
- Detect malicious JARM hashes when there's a C&C alert and add our own malicious JARM hashes TI file.
- Fix error getting IP confidence in P2P module.
- Fix false positive alerts about "connection to private IP" thanks to @Onyx2406.
- Fix problem killing all modules before the TI module stops.
- Fix problem detecting vertical and horizontal port scans.
- Improved CLI progress bar and status updates.
- Keep a history of the past user-agents by @haleelsada.
- More descriptive evidence.
- Refactor code thanks to @danieltherealyang.
- Update Slips default whitelist.
- Web UI highlighting, new icons, and bug fixes.

-1.0.3 (March 2023)
- Add HTTP unencrypted traffic detection by @haleelsada
- use termcolor by @haleelsada
- Instead of dos detection. slips is now detecting all executables thanks to @Onyx2406
- Updated the docs for contributing
- Fix Leak detector errors when a different version of yara is used.
- fix problem with counting the number of flows to be processed in the progress bar
- Remove debugging prints printed by the whois python library to stderr

-1.0.2 (Feb 2023)
- Support ASNs in our own_malicious_iocs.csv file
- Add a zeek script to recognize the gateway IP and add it to notice.log
- Don't alert "Connection to Private IP" when there's a DNS connection on port 53 UDP to the gateway
- Faster reading of netflow and suricata files
- Add a progress bar to slips showing the number of processed flows
- Fix having duplicate alerts
- Fix vertical and horizontal portscan errors
- Add the uids that caused an evidence to the evidence description in alerts.json
- Add a blocking indicator in alerts.json
- Fix wrong Source/Target type in alerts.json
- Fix error parsing AIP TI list.
- Update slips default whitelist
- Kill web interface on ctrl+c
- Use the current user's timezone in alerts.log and alets.json
- Fix problem displaying data from the db in the web interface
- Add the option to view blocked profiles only in the web interface
- Fix displaying alerts of profile in the webinterface
- Add the option to display all evidence in a profile
- Fix searching in the web interface
- Fix caching ASN ranges
- Code optimizations

1.0.1 (Jan 2023)
- fix FP horizontal portscans caused by zeek flipping connections
- Fix Duplicate evidence in multiple alerts
- Fix FP urlhaus detetcions, now we use it to check urls only, not domains.
- Fix md5 urlhaus lookups
- add support for sha256 hashes in files.log generated by zeek
- Add detection of weird HTTP methods
- Fix race condition trying to update TI files when running multiple slips instances
- Fix having multiple port scan alerts with the same timestamp
- Add detection for non-SSL connections on port 443
- Add detection for non-HTTP connections on port 80
- P2P can now work without adding the p2p4slips binary to PATH
- Add detection for connections to private IPs from private IPs
- Add detection of high entropy DNS TXT answers
- Add detection of connections to/from IPs outside the used local network.
- Add detection for DHCP scans
- Add detection for devices changing IPs.
- Support having IP ranges in your own local TI file own_malicious_iocs.csv
- Remove rstcloud TI file from slips.conf
- Add the option to change pastebin download detection threshold in slips.conf
- Add the option to change shannon entropy threshold detection threshold in slips.conf
- Store zeek files in the output directory by default
- Portscan detector is now called network service discovery
- Move all TI feeds to their separate files in the config/ directory for easier use
- Add the option to start slips web interface automatically using -w
- Fix multiple SSH client versions detection
- Add detection of IPs using multiple SSH server versions
- Wait 30 mins before the first connection without DNS evidence
- Optimize code and performance
- Update Kalispo dependencies to use more secure versions
- Change the rstcloud feed to https://raw.githubusercontent.com/rstcloud/rstthreats/master/feeds/full/random100_ioc_ip_latest.json

-1.0.0 (November 2022)
- ignore NXDOMAINs dns resolution when checking for 'dns without resolutions'
- Keep track of old peer reports about the same ip
- Add a new log file p2p_reports.log, for logging peer reports only
- Don't force kill all modules when using -P
- Add -g option for running slips on growing zeek dirs. (for example dirs generated by zeek running on an interface)
- Add support for hosts outside of the network in zeek generated software.log
- Make sure the domains that are part of DGA alerts are not whitelisted
- Don't stop slips when p2p is enabled but slips is given a file, not an interface.
- Add Detection of SSH password guessing by slips in addition to zeek.
- Blacklist IP used by blackmatter for exfiltration in config/own_malicious_iocs
- Detect empty connections to duckduckgo used by blackmatter for checking internet connection
- Fix pastebin downloads detection to include HTTPs too
- Change colors and CLI evidence format
- don't detect 'connection without dns' when running on an interface except for when it's done by your own IP
- Create profiles for all IPs by default (source and destination IPs)
- Create profiles for all ips reported by peers
- Alerts now contain attacks done by the profile only (excluding those done to the profile)
- Set evidence for each p2p report in the attackers profile
- Take p2p reports into consideration when deciding to block an IP
- Add Dockerfiles for MacOS M1
- Fix P2P and ubutnu-image Dockerfiles


-0.9.6 (October 2022)
- Detect DNS answers that have a blacklisted IP or CNAME
- Fix problem detecting SSH logins by zeek
- Make rotating zeek files configurable. how many days you want to keep the rotated files and how often to rotate
- Support running slips on a growing zeek dir. for example a zeek dir of an interface.
- Support looking up hashes and domains in URLhaus
- Support looking up IPs in Spamhaus
- Support looking up hashes in Circl.lu
- Remove support for VT hash lookups to save quota
- Add support for suricata ssh flows
- Fix saving the redis database
- Fix false positive connection without DNS
- Fix reading zeek tab files
- Fix vertical portscan detections by zeek
- Better detection of suspicious user agents
- Fix importing and exporting to warden servers
- whitelist top tranco top 10k domains for fewer false positive alerts
- Detect ICMP scans in netflow files
- Fix P2P
- Fix zeek rotating files on ctrl+c
- Kill slips on  when redis ConnectionError occurs
- Kill all modules after 15 mins to trying to stop them
- Keep track of profiles' past threat levels
- Don't alert ARP scans from the gateway
- Add an option to store the zeek log files inside the output dir


-0.9.5 (AUgust 2022)
* Slips
- Fix the way we update TI files
- Add a new web interface
- Detect Incompatible certificate CN
- Detect downloads from pastebin with size > 0.012 MBs
- Detect DOS executable downloads from http websites
- Update the mac database automatically
- Support using multiple home network parameters in slips.conf
- Add redis.conf for special redis configurations when running slips
- Improve portscan or ARP scan alerts
- Improve ARPA scan alerts to alert on unique domains
- Add new methods to detect data upload
- Add the option to close all redis servers when slips can't start because all port are unavailable
- Remove support for whitelisting an unsupported org by slips
- Better description of alerts exported to Slack
- Faster Whitelists
- Whitelist connections made by slips causing false positives
- Change the unknown ports detections to detect only established connections
- Change -killall argument behaviour. now supports closing a specific redis port or all of them at once
- Fix exporting module
- Fix false positive resolution without connection alerts
- Fix disabling alerts
- Fix saving and loading the database
- Fix running several slips instances
- Fix stopping the daemon with -S
- Fix how packets are calculated in portscan detections
- Fix 'multiple reconnections attempts' detection to detect 5 or more rejected reconnection attempts to the same IP on the same destination port


-0.9.3 (July 2022)
* Slips
- Run multiple slips instances on demand using (-m), and use redis port 6379 by default.
- Fix false positive 'DNS resolution without connection' alerts
- Faster Slips and reduced memory and CPU consumption
- Better 'unknown ports' detections
- Faster reading of local TI files
- Fix docker not working in macOS
- Fix problem generating the data upload alerts
- Improve contributing guidelines
- Update microsoft whitelisted IP ranges
- Fix problem stopping input process when slips stops
- Update the locations of GeoIP database in zeek for better zeek detections
- Fix P2P output dir, now it's the same as alerts.log and slips.log
- Update our usage of macvendors.com API
- Whitelist the connections made by slips, so now you won't be alerted when Slips is using virustotal.com or macvendors.com


-0.9.2 (June 2022)
* Slips
- Fix saving the database in MacOS and Linux
- Add a MacOS dockerfile to be able run Docker in MacOS
- Fix problem updating TI files
- Fix problem starting and stopping the Daemon
- Fix false positive ARP MITM attacks
- Fix problem stopping slips when using whitelists
- Fix problem opening unused redis ports

-0.9.1 (May 2022)
* Slips

- Drop root privileges in modules that don't need them
- Added support for running slips in the background as a daemon
- Fix the issue of growing zeek logs by deleting old zeek logs every 1 day. (optional but enabled by default)
- Added support for running several instances of slips at the same time.
- Saving and loading the db in macos
- Fix reading flows from stdin, now it supports zeek, argus and suricata
- Faster Startup of slips, now slips updates the TI files in the background
- Added slips.log where all Slips logs goes. in daemon and interactive mode
- Automatic starting of redis servers (cache and main databases).
- Added a new TI file https://hole.cert.pl/domains/domains.json
- Update the docs and added instructions for contributing and creating a new module

-0.9.0 (April 2022)
* Slips
 - P2P module: Added the support for sharing and receiving IPs' info with other peers. Can be run using docker or locally.
 - Parse zeek software.log and extract software type, version and user agent from it
 - Detect multiple SSH client versions. slips will now alert if an IP is detected using OpenSSH_8.1 then OpenSSH_7.1 for example
 - Detect DoH flows in ssl.log
 - Fix connection rest by peer error by changing the buffer limit in redis
 - Fix reading flows from stdin
 - Fix home_network parameter
 - Fix portscans detections
 - Fix DGA detections
 - Reduce p2p.log file size
 - Rotate p2p.log every 1 day and keep only the last day by default
 - Don't create p2p.log by default, unless create_p2p_log is set to yes in slips.conf
-0.8.5 (March 2022)
* Slips
  - Detect young domains that was registered less than 60 days ago.
  - Detect bad SMTP logins
  - Detect SMTP bruteforce
  - Detect DNS ARPA scans
  - Update our list of ports used by specific organizations to minimize false positive 'unknown destination port' alerts
  - Add support for Russia-Ukraine IoCs
  - Detect incompatible user agents by comparing mac vendors with user agents found in http traffic.
  - Detect the use of multiple user agents, for example Linux UA, then Apple UA, then MAC UA.
  - The default time to wait to alert on DNS without resolution now is 30 mins
  - The time to wait for DNS without resolution now works in interface capture mode and in reading any file
  - detect ICMP timestamp scan, Address scan and address mask scan
  - Support deleting of large log files (arp.log) in case the user doesn't want a copy of the log files after slips is done
  - Update our offline MAC vendor database and add support for getting unknown vendors from an online database
  - Fix FP Multiple reconnection attempts
  - Added a zeek script to recognize DoH flows for more real-time experience while using slips
  - Change the structure of slips files by splitting large modules into smaller files.
  - Reduce false positives by disabling 'connections without DNS' to a well known org
  - Fix 'multiple reconnection attemps' alerts
  - Update the list of our special organization ports
  - Document all the internet connections made by slips
  - Fix install.sh
  - Add errors.log to output/ dir to log errors encountered by slips.
-0.8.4 (Feb 2022)
* Slips
  - Add support for local JA3 feeds
  - Improve CESNET Module
  - Update and improve whitelists
  - Improve alerts by adding hostname to alerts printed in the CLI and in alerts.log
  - Faster startup of Slips, now TI files are updated concurrently.
  - Add a logstash configuration file to allow exporting slips alerts.
  - Add support for malicious SSL feeds.
  - Support blacklisting IP ranges taken from TI feeds.
  - profilerProcess optimizations.
  - Get device type, browser and OS info from user agents found in HTTP traffic.
  - Add "Blocked by Slips" comment to all iptables rules added by slips
  - Improve whitelisting by updating organizations' domains.
  - Update documentation
  - Fix invalid JSON alerts in alerts.json
  - Fix problem stopping slips.
  - Fix problem with redis stopping on error writing to disk.
  - Fix false positive 'not valid yet' SSL alerts
  - Descrease the amount of false positive C&C alerts

* Kalipso
  - Fix Kalipso in docker issue
  - Associate IPs with their hostname

-0.8.3 (Jan 2022)
* Slips
  - More accurate threat levels, now they're strings instead of values
  - Add CESNET sharing module, which supports exporting and importing event to and from warden servers
  - Improve Unknown ports alerts, now we don't have false positive alerts when apple devices are talking to each other using unknown ports
  - Added support for continuous integrations using Github Actions
  - Improvements in printing alerts, we now print each alert with it's timestamp and the evidence caused it
  - Local TI files now support threat levels. each entry now has it'sown threat level.
  - Improve empty HTTP connections. now supports (Yandix, bing and yahoo)
  - Detect JNDI string as suspicious user agent. used in Log4shell CVE-2021-44228.
  - Improve whitelists.
  - Improve code security.

-0.8.2
*	Slips
		- Detect gratoitous ARP
		- Detect unsolicited ARP
		- Detect MITM ARP attack
		- Detect DGA
		- Support popup notifications in Linux and mac. disabled by default. enable it by changing popup_alerts to yes in slips.conf
		- Add 5 new TI feeds (AmnestyTech domains)
		- The Threat Intelligence feeds are now assigned a threat level instead of confidence value by default (user can change), so you can establish how each list impact your detection.
		- Improve unknown ports detections. Now we don't alert for ports that appear in an FTP connection.
		- Improve threat levels and confidence of all alerts.
		- Add support for storing a copy of zeek files in the output directory.
		- Add support for enabling and disabling detections in slips.conf
		- Read RiskIQ email and API key from modules/RiskIQ/credentials instead of the configuration file.
		- Now log files are disabled by default, use -l or set create_log_files to yes in slips.conf for enabling them.
		- Support commenting TI files in slips.conf: when TI files are commented using ; in slips.conf, they are completely removed from our database.
		- Now slips generates alerts in IDEA format by default in alerts.json
		- Support importing and exporting alerts to warden servers. (CESNET sharing module)
		- Fix redis closing connection errors
		- Optimize our docker image

-0.8.1
*	Slips
		- The Threat Intelligence feeds are now assigned a tag value by default (user can change), so you can categorize feeds e.g. phshing, adtrackers, etc..
		- Add module to detect leaks of data in the traffic using YARA rules (works on PCAPs only)
		- Move RiskIQ api key to a separate file in modules/UpdateManager/api_key_secret
		- Add support for whitelisting MAC addresses
		- Add a new module for getting RiskIQ info like passive DNS etc.
		- Merge geoip, asn and RDNS modules into a single new module called IP_Info
		- Add detection for multiple connections to google.com on port 80
		- Add the known list of TOR exit nodes to the TI list
		- Improve DNS without connection and connection without DNS detections
		- Update our lists of organizations IPs, used for whitelisting
		- Improve the printing of evidence and alerts
		- Add SNI/DNS/RDNS to the IP to 'unknown ports' alerts description
		- Improve ICMP Sweep detections
- 0.8
    - Slips
		- Detect PING sweep scan.
		- The Threat Intelligence feeds are now assigned a confidence value by default (user can change), so you can establish how each list impact your detection.
        - Slips now allows you to re-train the machine learning model for flows with your own traffic. You can extend the current model, or start from scratch.
        - Compute the JA3 hash for all TLS connections using a Zeek script.
        - Use JA3 whitelists as detection in the Threat Intelligence module.
		- Detect malicious downloaded files by searching for their MD5 hash on virustotal.
		- Detect SSH password guessing by using the Zeek log for this.
		- Detect connection to and from port 0/TCP and 0/UDP.
		- Detect Connection without DNS resolution and DNS resolutions without a following TCP or UDP connection.
		- Use whitelists of IPs, domains, and complete Organizations (using lists of ASN and domains and IPs) to ignore flows or to ignore alerts (organizations preconfigured for Google, Apple, Facebook, and Twitter).
		- New module to detect data exfiltration by checking large transfers (commit ef88fc6).
		- Detect connections to unkown TCP and UDP ports (ignore P2P traffic).
		- New export alerts in suricata-style format.
		- Check suspicious user agents in HTTP (for now only 'httpsend', 'chm_msdn', 'pb').
		- New ARP-scan detector module.
		- Be able to run multiple independent instances of slips in the same machine.
		- Save and load redis databases to disk as backup for later analysis.
		- Add unit tests in tests/ folder.
        - Use our own Zeek configuration file, so Slips does not collide with the local installation.
        - Use our own Zeek scripts folder, so Slips does not collide with the local installation.
        - Add port 57621/UDP as known spotify-p2p-communication.
        - Add support for the format of many TI feeds.
        - Add the following Threat Intelligence lists by default to be downloaded and used:
            - https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv
            - https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_historical_blacklist_prioritized_by_newest_attackers.csv
            - https://raw.githubusercontent.com/stratosphereips/Civilsphere/main/threatintel/strangereallintel-cyberthreatintel.csv
            - https://raw.githubusercontent.com/Te-k/stalkerware-indicators/master/network.csv
            - https://raw.githubusercontent.com/stratosphereips/Civilsphere/main/threatintel/adserversandtrackers.csv
            - https://raw.githubusercontent.com/stratosphereips/Civilsphere/main/threatintel/civilsphereindicators.csv
            - https://raw.githubusercontent.com/botherder/targetedthreats/master/targetedthreats.cs
            - https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt
            - https://osint.digitalside.it/Threat-Intel/lists/latestips.txt
            - https://osint.digitalside.it/Threat-Intel/lists/latestips.txt
            - https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
            - https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
            - https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset
            - https://nerd.cesnet.cz/nerd/data/ip_rep.csv
            - https://lists.blocklist.de/lists/all.txt
            - https://lists.blocklist.de/lists/ssh.txt
            - https://lists.blocklist.de/lists/mail.txt
            - https://lists.blocklist.de/lists/bruteforcelogin.txt
            - https://feodotracker.abuse.ch/downloads/ipblocklist.csv
            - https://reputation.alienvault.com/reputation.generic
            - https://rstcloud.net/free/ioc/ioc_ip_latest.csv
            - https://www.binarydefense.com/banlist.txt
            - https://rstcloud.net/free/ioc/ioc_domain_latest.csv
            - https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/Cyber_Threat_Coalition_Domain_Blacklist.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/abuse-ch-ipblocklist.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/alienvault.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/binarydefense.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/cobaltstrike_ips.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/compromised-ips.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/cps-collected-iocs.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/dom-bl.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/illuminate.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/openphish.intel
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/filetransferportals.intel,
            - https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/predict_intel.intel
            - https://raw.githubusercontent.com/Te-k/stalkerware-indicators/master/network.csv
            - https://raw.githubusercontent.com/Te-k/stalkerware-indicators/master/quad9_blocklist.txt
            - https://raw.githubusercontent.com/kwouffe/cryptonote-hunt/master/nsec/full-results-2019-05-15.json
            - https://raw.githubusercontent.com/craiu/mobiletrackers/master/list.txt
        - Add support for URLs checking in the VirusTotal module. The URLs are also cached for performance improving.
        - Use the RiskIQ site API to download the IoC lists of Phishing domains (https://api.riskiq.net/pt/v2/articles/indicators)
        - Use the RiskIQ phishing domains for threat intelligence detection
        - Implement read the docs stratospherelinuxips.readthedocs.io
        - Improve how we read binetflow files
        - Add some new test datasets to ./datasets folder
        - Add requirements.txt
    - Kalipso
        - Add Reverse DNS to the 'i' hotkey
        - Timewindows have correct time and date in the interface
        - Large refactoring of code of whole Kalipso
        - Improve the documentation
- 0.7.3
	- Slips
		- Added RDNS module to retrieve reverse DNS of the IP
		- Fixed reading files with Zeek TABs
		- Fixed the docker image for Ubuntu
		- Added a new module for exporting alerts to Slack and TAXII server
		- Added new Threat Intelligence trackers
		- Added new notice.log detections
		- Fixed reading Zeek logs with TABs
		- Added a parameter -cb to clean chains in blocking module
		- Updated documentation with a usage
		- Added a new module for Zeek anomaly detections
		- Fixed a bug of tensorflow not working in the docker
	- Kalipso
		- Added reverse DNS to Kalipso IPInfo box
		- Fixed the version of the npm package
		- Fixed the print of evidences in the Evidence box
- 0.7.2 (published 2020/04/28)
	- Slips
		- New documentation in read-the-docs
		- Update of ASN files in the Update manager
		- Added new Threat Intelligence feeds
		- Added a custom -help function
		- Added new detection of self-signed certificates
		- Improvement of LSTM module to detect C&C channels
		- Added a duration of the connection in the timeline
		- Add a default configuration file, if nothing is specified
		- New docker version without a tensoflow
		- Fixed the levels of threat and confidence of all modules
	- Kalipso
		- Added a new hotkey -z to summarize alerts in all timewindows of the profile
		- Display of a flow duration in the timeline widget
		- Fixed the display of SNI only for TLS/SSL connections
		- Fixed the bug in dstPortServer hotkey
- 0.7.1 (published 2020/12/18)
	- Slips
		- fix the function of Slips to stop after pressing CTRL-C
		- fix Slips stopping automatically
		- add zeek tcp-inactivity-timeout=1hs
		- add module flowalert and alert when a long connection happens (more than 20 minutes)
		- add colors to the detection shown in the console
		- add 3 new TI feeds to slips conf by default
		- make longconnection feature in flowalert to ignore multicast
		- fix some TI files not being updated
		- check TI data in the host field of HTTP
		- check TI data in the SNI field of TLS requests
		- rename blessed module folder to kalipso
	- Kalipso
		- ESC - exit the hotkey, q - exit Kalipso
		- execution of Kalipso from Slips folder: $./kalipso.sh
		- added hotkey 'h' for help
		- changed hotkey 'g'(out tuples) on hotkey 'i'
		- added SNI of TLS/SSL column in 'i' and 'y' hotkeys
		- fix Kalipso being reshred when being in hotkeys
- 0.7.0 (published 2020/09/25)
	- Slips
		- VirusTotal module retrieves information for domains from DNS flows
		- Added new channel 'new_dns_flow'
		- Fixed portscan to eliminate detection for IPs that were resolved with DNS
		- VirusTotal module retrieves passive DNS information
		- VirusTotal module retrieves asn information and stores it for IP if missing
		- Storing in database multiple DNS resolutions per one IP
		- Fixed the function for blocking profile and timewindow in Evedince module
		- Added a field to the flow to put labels from modules
		- Fixed the display of DNS resolutions up to 3 for the IP in the timeline
		- Added functions to mark timewindow as finished
		- Default label of the flow in the slips.conf is changed to 'unknown'
		- Added a module to block IPs when running Slips on interface in Linux machine
		- Added a parameter '-b' to enable blocking module on the interface in Linux machine
		- Store DomainsInfo in cache database
	- Kalipso
		- Automatic reload of the interface. Interface is reloaded every 2 minutes. Opened timeline for ip and tw will not be updated, but the list of tws for current IP will be updated.
		- Changed the description of the old host IPs to 'old me' (before was 'me')
		- Changed the type of widget for IP info to listtable from blessed-contrib lib
- 0.6.9 (published 2020/08/12)
	- Slips
		- Added cache for IPs from Threat Inelligence files
		- Added cache for IPs Info
		- Added new module UpdateManager to update Threat Intelligence files
		- Changed the structure of VirusTotal Module
		- Added parameters in slips.conf for updating VirusTotal and Threat Intelligence
		- Added new channel 'core_messages', UpdateManager is subscribed to that
		- Added manager to search host IP, if Slips is running on interface and networks are changing
		- Flows in the timeline are sorted
		- Added architecture to close timewindow of a profile
		- Fixed the reading of nfdump file
		- Added parameter '-cc' to clear cache database
	- Kalipso
		- Hotkeys 'c' and 'p' are sorted by the size of totalbytes
- 0.6.8 (published 2020/07/07)
	- New version of Kalipso
		- Widgets are splitted in classes
		- Added comments
		- Fixed screen way for hotkeys
		- 'Esc' to exit Kalipso
		- 'q' to exit hotkey
- 0.6.7 (published 2020/06/30)
	- Add a test file for nfdump.
	- In the threat intelligence configuration add by default the file https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv. It has a blacklist of IP addresses that are attacking the Internet. Coming from the stratosphere laboratory and the aposemat project. The AIP program.
	- In the threat intelligence configuration add by default the file https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_historical_blacklist_prioritized_by_newest_attackers.csv. It has a blacklist of IP addresses that are attacking the Internet. Coming from the stratosphere laboratory and the aposemat project. The AIP program.
	- In the threat intelligence configuration add by default the file https://raw.githubusercontent.com/Te-k/stalkerware-indicators/master/network.csv with domains used for stalkerware
	- In the threat intelligence module configuration, add a static version of the IPs of the NSO group from Amnesty from https://raw.githubusercontent.com/AmnestyTech/investigations/master/2018-08-01_nso/indicators.csv
	- Change the old test-flows folder for the dataset folder
	- New section in the configuration file with the threat intelligence data
	- Ignore warnings
	- Update the template module
	- Read as input a zeek folder full of logs with -f
	- Fixed bugs in the timeline of Kalipso
	- New lstm module to detect C&C channels in the network. It detects channels by running a machine learning LSTM network on the behavioral letters.
	- Several bug fixed
	- New DNS blacklist management in the threat intelligence module
	- Better store of IPs in the database
	- Fix an error in how the behavioural letters where created
- 0.6.6
	- Added DNS resolution for IPs in timeline
	- Added inTuple key to the timeline for inbound flows when analysis_direction = 'all'
	- Changed the timeline format in Slips and Kalipso
	- Defined host IP in Slips and Kalipso if Slips is run on interface
- 0.6.5
	- Fixed Threat Intelligence module to be fully functional.
	- Added new feature to stop Slips automatically when input files ends.
	- Fixed the storing and display of inbound flows in analysis direction 'all'.
	- Fixed Kalipso to display inbound flows and h hotkey to display out tuples
- 0.5 Completely renewed architecture and code.
- 0.4 was never reached
- 0.3.5
- 0.3.4
	- This is a mayor version change. Implementing new algorithms for analyzing the results, management of IPs, connections, whois database and more features.
	- A new parameter to specify the file (-r). This is as fast as reading the file from stdin.
	- Now we have a configuration file slips.conf. In there you can specify from fixed parameters, the time formats, to the columns in the flow file.
