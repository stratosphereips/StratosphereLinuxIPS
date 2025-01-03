# Architecture

The architecture of Slips is basically:
    - To receive some data as input
    - To process it to a common format
    - To enrich it (gather all possible info about the IPs/MAC/User-Agents etc.)
    - To apply detection modules
    - To output results

Slips is heavily based on the Zeek monitoring tool as input tool for packets from the interface and pcap file, due to its excelent recognition of protocols and easiness to identify the content of the traffic.

Figure 1 shows how the data is analyzed by Slips.
As we can see, Slips internally uses <a href="https://zeek.org/">Zeek</a>, an
open source network security monitoring tool. Slips divides flows into profiles and
each profile into a timewindows.
Slips runs detection modules on each flow and stores all evidence,
alerts and features in an appropriate profile structure.
All profile info, performed detections, profiles and timewindows' data,
is stored inside a <a href="https://redis.io/">Redis</a> database.
All flows are read, interpreted by Slips, labeled, and stored in the SQLite database in the output/ dir of each run
The output of Slips is a folder with logs (output/ directory) that has alert.json, alerts.log, errors.log.
Kalipso, a terminal graphical user interface. or the Web interface.

<style>
.zoom {
  transition: transform .2s; /* Animation */
  margin: 0;
  position: relative;
  z-index:999;
}

.zoom:hover {
  transform: scale(1.8); /* (150% zoom)*/
}
</style>

<div class="zoom">
<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/slips_internal_architecture.jpg" title="Figure 1. The analysis of the network traffic by Slips.">
<figcaption><b>Figure 1.</b> The analysis of the network traffic by Slips. Its input, internal structure and output.</figcaption>
</div>
<br>


Below is more explanation on internal representation of data, usage of Zeek and usage of Redis inside Slips.
### Internal representation of data.

Slips works at a flow level, instead of a packet level, gaining a high level view of behaviors. Slips creates traffic profiles for each IP that appears in the traffic. A profile contains the complete behavior of an IP address. Each profile is divided into time windows. Each time window is 1 hour long by default and contains dozens of features computed for all connections that start in that time window. Detections are done in each time window, allowing the profile to be marked as uninfected in the next time window.

This is what slips stores for each IP/Profile it creates:

* Ipv4 - ipv4 of this profile
* IPv6 - list of ipv6 used by this profile
* Threat_level - the threat level of this profile, updated every TW.
* Confidence - how confident slips is that the threat level is correct
* Past threat levels - history of past threat levels
* Used software - list of software used by this profile, for example SSH, Browser, etc.
* MAC and MAC Vendor - Ether MAC of the IP and the name of the vendor
* Host-name - the name of the IP
* first User-agent - First UA seen use dby this profile.
* OS Type - Type of OS used by this profile as extracted from the user agent
* OS Name - Name of OS used by this profile as extracted from the user agent
* Browser - Name of the browser used by this profile as extracted from the user agent
* User-agents history -  history of the all user agents used by this profile
* DHCP - if the IP is a dhcp or not
* Starttime - epoch formatted timestamp of when the profile first appeared
* Duration -  the standard duration of every TW in this profile
* Modules labels - the labels assigned to this profile by each module
* Gateway - if the IP is the gateway (router) of the network
* Timewindow count -  Amount of timewindows in this profile
* ASN - autonomous service number of the IP
* Asnorg - name of the org that own the ASN of this IP
* ASN Number
* SNI - Server name indicator
* Reverse DNS - name of the IP in reverse dns
* Threat Intelligence - If the IP appeared in any of Slips blacklist
* Description - Description of this IP as taken from the blacklist
* Blacklist Threat level - threat level of the blacklisted that has this IP
* Passive DNS - All the domains that resolved into this IP
* Certificates - All the certificates that were used by this IP
* Geocountry - Country of this IP
* VirusTotal - contains virustotal scores of this IP
  * Down_file: files in virustotal downloaded from this IP
  * Ref_file: files in VT that referenced this IP
  * Com_file : files in VT communicating with this IP
  * Url ratio: The higher the score the more malicious this IP is


### Alerts vs Evidence

When running Slips, the alerts you see in red in the CLI or at the very bottom in kalispo, are a bunch of evidence. Evidence in slips are detections caused by a specific IP in a specific timeframe. Slips doesn't alert on every evidence/detection. it accumulates evidence and only generates and alert when the amount of gathered evidence crosses a threshold. After this threshold Slips generates an alert, marks the timewindow as malicious(displays it in red in kalipso and the web interface) and blocks the IP causing the alert if iptables is enabled.

Each alert has a threat level and confidence; the Threat level of each alert is Critical by default, and the confidence is the accumulated threat level of all the evidence of the alert normalized to a value ranging from 0 to 1. The more evidence the higher the confidence of the alert.

### Usage of Zeek.

Slips uses Zeek to generate files for most input types, and this data is used to create the profiles. For example, Slips uses this data to create a visual timeline of activities for each time window. This timeline consists of Zeek generated flows and additional interpretation from other logs like dns log and http log.


### Usage of Redis database.

All the data inside Slips is stored in Redis, an in-memory data structure.
Redis allows all the modules in Slips to access the data in parallel.
Apart from read and write operations, Slips takes advantage of the Redis messaging system called Redis PUB/SUB.
Processes may publish data into the channels, while others subscribe to these channels and process the new data when it is published.

### Usage of SQLite database.

Slips uses SQLite database to store all flows in Slips interpreted format.
The SQLite database is stored in the output/ dir and each flow is labeled to either 'malicious' or 'benign' based on slips detections.
all the labeled flows in the SQLite database can be exported to tsv or json format.


### Threat Levels

Slips has 5 threat levels.

<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;}
.tg td{border-color:black;border-style:solid;border-width:1px;font-family:Arial, sans-serif;font-size:14px;
  overflow:hidden;padding:10px 5px;word-break:normal;}
.tg th{border-color:black;border-style:solid;border-width:1px;font-family:Arial, sans-serif;font-size:14px;
  font-weight:normal;overflow:hidden;padding:10px 5px;word-break:normal;}
.tg .tg-0pky{border-color:inherit;text-align:left;vertical-align:top}
</style>
<table class="tg">
<thead>
  <tr>
    <th class="tg-0pky"><span style="font-weight:bold">Threat Level</span></th>
    <th class="tg-0pky"><span style="font-weight:bold">Description</span></th>
    <th class="tg-0pky"><span style="font-weight:bold">Example</span></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-0pky">Info</td>
    <td class="tg-0pky">Information, Do nothing</td>
    <td class="tg-0pky">SSH login</td>
  </tr>
  <tr>
    <td class="tg-0pky">Low</td>
    <td class="tg-0pky">Interesting activity to consider</td>
    <td class="tg-0pky">DNS without connection</td>
  </tr>
  <tr>
    <td class="tg-0pky">Medium</td>
    <td class="tg-0pky">Suspicious activity that shouldn't happen</td>
    <td class="tg-0pky">PING Sweep</td>
  </tr>
    <tr>
    <td class="tg-0pky">High</td>
    <td class="tg-0pky">Malicious activity</td>
    <td class="tg-0pky">Password guessing</td>
  </tr>
    </tr>
    <tr>
    <td class="tg-0pky">Critical</td>
    <td class="tg-0pky">Critical for your security, results in a direct block</td>
    <td class="tg-0pky">Malicious downloaded Files</td>
  </tr>


### How Slips Stops

- When slips is running on an interface or a growing zeek directory, slips keeps running forever until the user presses ctrl+c
- When Slips is analyzing a PCAP or a zeek directory or any other supported file, It keeps running until no more flows are received.
- After the modules receive that signal that says "no more new flows are coming", all modules keep processing the existing flows normally until they run out of msgs and stop.
- Modules stop only if no more msgs are received in their Redis channels, and if they receive the signal that slips is no longer receiving new flows.
- Slips knows that no more flows are arriving when it reaches the end of the given zeek/suricata/nfdump logs.
- If some processes are hanging in memory, slips wait by default 1 week before killing them. This can be modified in the config.yaml.

For more techincal details about this check https://stratospherelinuxips.readthedocs.io/en/develop/contributing.html#faq


</tbody>
</table>
