# Architecture

The architecture of Slips is basically:
    - To receive some data as input
    - To process it to a common format
    - To enrich it (gather all possible info about the IPs/MAC/User-Agents etc.)
    - To apply detection modules 
    - To output results

Slips is heavily based on the Zeek monitoring tool as input tool for packets from the interface and pcap file, due to its excelent recognition of protocols and easiness to identify the content of the traffic.

Figure 1 shows how the data is analyzed by Slips. As we can see, Slips internally uses <a href="https://zeek.org/">Zeek</a>, an open source network security monitoring tool. Slips divides flows into profiles and each proifle into a timewindows. Slips runs detection modules on each flow and stores all evidence, alerts and features in an appropriate profile structure. All data, i.e. zeek flows, performed detections, profiles and timewindows' data, is stored inside a <a href="https://redis.io/">Redis</a> database. The output of Slips is a folder with logs, alert.json or alerts.log, and Kalipso, a terminal graphical user interface.

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

**Internal representation of data.** Slips works at a flow level, instead of a packet level, gaining a high level view of behaviors. Slips creates traffic profiles for each IP that appears in the traffic. A profile contains the complete behavior of an IP address. Each profile is divided into time windows. Each time window is 1 hour long by default and contains dozens of features computed for all connections that start in that time window. Detections are done in each time window, allowing the profile to be marked as uninfected in the next time window.

**Alerts vs Evidence** When running Slips, the alerts you see in red in the CLI or at the very bottom in kalispo, are a bunch of evidence. Evidence in slips are detections caused by a specific IP in a specific timeframe. Slips doesn't alert on every evidence/detection. it accumulates evidence and only generates and alert when the amount of gathered evidence crosses a threshold. After this threshold Slips generates an alert, marks the timewindow as malicious(displays it in red in kalipso) and blocks the IP causing the alert.
 
**Usage of Zeek.** Slips uses Zeek to generate files for most input types, and this data is used to create the profiles. For example, Slips uses this data to create a visual timeline of activities for each time window. This timeline consists of Zeek generated flows and additional interpretation from other logs like dns log and http log.


**Usage of Redis database.** All the data inside Slips is stored in Redis, an in-memory data structure. Redis allows all the modules in Slips to access the data in parallel. Apart from read and write operations, Slips takes advantage of the Redis messaging system called Redis PUB/SUB. Processes may publish data into the channels, while others subscribe to these channels and process the new data when it is published. 


**Threat Levels** 

Slips has 4 threat levels.

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



</tbody>
</table>