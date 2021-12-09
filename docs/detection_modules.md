# Detection modules

Slips is a behavioral-based IPS that uses machine learning to detect malicious behaviors in the network traffic. It is a modular software that can be extended. When Slips is run, it spawns several child processes to manage the I/O, to profile attackers and to run the detection modules.

Here we describe what detection modules are run on the traffic to detect malicious behaviour.

## Detection Modules

Modules are Python-based files that allow any developer to extend the functionality of Slips. They process and analyze data, perform additional detections and store data in Redis for other modules to consume. Currently, Slips has the following modules:


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
    <th>Module</th>
    <th>Description</th>
    <th>Status</th>
  </tr>
  <tr>
    <td>ARP Detection</td>
    <td>Finds ARP scans and MITM with ARP in the local networrk.</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>Exporting</td>
    <td>Exports Slips alerts to Slack servers and STIX servers.</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>IP_Info</td>
    <td>Finds Geolocation country, and ASN for an IP address.</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>CESNET</td>
    <td>Send and receive alerts from warden servers.</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>RiskIQ</td>
    <td>Finds information from RiskIQ, such as passive DNS for domains and downloads the Threat Intelligence feed.</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>Update</td>
    <td>Takes care of downloading each of the files used by Slips, but only if there is a need to update them. It stores and checks the ETags of remote files to know if they changed. It can be configured to update each file with a different frequency. Most importantly it updates all the Threat Intelligence feeds.</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>Threat Intelligence</td>
    <td>Checks if any domain or IP is included in Threat Intelligence feeds. Domains include DNS requests, DNS replies, HTTP hostnames, and TLS SNI. IPs include source and destination IPs, both IPv4 and IPv6. </td>
    <td>✅</td>
  </tr>
  <tr>
    <td>https</td>
    <td>training&test of RandomForest to detect malicious https flows</td>
    <td>⏳</td>
  </tr>
  <tr>
    <td>port scan detector</td>
    <td>detects Horizontal and Vertical port scans</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>threat intelligence</td>
    <td>checks if each IP is in a list of malicious IPs</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>timeline</td>
    <td>creates a timeline of what happened in the network based on all the flows and type of data available</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>rnn-cc-detection</td>
    <td>detects command and control channels using recurrent neural network and the stratosphere behavioral letters</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>VirusTotal</td>
    <td>module to lookup IP address on VirusTotal</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>flowalerts</td>
    <td>Finds malicious behaviours by analyzing only one flow. Now detects: self-signed certificates, TLS certificates which validation failed, vertical port scans detected by Zeek (contrary to detected by Slips), horizontal port scans detected by Zeek (contrary to detected by Slips), password guessing in SSH as detected by Zeek, long connection, successful ssh</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>leak_detector</td>
    <td>module to  detect leaks of data in the traffic using YARA rules</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>ARP</td>
    <td>module to check for ARP attacks in ARP traffic</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>http_analyzer</td>
    <td>module to analyze HTTP traffic.</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>blocking</td>
    <td>Blocks the alerted IPs in the Linux iptables Firewall.</td>
    <td>✅</td>
  </tr>
  <tr>
    <td>flowmldetection</td>
    <td>module to detect malicious flows using machine learning</td>
    <td>✅</td>
  </tr>
  
</table>

If you want to contribute: improve existing Slips detection modules or implement your own detection modules, see section :doc:`Contributing <contributing>`.


