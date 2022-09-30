# Detection modules

Slips is a behavioral-based IPS that uses machine learning to detect malicious behaviors in the network traffic. It is a modular software that can be extended. When Slips is run, it spawns several child processes to manage the I/O, to profile attackers and to run the detection modules.

Here we describe what detection modules are run on the traffic to detect malicious behaviour.


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



### Virustotal Module

This module is used to lookup IPs, domains, and URLs on virustotal.

To use it you need to add your virustotal API key in ```modules/virustotal/api_key_secret```

### RiskIQ Module

This module is used to get different information (passive DNS, IoCs, etc.) from [RiskIQ](https://www.riskiq.com/)
To use this module your RiskIQ email and API key should be stored in ```modules/RiskIQ/credentials```  
  
the format of this file should be the following:  
  
```  
example@domain.com  
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  
```  
  
The hash should be your 64 character API Key.  
  
The path of the file can be modified by changing the ```RiskIQ_credentials_path``` parameter in ```slips.conf```

## Leak Detection Module

This module on runs on pcaps, it uses YARA rules to detect leaks.

You can add your own YARA rule in ```modules/leak_detector/yara_rules/rules``` and it will be automatically compiled and stored in ```modules/leak_detector/yara_rules/compiled``` and matched against every pcap.

## Blocking Module

To enable blocking in slips, start slips with the ```-p``` flag. 

This feature is only supported in linux using iptables.

## Exporting Alerts Module

Slips supports exporting alerts to other systems using different modules (ExportingAlerts, CESNET sharing etc.) 


For now the supported systems are:

- Slack
- TAXII Servers (STIX format)
- Warden servers
- suricata-like JSON format
- Logstash


Refer to the [exporting section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html) for detailed instructions on how to export.


## Flowalerts Module


This module is responsible for detecting malicious behaviours in your traffic.
    
Refer to the [Flowalerts section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/flowalerts.html) for detailed explanation of what Slips detects and how it detects.

## Disabled alerts

All Slips detections are turned on by default, You can configure which alerts you want to enable/disable in ```slips.conf``` 

Slips support disabling unwanted alerts, simply add the detection you want to disable in
the ```disabled_detections``` list and slips will not generate any alerts of this type.

for example:

    disabled_detections = [MaliciousJA3, DataExfiltration, SelfSignedCertificate]


Supported detections are:


ARPScan, ARP-outside-localnet, UnsolicitedARP, MITM-ARP-attack, SSHSuccessful, 
LongConnection, MultipleReconnectionAttempts,
ConnectionToMultiplePorts, InvalidCertificate, UnknownPort, Port0Connection, 
ConnectionWithoutDNS, DNSWithoutConnection,
MaliciousJA3, DataExfiltration, SelfSignedCertificate, PortScanType1, 
PortScanType2, Password_Guessing, MaliciousFlow,
SuspiciousUserAgent, multiple_google_connections, NETWORK_gps_location_leaked, 
 Command-and-Control-channels-detection,
ThreatIntelligenceBlacklistDomain, ThreatIntelligenceBlacklistIP,
MaliciousDownloadedFile, DGA, MaliciousSSLCert, YoungDomain, MultipleSSHVersions
DNS-ARPA-Scan, SMTPLoginBruteforce, BadSMTPLogin, 
IncompatibleUserAgent, ICMP-Timestamp-Scan, ICMP-AddressScan, ICMP-AddressMaskScan


## Threat Intelligence Module

Slips has a complex system to deal with Threat Intelligence feeds. 

Slips supports different kinds of IoCs from TI feeds (IPs, IP ranges, domains, JA3 hashes, SSL hashes)

File hashes and URLs aren't supported in TI feeds.

Besides the searching 40+ TI files for every IP/domain Slips encounters, It also uses the following websites for threat intelligence:

URLhaus: for IPs and domains lookups
Spamhaus: for IP lookups
Circl.lu: for hash lookups (for each downloaded file)


### Matching of IPs

Slips gets every IP it can find in the network (DNS answers, HTTP destination IPs, SSH destination IPs, etc.) 
and tries to see if it is in any blacklist.

If a match is found, it generates an evidence, if no exact match is found, 
it searches the Blacklisted ranges taken from different TI feeds.


### Matching of Domains
Slips gets every domain that can find in the network and tries to see if it is in any blacklist.
The domains are currently taken from:

- DNS requests
- DNS responses
- HTTP host names
- TLS SNI

Once a domain is found, it is verified against the downloaded list of domains from the blacklists defined in ```ti_files``` in the configuration file ```slips.conf```. 
If an exact match is found, then an evidence is generated. 

If an exact match is not found, then Slips verifies if the verified domain is a
subdomain of any domain in the blacklist. 


For example, if the domain in the traffic is _here.testing.com_,
Slips first checks if the exact domain _here.testing.com_ is in any blacklist,
and if there is no match, it checks if the domain _testing.com_ is in any blacklists too.

### Matching of JA3 Hashes

Every time Slips encounters an TLS flow,
it compares each JA3 and JA3s with the feeds of malicious JA3 and alerts when
there’s a match.
Slips is shipped with the Abuse.ch JA3 feed by default
You can add your own SSL feed by appending to the ```ja3_feeds``` key in ```slips.conf```

### Matching of SSL SHA1 Hashes

Every time Slips encounters an SSL flow, it tries to get the certificate hash from zeek ssl.log,
then it compares the hash with our list of blacklisted SSL certificates

Slips is shipped with the Abuse.ch SSL feed by default,

You can add your own SSL feed by appending to the ```ssl_feeds``` key in ```slips.conf```

### Local Threat Intelligence files

Slips has a local file for adding IoCs of your own, 
it's located in ```modules/ThreatIntelligence1/local_data_files/own_malicious_ips.csv``` by default,
this path can be changed by changing ```download_path_for_local_threat_intelligence``` in ```slips.conf```.

The format of the file is "IP address","Threat level", "Description"

Threat level available options: info, low, medium, high, critical

Refer to the [architecture section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html) for detailed explanation of Slips threat levels.


Example:
    
    "23.253.126.58","high","Simda CC"
    "bncv00.no-ip.info", "critical", "Variant.Zusy"

### Local JA3 hashes

Slips has a local file for adding JA3 hashes of your own, 
it's located in ```modules/ThreatIntelligence1/local_data_files/own_malicious_JA3.csv``` by default.

The format of the file is "JA3 hash", "Threat level", "Description"

Threat level available options: info, low, medium, high, critical

Refer to the [architecture section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html) for detailed explanation of Slips threat levels.

Example:

    "e7d705a3286e19ea42f587b344ee6865","medium","Standard tor client"
    "6734f37431670b3ab4292b8f60f29984", "high", "Trickbot Malwar"


### Adding your own remote feed


We update the remote ones regularly. The list of remote threat intelligence files is set in the variables ```ti_files``` variable in slips.conf. You can add your own remote threat intelligence feeds in this variable. Supported extensions are: .txt, .csv, .netset, ipsum feeds, or .intel.

Each URL should be added with a threat_level and a tag, the format is (url,threat_level,tag) 

tag is which category is this feed e.g. phishing, adtrackers, etc..


Threat level available options: info, low, medium, high, critical

Refer to the [architecture section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html) for detailed explanation of Slips threat levels.


Be sure the format is:

link, threat_level=0-1, tags=['tag1','tag2']

TI files commented using # may be processed as they're still in our database. 

Use ```;``` for commenting TI files in ```slips.conf``` instead of ```#```.

Commented TI files (lines starting with ;) will be completely removed from our database.


The remote files are downloaded to the path set in the ```download_path_for_local_threat_intelligence```. By default, the files are stored in the Slips directory ```modules/ThreatIntelligence1/remote_data_files/``` 


### Commenting a remote TI feed

If you have a remote file link that you wish to comment and remove from the database
you can do so by adding ';' to the line that contains the feed link in ```slips.conf```, don't use the '#'
for example to comment the ```bruteforcelogin``` feed you should do the following:
    
    ;https://lists.blocklist.de/lists/bruteforcelogin.txt, threat_level=medium, tags=['honeypot']

instead of:

    #https://lists.blocklist.de/lists/bruteforcelogin.txt, threat_level=medium, tags=['honeypot']

## Update Manager Module

To make sure Slips is up to date with the most recent IoCs in all feeds,
all feeds are loaded, parsed and updated periodically and automatically by 
Slips every 24 hours, which requires no user interaction.

The 24 hours interval can be changed by changing the ```malicious_data_update_period``` key in ```slips.conf```

Update manager is responsible for updating all remote TI files (including SSL and JA3 etc.)


By default, local slips files (organization_info, ports_info, etc.) are 
cached to avoid loading and parsing
them everytime we start slips. However, they are updated automatically by 
the update manager if they were changed on disk.


## IP Info Module

The IP info module has several ways of getting information about an IP address, it includes:

- ASN
- Country by Geolocation 
- Given a MAC, its Vendor 
- Reverse DNS

### ASN

Slips is shipped with an offline database (GeoLite2) in ```databases/GeoLite2-ASN.mmdb``` 
to search for ASNs, if
the ASN of a given IP is not in the GeoLite2 database, we try to get the ASN online
using the online database using the ```ipwhois``` library.
However, to reduce the amount of requests, we retrieve the range of the IP and we cache the whole range.
To search and cache the whole range of an IP, the module uses the ipwhois library. 
The ipwhois library gets the range of this IP by making a connection to the server ```cymru.com``` using a TXT DNS query. 
The DNS server is the one set up in the operating system. For example to get the ASN of the IP 13.32.98.150, 
you will see a DNS connection asking for the TXT record of the domain ```150.98.32.13.origin.asn.cymru.com```.

### Country by Geolocation 

Slips is shipped with an offline database (GeoLite2) in ```databases/GeoLite2-Country.mmdb``` 
to search for Geolocation.

### Mac Vendors

Slips is shipped with an offline database ```databases/macaddress-db.json``` for 
MAC address vendor mapping.

Slips updates this database by default every 2 weeks using the following online db

https://maclookup.app/downloads/json-database/get-db?t=22-08-19&h=d1d39c52de447a7e7194331f379e1e99f94f35f1

You can change how often this db is updated by changing the value of
```mac_db_update``` in ```slips.conf```.

Slips gets the MAC address of each IP from dhcp.log and arp.log and then searches the offline
database using the OUI.

If the vendor isn't found in the offline MAC database,
Slips tries to get the MAc using the online database https://www.macvendorlookup.com

The offline database is updated manually and shipped with slips, you can find it in 
the ```databases/``` dir.

Slips makes sure it doesn't perform duplicate searches of the same MAC Address either online, or offline.

## Reverse DNS
This is obtained by doing a standard in-addr.arpa DNS request.

## ARP Module

This module is used to check for ARP attacks in your network traffic.

By default, zeek doesn't generate and log ARP flows, but Slips is shipped with it's 
own zeek scripts that enable the logging of ARP flows in ```arp.log```

The detection techniques are:

- ARP scans
- ARP to a destination IP outside of local network
- Unsolicited ARP
- MITM ARP attack

### ARP Scans

Slips considers an IP performing an ARP scan if it sends 5 
or more non-gratuitous ARP to different destination addresses in 30 seconds or less.

### ARP to a destination IP outside of local network

Slips alerts when an ARP flow is being sent to an IP outside of local network as it's a weird behaviour 
that shouldn't be happening.

### Unsolicited ARP

Unsolicited ARP is used to update the neighbours' ARP caches but can also be used in ARP spoofing, we detect it with
threat level 'info', so we don't consider it malicious, we simply notify you about it.

### MITM ARP attack

Slips detects when a MAC with IP A, is trying to tell others that now that MAC 
is also for IP B (ARP cache attack)


## CESNET sharing Module

This module is responsible for importing and exporting alerts from and to warden server

Refer to the [exporting section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html) 
for detailed instructions on CESNET exporting and the format of the configuration files.

To enable the importing alerts from warden servers,
set ```receive_alerts```  to ```yes``` in slips.conf  

Slips imports 100 alerts from warden servers each day, and automatically stores the IoCs in our database


Time to wait before receiving alerts from warden server is 1 day by default, you can change this
by chaning the ```receive_delay``` in ```slips.conf```


These are the categories Slips imports:
['Availability', 'Abusive.Spam','Attempt.Login', 'Attempt', 'Information', 'Fraud.Scam', 'Information', 'Fraud.Scam']

## HTTP Analyzer Module

This module handles the detections of HTTP flows

Available detection are:

- Multiple empty connections
- Suspicious user agents
- Incompatible user agents
- Multiple user agents

### Multiple empty connections

Due to the usage of empty connections to popular site by malware to check for internet connectivity,
We consider this type of behaviour suspicious activity that shouldn't happen

We detect empty connection to 'bing.com', 'google.com', 'yandex.com', 'yahoo.com' etc.

### Suspicious user agents

Slips has a list of suspicious user agents, whenever one of them is found in the traffic, slips generates
and evidence.

Our current list of user agents has:
['httpsend', 'chm_msdn', 'pb', 'jndi', 'tesseract']
  
### Incompatible user agents

Slips uses and offline MAC address database to detect the type of device based on the MAC OUI.

First, Slips store the MAC address and vendor of every IP it sees (if available)

Second, When slips encounters a user agent in HTTP traffic it performs an online
query to http://useragentstring.com to get more info about this user agent, 
like the os type, name and browser.

Third, When slips has both information available (MAC vendor and user agent),
it compares them to detect incompatibility using a list of keywords for each operating system.

Available keywords for Apple: ('macos', 'ios', 'apple', 'os x', 'mac', 'macintosh', 'darwin')

Available keywords for Microsoft: ('microsoft', 'windows', 'nt') 

Available keywords for Android: ('android', 'google')

### Multiple user agents

Slips stores the MAC address and vendor of every IP it sees 
(if available) in the redis database. Then, when an IP iss seen 
using a different user agent than the one stored in the database, it tries to extract
os info from the user agent string, either by performing an online
query to http://useragentstring.com or by using zeek.

If an IP is detected using different user agents that refer to different
operating systems, an alert of type 'Multiple user agents' is made

for example, if an IP is detected using a macOS user agent then an android user agent,
slips detects this with 'low' threat level



## Leak Detector Module

This module work only when slips is given a PCAP

The leak detector module uses YARA rules to detect leaks in PCAPs

### Module requirements

In order for this module to run you need:
<ul>
  <li>to have YARA installed and compiled on your machine</li>
  <li>yara-python</li>
  <li>tshark</li>
</ul>

You can compile YARA by running

`wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.1.3.tar.gz 
  && tar -zxf v4.1.3.tar.gz 
  && cd yara-4.1.3 
  && ./bootstrap.sh 
  && ./configure 
  && make 
  && make install`

You can install yara-python by running

`git clone https://github.com/VirusTotal/yara-python yara-python && cd yara-python
python3 setup.py build && python3 setup.py install`

You can install tshark by running

`apt install wireshark`


### How it works

This module works by

  1. Compiling the YARA rules in the ```modules/leak_detector/yara_rules/rules/``` directory
  2. Saving the compiled rules in ```modules/leak_detector/yara_rules/compiled/```
  3. Running the compiled rules on the given PCAP
  4. Once we find a match, we get the packet containing this match and set evidence.


### Extending 

You can extend the module be adding more YARA rules in ```modules/leak_detector/yara_rules/rules/```. 

The rules will be automatically detected, compiled and run on the given PCAP.

If you want to contribute, improve existing Slips detection modules or implement your own detection modules, see section :doc:`Contributing <contributing>`.


## Portscan Detector Module

This module is responsibe for detecting scans such as:
- Vertical port scans
- Horizontal port scans
- PING sweeps


### Vertical port scans

Slips considers an IP performing a vertical port scan if it contacts 6 or more different destination ports in the same destination IP. The flows can be TCP or UDP, and both Established or Not Established. The initial threshold is 5 destination ports. On each flow the check is performed.

After detecting a vertical port scan, Slips waits 10 seconds to see if more flows arrive, since in most port scans the attcker will scan more ports. This avoids generating one port scan alert per flow in a long scan. Therfore Slips will wait until the scan finishes to alert on it. However, the first portscan is detected as soon as it happens so the analysts knows.

If one alert was generated (Slips waited 10 seconds and no more flows arrived to new ports in that dst IP) then the counter resets and the same attacker needs to do _again_ more than threshold destinations ports in one IP to be detected. This avoids the problem that after 5 flows that generated an alert, the 6 flow also generates an alert.

The total number of _packets_ in all flows in the scan give us the confidence of the scan.


### Horizontal port scans

Slips considers an IP performing a horizontal port scan if it contacted more than 6 destination IPs on the same specific port with not established connections. Slips checks both TCP and UDP connections for horizontal port scans. The initial threshold is now 6 destination IPs using the same destination ports. 

After detecting a horizontal port scan, Slips waits 10 seconds to see if more flows arrive, since in most port scans the attcker will scan more ports. This avoids generating one port scan alert per flow in a long scan. Therfore Slips will wait until the scan finishes to alert on it. However, the first portscan is detected as soon as it happens so the analysts knows.

If one alert was generated (Slips waited 10 seconds and no more flows arrived to new IPs) then the counter resets and the same attacker needs to do _again_ more than threshold destinations IPs in the same port to be detected. This avoids the problem that after 6 flows that generated an alert, the 7 flow also generates an alert.

Slips ignores the broadcast IP 255.255.255.255 has destination of port scans.


### PING Sweeps

ICMP messages can be used to find out which hosts are alive in a network. Slips relies on Zeek detecions for this, but it is done with our own Zeek scripts located in zeek-scripts/icmps-scans.zeek. The scripts detects three types of ICMP scans: 'ICMP-Timestamp', 'ICMP-Address', 'ICMP-AddressMask'.

The initial threshold is 25 ICMP flows.

# Connections Made By Slips

Slips uses online databases to query information about many different things, for example (user agents, mac vendors etc.)

The list below contains all connections made by Slips

useragentstring.com -> For getting user agent info if no info was found in Zeek
macvendorlookup.com -> For getting MAC vendor info if no info was found in the local maxmind db
ip-api.com -> For getting ASN info about IPs if no info was found in our Redis DB
ipinfo.io -> For getting your public IP
virustotal.com -> For getting scores about domains, IPs and URLs 
urlhaus-api.abuse.ch -> For getting info about contacted IPs and domains

---

If you want to contribute: improve existing Slips detection modules or implement your own detection modules, see section :doc:`Contributing <contributing>`.


## Zeek Scripts

Slips is shipped with it's own custom zeek scripts to be able to extend zeek functionality and 
customize the detections

### Detect DoH

In the ```detect_DoH.zeek``` script, slips has it's own list of ips that belong to dns/doh servers,

When slips encouters a connection to any IP of that list on port 443/tcp, it assumes it's a DoH connetion,

and times out the connection after 1h so that the connection won't take too long to appear in slips.

### Detect ICMP Scans

In the ```zeek-scripts/icmps-scans.zeek``` script, we 
check the type of ICMP in every ICMP packet seen in the network,

and we detect 3 types of ICMP scans: ICMP-Timestamp-Scan, ICMP-AddressScan,
and ICMP-AddressMaskScan based on the icmp type

We detect a scan every threshold. So we generate an evidence when there is 
5,10,15, .. etc. ICMP established connections to different IPs.


