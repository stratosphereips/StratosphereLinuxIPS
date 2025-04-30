# Features

This Section will contain a list of all features and detections listed in the
[flowalerts section](https://stratospherelinuxips.readthedocs.io/en/develop/flowalerts.html)
and the
[detection modules](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#detection-modules)
section and a brief description of how slips works.

## Flow Alerts Module

The module of flow alerts has several behavioral techniques to detect attacks by analyzing the content of each flow alone.

The detection techniques are:

- Long connections
- Successful SSH connections
- Connections without DNS resolution
- DNS resolutions to IPs that were never used
- Connections to unknown ports
- Data exfiltration
- Malicious JA3 hashes
- Connections to port 0
- Multiple reconnection attempts
- Alerts from Zeek: Self-signed certs, invalid certs, port-scans and address scans, and password guessing
- DGA
- Connection to multiple ports
- Malicious SSL certificates
- Young domains
- Bad SMTP logins
- SMTP login bruteforce
- DNS ARPA Scans
- Multiple SSH versions
- Incompatible CN
- Weird HTTP methods
- Non-SSL connections on port 443
- Connection to private IPs
- Connection to private IPs outside the current local network
- High entropy DNS TXT answers
- Devices changing IPs
- GRE tunnels
- GRE tunnel scan
- SSH version changing
- Invalid DNS resolutions

The details of each detection follows.


### Long Connections
Detect connections that are long, except the multicast connections.

By defualt, A connection in considered long if it exceeds 1500 seconds (25 Minutes).

This threshold can be changed ```config/slips.yaml``` by changing the value of  ```long_connection_threshold```

### Incompatible CN

Zeek logs each Certificate CN in ssl.log

When slips enccounters a cn that claims to belong to any of Slips supported orgs (Google, Microsoft, Apple or Twitter)
Slips checks if the destination address or the destination server name belongs to these org.

If not, slips generates an alert.


### CN URL Mismatch

Zeek logs each Certificate CN in ssl.log
For each CN Slips encounters, it checks if the server name is the same as the CN
Or if it belongs to the same org as the CN. if not, slips triggers an evidence



### High entropy DNS TXT answers

Slips check every DNS answer with TXT record for high entropy
strings.
Encoded or encrypted strings with entropy higher than or equal 5 will then be detected using shannon entropy
and alerted by slips.

the entropy threshold can be changed in slips.yaml by changing the value of ```entropy_threshold```



### Devices changing IPs

Slips stores the MAC of each new IP it sees in conn.log.

Then for every source address in conn.log, slips checks if the MAC of it was used by another IP.

If so, it alerts "Device changing IPs".


## GRE tunnels

Slips uses zeek tunnel.log to alert on GRE tunnels when found. Whenever one
any action other than "Tunnel::DISCOVER" is found, slips sets an evidence
with threat level low

## GRE tunnel scans

Slips uses zeek tunnel.log to alert on GRE tunnels scan. Slips considers any log with "Tunnel::DISCOVER" action a GRE scan.

The threat level of this evidence is low.



### SMTP login bruteforce

Slips alerts when 3+ invalid SMTP login attempts occurs within 10s


### Connection to private IPs


Slips detects when a private IP is connected to another private IP with threat level info.

But it skips this alert when it's a DNS or a DHCP connection on port
53, 67 or 68 UDP to the gateway IP.


### Connection to private IPs outside the current local network

Slips detects the currently used local network and alerts if it find a
connection to/from a private IP that doesn't belong to it.

For example if the currently used local network is: 192.168.1.0/24

and slips sees a forged packet going from 192.168.1.2 to 10.0.0.1, it will alert

Slips detects the current local network by using the local network of the private
ips specified in ```client_ips``` parameter in ```slips.yaml```

If no IPs are specified, slips uses the local network of the first private source ip
found in the traffic.

This threat level of this detection is low if the source ip is the one outside of local network
because it's unlikely.
and high if the destination ip is the one outside of local network.


Slips ignores evidence of this type when the destination IP is a private IP outside of local network and is
communicating on port 53/UDP. Slips marks that destination address as the DNS server when 5 flows are seen using port
53/udp while having DNS answers. this is likely a DNS misconfiguration hence a FP.


### Weird HTTP methods

Slips uses zeek's weird.log where zeek logs weird HTTP methods seen in http.log

When there's a weird HTTP method, slips detects it as well.

### Non-SSL connections on port 443

Slips detects established connections on port 443 that are not using SSL
using zeek's conn.log flows

if slips finds a flow using destination port 443 and the 'service' field
in conn.log isn't set to 'ssl', it alerts.

Sometimes zeek detects a connection from a source to a destination IP on port 443 as SSL, and another connection within
5 minutes later as non-SSL. Slips detects that and does not set an evidence for any of them.

Here's how it works


<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/how_non_ssl_evidence_works.png.png" >

## Non-HTTP connections on port 80.

Slips detects established connections on port 80 that are not using SSL
using zeek's conn.log flows.

if slips finds a flow using destination port 80 and the 'service' field
in conn.log isn't set to 'http', it sets and evidence.

If a flow without http as a service is found, slips first checks past and future flows from the
same src ip + dst ip + port to see if there's a flow with http as a service, if there is, slips ignores the alert.
This is done to avoid FPs coming from zeek.


### Connections without DNS resolution
This will detect connections done without a previous DNS resolution. The idea is that a connection without a DNS resolution is slightly suspicious.

If Slips runs by capturing packets directly from a network device (as opposed to, for example, a PCAP file), this detection will ignore all connections that happen in the first 3 minute of operation of Slips. This is because most times Slips is started when the computer is already running, and many DNS connections were already done. So waiting 3 minutes decreases the amount of False Positives.

This detection will ignore certain IP addresses for which a connection without DNS is ok. The exceptions are:

- Private IPs
- Localhost IPs (127.0.0.0/8)
- Reserved IPs (including the super broadcast 255.255.255.255)
- IPv6 local-link IPs
- Multicast IPs
- Broadcast IPs only if they are private
- Well known organizations


DNS resolutions of well known orgs might be done using DoH, in this case, slips
doesn't know about the DNS resolution because the resolved domain won't be in dns.log
so we simply ignore alerts of this time about well known org such as (facebook, apple, google, twitter, and microsoft)

Slips uses it's own lists of organizations info (IPs, IP ranges, domains, and ASNs) stored in ```slips_files/organizations_info``` to check
whether the IP/domain of each flow belong to a known org or not.

Slips doesn't detect 'connection without DNS' when running
on an interface except for when it's done by this instance's own IP.

check [DoH section](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#detect-doh)
of the docs for info on how slips detects DoH.


### Successful SSH connections

Slips detects successful SSH connections using 2 ways

1. Using Zeek. Zeek logs successful SSH connection to ssh.log by default
2. if all bytes sent in a SSH connection is more than 4290 bytes

### DNS resolutions without a connection

This will detect DNS resolutions for which no further connection was done.
A resolution without a usage is slightly suspicious.

The domains that are excepted are:

- All reverse DNS resolutions using the in-addr.arpa domain.
- All .local domains
- The wild card domain *
- Subdomains of cymru.com, since it is used by the ipwhois library to get the ASN of an IP and its range.
- WPAD domain from Windows
- domains without a TLD such as the Chrome test domains.
- DNS resolutions of any type other than AAAA and A

Slips doesn't detect 'DNS resolutions without a connection' when running
on an interface except for when it's done by this instance's own IP and only after 30 minutes has passed to
avoid false positives (assuming the connection did happen and yet to be logged).


When running on interface and files. For each DNS flow found, slips waits 30 mins zeek time
for the connection to be found before setting an evidence.

This is done by comparing each ts of every new dns flow to the pending detection, once 30 mins difference between the 2
flows is detected, slips sets the evidence.

To avoid accumulating so many pending DNS flows for 30 mins, slips checks if the connection of the pending DNS flows
arrived every 10 and 20 mins too, if not found, slips waits extra 10 mins (so that would be 30 mins total) and sets the
evidence.

### Connection to unknown ports

Slips has a list of known ports located in ```slips_files/ports_info/services.csv```

and a list of ports that belong to a specific organization in ```slips_files/ports_info/ports_used_by_specific_orgs.csv```

These are the cases where Slips marks the port as known and doesn't trigger an alert

1. If the port is in the list of well known ports in `services.csv`.
2. If Slips has that port's info in `ports_used_by_specific_orgs.csv` and the source and destination addresses belong to that organization.


Slips considers an IP belongs to an org if:

1. Both `saddr` and `daddr` have the organization's name in their MAC vendor (e.g. Apple.)
2. Both `saddr` and `daddr` belong to the range specified in the`ports_used_by_specific_orgs.csv` for that organization.
3. If the SNI, hostname, rDNS, ASN of this IP belong to this organization.
4. If the IP is hardcoded in any of the organizations IPs in `slips_files/organizations_info/`.

Otherwise, Slips triggers and "unknown port" evidence.

For example, even though 5223/TCP isn't a well known port, Apple uses it in Apple Push Notification Service (APNS).

The threat level of this evidence depends on the state of hte flow. established connections have higher threat levels.

### Data exfiltration

Slips generate a 'possible data exfiltration alerts when the number of uploaded files to any IP exceeds 700 MBs.

The number of MBs can be modified by editting the value of ```data_exfiltration_threshold``` in ```config/slips.yaml```

### Malicious JA3 and JA3s hashes

Slips uses JA3 hashes to detect C&C servers (JA3s) and infected clients (JA3)

Slips is shipped with it’s own zeek scripts that add JA3 and JA3s fingerprints to the SSL log files generated by zeek.

Slips supports JA3 feeds in addition to having more than 40 different threat intelligence feeds.
The JA3 feeds contain JA3 fingerprints that are identified as malicious.
The JA3 threat intelligence feed used by Slips now is Abuse.ch JA3 feed.
And you can add other JA3 TI feeds in ```ja3_feeds``` in ```config/slips.yaml```.

### Connections to port 0

There has been a significant rise in the number of attacks listed as Port 0.
Last year, these equated to 10% of all attacks, but now it’s up to almost 25%.

Slips detects any connection to port 0 using any protocol other than 'IGMP' and 'ICMP' as malicious.


### Multiple reconnection attempts

Multiple reconnection attempts in Slips are 5 or more not established flows (reconnections) to the same destination IP.



### Zeek alerts

By default, Slips depends on Zeek for detecting different behaviours, for example
Self-signed certs, invalid certs, port-scans and address scans, and password guessing.

Some scans are also detected by Slips independently of Zeek, like ICMP sweeps and vertical/horizontal portscans.
Check  []() section for more info #todo


### DGA

When the DNS server fails to resolve a domain, it responds back with NXDOMAIN code.

To detect DGA, Slips will count the amount of NXDOMAINs met in the DNS traffic of each source IP.

Then we alert when there is 10 or more NXDOMAINs.

Every 10,15,20 ..etc slips generates an evidence.

### Connection to multiple ports

When Slips encounters a connection to or from a specific IP and a specific port, it scans previous connections looking for connection to/from that same IP using a different port.

It alerts when finding two or more connections to the same IP.

### Malicious SSL certificates

Slips uses SSL certificates sha1 hashes to detect C&C servers.

Slips supports SSL feeds and is shipped with Abuse.ch feed of malicious SSL hashes by default.
And you can add other SSL feeds in ```ssl_feeds``` in ```config/slips.yaml```.

### Young Domains

Slips uses whois python library to get the creation date of every domain met in the dns flows.

If a domain's age is less than 60 days, slips sets an alert.

Not all domains are supported, here's the list of supported TLDs.

    ['.ac_uk', '.am', '.amsterdam', '.ar', '.at', '.au',
    '.bank', '.be', '.biz', '.br', '.by', '.ca', '.cc',
    '.cl', '.club', '.cn', '.co', '.co_il', '.co_jp', '.com',
    '.com_au', '.com_tr', '.cr', '.cz', '.de', '.download', '.edu',
    '.education', '.eu', '.fi', '.fm', '.fr', '.frl', '.game', '.global_',
    '.hk', '.id_', '.ie', '.im', '.in_', '.info', '.ink', '.io',
    '.ir', '.is_', '.it', '.jp', '.kr', '.kz', '.link', '.lt', '.lv',
    '.me', '.mobi', '.mu', '.mx', '.name', '.net', '.ninja',
    '.nl', '.nu', '.nyc', '.nz', '.online', '.org', '.pe',
    '.pharmacy', '.pl', '.press', '.pro', '.pt', '.pub', '.pw',
    '.rest', '.ru', '.ru_rf', '.rw', '.sale', '.se', '.security',
    '.sh', '.site', '.space', '.store', '.tech', '.tel', '.theatre',
    '.tickets', '.trade', '.tv', '.ua', '.uk', '.us', '.uz', '.video',
    '.website', '.wiki', '.work', '.xyz', '.za']

### Bad SMTP logins

Slips uses zeek to detect SMTP connections,
When zeek detects a bad smtp login, it logs it to smtp.log, then slips reads
this file and sets an evidence.

### SMTP bruteforce

Slips detects a SMTP bruteforce when 3 or more bad SMTP
logins happen within 10 seconds.

---

With every generated evidence, Slips gathers as much info
about the malicious IP and prints it with the alert.

So instead of having an alerts saying:

    Detected SSL certificate validation failed with (certificate has expired) Destination IP: 216.58.201.70.

Slips gathers AS, hostname, SNI, rDNS and any available data about this IP and you get an alert saying:

    Detected SSL certificate validation failed with (certificate has expired) Destination IP:
    216.58.201.70. AS: GOOGLE, US, SNI: 2542116.fls.doubleclick.net, rDNS: prg03s01-in-f70.1e100.net


### DNS ARPA Scans

Whenever slips sees a new domain in dns.log, if the domain ends with '.in-addr.arpa'
slips keeps trach of this domain and the source IP that made the DNS request.

Then, if the source IP is seen doing 10 or more ARPA queries within 2 seconds,
slips generates an ARPA scan detection.


### SSH version changing

Zeek logs the used software and software versions in software.log, so slips knows from this file the software used by different IPs,
like whether it's an SSH::CLIENT, an HTTP::BROWSER, or an HTTP::SERVER

When slips detects an SSH client or an SSH server, it stores it with the IP and the SSH versions used in the database

Then whenever slips sees the same IP using another SSH version, it compares the stored SSH versions with the current SSH versions

If they are different, slips generates an alert

## Invalid DNS resolutions

Some DNS resolvers answer the DNS query to adservers with 0.0.0.0 or 127.0.0.1 as the ip of the domain to block the domain.
Slips detects this and sets an informational evidence.

This detection doesn't apply to queries ending with ".arpa" or ".local"


## Detection modules

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

This module is used to lookup IPs, domains, and URLs on virustotal

To use it you need to add your virustotal API key in ```config/vt_api_key```

### RiskIQ Module

This module is used to get different information (passive DNS, IoCs, etc.) from [RiskIQ](https://www.riskiq.com/)
To use this module your RiskIQ email and API key should be stored in ```config/RiskIQ_credentials```

the format of this file should be the following:

```
example@domain.com
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The hash should be your 64 character API Key.

The path of the file can be modified by changing the ```RiskIQ_credentials_path``` parameter in ```config/slips.yaml```

### Leak Detection Module

This module on runs on pcaps, it uses YARA rules to detect leaks.

You can add your own YARA rule in ```modules/leak_detector/yara_rules/rules``` and it will be automatically compiled and stored in ```modules/leak_detector/yara_rules/compiled``` and matched against every pcap.

### Blocking Module

To enable blocking in slips, start slips with the ```-p``` flag.

This feature is only supported in linux using iptables natively and using docker.

### Exporting Alerts Module

Slips supports exporting alerts to other systems using different modules (ExportingAlerts, CESNET sharing etc.)


For now the supported systems are:

- Slack
- TAXII Servers (STIX format)
- Warden servers
- IDEA JSON format
- Logstash


Refer to the [exporting section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html) for detailed instructions on how to export.


### Flowalerts Module


This module is responsible for detecting malicious behaviours in your traffic.

Refer to the [Flowalerts section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/flowalerts.html) for detailed explanation of what Slips detects and how it detects.

### Disabled alerts

All Slips detections are turned on by default, You can configure which alerts you want to enable/disable in ```config/slips.yaml```

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


### Threat Intelligence Module

Slips has a complex system to deal with Threat Intelligence feeds.

Slips supports different kinds of IoCs from TI feeds (IPs, IP ranges, domains, JA3 hashes, SSL hashes)

File hashes and URLs aren't supported.


#### Matching of IPs

Slips gets every IP it can find in the network and tries to see if it is in any blacklist.

If a match is found, it generates an evidence, if no exact match is found, it searches the Blacklisted ranges taken from different TI feeds


#### Matching of Domains
Slips gets every domain that can find in the network and tries to see if it is in any blacklist.
The domains are currently taken from:

- DNS requests
- DNS responses
- HTTP host names
- TLS SNI

Once a domain is found, it is verified against the downloaded list of domains from the blacklists defined in ```ti_files``` in the configuration file ```config/slips.yaml```.
If an exact match is found, then an evidence is generated.

If an exact match is not found, then Slips verifies if the verified domain is a
subdomain of any domain in the blacklist.


For example, if the domain in the traffic is _here.testing.com_,
Slips first checks if the exact domain _here.testing.com_ is in any blacklist,
and if there is no match, it checks if the domain _testing.com_ is in any blacklists too.

#### Matching of JA3 Hashes

Every time Slips encounters an TLS flow,
it compares each JA3 and JA3s with the feeds of malicious JA3 and alerts when
there’s a match.
Slips is shipped with the Abuse.ch JA3 feed by default
You can add your own SSL feed by appending to the file defined by the ```ja3_feeds``` key in
```config/slips.yaml```, which is by default ```config/JA3_feeds.csv```

#### Matching of SSL SHA1 Hashes

Every time Slips encounters an SSL flow, it tries to get the certificate hash from zeek ssl.log,
then it compares the hash with our list of blacklisted SSL certificates

Slips is shipped with the Abuse.ch SSL feed by default,

You can add your own SSL feed by appending to the file defined by the ```ssl_feeds``` key in ```config/slips.yaml```, which is by default
```config/SSL_feeds.csv```

#### Local Threat Intelligence files

Slips has a local file for adding IoCs of your own,
it's located in ```config/local_data_files/own_malicious_iocs.csv``` by default,
this path can be changed by changing ```download_path_for_local_threat_intelligence``` in ```config/slips.yaml```.

The format of the file is "IP address","Threat level", "Description"

Threat level available options: info, low, medium, high, critical

Refer to the [architecture section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html) for detailed explanation of Slips threat levels.


Example:

    "23.253.126.58","high","Simda CC"
    "bncv00.no-ip.info", "critical", "Variant.Zusy"

#### Local JA3 hashes

Slips has a local file for adding JA3 hashes of your own,
it's located in ```config/local_data_files/own_malicious_JA3.csv``` by default.

The format of the file is "JA3 hash", "Threat level", "Description"

Threat level available options: info, low, medium, high, critical

Refer to the [architecture section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html) for detailed explanation of Slips threat levels.

Example:

    "e7d705a3286e19ea42f587b344ee6865","medium","Standard tor client"
    "6734f37431670b3ab4292b8f60f29984", "high", "Trickbot Malwar"


#### Adding your own remote feed


We update the remote ones regularly. The list of remote threat intelligence files is set in the variables ```ti_files``` variable in config/slips.yaml. You can add your own remote threat intelligence feeds in this variable. Supported extensions are: .txt, .csv, .netset, ipsum feeds, or .intel.

Each URL should be added with a threat_level and a tag, the format is (url,threat_level,tag)

tag is which category is this feed e.g. phishing, adtrackers, etc..


Threat level available options: info, low, medium, high, critical

Refer to the [architecture section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html) for detailed explanation of Slips threat levels.

TI files commented using # may be processed as they're still in our database.

Use ```;``` for commenting TI files in ```config/slips.yaml``` instead of ```#```.

Commented TI files (lines starting with ;) will be completely removed from our database.


The remote files are downloaded to the path set in the ```download_path_for_local_threat_intelligence```. By default, the files are stored in the Slips directory ```modules/ThreatIntelligence1/remote_data_files/```


#### Commenting a remote TI feed

If you have a remote file link that you wish to comment and remove from the database
you can do so by adding ';' to the line that contains the feed link in ```config/slips.yaml```, don't use the '#'
for example to comment the ```bruteforcelogin``` feed you should do the following:

    ;https://lists.blocklist.de/lists/bruteforcelogin.txt,medium,['honeypot']

instead of:

    #https://lists.blocklist.de/lists/bruteforcelogin.txt,medium,['honeypot']

### Update Manager Module

To make sure Slips is up to date with the most recent IoCs in all feeds,
all feeds are loaded, parsed and updated periodically and automatically by
Slips every 24 hours, which requires no user interaction.

The 24 hours interval can be changed by changing the ```TI_files_update_period``` key in ```config/slips.yaml```

Update manager is responsible for updating all remote TI files (including SSL and JA3 etc.)


By default, local slips files (organization_info, ports_info, etc.) are
cached to avoid loading and parsing
them everytime we start slips. However, they are updated automatically by
the update manager if they were changed on disk.


### IP Info Module

The IP info module has several ways of getting information about IP and MAC address, it includes:

- ASN
- Country by Geolocation
- MAC Vendors
- Reverse DNS

#### ASN

Slips is shipped with an offline database (GeoLite2) in ```databases/GeoLite2-ASN.mmdb```
to search for ASNs, if
the ASN of a given IP is not in the GeoLite2 database, we try to get the ASN online
using the online database using the ```ipwhois``` library.
However, to reduce the amount of requests, we retrieve the range of the IP and we cache the whole range. To search and cache the whole range of an IP, the module uses the ipwhois library. The ipwhois library gets the range of this IP by making a connection to the server ```cymru.com``` using a TXT DNS query. The DNS server is the one set up in the operating system. For example to get the ASN of the IP 13.32.98.150, you will see a DNS connection asking for the TXT record of the domain ```150.98.32.13.origin.asn.cymru.com```.

#### Country by Geolocation

Slips is shipped with an offline database (GeoLite2) in ```databases/GeoLite2-Country.mmdb```
to search for Geolocation.

#### Mac Vendors

Slips is shipped with an offline database ```databases/macaddress-db.json``` for
MAC address vendor mapping.

This database is a combination of 2 different online databases, but the format of them
is changed to a format slips understands and to reduce the size of the db.

Slips gets the MAC address of each IP from dhcp.log and arp.log and then searches the offline
database using the OUI.

If the vendor isn't found in the offline MAC database,
Slips tries to get the MAc using the online database https://www.macvendorlookup.com

The offline database is updated manually and shipped with slips, you can find it in
the ```databases/``` dir.

Slips makes sure it doesn't perform duplicate searches of the same MAC Address either online, or offline.

#### Reverse DNS
This is obtained by doing a standard in-addr.arpa DNS request.

### ARP Module

This module is used to check for ARP attacks in your network traffic.

By default, zeek doesn't generate and log ARP flows, but Slips is shipped with it's
own zeek scripts that enable the logging of ARP flows in ```arp.log```

The detection techniques are:

- ARP scans
- ARP to a destination IP outside of local network
- Unsolicited ARP
- MITM ARP attack

#### ARP Scans

Slips considers an IP performing an ARP scan if it sends 5
or more non-gratuitous ARP to different destination addresses in 30 seconds or less.

#### ARP to a destination IP outside of local network

Slips alerts when an ARP flow is being sent to an IP outside of local network as it's a weird behaviour
that shouldn't be happening.

#### Unsolicited ARP

Unsolicited ARP is used to update the neighbours' ARP caches but can also be used in ARP spoofing, we detect it with
threat level 'info', so we don't consider it malicious, we simply notify you about it.

#### MITM ARP attack

Slips detects when a MAC with IP A, is trying to tell others that now that MAC
is also for IP B (ARP cache attack)


### CESNET sharing Module

This module is responsibe for importing and exporting alerts from and to warden server

Refer to the [exporting section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html)
for detailed instructions on CESNET exporting and the format of the configuration files.

To enable the importing alerts from warden servers,
set ```receive_alerts```  to ```yes``` in config/slips.yaml

Slips imports 100 alerts from warden servers each day, and automatically stores the aleerts in our database


Time to wait before receiving alerts from warden server is 1 day by default, you can change this
by chaning the ```receive_delay``` in ```config/slips.yaml```


These are the categories we import:
['Availability', 'Abusive.Spam','Attempt.Login', 'Attempt', 'Information', 'Fraud.Scam', 'Information', 'Fraud.Scam']

### HTTP Analyzer Module

This module handles the detections of HTTP flows

Available detection are:

- Multiple empty connections
- Suspicious user agents
- Incompatible user agents
- Multiple user agents
- Downloads from pastebin
- Executable downloads

#### Multiple empty connections

Due to the usage of empty connections to popular site by malware to check for internet connectivity,
We consider this type of behaviour suspicious activity that shouldn't happen

We detect empty connection to 'bing.com', 'google.com', 'yandex.com', 'yahoo.com', 'duckduckgo.com' etc.

If Google is whitelisted in `whitelist.conf`, this detection will be suppressed.


#### Suspicious user agents

Slips has a list of suspicious user agents, whenever one of them is found in the traffic, slips generates
and evidence.

Our current list of user agents has:
['httpsend', 'chm_msdn', 'pb', 'jndi', 'tesseract']

#### Incompatible user agents

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

#### Multiple user agents

Slips stores the MAC address and vendor of every IP it sees
(if available) in the redis database. Then, when an IP iss seen
using a different user agent than the one stored in the database, it tries to extract
os info from the user agent string, either by performing an online
query to http://useragentstring.com or by using zeek.

If an IP is detected using different user agents that refer to different
operating systems, an alert of type 'Multiple user agents' is made

for example, if an IP is detected using a macOS user agent then an android user agent,
slips detects this with 'low' threat level

#### Pastebin downloads

Some malware use pastebin as the host of their malicious payloads.

Slips detects downloads of files from pastebin with size >= 700 bytes.

This value can be customized in slips.yaml by changing ```pastebin_download_threshold```

When found, slips alerts pastebin download with threat level low because not all downloads from pastebin are malicious.


#### Executable downloads

Slips generates an evidence everytime there's an
executable download from an HTTP website.


### Leak Detector Module

This module work only when slips is given a PCAP

The leak detector module uses YARA rules to detect leaks in PCAPs

#### Module requirements

In order for this module to run you need:
<ul>
  <li>to have YARA installed and compiled on your machine</li>
  <li>yara-python</li>
  <li>tshark</li>
</ul>

You can install YARA by running

```sudo apt install yara```

You can install tshark by running

`sudo apt install wireshark`


#### How it works

This module works by

  1. Compiling the YARA rules in the ```modules/leak_detector/yara_rules/rules/``` directory
  2. Saving the compiled rules in ```modules/leak_detector/yara_rules/compiled/```
  3. Running the compiled rules on the given PCAP
  4. Once we find a match, we get the packet containing this match and set evidence.


#### Extending

You can extend the module be adding more YARA rules in ```modules/leak_detector/yara_rules/rules/```.

The rules will be automatically detected, compiled and run on the given PCAP.

If you want to contribute, improve existing Slips detection modules or implement your own detection modules, see section :doc:`Contributing <contributing>`.


### Network service discovery Module

This module is responsibe for detecting scans such as:
- Vertical port scans
- Horizontal port scans
- PING sweeps
- DHCP scans


#### Vertical port scans

Slips checks both TCP and UDP connections for port scans.


Slips considers an IP performing a vertical port scan if it scans 6 or more different
destination ports

We detect a scan every threshold. So we detect when
there is 6, 9, 12, etc. destination ports per destination IP.

#### Horizontal port scans

Slips checks both TCP and UDP connections for horizontal port scans.


Slips considers an IP performing a horizontal port scan if it contacted more than 3
destination IPs on a specific port with not established connections.


We detect a scan every threshold. So we detect when
there is 6, 9, 12, etc. destination destination IPs.


#### PING Sweeps

PING sweeps or ICMP sweeps is used to find out
which hosts are alive in a network or large number of IP addresses using PING/ICMP.


We detect a scan every threshold. So we generate an evidence when there is
5,10,15, .. etc. ICMP established connections to different IPs.


We detect 3 types of ICMP scans: ICMP-Timestamp-Scan, ICMP-AddressScan,
and ICMP-AddressMaskScan

Slips does this detection using Slips' own zeek script located in
zeek-scripts/icmps-scans.zeek for zeek and pcap files and using the portscan module for binetflow files.

## Connections Made By Slips

Slips uses online databases to query information about many different things, for example (user agents, mac vendors etc.)

The list below contains all connections made by Slips

useragentstring.com -> For getting user agent info if no info was found in Zeek
macvendorlookup.com -> For getting MAC vendor info if no info was found in the local maxmind db
ip-api.com/json/ -> For getting ASN info about IPs if no info was found in our Redis DB
ipinfo.io/json -> For getting your public IP
virustotal.com -> For getting scores about downloaded files, domains, IPs and URLs
cymru.com -> For getting the range of a specific IP to cache the ASN of this range. TXT DNS queries are made to this domain.


By default, slips whitelists alerts from or to any of the above domains, witch means that if an alert was detected
to one of the above alerts, slips does not detect it assuming it's a false positive and the connection was made
internally by slips.


You can change this behaviour by updating ```config/whitelist.conf```.

## Ensembling


Ensembling in Slips is done by the Evidence Process.

Every time the evidence process gets a new evidence from the detection modules, it retrieves all the past evidence by this
the source IP, in the current timewindow from the datbase.

Then, Slips uses the following equation to
get the score of each evidence

threat_level = threat_level * confidence

Slips accumulates the threat level of all evidenc, then, it checks if the accumulated threat
level reached a certain threshold or not.

If the accumulated threat level reached the threshold specified in
```evidence_detection_threshold```, Slips generates and alert.
If not, slips waits for the next evidence, accumulates threat levels, and checks again until the threshold is reached.


## Controlling Slips Sensitivity

The threshold that controls Slips sensitivity is determined
by the ```evidence_detection_threshold``` key in ```config/slips.yaml```,
by default it is set to ```0.25```.


This threshold is used in slips according to the following equation

threshold per width = detection_threshold * width / 60

For example, if you're using the default slips width 3600, the threshold used in slips will be

0.25 * 3600 / 60 = 15

This equation's goal is to make it more sensitive on smaller tws, and less sensitive on longer tws


When the accumulated threat levels of all evidence detected in a timewindow exceeds 15, slips will generate an alert.

In simple terms, it means slips will alert when users get the equivalent of 1 alert per minute.


The default threshold of 0.25 gives you balanced detections with
the optimal false positive rate and accuracy.


Here are more options
  - 0.08:  Use this threshold If you want Slips to be super sensitive with higher FPR,
         using this means you are less likely to miss a
         detection but more likely to get false positives
  - 0.25:  Optimal threshold, has the most optimal FPR and TPR.
  - 0.43:  Use this threshold If you want Slips to be insensitive.
         Using this means Slips will need so many evidence to trigger an alert.
         May lead to false negatives



## Zeek Scripts

Slips is shipped with it's own custom zeek scripts to be able to extend zeek functionality and
customize the detections

#### Detect DoH

In the ```detect_DoH.zeek``` script, slips has it's own list of ips that belong to dns/doh servers,

When slips encouters a connection to any IP of that list on port 443/tcp, it assumes it's a DoH connetion,

and times out the connection after 1h so that the connection won't take too long to appear in slips.

#### Detect ICMP Scans

In the ```zeek-scripts/icmps-scans.zeek``` script, we
check the type of ICMP in every ICMP packet seen in the network,

and we detect 3 types of ICMP scans: ICMP-Timestamp-Scan, ICMP-AddressScan,
and ICMP-AddressMaskScan based on the icmp type

We detect a scan every threshold. So we generate an evidence when there is
5,10,15, .. etc. ICMP established connections to different IPs.

### CPU Profiling

Slips is shipped with its own tool for CPU Profiling, it can be found it ```slips_files/common/cpu_profiler.py```

CPU Profiling supports 2 modes: live and development mode

#### Live mode:
The main purpose of this mode it to show live CPU stats in the web interface.
"live" mode publishes updates during the runtime of the program to the redis channel 'cpu_profile' so that the web interface can use them

#### Development mode:

 Setting the mode to "dev" outputs a JSON file of the CPU usage at the end of the program run.
 It is recommended to only use dev mode for static file inputs (pcaps, suricata files, binetflows, etc.) instead of interface and growing zeek dirs, because longer runs result in profiling data loss and not everything will get recorded.
The JSON file created in this mode is placed in the output dir of the current run and can be viewed by running the following command

```vizviewer results.json```

then going to http://127.0.0.1:9001/ in your browser for seeing the visualizations of the CPU usage


Options to enable cpu profiling can be found under the [Profiling] section of the ```slips.yaml``` file.
```cpu_profiler_enable``` set to "yes" enables cpu profiling, or "no" to disable it.
```cpu_profiler_mode``` can be set to "live" or "dev". Setting to
```cpu_profiler_multiprocess``` can be set to "yes" or "no" and only affects the dev mode profiling. If set to "yes" then all processes will be profiled. If set to "no" then only the main process (slips.py) will be profiled.
```cpu_profiler_output_limit``` is set to an integer value and only affects the live mode profiling. This option sets the limit on the number of processes output for live mode profiling updates.
```cpu_profiler_sampling_interval``` is set to an integer value and only affects the live mode profiling. This option sets the duration in seconds of live mode sampling intervals. It is recommended to set this option greater than 10 seconds otherwise there won't be much useful information captured during sampling.

### Memory Profiling
Memory profiling can be found in ```slips_files/common/memory_profiler.py```

Just like CPU profiling, it also has supports live and development mode.
Set ```memory_profiler_enable``` to ```yes``` to enable this feature.
Set ```memory_profiler_mode``` to ```live``` to use live mode or ```dev``` to use development mode profiling.

#### Live Mode
This mode shows memory usage stats during the runtime of the program.
```memory_profiler_multiprocess``` controls whether live mode tracks all processes or only the main process. If set to no, the program will wait for you to connect from a different terminal using the command ```memray live <port_number>```, where port_number is 5000 by default. After connection, the program will continue with its run and the terminal that is connected will receive a feed of the memory statistics. If set to yes, the redis channel "memory_profile" can be used to set pid of the process to be tracked. Only a single process can be tracked at a time. The interface is cumbersome to use from the command line so multiprocess live profiling is intended to be used primarily from the web interface.

#### Development Mode
When enabled, the profiler will output the profile data into the output directory. The data will be in the ```memoryprofile``` directory of the output directory of the run. Each process during the run of the program will have an associated binary file. Each of the generated binaries will automatically be converted to viewable html files, with each process converted to a flamegraph and table format. All generated files will be denoted by their PID.

---

If you want to contribute: improve existing Slips detection modules or implement your own detection modules, see section :doc:`Contributing <contributing>`.
