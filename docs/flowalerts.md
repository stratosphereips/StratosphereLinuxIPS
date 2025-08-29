# Flow Alerts Module

The module of flow alerts has several behavioral techniques to detect attacks by analyzing the content of each flow alone.

The detection techniques are:

- Long connections
- Successful SSH connections
- Connections without DNS resolution
- DNS resolutions without a connection
- Connections to unknown ports
- Data exfiltration
- Malicious JA3 hashes
- Connections to port 0
- Multiple reconnection attempts
- Alerts from Zeek: Self-signed certs, invalid certs, port-scans and address scans, and password guessing
- DGA
- Connection to multiple ports
- Malicious SSL certificates
- Pastebin downloads
- Young domains
- Bad SMTP logins
- SMTP login bruteforce
- DNS ARPA Scans
- SSH version changing
- Incompatible CN
- CN URL Mismatch
- Weird HTTP methods
- Non-SSL connections on port 443
- Connection to private IPs
- Connection to private IPs outside the current local network
- High entropy DNS TXT answers
- Devices changing IPs
- GRE tunnels
- GRE tunnel scan
- Invalid DNS answers
The details of each detection follows.


## Long Connections
Detect connections that are long, except the multicast connections.

By defualt, A connection in considered long if it exceeds 1500 seconds (25 Minutes).

This threshold can be changed ```slips.yaml``` by changing the value of  ```long_connection_threshold```

## Connections without DNS resolution
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
so we simply ignore alerts of this type when connected to well known organizations.
In particular Facebook, Apple, Google, Twitter, and Microsoft.

Slips uses it's own lists of organizations and information about them (IPs, IP ranges, domains, and ASNs).
They are stored in ```slips_files/organizations_info``` and they are used to check whether the IP/domain
of each flow belong to a known org or not.

Slips also doesn't detect connection without DNS to any domain in the tranco whitelist.

Slips doesn't detect 'connection without DNS' when running
on an interface except for when it's done by this instance's own IP and only after 30 minutes has passed
to avoid false positives (assuming the DNS resolution of these connections did happen before slips started).

check the [DoH section](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#detect-doh)
of the docs for info on how slips detects DoH.


## Successful SSH connections

Slips detects successful SSH connections using 2 ways

1. Using Zeek. Zeek logs successful SSH connection to ssh.log by default
2. If all bytes sent in a SSH connection is more than 4290 bytes

## DNS resolutions without a connection

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



## Connection to unknown ports

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


## Data Upload

Slips generates 'possible data upload' alerts when the number of uploaded bytes to any IP exceeds 100 MBs over
the timewindow period which is, by default, 1h.

See detailed explanation of timewindows
[here](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html?highlight=timewindows#architecture).

The number of MBs can be modified by changing the value of ```data_exfiltration_threshold``` in ```slips.yaml```


Slips also detects data upload when an IP uploads >=100MBs to any IP in 1 connections.

## Malicious JA3 and JA3s hashes

Slips uses JA3 hashes to detect C&C servers (JA3s) and infected clients (JA3)

Slips is shipped with it’s own zeek scripts that add JA3 and JA3s fingerprints to the SSL log files generated by zeek.

Slips supports JA3 feeds in addition to having more than 40 different threat intelligence feeds.
The JA3 feeds contain JA3 fingerprints that are identified as malicious.
The JA3 threat intelligence feed used by Slips now is Abuse.ch JA3 feed.
And you can add other JA3 TI feeds in ```ja3_feeds``` in ```slips.yaml```.

## Connections to port 0

There has been a significant rise in the number of attacks listed as Port 0.
Last year, these equated to 10% of all attacks, but now it’s up to almost 25%.

Slips detects any connection to port 0 using any protocol other than 'IGMP' and 'ICMP' as malicious.


## Multiple reconnection attempts

Multiple reconnection attempts in Slips are 5 or more not established flows (reconnections) to
the same destination IP on the same destination port.

## Zeek alerts

By default, Slips depends on Zeek for detecting different behaviours, for example
Self-signed certs, invalid certs, port-scans, address scans, and password guessing.

Password guessing is detected by zeek when 30 failed ssh logins happen over 30 mins.

Some scans are also detected by Slips independently of Zeek, like ICMP sweeps and vertical/horizontal portscans.
Check
[PING Sweeps](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#ping-sweeps)
section for more info

## SMTP login bruteforce

Slips alerts when 3+ invalid SMTP login attempts occurs within 10s

## Password Guessing

Password guessing is detected using 2 ethods in slips
1. by Zeek engine. when 30 failed ssh logins happen over 30 mins.
2. By slips. when 20 failed ssh logins happen over 1 tiemwindow.

## DGA

When the DNS server fails to resolve a domain, it responds back with NXDOMAIN code.

To detect DGA, Slips will count the amount of NXDOMAINs met in the DNS traffic of each source IP.

Then we alert when there is 10 or more NXDOMAINs.

Every 10,15,20 ..etc slips generates an evidence.

## Connection to multiple ports

When Slips encounters a connection to or from a specific IP and a specific port, it scans previous connections looking for connection to/from that same IP using a different port.

It alerts when finding two or more connections to the same IP.

## Malicious SSL certificates

Slips uses SSL certificates sha1 hashes to detect C&C servers.

Slips supports SSL feeds and is shipped with Abuse.ch feed of malicious SSL hashes by default.
And you can add other SSL feeds in ```ssl_feeds``` in ```slips.yaml```.


## Pastebin downloads

Slips detects downloads from pastebin using SSL and HTTP

It alerts when a downloaded file from pastebin exceeds 700 bytes

This value can be customized in slips.yaml by changing ```pastebin_download_threshold```

Slips detects the pastebin download once the SSL connection is over , which may take hours.

## Young Domains

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

## Bad SMTP logins

Slips uses zeek to detect SMTP connections,
When zeek detects a bad smtp login, it logs it to smtp.log, then slips reads
this file and sets an evidence.

## SMTP bruteforce

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


## DNS ARPA Scans

Whenever slips sees a new domain in dns.log, if the domain ends with '.in-addr.arpa'
slips keeps trach of this domain and the source IP that made the DNS request.

Then, if the source IP is seen doing 10 or more ARPA queries within 2 seconds,
slips generates an ARPA scan detection.


## SSH version changing


Zeek logs the used software and software versions in software.log, so slips knows from this file the software used by different IPs,
like whether it's an SSH::CLIENT, an HTTP::BROWSER, or an HTTP::SERVER

When slips detects an SSH client or an SSH server, it stores it with the IP and the SSH versions used in the database

Then whenever slips sees the same IP using another SSH version, it compares the stored SSH versions with the current SSH versions

If they are different, slips generates an alert

## Incompatible CN

Zeek logs each Certificate CN in ssl.log

When slips encounters a cn that claims to belong to any of Slips supported orgs (Google, Microsoft, Apple or Twitter)
Slips checks if the destination address or the destination server name belongs to these org.

If not, slips generates an evidence.


## CN URL Mismatch

Zeek logs each Certificate CN in ssl.log
For each CN Slips encounters, it checks if the server name is the same as the CN
Or if it belongs to the same org as the CN. if not, slips triggers an evidence

## Weird HTTP methods

Slips uses zeek's weird.log where zeek logs weird HTTP methods seen in http.log

When there's a weird HTTP method, slips detects it as well.


## Non-SSL connections on port 443

Slips detects established connections on port 443 that are not using SSL
using zeek's conn.log flows

if slips finds a flow using destination port 443 and the 'service' field
in conn.log isn't set to 'ssl', it alerts.

Sometimes zeek detects a connection from a source to a destination IP on port 443 as SSL, and another connection within
5 minutes later as non-SSL. Slips detects that and does not set an evidence for any of them.

Here's how it works


<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/how_non_ssl_evidence_works.png.png" >



## Connection to private IPs

Slips detects when a private IP is connected to another private IP with threat level info.

But it skips this alert when it's a DNS or a DHCP connection on port
53, 67 or 68 UDP to the gateway IP.

## Connection to private IPs outside the current local network

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

## High entropy DNS TXT answers

Slips check every DNS answer with TXT record for high entropy
strings.
Encoded or encrypted strings with entropy higher than or equal 5 will then be detected using shannon entropy
and alerted by slips.

the entropy threshold can be changed in slips.yaml by changing the value of ```entropy_threshold```

## Devices changing IPs

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


## Invalid DNS resolutions

Some DNS resolvers answer the DNS query to adservers with 0.0.0.0 or 127.0.0.1 as the ip of the domain to block the domain.
Slips detects this and sets an informational evidence.

This detection doesn't apply to queries ending with ".arpa" or ".local"
