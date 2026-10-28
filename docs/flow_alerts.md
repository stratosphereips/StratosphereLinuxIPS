# `flow_alerts` Module

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
- Alerts from Zeek: Self-signed certs, invalid certs, port-scans and address scans
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
- Tor exit nodes
The details of each detection follows.

## TCP direction when capture starts during an existing connection

Zeek can first see packets after a TCP connection has already started. Its
recorded source then does not necessarily identify the computer that opened
the connection. A state such as `SF` alone does not prove who connected.

For example, a client may already be connected to Matterhorn on TCP port 902.
If capture first sees a reply, Zeek may record Matterhorn:902 as the source and
the client's temporary port 59148 as the destination. History `AdDTafF` contains
no handshake. Slips must not report that as Matterhorn connecting to an unknown
service on port 59148.

When Zeek packet history is present, checks that assign client/server roles
require a source SYN (`S`) or a destination SYN-ACK (`h`). This applies to
unknown ports, reconnection attempts, connections without DNS, private-network
connection checks, connections to multiple ports, and non-HTTPS on port 443.
Ongoing traffic is still stored, and byte-volume and connection-length checks
still run. Slips does not guess direction from which port number is smaller.
Inputs without a Zeek history field keep their existing behavior; an empty
Zeek history cannot confirm an initiator.

The `^` marker means Zeek already flipped its recorded endpoints. Slips keeps
those endpoints, ports, counters, UID and raw history unchanged. Flags before
each marker are interpreted in the roles used at that moment, then related to
the final endpoints. For example, `H^S` supports the final source as client;
`S^` does not. A marker alone is not a reason to reverse or discard a flow.
See Zeek's [connection direction documentation](https://docs.zeek.org/en/master/advanced/devel/conn.html#flipping-connections).


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
- DNS service connections over UDP or TCP port 53 to configured DNS servers,
  or to servers observed returning `NOERROR` or `NXDOMAIN` DNS replies. A resolver
  is normally contacted directly by IP, so it does not need a preceding lookup
  of its own address. This also applies when Zeek leaves the connection's
  application protocol blank. The detector rechecks after its existing
  15-second processing grace period so a reply processed later can establish
  the resolver. Observed responders are kept separately per interface in a
  bounded 4,096-entry cache and qualify within 24 hours of the connection's
  capture time. Queries without replies and `SERVFAIL`/`REFUSED` responses do
  not establish a working resolver. A decoded reply can establish the responder
  even when Zeek could not retain its question. This exception only affects
  `CONNECTION_WITHOUT_DNS`; DNS anomaly and threat-intelligence checks still run.


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

Unknown-port and connection-to-private-IP evidence are skipped when either
endpoint is multicast, the IPv4 limited-broadcast address, or the monitored
interface's subnet-directed broadcast address at capture time. A recorded
broadcast or multicast destination MAC also excludes the flow, even when the
subnet is unknown or has since changed.

Apple services follow [Apple's documented TCP/UDP ports](https://support.apple.com/en-hk/103229).
Fixed services include APNs on TCP 5223 and 2197, Remote Desktop and
Classroom, AirPlay, Bonjour, printing, and device pairing on TCP 62078.
TCP and UDP are separate entries; knowing TCP 5223 does not exempt UDP 5223.

Broad application ranges (TCP 8000–8999 and 42000–42999, UDP 3478–3497 and
16384–16472, and TCP/UDP 49152–65535) remain in the organization-specific
file. They count as known only when the existing Apple identity checks
match. This keeps arbitrary high ports on other hosts eligible for
Unknown Port detection. These entries do not whitelist traffic; other
behavioral and threat-intelligence detections still run.

The feed updater imports changed port files into the shared cache at
startup. Restart Slips after updating the files to load the new entries.
Existing evidence is retained.

The threat level of this evidence depends on the state of hte flow. established connections have higher threat levels.


## Data Upload

Slips generates 'possible data upload' alerts when the number of uploaded bytes to any IP exceeds 100 MBs over
the timewindow period which is, by default, 1h.

See detailed explanation of timewindows
[here](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html?highlight=timewindows#architecture).

The number of MBs can be modified by changing the value of ```data_exfiltration_threshold``` in ```slips.yaml```


Slips also detects data upload when an IP uploads >=100MBs to any IP in 1 connections.

## Tor Exit Nodes

Slips generates informational evidence when it detects a tor exit node from the list https://check.torproject.org/torbulkexitlist.

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
Self-signed certs, invalid certs, port-scans, and address scans.

Some scans are also detected by Slips independently of Zeek, like ICMP sweeps and vertical/horizontal portscans.
Check
[PING Sweeps](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#ping-sweeps)
section for more info

## SMTP login bruteforce

Slips alerts when 3+ invalid SMTP login attempts occurs within 10s

## SSH brute_force_detector

SSH brute force detector is documented in the dedicated `brute_force_detector` module page:

- [brute_force_detector Module](brute_force_detector.md)

The `flow_alerts` module still detects successful SSH sessions, but SSH password guessing is no longer owned by `flow_alerts`.

## DGA

When the DNS server fails to resolve a domain, it responds back with NXDOMAIN code.

Slips counts distinct failed DNS names per source IP and time window. Retries,
case changes, trailing dots, and a `.lan` search-suffix variant of the same
public name count once. Local service-discovery names, reverse lookups,
`.local`, and reserved `.invalid` names do not contribute to this DGA signal.

Evidence starts at 10 distinct failed names and recurs for every five new
distinct names (15, 20, and so on). Existing evidence remains in run history;
the corrected counting applies to new DNS traffic after restarting Slips.
DNS resolvers that block domains by returning NXDOMAIN can still contribute
distinct names to this signal. Review the linked DNS flows and local resolver
policy before treating a DGA evidence record as an infection.

## Connection to multiple ports

When Slips encounters a connection to or from a specific IP and a specific port, it scans previous connections looking for connection to/from that same IP using a different port.

It alerts when finding two or more connections to the same IP.

## Malicious SSL certificates

Slips uses SSL certificates sha1 hashes to detect C&C servers.

Slips supports SSL feeds and is shipped with Abuse.ch feed of malicious SSL hashes by default.
And you can add other SSL feeds in ```ssl_feeds``` in ```slips.yaml```.

### Certificate organization and capture dates

`TLS_PROVIDER_IMPERSONATION` (**Suspected TLS provider impersonation**) is
**high threat**. It checks whether the certificate's organization fields name
a supported provider while both the server name and destination IP are
outside that provider's known domains and networks. A provider name appearing
only inside an unrelated hostname is not enough. A missing certificate
subject, server name, or bundled provider-domain list skips this check.

The description names the server, its claimed provider, and the client that
connected. The server presenting the certificate is the suspected attacker;
the client is the potential victim. The high-threat evidence belongs to the
server's profile. The triggering connection retains its original direction.
Provider lists can be incomplete, so the finding describes suspected
impersonation rather than claiming it has proved who owns the domain.

Domains bundled with Slips are loaded once when the detector starts, so a
missing or older shared cache does not by itself flag those legitimate
domains. A provider domain hosted on a CDN is accepted even if that CDN's IP
is outside the provider's networks. For example, `mem.gfx.ms` is used by
[Microsoft Support](https://support.microsoft.com/en-us/); the bundled
Microsoft domains include `gfx.ms` and `assets.onestore.ms`, both listed in
[Microsoft's service endpoints](https://learn.microsoft.com/microsoft-365/enterprise/urls-and-ip-address-ranges).
Exact domains and their subdomains match;
names such as `gfx.ms.attacker.example` do not.

The network lookup reads decoded
IP ranges from the shared organization cache; it does not require those
ranges to exist in each analysis database. For example,
`104.244.43.176` belongs to the bundled Twitter range `104.244.40.0/21` and
must not trigger this finding just because a separate file analysis has an
empty run database.

This check is independent of certificate dates. Zeek's certificate validation
uses the captured network time by default, not the date when the webpage is
opened ([Zeek x509_verify documentation](https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_X509.functions.bif.zeek.html#id-x509_verify)).
Imported logs may already contain a date error. If their timestamps are only
relative seconds, Slips cannot reconstruct the original calendar date or
decide whether the certificate was valid then. The web details show
**Certificate dates unknown**, explain the missing date, and preserve the
original validation text. An old capture with real calendar timestamps keeps
its recorded result; it is not revalidated against today. Non-date errors
such as self-signed certificates are not hidden.

The organization lookup fix applies to new analysis runs using the updated
code, or after restarting a running capture. Existing saved
evidence and alert scores remain historical records; viewing a saved output
does not run the detectors again or delete earlier findings. The old name,
`INCOMPATIBLE_CN`, remains an accepted alias for stored evidence, P2P input
and evidence-specific whitelist rules. New detections use the new name.
Saved findings retain their original threat and profile; the web labels
the old type **TLS provider mismatch**. Reanalyze into a new output
folder to apply the corrected detector and scores to an old capture.

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

Slips detects when a private IP is connected to another private IP with threat level info. ICMP traffic does not produce `CONNECTION_TO_PRIVATE_IP` evidence.
Broadcast and multicast traffic is excluded, as is UDP mDNS on source or
destination port 5353, including unicast mDNS replies.
Slips checks the recorded destination MAC as well as the IP addresses: an
Ethernet broadcast (`ff:ff:ff:ff:ff:ff`) or multicast destination does not
produce this evidence, even if the interface subnet is unknown. For IP-only
flows, subnet-directed broadcasts are checked against the subnet active at
the flow's capture time, including delayed flows processed after a network
change. Without a known subnet or group destination MAC, an address ending
in `.255` is not assumed to be broadcast; it can be a valid host address on
other subnet sizes. These exclusions also apply to unknown-port evidence.

But it skips this alert when it's a DNS or a DHCP connection on port
53, 67 or 68 UDP to the gateway IP.

Slips also skips this alert for DNS traffic on port 53 and for DHCPv6 traffic
on ports 546 and 547. When Slips sees a private DNS flow in the analyzed
traffic, it records that destination address as a DNS server and prints it to
the display and to slips.log.

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
communicating on port 53/UDP. Slips marks that destination address as the DNS server as soon as it sees a private
DNS flow in `dns.log` and prints `Detected DNS server by traffic heuristic: <ip>` to the display and `slips.log`.
The same heuristic applies to private IPv4 and IPv6 DNS servers. this is likely a DNS misconfiguration hence a FP.

Slips also ignores this evidence when the checked IP is one of the DNS
servers detected from the analyzed DNS traffic and the matching DNS server
port is 53. This applies to both IPv4 and IPv6 resolver addresses and
covers requests sent to the resolver and replies coming back from it.

For `CONNECTION_TO_PRIVATE_IP`, Slips suppresses DHCPv6 traffic on ports 546
and 547. This avoids false positives when the same local network device
provides both DNS and DHCPv6 services but answers with a different IPv6
address, such as a link-local address.

## High entropy DNS TXT answers

Slips checks DNS TXT answers for high entropy. Reverse DNS `.arpa` TXT
answers use a higher Shannon entropy threshold of 5.8 because ordinary
device and service metadata often contains long encoded values.
strings.
Encoded or encrypted strings with entropy higher than or equal 5 will then be detected using shannon entropy
and alerted by slips.

the entropy threshold can be changed in slips.yaml by changing the value of ```entropy_threshold```

## Devices changing IPs

For a private IPv4 source first seen in conn.log, Slips checks whether its
unicast MAC was previously associated with a different private IPv4 address.
If so, it reports "Device changing IPs". Link-local and special addresses are
excluded.

Public IPs and the capture interface's gateway are excluded from this check.
For routed traffic, the Ethernet MAC belongs to the local router, not the
remote IP. Public IPs are not stored as device MAC owners, and this detector
ignores any public IP entries left by older versions. Gateway information
learned by another worker is used immediately, without requiring each worker
to infer the gateway again.


## GRE tunnels

Slips uses zeek tunnel.log to alert on GRE tunnels when found. Whenever one
any action other than "Tunnel::DISCOVER" is found, slips sets an evidence
with threat level low

## GRE tunnel scans

Slips uses zeek tunnel.log to alert on GRE tunnels scan. Slips considers any log with "Tunnel::DISCOVER" action a GRE scan.

The threat level of this evidence is low.

## Login log entries

Slips reads Zeek `login.log` entries generated by `zeek-scripts/login.zeek`. It can detect telnet, rlogin, or rsh logins.
For each entry in the zeek logs, the profiler publishes a `new_login` message and
`flow_alerts` sets informational evidence for the server receiving the login.


## Invalid DNS resolutions

Some DNS resolvers answer the DNS query to adservers with 0.0.0.0 or 127.0.0.1 as the ip of the domain to block the domain.
Slips detects this and sets an informational evidence.

This detection doesn't apply to queries ending with ".arpa" or ".local"
