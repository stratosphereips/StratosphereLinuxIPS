# Flow Alerts

The module of flow alerts has several behavioral techniques to detect attacks by analyzing the content of each flow alone.

The detection techniques are:

- Detect long connections
- Detect successful SSH connections using Slips technique
- Detect successful SSH connections using Zeek technique
- Detect SSH bruteforcing using Zeek technique
- Detect connections without DNS resolution
- Detect DNS resolutions to IPs that were never used
- Detect connections to unknown ports
- Detect data exfiltration
- Detect malicious JA3 files
- Detect connections to port 0
- Detect self-signed certificates using Zeek
- Detect invalid certificates using Zeek
- Detect multiple reconnection attempts to the same dst port with not established flows
- Detect alerts from Zeek: Self-signed certs, invalid certs, port-scans and address scans, and password guessing 
- Detect DGA
- 
The details of each detection follows.

## Detect connections without DNS resolution
This detection will ignore certain IP addresses for which a connection without DNS is ok. The exceptions are:

- If Slips runs in a network device (as opposed to, for example, a pcap) ignore all connections that happen in the first 1 minute of operation of Slips. 
This is because most DNS resolutions already happen and there are many false positives.
=======
- Detect multiple reconnection attempts to the same destination port with not established flows
- Detect alerts from Zeek: Self-signed certs, invalid certs, port-scans and address scans, and password guessing 
- Detect DGA

The details of each detection follows.


## Detect long connections
Detect connections that are long, except the multicast connections.

## Detect connections without DNS resolution
This will detect connections done without a previous DNS resolution. The idea is that a connection without a DNS resolution is slightly suspicious.

If Slips runs by capturing packets directly from a network device (as opposed to, for example, a PCAP file), this detection will ignore all connections that happen in the first 3 minute of operation of Slips. This is because most times Slips is started when the computer is already running, and many DNS connections were already done. So waiting 3 minutes decreases the amount of False Positives.

This detection will ignore certain IP addresses for which a connection without DNS is ok. The exceptions are:

- Private IPs
- Localhost IPs (127.0.0.0/8)
- Reserved IPs (including the super broadcast 255.255.255.255)
- IPv6 local-link IPs
- Multicast IPs
- Broadcast IPs only if they are private


## Detect DNS resolutions without a connection
This will detect DNS resolutions for which no further connection was done. A resolution without a usage is slightly suspicious.

The domains that are excepted are:

- All reverse DNS resolutions using the in-addr.arpa domain.
- All .local domains
- The wild card domain *
- Subdomains of cymru.com, since it is used by the ipwhois library to get the ASN of an IP and its range.
- Ignore WPAD domain from Windows
- Ignore domains without a TLD such as the Chrome test domains.

## Detect DGA

When the dns server fails to resolve a domain, it responds back with NXDOMAIN code.

To detect DGA, Slips will count the amount of NXDOMAINs met in the DNS traffic of each source IP.

Then we alert when there is 10 or more NXDOMAINs.

Every 10,15,20 ..etc slips generates an alert.

## Still under construction...
