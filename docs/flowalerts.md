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

The details of each detection follows.

## Detect connections without DNS resolution
This detection will ignore certain IP addresses for which a connection without DNS is ok. The exceptions are:

- If Slips runs in a network device (as opposed to, for example, a pcap) ignore all connections that happen in the first 1 minute of operation of Slips. 
This is because most DNS resolutions already happen and there are many false positives.

- Private IPs
- Localhost IPs (127.0.0.0/8)
- Reserved IPs (including the super broadcast 255.255.255.255)
- IPv6 local-link IPs
- Multicast IPs
- Broadcast IPs only if they are private

## Still under construction...
