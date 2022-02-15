# Threat Intelligence

Slips has a complex system to deal with Threat Intelligence feeds. 

Slips supports different kinds of IoCs from TI feeds (IPs, IP ranges, domains, JA3 hashes, SSL hashes)

File hashes and URLs aren't supported.

To make sure Slips is up to date with the most recent IoCs in all feeds,
all feeds are loaded, parsed and updated periodically and automatically by Slips every 24 hours, which requires no user interaction.


## Matching of IPs

Slips gets every IP it can find in the network and tries to see if it is in any blacklist.

If a match is found, it generates an evidence, if no exact match is found, it searches the Blacklisted ranges taken from different TI feeds


## Matching of Domains
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

## Matching of JA3 Hashes

Every time Slips encounters an TLS flow,
it compares each JA3 and JA3s with the feeds of malicious JA3 and alerts when there’s a match.

## Matching of SSL SHA1 Hashes
#todo 

## Local Threat Intelligence files

Slips has a local file for adding IoCs of your own, 
it's located in ```modules/ThreatIntelligence1/local_data_files/``` by default,
this path can be changed by changing ```download_path_for_local_threat_intelligence``` in ```slips.conf```.

The format of the file is "IP address","Threat level", "Description"

Threat level available options: info, low, medium, high, critical

Refer to the [architecture section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html) for detailed explanation of Slips threat levels.


Example:
    
    "23.253.126.58","high","Simda CC"
    "bncv00.no-ip.info", "critical", "Variant.Zusy"


## Adding your own remote feed
#todo
## Removing a TI feed from the database
#todo