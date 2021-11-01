# Threat Intelligence

Slips has a complex system to deal with Threat Intelligence feeds. The general features are:

- Use a configuration file to indicate which threat intelligence feeds to download


## Matching of Domains
Slips gets every domain that can find in the network and tries to see if it is in any blacklist. The domains are currently taken from:

- DNS requests
- DNS responses
- HTTP host names
- TLS SNI

Once a domain is found, it is verified against the downloaded list of domains from the blacklists defined in the configuration file. If an exact match is found, then the corresponding alert is generated. If an exact match is not found, then Slips verifies if the verified domain is a subdomain of any domain in the blacklist. 

For example, if the domain in the traffic is _here.testing.com_, Slips first checks if the exact domain _here.testing.com_ is in any blacklist, and if there is no match, it checks if the domain _testing.com_ is in any blacklists too.
