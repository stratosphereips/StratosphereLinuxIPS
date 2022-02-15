# IP Info

The IP info module has several ways of getting information about an IP address, it includes:

- ASN
- Country by Geolocation 
- Given a MAC, its Vendor 
- Reverse DNS

## ASN

Slips is shipped with an offline database (GeoLite2) in ```databases/GeoLite2-ASN.mmdb``` 
to search for ASNs, if
the ASN of a given IP is not in the GeoLite2 database, we try to get the ASN online
using the online database using the ```ipwhois``` library.
However, to reduce the amount of requests, we retrieve the range of the IP and we cache the whole range. To search and cache the whole range of an IP, the module uses the ipwhois library. The ipwhois library gets the range of this IP by making a connection to the server ```cymru.com``` using a TXT DNS query. The DNS server is the one set up in the operating system. For example to get the ASN of the IP 13.32.98.150, you will see a DNS connection asking for the TXT record of the domain ```150.98.32.13.origin.asn.cymru.com```.

## Country by Geolocation 

Slips is shipped with an offline database (GeoLite2) in ```databases/GeoLite2-Country.mmdb``` 
to search for Geolocation.

## Mac Vendors

Slips is shipped with an offline database ```databases/macaddress-db.json``` for 
MAC address vendor mapping.

Slips gets the MAC address of each IP from dhcp.log and then searches the offline
database using the OUI.

Slips makes sure it doesn't perform duplicate searches of the same MAC Address.

## Reverse DNS
This is obtained by doing a standard in-addr.arpa DNS request.

