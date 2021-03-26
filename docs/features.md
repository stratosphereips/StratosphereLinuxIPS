# Features

## Input and Output

Input / Output. There are two I/O processes in Slips: the input process and the output process. 
The idea of Slips is to focus on the machine learning part of the detection and not in capturing the network traffic. 
The input process reads flows of different types:
Pcap files (internally using Zeek[4]) 
Packets directly from an interface (internally using Zeek)
Suricata flows (from JSON files created by Suricata, such as eve.json)
Argus flows (CSV file separated by commas or TABs) 
Zeek/Bro flows from a Zeek folder with log files
Nfdump flows from a binary nfdump file
All the input flows are converted to an internal format. So once read, Slips works the same with all of them.
The output process collects output from the modules and handles the display of information on screen.



## Modules

Modules are Python-based files that allow any developer to extend the functionality of Slips. They process and analyze data, perform additional detections and store data in Redis for other modules to consume. Currently, Slips has the following modules:
asn - module to load and find the ASN of each IP
Geoip - module to find the country and geolocation information of each IP
ML for https - module to train or test a RandomForest to detect malicious https flows
Port scan detector - module to detect Horizontal and Vertical port scans 
Threat Intelligence - module to check if each IP is in a list of malicious IPs 
Timeline - module to create a timeline of what happened in the network based on all the flows and type of data available
Lstm-cc-detection -  module to detect command and control channels using LSTM neural network and the stratosphere behavioral letters
VirusTotal - module to lookup IP address on VirusTotal[5]
Kalipso - graphical user interface to display analyzed traffic by Slips
LongConnections -  module to detect long duration connections in the network traffic
Malicious IRC - Machine Learning module to detect malicious IRC sessions, channels, and users
P2P - module to share detection data between different instances of Slips by creating a custom p2p local network
Update Manager - module to  update periodically Threat Intelligence files and control their changes by incrementally updating the database
Blocking - module to block detected malicious IPs in the firewall. Currently available for Linux.

