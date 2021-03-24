<h1 align="center"> 
![Slips_logo](slips_logo.png)
<br>
Slips v0.7.1
</h1>


<h4 align="center"> 
Behavioral based Intrusion Prevention System<br>

Complete documentation of Slips is **[here](https://stratospherelinuxips.readthedocs.io/en/latest/) <br>

[Introduction](#introduction) — [Slips in action](#slips-in-action) — [Running Slips in a Docker](#running-slips-in-a-docker) — [Authors and Contributors](#authors-and-contributors)
</h4>

## Introduction

Stratosphere Linux IPS, shortly Slips, is a Python-based intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. Slips was designed to focus on targeted attacks, to detect of command and control channels and to provide good visualisation for the analyst. Slips is able to analyze real live traffic from the device and the large network captures in the type of a pcap files, Suricata, Zeek/Bro and Argus flows. As a result, Slips highlights suspicious behaviour and connections that needs to be deeper analyzed. 

Slips is a modular software. Each module is designed to perform a specific detection in the network traffic. Current version of Slips contains following modules:
- asn - module to load and find the ASN of each IP
- geoip - module to find the country and geolocation information of each IP
- https - module to train or test a RandomForest to detect malicious https flows
- port scan detector - module to detect Horizontal and Vertical port scans 
- threat Intelligence - module to check if each IP is in a list of malicious IPs 
- timeline - module to create a timeline of what happened in the network based on all the flows and type of data available
- lstm-cc-detection -  module to detect command and control channels using LSTM neural network and the stratosphere behavioral letters
- VirusTotal - module to lookup IP address on VirusTotal
- flowalerts - module to find malicious behaviour in each flow. Current measures are: long duration of the connection, successful ssh.
- [in process] blocking - module to block malicious IPs connecting to the device

Slips has its own console graphical user interface called Kalipso. Kalipso summarizes the detections performed by Slips in colorful graphs and tables.

Complete documentation of Slips internal architecture and how to implement new modules ia available here: https://stratospherelinuxips.readthedocs.io/en/latest/

## Slips in action

![](slips-kalipso.gif)


## Running Slips in a Docker

The easiest way to run Slips is inside a docker. Current version of Slips docker can analyze network captures (pcap, Zeek flows, Argus flows, etc.), but is not able to analyze real live traffic. How to use Slips docker from DockerHub:

	mkdir ~/dataset
	cp <some-place>/myfile.pcap ~/dataset
  	docker run -it --rm --net=host -v ~/dataset:/StratosphereLinuxIPS/dataset stratosphereips/slips:latest
  	./slips.py -c slips.conf -f dataset/myfile.pcap
  	./kalipso.sh


## Authors and Contributors

- Main author: Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com. 
- Ondrej Lukas: During the original slips code, he worked on the new detection metric of infected IPs based on timewindows, detection windows, weighted scores and averages. Also all the ip_handler, alerts classes, etc.
- Frantisek Strasak. Work on all the new version of slips, features, output, core and the https Machine Learning detection module. (https://github.com/frenky-strasak)
- Dita hollmannova: Worked in the VirusTotal module and the Whois modul. (dita.hollmannova@gmail.com)
- Kamila Babayeva: Implemented the NodeJS interface (kamifai14@gmail.com)
- Elaheh Biglar Beigi
- MariaRigaki 
- kartik88363
- arkamar
