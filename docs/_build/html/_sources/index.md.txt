<h1 align="left"> 

![Slips_logo](../slips_logo.png) 
<br>Slips v0.7.1
</h1>

Stratosphere Linux IPS, shortly Slips, is a Python-based intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. Slips was designed to focus on targeted attacks, to detect of command and control channels and to provide good visualisation for the analyst. Slips is able to analyze real live traffic from the device and the large network captures in the type of a pcap files, Suricata, Zeek/Bro and Argus flows. As a result, Slips highlights suspicious behaviour and connections that needs to be deeper analyzed. 

Slips is a behavioral-based IPS that uses machine learning to detect malicious behaviors in the network traffic. It is a modular software that can be extended. When Slips is run, it spawns several child processes to manage the I/O, to profile attackers and to run the detection modules. It also requires the Redis[3] database to store all the information. In order to detect attacks, Slips runs its Kalipso interface.

## Contents

* [Installation](installation.md)
* [Usage](usage.md)
* [Features](features.md)
* [Architecture](architecture.md)
* [Contributing](contributing.md)
