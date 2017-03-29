# Stratosphere Linux IPS (slips) Version 0.3.4
This is the linux version of the Stratosphere IPS, a behavioral-based intrusion detection and prevention system that uses machine learning algorithms to detect malicious behaviors. It is part of a larger suite of programs that include the [Stratosphere Windows IPS] and the [Stratosphere Testing Framework].

This alpha version receives flows from a ra client ([Argus] Suite) and process them using a specific algorithm. The purpose of the Alpha version is to get feedback from the community, please send us your bug reports, feature requests and ideas. See the [Stratosphere IPS Website](https://stratosphereips.org).

## Platform
Slips (using argus) has been tested on Linux Debian 8 and Apple IOS 10.9.5 so far.

## Architecture
The idea of slips is to focus on the machine learning part of the detection and not in capturing the network traffic. That is why the traffic is received from an external Argus instance. Argus captures the packets in the networks and makes them _available_ to anyone connecting to the Argus port. Argus do not send the packets until somebody ask for them.

The basic architecture is to read the flows from an Argus instance using the __ra__ tool and to send the flows to slips as standard input. This way of working is very good because we can analyze the traffic of our own computer, and also we can analyze the traffic of a remote network or any other computer where an Argus instance is running. Actually if you run the Argus program in any Windows, Mac or router, slips can analyze the traffic.

## Usage
To use this alpha version you will need an argus instance running and listening in one port.

- If you don't have an Argus instance, first install it:
    - Source install from [Argus].
    - In Debian and Ubuntu you can do
        - sudo apt-get install argus argus-clients

- To run argus in your own computer you should do:
    - argus -B localhost -F [slipsfolder]/argus.conf

    This will run argus in your interface, open the port 561 in the localhost address only and run in background. See the argus configuration file and the Argus documentation for more information. (port 561 is used because is not in the default port list of nmap, so there are fewer chances that anybody will find it).

- Then you start the slips program receiving packets from a ra client.

    ra -F [slipsfolder]/ra.conf -n -Z b -S 127.0.0.1:561 | [slipsfolder]/./slips.py -f [slipsfolder]/models -d

    This will read the network traffic in your computer and try to detect some malicious behavior by applying the models in the folder __models__.

    > Warning! You should wait at least one hour before Argus starts sending flows to slips. After this first hour the flows will arrive continually, but Argus is configured to read packets for one hour before it can create the flows. The best way of avoiding this is to let Argus run in the computer all the time and just connect with slips when you want. Remember: when is running Argus do not store the packets.

## Detection Models
The core of the slips program is not only the machine learning algorithm, but more importantly the __behavioral models__. The behavioral models are created with the [Stratosphere Testing Framework] and are exported by our research team. This is very important because the models are _curated_ to maximize the detection. If you want to play and create your own behavioral models see the Stratosphere Testing Framework documentation.

The behavioral models are stored in the __models__ folder and will be updated regularly. In this version you should pull the git repository by hand to update the models.

## Features 
This version of slips comes with the following features:

- If you execute slips without the -m parameter it will __not__ detect any behavior in the network but just print the tuples (see the Stratosphere web page for more information). So actually you can also use slips to see what is happening in your network even without detection.
- Use -a to restrict the minimum amount of letters that the tuples had to have to be considered for detection. The default is a minimum of 3 letters which is enough for having at least one periodic letter.
- slips works by separating the traffic in time windows. This allows it to report to the user the detections in a fixed amount of time. The default time window is now __1 minute__ but you can change it with the parameter -w (a time window of five minutes is also recommended). (Warning: In the future we will update this to also consider the detection of IP addresses instead of tuples)
- If you want to tell slips to actually try to detect something, you should specify -m to tell slips where to find the behavioral models.
- The -p option tells slips to print the tuples that were detected. Even if the detection is working, without -p the tuples are not printed.
- If you want to be alerted of any detection without looking at the screen you can specify -s to have a sound alert. You need to install the pygames libraries.
- If you want to avoid doing any detection you should use -D.
- If you want to anonymize the source IP addresses before doing any processing, you can use -A. This will force all the source IPs to be hashed to MD5 in memory. Also a file is created in the current folder with the relationship of original IP addresses and new hashed IP addresses. So you can later relate the detections.


## The use of verbose (-v)

- -v 0: 
    - In each time window shows:
        - Print the detected source IP address, together with info about the thresholds and scores.
- -v 1: 
    - In each time window shows:
        - Print the detected source IP address, together with info about the thresholds and scores.
- -v 2: 
    - For each detected source IP, print also the detected connections.
- -v 3: 
    - For each detected connection, print also the which model matched that connection and when.
- -v 4: 
    - Print the source IP addresses that were NOT detected.
- -v 5: 
    - For the NOT detected IP, print the connections
- -v 6: 
    - For the NOT detected IP, print each NOT detected test for each connection



[Argus]: http://qosient.com/argus/ "Argus"
[Stratosphere Testing Framework]: https://github.com/stratosphereips/StratosphereTestingFramework
[Stratosphere Windows IPS]: https://github.com/stratosphereips/StratosphereIps

### Where does it work
- Slips runs in 
    - Ubuntu 16.04 LTS
    - Debian stable/testing/unstable
    - MacOS 10.9.5, 10.10.x to 10.12.x
- To try:
    - Android
    - IOS
### Roadmap

### Changelog
- 0.3.4
    - This is a mayor version change. Implementing new algorithms for analyzing the results, management of IPs, connections, whois database and more features.
    - A new parameter to specify the file (-r). This is as fast as reading the file from stdin.
    - Now we have a configuration file slips.conf. In there you can specify from fixed parameters, the time formats, to the columns in the flow file.
- 0.3.3alpha
    - First stable version with a minimal algorithm for detecting behavioral threats.



### TODO
- Make a good reference to the installation of argus 3.x
- Create a local DB of IPs so we can rememeber info about them (sqlite)
- Add priories to the log: CRITIAL, etc.
- If even the format of the flows change during the read, one idea is to search for an exception in the read of the format and then check which is the new format in the flow. Only check when there is an exception.

### Author and Contributors

- The author of the project is Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com. (Send an email for bugs, reports, ideas or comments)
- Ondrej Lukas: New detection metric of infected IPs based on timewindows, detection windows, weighted scores and averages. Also all the ip_handler, alerts classs, etc. 
- Elaheh Biglar Beigi
- MariaRigaki 
- kartik88363
