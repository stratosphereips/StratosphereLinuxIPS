# Stratosphere Linux IPS (Slips) Version 0.6.7

Slips is a behavioral-based Python intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. Slips was designed to focus on targeted attacks, detection of command and control channels to provide good visualisation for the analyst.
Slips is a modular software 

# Installation

## Running in a Docker

Now Slips can be run inside a docker if you want to analyze flow or pcap files. If you need to analyze the traffic of your computer (access to the network card) then, for now, you need to install Slips in your own computer.

## From the Docker Hub

	docker run -it --rm --net=host stratosphereips/slips:v0.6.7
	./slips.py -c slips.conf -f dataset/test3.binetflow


### If you want to share files between your host and the docker, you can do:

	mkdir ~/dataset
	cp <some-place>/myfile.pcap ~/dataset
	docker run -it --rm --net=host -v ~/dataset:/StratosphereLinuxIPS/dataset stratosphereips/slips:v0.6.7
	./slips.py -c slips.conf -f dataset/myfile.pcap


## Build the docker from the Dockerfile

To build the docker locally from the Docker file, you can do as follows (we use --no-cache so the git clone is done all the time).
If you cloned StratosphereLinuxIPS in '~/code/StratosphereLinuxIPS', then you can build the Docker image with:

	cd docker
	docker build --no-cache -t slips -f Dockerfile .
	docker run -it --rm --net=host -v ~/code/StratosphereLinuxIPS/dataset:/StratosphereLinuxIPS/dataset slips
	./slips.py -c slips.conf -f dataset/test3.binetflow

You can now put pcap files or other flow files in the ./dataset/ folder and analyze them

	cp some-pcap-file.pcap ~/code/StratosphereLinuxIPS/dataset
	docker run -it --rm --net=host -v ../dataset/:/StratosphereLinuxIPS/dataset slips
	./slips.py -c slips.conf -f dataset/some-pcap-file.pcap


## Dependencies
The minimum Slips requirements are:

- python 3.7+

- Redis database running (see http://redis.org)
    - In debian/ubuntu: ```apt-get install redis```
- py37-redis 3.4.1+ 
    - In debian/ubuntu: ```pip3 install redis```
- maxminddb libraries for python (pip3 install maxminddb). Or ignore the geoip module in the conf.
- Zeek (Bro) https://docs.zeek.org/en/stable/install/install.html
- python-watchdog
    - In debian/ubuntu: ```apt-get install python3-watchdog```
- validators (For threatintellingence module)
	- ```pythong -m pip install validators```
  
To run redis you can:
    - In Linux, as a daemon: redis-server --daemonize yes
    - In macOS, as a daemon: sudo port load redis
    - By hand and leaving redis running on the console in the foreground: redis-server /opt/local/etc/redis.conf

For using Kalipso interface you need to have:
- Node.js -https://nodejs.org
- npm (should be automatically installed with Node.js)
With npm you should install the following libraries
    - npm install blessed
    - npm install blessed-contrib
    - npm install redis
    - npm install async
    - npm install chalk
    - nom install strip-ansi
    - npm install clipboardy 
    - npm install fs

##### Installation of Zeek (Bro)
Slips uses Zeek to generate files for most input types.

- How to install and set Zeek (Bro) properly?

    - Download a binary package ready for your system. Complete up to date instructions here: https://software.opensuse.org//download.html?project=security%3Azeek&package=zeek

        - For Ubuntu, for example, you can do:
            ```
            sudo sh -c "echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_19.04/ /' > /etc/apt/sources.list.d/security:zeek.list"
            wget -nv https://download.opensuse.org/repositories/security:zeek/xUbuntu_19.04/Release.key -O Release.key
            sudo apt-key add - < Release.key
            sudo apt-get update
            sudo apt-get install zeek
            ```
 
    - Make Zeek visible for Slips. Some ideas:
        - Create a link to "/bin" folder from compiled Zeek (Bro) folder like 
            ```
            "sudo ln -s PATH_TO_COMPILED_BRO_FOLDER/bin/bro /usr/local/bin"
            ```
        
            This is usually in /opt/bro
            ```
            "sudo ln -s /opt/bro/bin/bro /usr/local/bin"
            ```

            In case you installed Zeek 3.0, the binaries and folders are now called zeek
            ```
            "sudo ln -s /opt/zeek/bin/zeek /usr/local/bin/bro"
            ```

            Notice how we still call the binary bro, until we update slips.

        - or add path from your compiled zeek (bro) folder to ~/.bashrc file.


# Fast usage in your own traffic
1. Start Redis: `redis-server --daemonize yes`
2. Run Slips: `./slips.py -c slips.conf -i <interface>` (be sure you use python3)
3. Check the folder called with the date of today. All files are updated every 5 seconds.
4. Use Kalipso to see the results (option -G in Slips to start Kalipso automatically, or go to StratosphereLinuxIPS/modules/blessed and execute `node ips_timewindows.js` to start Kalipso when needed)

Requirements to capture your own traffic:
- curl
    - In debian/ubuntu: ```apt-get install curl```
- get authorization to zeek to capture the traffic in the linux interface:
    - ```setcap cap_net_raw,cap_net_admin=eip /usr/local/zeek/bin/zeek```
-------

# Architecture of operation
Slips works at a flow level, instead of a packet level, gaining a high level view of behaviors. Slips creates traffic profiles for each IP address that appears in the traffic. A profile contains the complete behavior of an IP address. Each profile is divided into time windows. Each time window is 1 hour long by default and contains dozens of features computed for all connections that start in that time window. Detections are done in each time window, allowing the profile to be marked as uninfected in the next time window.

#Slips processes
When Slips is run, it spawns several child processes to manage the I/O, to profile attackers and to run the detection modules. It also connects to the Redis database to store all the information. In order to detect attacks, Slips runs its Kalipso interface.

 
## Input Data 
The input process reads flows of different types:
	-Pcap files (internally using Zeek) 
	-Packets directly from an interface (internally using Zeek)
	-Suricata flows (from JSON files created by Suricata, such as eve.json)
	-Argus flows (CSV file separated by commas or TABs) 
	-Zeek/Bro flows from a Zeek folder with log files
	-Nfdump flows from a binary nfdump file
All the input flows are converted to an internal format. So once read, Slips works the same with all of them.


## Output

## Text Output
The output process collects output from the modules and handles collected data display. Currently Slips creates log files as an output and runs a graphical user interface Kalipso.

The log files of Slips are stored in a folder called as the current date-time. So that multiple executions will not override the results. Inside this folder there is a folder per a IP address that is being profiled. See Section _Architecture of Operation_ to understand which IP addresses are converted into profiles. Apart from the folders of the profiles, some files are created in this folder containing information about the complete capture, such as _Blocked.txt_ that has information about all the IP addresses that were detected and blocked.

Inside the folder of each profile there are three types of files: time window files, timeline file and profile file.

### Time window files
Each of these files contains all the features extracted for this time window and its name is the start-time of the time window.

### Timeline file
The timeline file is created by the timeline module and is a unique file interpreting what this profile IP address did. 

### Profile file
This file contains generic features of the profile that are not part of any individual time-window, such as information about its Ethernet MAC address.

# History of Slips
This is the new version of the Stratosphere IPS, a behavioral-based intrusion detection and prevention system that uses machine learning algorithms to detect malicious behaviors. It is part of a larger suite of programs that include the [Stratosphere Windows IPS] and the [Stratosphere Testing Framework].

## Usage

Example of specific usage: Slips can be used by passing input files:

    ./slips.py -c slips.conf -f dataset/test3.binetflow, where -c is the configuration file, -f is the binetflow input file

Other parameters for different input types:
	-r is for pcap
	-f <filename: is for binetflow files 
	-f <folder name: for zeek folders with log files 
	-b is for nfdump 
	-i interface

To read your own packets you can do:
	sudo ./slips.py -c slips.conf -i <interface>
   
## Kalipso
Kalipso is the Nodejs-based console interface of Slips. It works by reading the Redis datbase and showing you the results. You start it automatically by running Slips with -G option or manually by `node ips_timewindows.js` from StratosphereLinuxIPS/modules/blessed. You can exit Kalipso by pressing q or Control-C.


## Detection Models
Modules are Python-based files that allow any developer to extend the functionality of Slips. They process and analyze data, perform additional detections and store data in Redis for other modules to consume. Currenty, Slips has the following modules:
	_asn_ - module to load and find the ASN of each IP
	_geoip_ - module to find the country and geolocation information of each IP
	_https_ - module to train or test a RandomForest to detect malicious https flows
	_port scan detector_ - module to detect Horizontal and Vertical port scans 
	_threat Intelligence_ - module to check if each IP is in a list of malicious IPs 
	_timeline_ - module to create a timeline of what happened in the network based on all the 	  flows and type of data available
	_VirusTotal_ - module to lookup IP address on VirusTotal
	_Kalipso_ - graphical user interface to display analyzed traffic by Slips
The behavioral models are stored in the __models__ folder and will be updated regularly. In this version you should pull the git repository by hand to update the models.

The core of the Slips program is not only the machine learning algorithm, but more importantly the __behavioral models__ that are used to describe flows based on flows' duration, size, and periodicty. This is very important because the models are _curated_ to maximize the detection. More about behavioral models is in [Stratosphere Testing Framework].


## The use of verbose (-v)
[rewrite]


### Where does it work
[rewrite]
- Slips runs in 
    - Ubuntu 16.04+
    - Debian stable/testing/unstable
    - MacOS 10.9.5, 10.10.x to 10.12.x
- To try:
    - Android
    - IOS


### Roadmap
[rewrite]


### Changelog
[rewrite]
- 0.6.7
	- New lstm module to detect C&C channels in the network
	- Several bug fixed
	- New DNS blacklist management in the threat intelligence module
	- Better store of IPs in the database
	- Fix an error in how the behavioural letters where created
- 0.6.6 
	- Added DNS resolution for IPs in timeline
	- Added inTuple key to the timeline for inbound flows when analysis_direction = 'all'
	- Changed the timeline format in Slips and Kalipso
	- Defined host IP in Slips and Kalipso if Slips is run on interface
- 0.6.5 
	- Fixed Threat Intelligence module to be fully functional.
	- Added new feature to stop Slips automatically when input files ends.
	- Fixed the storing and display of inbound flows in analysis direction 'all'.
	- Fixed Kalipso to display inbound flows and h hotkey to display out tuples
- 0.5 Completely renewed architecture and code.
- 0.4 was never reached
- 0.3.5
- 0.3.4
	- This is a mayor version change. Implementing new algorithms for analyzing the results, management of IPs, connections, whois database and more features.
	- A new parameter to specify the file (-r). This is as fast as reading the file from stdin.
	- Now we have a configuration file slips.conf. In there you can specify from fixed parameters, the time formats, to the columns in the flow file.
- 0.3.3alpha
	- First stable version with a minimal algorithm for detecting behavioral threats.

### Current status
We are developing a new module _lstm-cc-detection_. This is a module to detect command and control channels using LSTM neural network and the stratosphere behavioral letters

# Common errors
- If you see the error 

    ```
    Error in run() of timeout must be non-negative
    <class 'ValueError'>
    timeout must be non-negative
    ```

It means that you have an older version of the xxx library. Please update to version > 

Fails
python3-redis 3.0.1
python3-redis 3.3.11
ii  redis-server                              5:5.0.2-1                                amd64        Persistent key-value database with network interface
ii  redis-server                              5:5.0.6-1                                amd64        Persistent key-value database with network interface



Works
redis (2.10.5)

VM
apt
    python3-redis 3.3.11
    ii  redis-server                              5:5.0.6-1                            amd64        Persistent key-value database with network interface

jin
apt
    ii  redis-server                              4:4.0.1-7                            amd64        Persistent key-value database with network interface
pip
redis               3.2.1




### Author and Contributors
[rewrite]

- Main author: Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com. 
- Ondrej Lukas: During the original slips code, he worked on the new detection metric of infected IPs based on timewindows, detection windows, weighted scores and averages. Also all the ip_handler, alerts classes, etc.
- Frantisek Strasak. Work on all the new version of slips, features, output, core and the https Machine Learning detection module. (https://github.com/frenky-strasak)
- Dita hollmannova: Worked in the VirusTotal module and the Whois modul. (dita.hollmannova@gmail.com)
- Kamila Babayeva: Implemented the NodeJS interface (kamifai14@gmail.com)
- Elaheh Biglar Beigi
- MariaRigaki 
- kartik88363
- arkamar


[Stratosphere Testing Framework]: https://github.com/stratosphereips/StratosphereTestingFramework
[Stratosphere Windows IPS]: https://github.com/stratosphereips/StratosphereIps
[Zeek]: https://www.zeek.org/download/index.html 
