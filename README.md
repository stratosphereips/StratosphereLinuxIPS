# Stratosphere Linux IPS (Slips) Version 0.7.1

Slips is a behavioral-based Python intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. Slips was designed to focus on targeted attacks, detection of command and control channels to provide good visualisation for the analyst.
Slips is a modular software 
## Example
![](slips-kalipso.gif)
# Installation

## Running in a Docker

Now Slips can be run inside a docker if you want to analyze flow or pcap files. If you need to analyze the traffic of your computer (access to the network card) then, for now, you need to install Slips in your own computer.

### From the Docker Hub

	docker run -it --rm --net=host stratosphereips/slips:v0.7.1
	./slips.py -c slips.conf -f dataset/test3.binetflow


### If you want to share files between your host and the docker, you can do:

	mkdir ~/dataset
	cp <some-place>/myfile.pcap ~/dataset
	docker run -it --rm --net=host -v ~/dataset:/StratosphereLinuxIPS/dataset stratosphereips/slips:v0.7.1
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

## Install in your computer completely
## Clone the repo

	git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git

## Install Dependencies
	- python 3.7+
	- Redis database (In debian/ubuntu: apt-get install redis)
	- python3 -m pip install --upgrade pip (Be sure your pip3 is the latest)
	- python3 -m pip install redis (>3.4.x)
	- python3 -m pip install maxminddb
	- python3 -m pip install watchdog
	- python3 -m pip install validators
	- python3 -m pip install urllib3
	- python3 -m pip install sklearn (for the ML modules, ignore if you ignore the package)
	- python3 -m pip install numpy (for the ML modules, ignore if you ignore the package)
	- python3 -m pip install tensorflow (for the ML modules, ignore if you ignore the package)
	- python3 -m pip install keras (for the ML modules, ignore if you ignore the package)
	- python3 -m pip install pandas (for the ML modules, ignore if you ignore the package)
	- python3 -m pip install certifi (for the VirusTotal module)
	- python3 -m pip install colorama
	- Zeek (https://zeek.org/get-zeek/)
  
For using Kalipso interface you need to have:

	- apt-get install node.js
	- apt-get install npm
With npm you should install the following libraries

	- npm install blessed
	- npm install blessed-contrib
	- npm install redis
	- npm install async
	- npm install chalk
	- npm install strip-ansi
	- npm install clipboardy 
	- npm install fs
	- npm install sorted-array-async

#### To run redis

    - In Linux, as a daemon: redis-server --daemonize yes
    - In macOS, as a daemon: sudo port load redis
    - By hand and leaving redis running on the console in the foreground: redis-server /opt/local/etc/redis.conf

##### Installation of Zeek (Bro)
Slips uses Zeek to generate files for most input types.

- How to install and set Zeek (Bro) properly?

    - Download a binary package ready for your system. Complete up to date instructions here https://zeek.org/get-zeek/

    - Make Zeek visible for Slips. Some ideas:
        - Create a link to "/bin" folder from compiled Zeek folder like 
            ```
            "sudo ln -s /opt/zeek/bin/zeek /usr/local/bin"
            ```

            ```
            "sudo ln -s PATH_TO_COMPILED_ZEEK_FOLDER/bin/zeek /usr/local/bin"
            ```
        
# Fast usage in your own traffic
1. Start Redis: `redis-server --daemonize yes`
2. Run Slips: `./slips.py -c slips.conf -i <interface>` (be sure you use python3)
3. Use Kalipso to see the results 
 a. ./kalipso.sh
 b. Optionally run slips with -G to start Kalipso automatically
4. Local logs are stored in the folder called with the date of today. All files are updated every 5 seconds.

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

# The concept of time in slips

- Every time we receive something, we update the TW modification time in a new redis ordered set (zset) (the old is not used). This set has the TW id and the time of last modification. The TW in this zset are never deleted.
- We update the slips_internal_time, every time we receive anything
- Every 5 seconds, slips.py, retrieves the sublist of TW from the zset that were modified in the last “time window width” (default 1hs).
- This list of TW that were modified is used to print the statistics and as part of the set_host_ip check in slips.py.
- In theory if a TW was not modifed in the last hs, then it should not appear in the list, which decreases until no TW was modified for some rounds, and we stop slips.

## Timeout of traffic
Zeek has a parameter called "tcp_inactivity_timeout". By default is 5 minutes, like in TCP. However, it may happen that due to different circonstances there is more than 5 minutes delay between packets (even in normal connections from Google). Since Slips usually has a time window width of 1hs, it can wait more until having the complete flow. For this reason Slips modifies the "tcp_inactivity_timeout" to be 1hs. 

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




