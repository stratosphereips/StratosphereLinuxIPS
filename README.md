# Stratosphere Linux IPS (slips) Version 0.6.2
Slips is an intrusion prevention system that is based on behavioral detections and machine learning algorithms. It's core is to separate the traffic into profiles for each IP address, and then separate the traffic further into time windows. Into each of these time windows slips extracts dozens of features and then analyses them in different ways. Slips also implements a module API, so anyone can create a single python file that quickly implements a new detection algorithm. 

# Installation

## Dependencies
The minimum slips requirements are:

- python 3.7 or more

- Redis database running (see http://redis.org)
    - In debian/ubuntu: ```apt-get install redis```
- py37-redis 
    - In debian/ubuntu: ```apt-get install python3-redis```
- maxminddb libraries for python (pip3 install maxminddb). Or ignore the geoip module in the conf.
- Zeek (Bro) https://docs.zeek.org/en/stable/install/install.html
- python-watchdog
    - In debian/ubuntu: ```apt-get install python3-watchdog```
  
To run redis you can:
    - In Linux, as a daemon: redis-server --daemonize yes
    - In macos, as a daemon: sudo port load redis
    - By hand and leaving redis running on the console in the foreground: redis-server /opt/local/etc/redis.conf

For using the kalipso interface you need to have
- nodejs
- npm
With npm you should install the following libraries
    - npm install blessed-contrib
    - npm install redis
    - npm install async
    - npm install ansi-colors
    - npm install clipboardy 

##### Installation of Zeek (Bro)
Zeek is a main part of slips and is used to convert all the pcaps and packets to nice information.

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
 
    - Make Zeek visible for slips. Some ideas:
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
2. Run slips: `./slips.py -c slips.conf -i <interface>` (be sure you use python3)
3. Check the folder called with the date of today. All files are updated every 5 seconds.
4. Use kalipso to see the results (option -G in slips)


-------

# Architecture of operation
- The data collected and used is on the _profile_ level and up. Slips does not work with data at the _flow_ level or _packet_ level to classify. This means that the simplest data structure available inside slips is the profile of an IP address. The modules can not access individual flows.

## Input Data
Slips can read flows from different input types. In particular:
- Pcap files (internally using Zeek).
- Packets directly from an interface (internally using Zeek).
- Suricata flows (from JSON files created by suricata, such as eve.json).
- Argus flows (CSV file separated by commas or TABs).
- Zeek/Bro flows from a Zeek folder with log files.
- Zeek/Bro flows from a conn.log file only.
- Nfdump flows from a binary nfdump file.

All the flows are converted to an internal format so once read, slips works the same with all of them.
The best formats to use are from a pcap file, from an interface or from a folder with Zeek logs. This is because then Zeek will generate other log files, such as http.log, that will be used by slips.


## Output

## Text Output
For now slips only creates log files as output, but more outputs are planned as ncurses and web.

The output of slips is stored in a folder called as the current date-time using seconds. So multiple executions will not override the results. Inside this main folder there is one folder per IP address that is being profiled. See Section _Architecture of Operation_ to understand which IP addresses are converted into profiles. Apart from the folders of the profiles, some files are created in this folder containing information about the complete capture, such as _Blocked.txt_ that has information about all the IP addresses that were detected and blocked.

Inside the folder of each profile there are three types of files: time-window files, timeline file and profile file.

### Time window files
Each of these files contains all the features extracted for this time window and its name is the start-time of the time window.

### Timeline file
The timeline file is created by the timeline module and is a unique file interpreting what this profile IP did. 

### Profile file
This file contains generic features of the profile that are not part of any individual time-window, such as information about its Ethernet MAC address.

# History of Slips
This is the new version of the Stratosphere IPS, a behavioral-based intrusion detection and prevention system that uses machine learning algorithms to detect malicious behaviors. It is part of a larger suite of programs that include the [Stratosphere Windows IPS] and the [Stratosphere Testing Framework].

## Usage

- Start redis

    In macos using ports, if you prefer to start a redis server manually, rather than using 'port load', then use this command:

        redis-server /opt/local/etc/redis.conf

    A startup item has been generated that will aid in starting redis with launchd. It is disabled by default. Execute the following command to start it, and to cause it to launch at startup:

        sudo port load redis

# More specific usage examples

Slips can be used by passing flows in its stdin, like this:

    cat test-flows/test3.binetflow | ./slips.py -l -c slips.conf -v 2 

    ./slips.py -r test-flows/test3.binetflow -l -c slips.conf -v 2 

To read your own packets you can do:

    sudo argus -i eth0 -S 5 -w - |ra -n -r -  | ./slips.py -l -v 2 -c slips.conf

    Which means run argus in eth0, report flows every 5s, give them to ra, ra only prints the flows, and slips works with them.


## Kalipso
Kalipso is the Nodejs-based console interface of slips. It works by reading the redis datbase and showing you the results. You start it by running slips with -G option. You can get out of it by pressiong q.


## Detection Models
[rewrite]
The core of the slips program is not only the machine learning algorithm, but more importantly the __behavioral models__. The behavioral models are created with the [Stratosphere Testing Framework] and are exported by our research team. This is very important because the models are _curated_ to maximize the detection. If you want to play and create your own behavioral models see the Stratosphere Testing Framework documentation.

The behavioral models are stored in the __models__ folder and will be updated regularly. In this version you should pull the git repository by hand to update the models.


## Features 
- Each flow from the pcap is stored only once. Even if you load the same pcap again when not deleting the DB.
- For now, everytime slips starts the database is deleted.
- Slips can detect port scans. For now the types detected are:
 - Horizontal port scans. Same src ip, sending TCP not established flows, to more than 3 dst ips. The amount of packetes is the confidence.
 - Too many not established connections. This is a type of detection that focuses on the same dst ip. If > 3 packets are sent in not establised tcp flows to the same dst port, then this is triggered.

[rewrite]
This version of slips comes with the following features:

- If you execute slips without the `-m` parameter it will __not__ detect any behavior in the network but just print the tuples (see the Stratosphere web page for more information). So actually you can also use slips to see what is happening in your network even without detection.
- Use `-a` to restrict the minimum amount of letters that the tuples had to have to be considered for detection. The default is a minimum of 3 letters which is enough for having at least one periodic letter.
- slips works by separating the traffic in time windows. This allows it to report to the user the detections in a fixed amount of time. The default time window is now __1 minute__ but you can change it with the parameter `-w` (a time window of five minutes is also recommended). (Warning: In the future we will update this to also consider the detection of IP addresses instead of tuples)
- If you want to tell slips to actually try to detect something, you should specify `-m` to tell slips where to find the behavioral models.
- The `-p` option tells slips to print the tuples that were detected. Even if the detection is working, without `-p` the tuples are not printed.
- If you want to be alerted of any detection without looking at the screen you can specify `-s` to have a sound alert. You need to install the pygames libraries.
- If you want to avoid doing any detection you should use `-D`.
- If you want to anonymize the source IP addresses before doing any processing, you can use `-A`. This will force all the source IPs to be hashed to MD5 in memory. Also a file is created in the current folder with the relationship of original IP addresses and new hashed IP addresses. So you can later relate the detections.


## The use of verbose (-v)
[rewrite]


### Where does it work
[rewrite]
- Slips runs in 
    - Ubuntu 16.04 LTS
    - Debian stable/testing/unstable
    - MacOS 10.9.5, 10.10.x to 10.12.x
- To try:
    - Android
    - IOS


### Roadmap
[rewrite]


### Changelog
[rewrite]
- 0.5 Completely renewed architecture and code.
- 0.4 was never reached
- 0.3.5
- 0.3.4
    - This is a mayor version change. Implementing new algorithms for analyzing the results, management of IPs, connections, whois database and more features.
    - A new parameter to specify the file (-r). This is as fast as reading the file from stdin.
    - Now we have a configuration file slips.conf. In there you can specify from fixed parameters, the time formats, to the columns in the flow file.
- 0.3.3alpha
    - First stable version with a minimal algorithm for detecting behavioral threats.


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
