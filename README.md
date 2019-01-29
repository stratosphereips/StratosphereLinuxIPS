# Stratosphere Linux IPS (slips) Version 0.5
This is the new version of the Stratosphere IPS, a behavioral-based intrusion detection and prevention system that uses machine learning algorithms to detect malicious behaviors. It is part of a larger suite of programs that include the [Stratosphere Windows IPS] and the [Stratosphere Testing Framework].

## Install

### Dependencies
- python3.6 or greater
- Be sure that you install the redis libraries for your python3 version. This can be done with pip3, but your 'python3' executable in your path should point to the version of python you are using, such as python3.7
- py37-redis
    

## Architecture of operation

- The data collected and used is on the _profile_ level and up. Slips does not work with data at the _flow_ level or _packet_ level to classify. This means that the simplest data structure available inside slips is the profile of an IP address. The modules can not access individual flows.

## Usage
To use this alpha version you will need an argus instance running and listening in one port.

- If you don't have an Argus instance, first install it:
    - Source install from [Argus].
    - In Debian and Ubuntu you can do
        ```
        sudo apt-get install argus argus-clients
        ```

- To run argus in your own computer you should do:
    ```
    argus -B localhost -F [slipsfolder]/argus.conf
    ```

## Usage

1. Start Redis
    - In macos
        - redis-server /opt/local/etc/redis.conf
        - sudo port load redis
2. Use slips
    ```
    cat test-flows/test3.binetflow | ./slips.py -l -c slips.conf -v 2 -e 1
    ```



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
- 0.5 Completely renewed architecture and code.
- 0.4 was never reached
- 0.3.5
- 0.3.4
    - This is a mayor version change. Implementing new algorithms for analyzing the results, management of IPs, connections, whois database and more features.
    - A new parameter to specify the file (-r). This is as fast as reading the file from stdin.
    - Now we have a configuration file slips.conf. In there you can specify from fixed parameters, the time formats, to the columns in the flow file.
- 0.3.3alpha
    - First stable version with a minimal algorithm for detecting behavioral threats.



### Author and Contributors

- The author of the project is Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com. (Send an email for bugs, reports, ideas or comments)
- Ondrej Lukas: New detection metric of infected IPs based on timewindows, detection windows, weighted scores and averages. Also all the ip_handler, alerts classes, etc.
- Elaheh Biglar Beigi
- MariaRigaki 
- kartik88363


[Argus]: http://qosient.com/argus/ "Argus"
[Stratosphere Testing Framework]: https://github.com/stratosphereips/StratosphereTestingFramework
[Stratosphere Windows IPS]: https://github.com/stratosphereips/StratosphereIps
