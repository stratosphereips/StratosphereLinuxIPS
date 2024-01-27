# Installation

There are two ways to install and run Slips: inside a Docker or in your own computer. We suggest to install and to run Slips inside a Docker since all dependencies are already installed in there. However, current version of docker with Slips does not allow to capture the traffic from the computer's interface. We will describe both ways of installation anyway. 



## Table of Contents

* [Docker](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#slips-in-docker)
  * Dockerhub (recommended)
    * On a linux host
      * [Without P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-linux)
      * [With P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-p2p-support-on-linux)
    * On MacOS M1 host
      * [Without P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-macos-m1)
    * On MacOS Intel processor
      * [Without P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-macos-intel-processors) 
      * [With P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-p2p-support-on-macos-intel)
  * [Docker-compose](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#running-slips-using-docker-compose)
  * [Dockerfile](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#building-slips-from-the-dockerfile)
* Native
  * [Using install.sh](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#install-slips-using-shell-script)
  * [Manually](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-slips-manually)
* [on RPI (Beta)](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-slips-on-a-raspberry-pi)



## Slips in Docker

Slips can be run inside a Docker. Either using our docker image with from DockerHub (recommended)
or building Slips image from the Dockerfile for more advanced users.

In both cases, you need to have the Docker platform installed in your computer.
Instructions how to install Docker is https://docs.docker.com/get-docker/.

The recommended way of using slips would be to
* [Run Slips from Dockerhub](#Running-Slips-from-DockerHub)

For more advanced users, you can:
* [Run Slips using docker compose](#Running-Slips-using-docker-compose)
* [Build Slips using the dockerfile](#Running-Slips-using-the-dockerfile)


### Running Slips from DockerHub

1. First, choose the correct image for your architecture

####  For linux 

###### Analyse your own traffic
	- `docker run --rm -it -p 55000:55000 --net=host --cap-add=NET_ADMIN -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset --name slips stratosphereips/slips:latest /StratosphereLinuxIPS/slips.py -i eno1`
    - Please change the name of the interface for your own. 
    - Check the alerts slips generated
      - ```tail -f output/eno1*/alerts.log ```

###### Analyze your PCAP file 
	- Prepare a dataset directory
		- `mkdir dataset`
		- `cp myfile.pcap dataset`
	  - Run Slips
		- `docker run --rm -it -p 55000:55000 --net=host --cap-add=NET_ADMIN -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset --name slips stratosphereips/slips:latest /StratosphereLinuxIPS/slips.py -f dataset/myfile.pcap`
	  - Check the alerts slips generated
		  - ```tail -f output/myfile*/alerts.log ```


####  For MacOS M1

###### Analyse your own traffic 
	- `docker run --rm -it -p 55000:55000 --net=host --cap-add=NET_ADMIN -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset --name slips stratosphereips/slips:latest /StratosphereLinuxIPS/slips.py -i eno1`
    - Please change the name of the interface for your own. 
    - Check the alerts slips generated
      - ```tail -f output/eno1*/alerts.log ```

    docker run -it --rm --net=host stratosphereips/slips_macos_m1:latest

Docker with P2P is not supported for MacOS M1.


#### For MacOS Intel processors

###### Analyse your own traffic 
	- `docker run --rm -it -p 55000:55000 --net=host --cap-add=NET_ADMIN -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset --name slips stratosphereips/slips:latest /StratosphereLinuxIPS/slips.py -i eno1`
    - Please change the name of the interface for your own. 
    - Check the alerts slips generated
      - ```tail -f output/eno1*/alerts.log ```
      
###### Analyze your PCAP file 
	- Prepare a dataset directory
		- `mkdir dataset`
		- `cp myfile.pcap dataset`
	  - Run Slips
		- `docker run --rm -it -p 55000:55000 --net=host --cap-add=NET_ADMIN -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset --name slips stratosphereips/slips:latest /StratosphereLinuxIPS/slips.py -f dataset/myfile.pcap`
	  - Check the alerts slips generated
		  - ```tail -f output/myfile*/alerts.log ```



####  For P2P support on Linux 

###### To analyze your own traffic with p2p
	- `docker run --rm -it -p 55000:55000 --net=host --cap-add=NET_ADMIN -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset --name slips stratosphereips/slips_p2p:latest /StratosphereLinuxIPS/slips.py -i eno1 -o output_dir `
    - Please change the name of the interface for your own. 
    - Check evidence
      ```tail -f output_dir/alerts.log ```

#### For P2P support on MacOS Intel

###### Analyze your own traffic 
	- `docker run --rm -it -p 55000:55000 --net=host --cap-add=NET_ADMIN -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset --name slips stratosphereips/slips_p2p:latest /StratosphereLinuxIPS/slips.py -i eno1 -o output_dir `
    - Please change the name of the interface for your own. 
    - Check evidence
      ```tail -f output_dir/alerts.log ```



---

Once your image is ready, you can run slips using the following command:

    ./slips.py -f dataset/dataset/test7-malicious.pcap

To analyze your own file using slips, you can mount it to your docker using -v

	mkdir ~/dataset
	cp <some-place>/myfile.pcap ~/dataset
	docker run -it --rm --net=host -v ~/dataset:/StratosphereLinuxIPS/dataset stratosphereips/slips:latest
	./slips.py -f dataset/myfile.pcap


### Updating the image in case there is a new one

	docker pull stratosphereips/slips:latest

### Known Error in old GPUs
If you happen to get the error `Illegal instruction (core dumped)` it means that tensorflow can not be run from inside Docker in your GPU. We recommend to  disable the modules using machine learning by modifying the `disable` line in the configuration to be like this
	`disable = [template, ensembling, rnn-cc-detection, flowmldetection]`

If you were running slips directly from the docker without cloning the repo, you can do this modification in two ways:
1. Modify the container
	1. Run the docker in background using the same command as above but with `-d`
	2. Get into the docker with `docker exec -it slips /bin/bash`, and then modifying the configuration file in `config/slips.conf` to add the disabled modules
	3. Run Slips from inside the docker
			`./slips.py -i enp7s0`
1. You can 
	1. Clone the Slips repo (clone the same version as the docker you are downloading), 
	2. Modify your local `config/slips.conf`
	3. Run the docker command above but by mounting the volume of the config.
		`docker run --rm -it -p 55000:55000 --net=host --cap-add=NET_ADMIN -v $(pwd)/config:/StratosphereLinuxIPS/config/ -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset --name slips stratosphereips/slips:latest /StratosphereLinuxIPS/slips.py -i eno1`

---
### Run Slips sharing files between the host and the container

The following instructions will guide you on how to run a Slips docker container with file sharing between the host and the container.

```bash
    # create a directory to load pcaps in your host computer
    mkdir ~/dataset
    
    # copy the pcap to analyze to the newly created folder
    cp <some-place>/myfile.pcap ~/dataset
    
    # create a new Slips container mapping the folder in the host to a folder in the container
    docker run -it --rm --net=host --name slips -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset stratosphereips/slips:latest
    
    # run Slips on the pcap file mapped to the container
    ./slips.py -f dataset/myfile.pcap
```

### Run Slips with access to block traffic on the host network

In Linux OS, the Slips can be used to analyze and **block** network traffic on the host network interface. To allow the container to see the host interface traffic and block malicious connections, it needs to run with the option `--cap-add=NET_ADMIN`. This option enables the container to interact with the network stack of the host computer. To block malicious behavior, run Slips with the parameter `-p`.

Change eno1 in the command below to your own interface

```bash
    # run a new Slips container with the option to interact with the network stack of the host
    docker run -it --rm --net=host --cap-add=NET_ADMIN --name slips stratosphereips/slips:latest
    
    # run Slips on the host interface `eno1` with active blocking `-p`
    ./slips.py -i eno1 -p
```

---

### Running Slips using docker compose


Change enp1s0 to your current interface in docker/docker-compose.yml and start slips using
    
    docker compose -f docker/docker-compose.yml up

Now everything inside your host's ```config``` and ```dataset``` directories is
mounted to ```/StratosphereLinuxIPS/config/``` and ```/StratosphereLinuxIPS/dataset/``` in Slips docker.

To run slips on a pcap instead of your interface you can do the following:

1. put the pcap in the ```dataset/``` dir in your host
2. change the entrypoint in the docker compose file to
    ["python3","/StratosphereLinuxIPS/slips.py","-f","dataset/<pcapname>.pcap"]
3. restart slips using ```docker compose -f docker/docker-compose.yml up```


#### Limitations

The main limitation of running Slips in a Docker is that every time the container stops, all files inside the container are deleted, including the Redis database of cached data, and you lose all your Threat Intelligence (TI) data and previous detections. Next time you run Slips, it will start making detections without all the TI data until downloading the data again. The only solution is to keep the container up between scans.


---

### Building Slips from the Dockerfile


First, you need to check which image is suitable for your architecture.

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/docker_images.png" width="850px"


Before building the docker locally from the Dockerfile, first you should clone Slips repo or download the code directly: 

	git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git

If you cloned Slips in '~/code/StratosphereLinuxIPS', then you can build the Docker image with:

**NOTE: replace ubuntu-image with the image that fits your archiecture**

	cd ~/code/StratosphereLinuxIPS/docker/ubunutu-image
	docker build --no-cache -t slips -f Dockerfile .
	docker run -it --rm --net=host -v ~/code/StratosphereLinuxIPS/dataset:/StratosphereLinuxIPS/dataset slips
	./slips.py -c config/slips.conf -f dataset/test3-mixed.binetflow

If you don't have Internet connection from inside your Docker image while building, you may have another set of networks defined in your Docker. For that try:

	docker build --network=host --no-cache -t slips -f Dockerfile .
	
You can also put your own files in the /dataset/ folder and analyze them with Slips:

	cp some-pcap-file.pcap ~/code/StratosphereLinuxIPS/dataset
	docker run -it --rm --net=host -v ../dataset/:/StratosphereLinuxIPS/dataset slips
	./slips.py -f dataset/some-pcap-file.pcap


Note that some GPUs don't support tensorflow in docker which may cause "Illegal instruction" errors when running slips.

To fix this you can disable all machine learning based modules when running Slips in docker, or run Slips locally.

---



## Installing Slips natively

Slips is dependent on three major elements: 

Python 3.8
Zeek
Redis database 7.0.4

To install these elements we will use APT package manager. After that, we will install python packages required for Slips to run and its modules to work. Also, Slips' interface Kalipso depend on Node.JS and several npm packages. 




**Instructions to download everything for Slips are below.**
<br>

### Install Slips using shell script
You can install it using install.sh

	sudo chmod +x install.sh
	sudo ./install.sh


### Installing Slips manually
#### Installing Python, Redis, NodeJs, and required python and npm libraries.

Update the repository of packages so you see the latest versions:

	apt-get update
	
Install the required packages (-y to install without asking for approval):

    apt-get -y install tshark iproute2 python3.8 python3-tzlocal net-tools python3-dev build-essential python3-certifi curl git gnupg ca-certificates redis wget python3-minimal python3-redis python3-pip python3-watchdog nodejs redis-server npm lsof file iptables nfdump zeek whois yara
    apt install -y --no-install-recommends nodejs
	
Even though we just installed pip3, the package installer for Python (3.8), we need to upgrade it to its latest version:

	python3 -m pip install --upgrade pip

Now that pip3 is upgraded, we can proceed to install all required packages via pip3 python packet manager:

	sudo pip3 install -r install/requirements.txt

_Note: for those using a different base image, you need to also install tensorflow==2.2.0 via pip3._

As we mentioned before, the GUI of Slips known as Kalipso relies on NodeJs v19. Make sure to use NodeJs greater than version 12. For Kalipso to work, we will install the following npm packages:

    curl -fsSL https://deb.nodesource.com/setup_19.x | bash - && apt install -y --no-install-recommends nodejs
    cd modules/kalipso &&  npm install

####  Installing Zeek

The last requirement to run Slips is Zeek. Zeek is not directly available on Ubuntu or Debian. To install it, we will first add the repository source to our apt package manager source list. The following two commands are for Ubuntu, check the repositories for the correct version if you are using a different OS:

	echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list

We will download and store the gpg signature from the package for apt to read:

	curl -fsSL http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

Finally, we will update the package manager repositories and install zeek

	apt-get update
	apt-get -y install zeek
	
To make sure that zeek can be found in the system we will add its link to a known path:

	ln -s /opt/zeek/bin/zeek /usr/local/bin

#### Running Slips for the First Time


Be aware that the first time you run Slips it will start updating 
all the databases and threat intelligence files in the background.
However, it will give you as many detections as possible _while_ updating. 
You may have more detections if you rerun Slips after the updates.
Slips behaves like this, so you don't have to wait for the updates to 
finish to have some detections. however, you can change that in the config file by setting ```wait_for_TI_to_finish``` to yes.


Depending on the remote sites, downloading and updating the DB may take up to 4 minutes. 
Slips stores this information in a cache Redis database, 
which is kept in memory when Slips stops. Next time Slips runs, it will read from this database.
The information in the DB is updated periodically according to the configuration file (usually one day).

You can check if the DB is running this by looking at your processes:

```
    ps afx | grep redis
    9078 ?        Ssl    1:25 redis-server *:6379
```

You can kill this redis database by running:

```
    ./slips.py -k
    Choose which one to kill [0,1,2 etc..]
    [0] Close all servers
    [1] conn.log - port 6379
```
then choosing 1.



## Installing Slips on a Raspberry PI

Slips on RPI is currently in beta and is actively under development. 
While it is functional, please be aware that there may be occasional bugs or changes in functionality as we work to 
improve and refine this feature. Your feedback and contributions are highly valuable during this stage!


Instead of compiling zeek, you can grab the zeek binaries for your OS

Packages for Raspbian 11:

[https://download.opensuse.org/repositories/security:/zeek/Raspbian_11/armhf/zeek_4.2.1-0_armhf.deb](https://download.opensuse.org/repositories/security:/zeek/Raspbian_11/armhf/zeek_4.2.1-0_armhf.deb)


Packages for Raspbian 10:

[https://download.opensuse.org/repositories/security:/zeek/Raspbian_10/armhf/zeek_4.2.1-0_armhf.deb](https://download.opensuse.org/repositories/security:/zeek/Raspbian_10/armhf/zeek_4.2.1-0_armhf.deb)

