FROM tensorflow/tensorflow

# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive

# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER True

# Install wget and add Zeek repository to our sources.
RUN apt update && apt install -y --no-install-recommends \
    wget \
    ca-certificates \
    git \
 && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_18.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# Install Slips dependencies.
RUN apt update && apt install -y --no-install-recommends \
    python3 \
    curl \
    redis-server \
    zeek \
    python3-pip \
	python3-certifi \
	python3-dev \
	file \
	lsof \
	net-tools \
	iptables \
	iproute2 \
	nfdump \
	tshark \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro

# Upgrade pip3
RUN pip3 install --upgrade pip

# To avoid user interaction with tzdata
ENV DEBIAN_FRONTEND=noninteractive

# Install redis using PIP3
RUN pip3 install wheel redis setuptools validators colorama
RUN pip3 install maxminddb pandas sklearn urllib3 scipy watchdog
RUN pip3 install stix2 cabby ipwhois pytest yara-python
RUN pip3 install slackclient tzlocal psutil pytest-xdist
RUN pip3 install --ignore-installed six

# Compile and install YARA
RUN git clone https://github.com/VirusTotal/yara-python yara-python \
    && cd yara-python \
    && python setup.py build \
    && python setup.py install

# Download and unpack Slips.
RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git
RUN cd StratosphereLinuxIPS && chmod 774 slips.py

# For Kalipso:
RUN curl -sL https://deb.nodesource.com/setup_10.x  | bash -
RUN apt install -y --no-install-recommends nodejs
RUN npm install async fs blessed blessed-contrib clipboardy chalk strip-ansi redis sorted-array-async yargs

# Switch to Slips installation dir when login.
WORKDIR /StratosphereLinuxIPS
CMD redis-server --daemonize yes && /bin/bash

