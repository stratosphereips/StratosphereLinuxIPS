FROM ubuntu

# Install wget and add Zeek repository to our sources.
RUN apt update && apt install -y --no-install-recommends \
    wget \
    ca-certificates \
    git \
    curl \
    gnupg \
 && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# Install Slips dependencies.
RUN apt update && apt install -y --no-install-recommends \
    python3 \
    redis-server \ 
    zeek \
    python3-pip \
    python3-certifi \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro

# Upgrade pip3
RUN pip3 install --upgrade pip

# Install redis using PIP3
RUN pip3 install wheel
RUN pip3 install redis
RUN pip3 install setuptools
RUN pip3 install validators
RUN pip3 install colorama
RUN pip3 install maxminddb
RUN pip3 install pandas
RUN pip3 install sklearn
RUN pip3 install urllib3
RUN pip3 install scipy
RUN pip3 install watchdog
RUN pip3 install slackclient
RUN pip3 install stix2
RUN pip3 install cabby
RUN pip3 install --ignore-installed six
RUN pip3 install --upgrade tensorflow==2.1.0

# Download and unpack Slips.
RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git
RUN cd StratosphereLinuxIPS && git checkout develop && chmod 774 slips.py

# For Kalipso:
RUN curl -sL https://deb.nodesource.com/setup_10.x  | bash -
RUN apt install -y --no-install-recommends nodejs
RUN npm install async fs blessed blessed-contrib clipboardy chalk strip-ansi redis sorted-array-async yargs

# Switch to Slips installation dir when login.
WORKDIR /StratosphereLinuxIPS
CMD redis-server --daemonize yes && /bin/bash

