FROM ubuntu

# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive

# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER True

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
    python3-dev \
    file \
    lsof \
    net-tools \
    iproute2 \
    iptables \
    psutils \
    python3-tzlocal \
    nfdump \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro

# Upgrade pip3
RUN pip3 install --upgrade pip


# To avoid user interaction with tzdata
ENV DEBIAN_FRONTEND=noninteractive

# Compile and install YARA
RUN git clone https://github.com/VirusTotal/yara-python yara-python \
    && cd yara-python \
    && python setup.py build \
    && python setup.py install


# Install redis using PIP3
RUN pip3 install wheel redis setuptools validators colorama maxminddb pandas
RUN pip3 install sklearn urllib3 scipy watchdog slackclient stix2 cabby
RUN pip3 install ipwhois pytest pytest-xdist yara-python
RUN pip3 install --ignore-installed six
RUN pip3 install --upgrade tensorflow==2.4.1

# Download and unpack Slips.
RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git
RUN cd StratosphereLinuxIPS && chmod 774 slips.py

# For Kalipso:
RUN curl -sL https://deb.nodesource.com/setup_12.x  | bash -
RUN apt install -y --no-install-recommends nodejs
RUN npm install blessed blessed-contrib redis async chalk strip-ansi@6.0.0 clipboardy fs sorted-array-async yargs

# Switch to Slips installation dir when login.
WORKDIR /StratosphereLinuxIPS
CMD redis-server --daemonize yes && /bin/bash

