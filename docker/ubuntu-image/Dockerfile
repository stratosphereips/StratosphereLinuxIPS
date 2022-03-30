FROM ubuntu

# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive

# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER True

# destionation dir for slips inside the container
ENV SLIPS_DIR /StratosphereLinuxIPS

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
    build-essential \
    file \
    lsof \
    net-tools \
    iproute2 \
    iptables \
    python3-tzlocal \
    nfdump \
    tshark \
    git \
    whois \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro

# Requirements for compiling yara
RUN apt install -y automake libtool make gcc pkg-config

# Compile and install YARA
RUN wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.1.3.tar.gz \
  && tar -zxf v4.1.3.tar.gz \
  && cd yara-4.1.3 \
  && ./bootstrap.sh \
  && ./configure \
  && make \
  && make install


RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS ${SLIPS_DIR}/
RUN (cd ${SLIPS_DIR} && chmod 774 slips.py)


# Upgrade pip3 and install slips requirements
RUN pip3 install --upgrade pip
RUN pip3 install -r ${SLIPS_DIR}/requirements.txt


# For Kalipso:
RUN curl -sL https://deb.nodesource.com/setup_12.x  | bash -
RUN apt install -y --no-install-recommends nodejs
RUN npm install blessed blessed-contrib redis@3.1.2 async chalk@4.1.2 strip-ansi@6.0.0 clipboardy fs sorted-array-async yargs

# Switch to Slips installation dir when login.
WORKDIR ${SLIPS_DIR}

CMD redis-server --daemonize yes && /bin/bash
