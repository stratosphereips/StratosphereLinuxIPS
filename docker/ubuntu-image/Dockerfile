FROM ubuntu:20.04

# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive

# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER True

# destionation dir for slips inside the container
ENV SLIPS_DIR /StratosphereLinuxIPS

# Install wget and add Zeek and redis repositories to our sources.
RUN apt update && apt install -y --no-install-recommends \
    wget \
    ca-certificates \
    git \
    curl \
    gnupg \
    lsb-release \
 && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg \
 && curl -fsSL https://packages.redis.io/gpg |  gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" > /etc/apt/sources.list.d/redis.list


# Install Slips dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    zeek \
    redis \
    python3-pip \
    python3-certifi \
    python3-dev \
    build-essential \
    file \
    lsof \
    net-tools \
    iptables \
    iproute2 \
    python3-tzlocal \
    nfdump \
    tshark \
    git \
    whois \
    vim \
    yara \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro


RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS ${SLIPS_DIR}/
RUN (cd ${SLIPS_DIR} && chmod 774 slips.py)


# Upgrade pip3 and install slips requirements
RUN pip3 install --no-cache-dir --upgrade pip
RUN pip3 install --no-cache-dir -r ${SLIPS_DIR}/install/requirements.txt


# For Kalipso:
RUN curl -fsSL https://deb.nodesource.com/setup_21.x |  bash -  && apt install -y --no-install-recommends nodejs

# Switch to kalipso dir to install node dependencies
WORKDIR ${SLIPS_DIR}/modules/kalipso
RUN npm install

# Switch to Slips installation dir when login.
WORKDIR ${SLIPS_DIR}

CMD redis-server --daemonize yes && /bin/bash
