FROM ubuntu:20.04

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
    nano \
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
    golang \
    vim \
    yara \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro


RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS/ ${SLIPS_DIR}/
WORKDIR ${SLIPS_DIR}
RUN git submodule sync && git pull --recurse-submodules
# Switch to Slips installation dir when login.
RUN chmod 774 slips.py &&  git submodule init && git submodule update


# set use_p2p to yes in the config file
RUN sed -i 's/use_p2p = no/use_p2p = yes/g' config/slips.conf


# build the pigeon and Add pigeon to path
SHELL ["/bin/bash", "-c"]
RUN cd p2p4slips && go build && echo "export PATH=$PATH:/StratosphereLinuxIPS/p2p4slips/" >> ~/.bashrc && source ~/.bashrc

WORKDIR ${SLIPS_DIR}
# Upgrade pip3 and install slips requirements
RUN pip3 install --upgrade pip
RUN pip3 install -r install/requirements.txt


# For Kalipso:
RUN curl -fsSL https://deb.nodesource.com/setup_19.x | bash - && apt install -y --no-install-recommends nodejs

# Switch to kalipso dir to install node dependencies
WORKDIR ${SLIPS_DIR}/modules/kalipso
RUN npm install

WORKDIR ${SLIPS_DIR}
CMD redis-server --daemonize yes && /bin/bash
