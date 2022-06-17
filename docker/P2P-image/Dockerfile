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
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro

RUN git clone --recurse-submodules --remote-submodules https://github.com/stratosphereips/StratosphereLinuxIPS/ ${SLIPS_DIR}/
# Switch to Slips installation dir when login.
WORKDIR ${SLIPS_DIR}
RUN chmod 774 slips.py &&  git submodule init && git submodule update && rm slips.conf
# so we can set use_p2p to yes
COPY slips.conf ${SLIPS_DIR}/

# build the pigeon and Add pigeon to path
SHELL ["/bin/bash", "-c"]
RUN cd p2p4slips && go build && echo "export PATH=$PATH:/StratosphereLinuxIPS/p2p4slips/" >> ~/.bashrc && source ~/.bashrc

WORKDIR ${SLIPS_DIR}
# Upgrade pip3 and install slips requirements
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt


# For Kalipso:
RUN curl -sL https://deb.nodesource.com/setup_12.x  | bash -
RUN apt install -y --no-install-recommends nodejs
RUN npm install blessed@0.1.81 blessed-contrib@4.10.0 redis@3.1.2 async@3.2.0 chalk@4.1.2 strip-ansi@6.0.0  clipboardy@2.3.0 fs@0.0.1-security sorted-array-async@0.0.7 yargs@17.0.1

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


CMD redis-server --daemonize yes && /bin/bash
