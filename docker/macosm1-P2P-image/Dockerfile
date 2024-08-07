FROM ubuntu:22.04
# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive
# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER=True
# destionation dir for slips inside the container
ENV SLIPS_DIR=/StratosphereLinuxIPS

ENV NODE_VERSION=22.5.0
ENV NVM_DIR=/root/.nvm

# use bash instead of sh
SHELL ["/bin/bash", "-c"]

# Install wget and add Zeek and redis repositories to our sources.
RUN apt update && apt install -y --no-install-recommends \
    wget \
    ca-certificates \
    git \
    curl \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    python3-certifi \
    python3-dev \
    build-essential \
    file \
    lsof \
    iptables \
    iproute2 \
    python3-tzlocal \
    nfdump \
    tshark \
    whois \
    yara \
    net-tools \
    git \
    vim \
    less \
    tcpdump \
    screen \
    mc \
    tmux \
    golang \
    iputils-ping \
 && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg \
 && curl -fsSL https://packages.redis.io/gpg |  gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" > /etc/apt/sources.list.d/redis.list \
 && curl -fsSL https://deb.nodesource.com/setup_21.x |  bash - \
 && apt install -y --no-install-recommends \
    zeek \
    redis \
    nodejs \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro \
 && apt clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
# Upgrade pip3 and install slips requirements
RUN pip3 install --no-cache-dir --upgrade pip

# Switch to Slips installation dir on login.
WORKDIR ${SLIPS_DIR}

COPY . $SLIPS_DIR

RUN  pip install --ignore-installed --no-cache-dir -r install/requirements.txt \
    && chmod 774 slips.py \
    && git init \
    && git remote add origin https://github.com/stratosphereips/StratosphereLinuxIPS.git \
    && cd modules/kalipso \
    && npm install

# Change the configuration file to have use_p2p = yes
RUN sed -i "s/use_p2p : 'no'/use_p2p : 'yes'/" config/slips.yaml

# build the pigeon and add pigeon to path
RUN cd p2p4slips \
    && go build \
    && export PATH="$PATH:/StratosphereLinuxIPS/p2p4slips/";

CMD /bin/bash
