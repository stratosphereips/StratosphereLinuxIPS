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
    curl \
    gnupg \
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
    net-tools \
    vim \
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


# Copy slips from the current directory into slips dir inside the container
RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS ${SLIPS_DIR}/
RUN (cd ${SLIPS_DIR} && chmod 774 slips.py)


# Upgrade pip3 and install Slips requirements
RUN pip3 install --upgrade pip
RUN pip3 install -r ${SLIPS_DIR}/requirements.txt


# manually install tensorflow==2.4.1
RUN pip3 install --ignore-installed tensorflow==2.4.1

# Download and unpack Slips.
RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git
RUN cd StratosphereLinuxIPS && chmod 774 slips.py



# Upgrade pip3 and install Slips requirements
RUN pip3 install --upgrade pip
RUN pip3 install -r ${SLIPS_DIR}/requirements.txt


# For Kalipso:
RUN curl -sL https://deb.nodesource.com/setup_12.x  | bash -
RUN apt install -y --no-install-recommends nodejs
RUN npm install blessed@0.1.81 blessed-contrib@4.10.0 redis@3.1.2 async@3.2.0 chalk@4.1.2 strip-ansi@6.0.0  clipboardy@2.3.0 fs@0.0.1-security sorted-array-async@0.0.7 yargs@17.0.1

# Switch to Slips installation dir when login.
WORKDIR ${SLIPS_DIR}

CMD redis-server --daemonize yes && /bin/bash

