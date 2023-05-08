FROM tensorflow/tensorflow

# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive

# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER True

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
    yara \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro


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
RUN curl -fsSL https://deb.nodesource.com/setup_19.x | bash - && apt install -y --no-install-recommends nodejs

# Switch to kalipso dir to install node dependencies
WORKDIR ${SLIPS_DIR}/modules/kalipso
RUN npm install

# Switch to Slips installation dir when login.
WORKDIR ${SLIPS_DIR}

CMD redis-server --daemonize yes && /bin/bash

