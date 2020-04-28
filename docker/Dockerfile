FROM debian:buster

# Install wget and add Zeek repository to our sources.
RUN apt update && apt install -y --no-install-recommends \
    wget \
    ca-certificates \
    gnupg \
    git \
 && echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_10/ /' > /etc/apt/sources.list.d/security:zeek.list \
 && wget -nv https://download.opensuse.org/repositories/security:zeek/Debian_10/Release.key -O Release.key \
 && apt-key add - < Release.key \
 && rm Release.key

# Install Slips dependencies.
RUN apt update && apt install -y --no-install-recommends \
    curl \
    python3 \
    python3-certifi \
    python3-maxminddb \
    python3-pandas \
    python3-scipy \
    python3-sklearn \
    python3-urllib3 \
    python3-watchdog \
    redis-server \
    zeek \
    python3-pip \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro

# Install redis using PIP3
RUN pip3 install redis

# Download and unpack Slips.
#RUN wget -nv https://github.com/stratosphereips/StratosphereLinuxIPS/archive/master.tar.gz -O /slips.tar.gz \
RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git
RUN cd StratosphereLinuxIPS && git checkout develop && chmod 774 slips.py && mkdir dataset

# For Kalipso:
RUN curl -sL https://deb.nodesource.com/setup_10.x  | bash -
RUN apt install -y --no-install-recommends nodejs
RUN cd StratosphereLinuxIPS/modules/blessed && npm install \
    async \
    ansi-colors \
    blessed \
    blessed-contrib \
    clipboardy \
    chalk \
    strip-ansi \
    redis

# Switch to Slips installation dir when login.
WORKDIR /StratosphereLinuxIPS
CMD redis-server --daemonize yes && /bin/bash
