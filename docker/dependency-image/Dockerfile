# this image contains the dependencies of slips
# to save time in CI
# This image doesn't have slips installed, we'll be doing this from .github/workflows/CI.yml
# this image doesn't have node.js requirements and doesn't support kalipso
# because it's only used for unit testing,
# and we don't have unit tests for kalipso yet

FROM ubuntu

# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive

# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER True

# When using github actions, we build and run this image but we have no control over
# the running options, for example we can't use --cap-add NET_ADMIN
# so all blocking module unit tests will fail because we don't have admin privs
# we use this environment variable to check if we're running this image (this means slips is
# running in github actions) we disable the blocking module unit tests
ENV IS_DEPENDENCY_IMAGE True

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

RUN pip3 install wheel redis setuptools validators psutil colorama maxminddb pandas sklearn urllib3 scipy watchdog slackclient stix2 cabby ipwhois pytest pytest-xdist yara-python
RUN pip3 install --ignore-installed six
RUN pip3 install --upgrade tensorflow==2.4.1

CMD redis-server --daemonize yes && /bin/bash