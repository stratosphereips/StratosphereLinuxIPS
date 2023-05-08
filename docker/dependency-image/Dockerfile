# this image contains the dependencies of slips
# to save time in CI
# This image doesn't have slips installed, we'll be doing this from .github/workflows/CI-staging.yml
# this image doesn't have node.js requirements and doesn't support kalipso
# because it's only used for unit testing,
# and we don't have unit tests for kalipso yet

FROM ubuntu:20.04

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

# destionation dir for slips inside the container
ENV SLIPS_DIR /Slips


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
    vim \
    yara \
 && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro


# Install python dependencies

# you should build the image using
# docker build --no-cache -t slips_dependencies -f docker/dependency-image/Dockerfile .
# or this step won't be able to find requirements.txt
COPY requirements.txt ${SLIPS_DIR}/

# Upgrade pip3 and install slips requirements
RUN pip3 install --no-cache-dir --upgrade pip
RUN pip3 install --no-cache-dir -r ${SLIPS_DIR}/requirements.txt


CMD redis-server --daemonize yes && /bin/bash