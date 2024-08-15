# this image contains the dependencies of slips
# to save time in CI
# This image doesn't have slips installed, we'll be doing this from .github/workflows/CI-staging.yml
# this image doesn't have node.js requirements and doesn't support kalipso
# because it's only used for unit testing,
# and we don't have unit tests for kalipso yet
FROM ubuntu:22.04

# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive

# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER=True

# When using github actions, we build and run this image but we have no control over
# the running options, for example we can't use --cap-add NET_ADMIN
# so all blocking module unit tests will fail because we don't have admin privs
# we use this environment variable to check if we're running this image (this means slips is
# running in github actions) we disable the blocking module unit tests
ENV IS_DEPENDENCY_IMAGE=True

# destionation dir for slips inside the container
ENV SLIPS_DIR=/Slips


RUN apt update && apt install -y --no-install-recommends \
    wget \
    ca-certificates \
    git \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    build-essential \
    file \
    lsof \
    iptables \
    iproute2 \
    nfdump \
    tshark \
    whois \
    yara \
    net-tools \
    vim \
    less \
    unzip \
    python3-certifi \
    python3-dev \
    python3-tzlocal \
    python3-pip \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' |  tee /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor |  tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
    && curl -fsSL https://packages.redis.io/gpg |  gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" > /etc/apt/sources.list.d/redis.list \
    && apt update \
    && apt install -y --no-install-recommends --fix-missing \
    zeek \
    redis \
    && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro \
    && apt clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN git clone https://github.com/IDMEFv2/python-idmefv2  \
    && cd python-idmefv2 \
    && git submodule update --init --recursive \
    && python3 setup.py install \
    && cd ..

# you should build the image using
# docker build --no-cache -t slips_dependencies -f docker/dependency-image/Dockerfile .
# or this step won't be able to find requirements.txt
COPY install/requirements.txt ${SLIPS_DIR}/install/requirements.txt

WORKDIR ${SLIPS_DIR}

RUN pip3 install -r install/requirements.txt


CMD redis-server --daemonize yes && /bin/bash
