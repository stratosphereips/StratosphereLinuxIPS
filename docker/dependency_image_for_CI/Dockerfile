# This Dockerfile builds a dependency image for CI testing of (SLIPS).
# this img contains apt and pip dependencies, zeek and redis.

FROM ubuntu:22.04
# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive
# Blocking module requirement to avoid using
ENV IS_IN_A_DOCKER_CONTAINER=True

ENV NODE_VERSION=22.5.0
ENV NVM_DIR=/root/.nvm

# use bash instead of sh
SHELL ["/bin/bash", "-c"]


# donwload apt dependencies from slips develop branch and install them
RUN apt-get update -o Acquire::Retries=5 -o Acquire::https::No-Cache=True \
    && apt-get install -y --no-install-recommends --fix-broken --fix-missing \
        curl \
        gnupg \
        ca-certificates \
        lsb-release \
        software-properties-common \
        vim \
        less \
        unzip \
        nano \
        tree \
        tmux \
    && curl -fsSL \
        https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/install/apt_dependencies.txt \
        -o /tmp/apt_dependencies.txt \
    && apt-get install -y --no-install-recommends \
        $(grep -vE '^\s*#|^\s*$' /tmp/apt_dependencies.txt) \
    && rm -f /tmp/apt_dependencies.txt

# donwload pip requirements from slips develop branch and install them
# set -e tells the shell to exit immediately if any command returns a non-zero status.
RUN set -e; \
    curl -fsSL https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/install/requirements.txt \
    -o /tmp/requirements.txt \
    && python3 -m pip install --upgrade pip \
    && python3 -m pip install --no-cache-dir --ignore-installed -r /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt


RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
        | gpg --dearmor -o /usr/share/keyrings/zeek.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/zeek.gpg] \
        http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
        > /etc/apt/sources.list.d/zeek.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        zeek-8.0 \
    && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


RUN curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg \
    && chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb \
    $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list \
    && apt-get update && apt-get install -y redis-server=6:8.4.0-1*



CMD /bin/bash
