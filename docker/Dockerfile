# Build Iris
FROM golang:1.17 AS build

# Set Go modules to "on" to avoid issues with GOPATH
ENV GO111MODULE=on
ENV GOPATH=""

COPY iris/go.mod ./
COPY iris/go.sum ./

RUN go mod download

COPY iris/cmd ./cmd
COPY iris/pkg ./pkg

RUN go build -o /iris/iris cmd/peercli.go

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
    golang \
    python3-certifi \
    python3-dev \
    python3-tzlocal \
    python3-pip \
    nano \
    tree \
    tmux \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' |  tee /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor |  tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
    && apt update \
    && apt install -y --no-install-recommends --fix-missing \
    zeek \
    npm \
    && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro \
    && apt clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash - \
    && export NVM_DIR="$HOME/.nvm" \
    && [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  \
    && nvm install 22

# why are we compiling redis instead od just using apt?
# to support running slips on the rpi (arm64). the rpi uses jemmalloc by default, which expects a different page size
# than the default on x86_64
RUN pip3 install --no-cache-dir --upgrade pip \
    && git clone https://github.com/redis/redis \
    && cd redis \
    && make distclean \
    && make MALLOC=libc

ENV PATH="$PATH:/redis/src"


# Switch to Slips installation dir on login.
WORKDIR ${SLIPS_DIR}

COPY . $SLIPS_DIR

# Retrieve Iris
COPY --from=build /iris/iris ./modules/irisModule


RUN  pip install --ignore-installed --no-cache-dir -r install/requirements.txt \
    && chmod 774 slips.py \
    && git init \
    && git remote add origin https://github.com/stratosphereips/StratosphereLinuxIPS.git \
    && cd modules/kalipso \
    && npm install \
    && cd ../../p2p4slips \
    && go build

ENV PATH="$PATH:/StratosphereLinuxIPS/p2p4slips/"


WORKDIR ${SLIPS_DIR}

CMD /bin/bash
