# Build Iris with a Go toolchain that matches iris/go.mod.
FROM golang:1.22.2 AS build-iris

# Set Go modules to "on" to avoid issues with GOPATH
ENV GO111MODULE=on
ENV GOPATH=""

COPY iris/go.mod ./
COPY iris/go.sum ./

RUN go mod download

COPY iris/cmd ./cmd
COPY iris/pkg ./pkg

RUN go build -buildvcs=false -o /artifacts/iris cmd/peercli.go


FROM golang:1.26.3 AS build-p2p

ENV GO111MODULE=on
ENV GOPATH=""

WORKDIR /src

COPY p2p4slips/go.mod ./
COPY p2p4slips/go.sum ./

RUN go mod download

COPY p2p4slips ./

RUN go build -buildvcs=false -o /artifacts/p2p4slips


FROM ubuntu:22.04 AS build-redis

# With Docker BuildKit/buildx, TARGETARCH is automatically set based on the
# platform currently being built.
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-c"]

WORKDIR /

RUN apt-get update -o Acquire::Retries=5 -o Acquire::https::No-Cache=True \
    && apt-get install -y --no-install-recommends --fix-broken --fix-missing \
    ca-certificates \
    curl \
    build-essential \
    && curl -fsSLO https://download.redis.io/redis-stable.tar.gz \
    && tar xzf redis-stable.tar.gz \
    && cd redis-stable \
    && make distclean \
    && if [[ "$TARGETARCH" == "arm64" || "$TARGETARCH" == "arm" ]]; then \
           echo "Building Redis for $TARGETARCH with libc malloc"; \
           make MALLOC=libc -j"$(nproc)"; \
       else \
           echo "Building Redis for $TARGETARCH with jemalloc"; \
           make MALLOC=jemalloc -j"$(nproc)"; \
       fi \
    && ./src/redis-server --version \
    && rm -f /redis-stable.tar.gz \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


FROM ubuntu:22.04 AS final

# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive

# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER=True

# Destination dir for Slips inside the container
ENV SLIPS_DIR=/StratosphereLinuxIPS

# Use bash instead of sh
SHELL ["/bin/bash", "-c"]

WORKDIR ${SLIPS_DIR}

COPY . ${SLIPS_DIR}
COPY --from=build-iris /artifacts/iris ./modules/iris/iris
COPY --from=build-p2p /artifacts/p2p4slips ./p2p4slips/p2p4slips
COPY --from=build-p2p /usr/local/go /usr/local/go
COPY --from=build-redis /redis-stable /redis-stable

RUN apt-get update -o Acquire::Retries=5 -o Acquire::https::No-Cache=True \
    && apt-get install -y --no-install-recommends --fix-broken --fix-missing \
    $(grep -Ev '^(build-essential|golang|python3-dev)$' install/apt_dependencies.txt) \
    build-essential \
    python3-dev \
    lsb-release \
    vim \
    less \
    unzip \
    nano \
    tree \
    tmux \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends --fix-missing \
    zeek-8.0 \
    && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN pip3 install --no-cache-dir --upgrade pip \
    && pip install --ignore-installed --no-cache-dir -r install/requirements.txt \
    && chmod 774 slips.py \
    && git init \
    && git remote add origin https://github.com/stratosphereips/StratosphereLinuxIPS.git \
    && apt-get purge -y \
    build-essential \
    python3-dev \
    gcc \
    g++ \
    make \
    dpkg-dev \
    libc6-dev \
    linux-libc-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH="$PATH:/redis-stable/src:/StratosphereLinuxIPS/p2p4slips:/usr/local/go/bin"

WORKDIR ${SLIPS_DIR}

CMD /bin/bash
