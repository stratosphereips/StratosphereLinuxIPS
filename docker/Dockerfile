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


FROM ubuntu:22.04 AS base

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

RUN apt-get update -o Acquire::Retries=5 -o Acquire::https::No-Cache=True \
    && apt-get install -y --no-install-recommends --fix-broken --fix-missing \
    $(cat install/apt_dependencies.txt) \
    lsb-release \
    software-properties-common \
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

COPY --from=build /iris/iris ./modules/irisModule

RUN pip3 install --no-cache-dir --upgrade pip \
    && pip install --ignore-installed --no-cache-dir -r install/requirements.txt \
    && chmod 774 slips.py \
    && git init \
    && git remote add origin https://github.com/stratosphereips/StratosphereLinuxIPS.git

WORKDIR ${SLIPS_DIR}/p2p4slips

RUN go build

ENV PATH="$PATH:/StratosphereLinuxIPS/p2p4slips/"


# Final image: choose Redis allocator based on the target architecture.
FROM base AS final
# With Docker BuildKit/buildx, TARGETARCH is automatically set based on the platform currently being built.
ARG TARGETARCH

WORKDIR /

RUN curl -fsSLO https://download.redis.io/redis-stable.tar.gz \
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
    && rm -f /redis-stable.tar.gz

ENV PATH="$PATH:/redis-stable/src"

WORKDIR ${SLIPS_DIR}

CMD /bin/bash
