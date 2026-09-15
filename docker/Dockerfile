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
           make build redis MALLOC=libc -j"$(nproc)"; \
       else \
           echo "Building Redis for $TARGETARCH with jemalloc"; \
           make build redis MALLOC=jemalloc -j"$(nproc)"; \
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

# Git ref (branch, tag, or full commit SHA) to build Slips from. Passed by
# CI as the exact commit being tested/published; defaults to master for
# manual/local builds.
ARG SLIPS_GIT_REF=master

WORKDIR ${SLIPS_DIR}

# Clone Slips directly from GitHub instead of COPYing the host build
# context. This guarantees the image is always built from a clean,
# correctly-checked-out tree regardless of what's sitting in the local
# working directory (uncommitted changes, stray/sensitive files, a host
# clone that never ran `git lfs pull`, ...), and it leaves a real .git repo
# with git-lfs available in the final image so `git checkout <branch>` done
# later inside a running container also resolves LFS-tracked files
# (ml_linear_model/ml_online_model) correctly instead of leaving pointer
# text files behind.
RUN apt-get update -o Acquire::Retries=5 \
    && apt-get install -y --no-install-recommends git git-lfs ca-certificates \
    && git init . \
    && git remote add origin https://github.com/stratosphereips/StratosphereLinuxIPS.git \
    && git fetch --depth 1 origin "${SLIPS_GIT_REF}" \
    && git checkout FETCH_HEAD \
    && git lfs install \
    && git lfs pull \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build-iris /artifacts/iris ./modules/iris/iris
COPY --from=build-p2p /artifacts/p2p4slips ./p2p4slips/p2p4slips
COPY --from=build-p2p /usr/local/go /usr/local/go
COPY --from=build-redis /redis-stable /redis-stable

# ml_linear_model/ml_online_model artifacts are stored with git LFS. If the
# build context was checked out without pulling LFS objects (missing
# git-lfs, or a clone/checkout that didn't fetch them), these files are
# left as LFS pointer text files instead of the real pickled models, which
# crashes those modules at runtime with "invalid load key, 'v'.". Fail the
# build early instead of shipping a broken image.
RUN for f in \
        modules/ml_linear_model/artifacts/model.bin \
        modules/ml_online_model/artifacts/model.bin; do \
        if head -c 7 "$f" | grep -q "version"; then \
            echo "ERROR: $f is a git-lfs pointer file, not the real model." >&2; \
            echo "Run 'git lfs install && git lfs pull' in your clone before building this image." >&2; \
            exit 1; \
        fi; \
    done

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
    zeek-lts \
    && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN pip3 install --no-cache-dir --upgrade pip \
    && pip install --ignore-installed --no-cache-dir -r install/requirements.txt \
    && chmod 774 slips.py \
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
