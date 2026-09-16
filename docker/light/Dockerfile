FROM ubuntu:24.04
# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive
# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER=True
# destionation dir for slips inside the container
ENV SLIPS_DIR=/StratosphereLinuxIPS

# use bash instead of sh
SHELL ["/bin/bash", "-c"]

# With Docker BuildKit/buildx, TARGETARCH is automatically set based on the
# platform currently being built.
ARG TARGETARCH

# Install wget and add Zeek and redis repositories to our sources.
# set -eux for safer builds (stop on error, show commands)
#
# On amd64, install Redis 8 from the official apt repo (it ships jemalloc,
# which is fine there). On arm/arm64 (e.g. Raspberry Pi), the apt build's
# jemalloc assumes the x86_64 default page size, which doesn't match the
# Pi's page size and breaks Redis at runtime, so build Redis from source
# there with libc malloc instead.
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates gnupg wget curl \
    && apt-get update && apt-get install -y --no-install-recommends \
        git lsb-release software-properties-common \
        build-essential file lsof iproute2 tshark whois yara net-tools less unzip \
        python3-certifi python3-dev python3-tzlocal python3-pip \
    && if [ "$TARGETARCH" = "arm64" ] || [ "$TARGETARCH" = "arm" ]; then \
        echo "Building Redis for $TARGETARCH from source with libc malloc"; \
        curl -fsSLO https://download.redis.io/redis-stable.tar.gz; \
        tar xzf redis-stable.tar.gz; \
        cd redis-stable; \
        make distclean; \
        make build core MALLOC=libc -j"$(nproc)"; \
        make install; \
        cd ..; \
        rm -rf redis-stable redis-stable.tar.gz; \
    else \
        curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg; \
        chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg; \
        echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb \
        $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list; \
        apt-get update; \
        apt-get install -y --no-install-recommends redis-tools=6:8.4.0-1* redis-server=6:8.4.0-1*; \
    fi \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
        | tee /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
        | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
    && apt-get update && apt-get install -y --no-install-recommends --fix-missing zeek-lts  \
    && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Git ref (branch, tag, or full commit SHA) to build Slips from. Passed by
# CI as the exact commit being tested/published; defaults to master for
# manual/local builds.
ARG SLIPS_GIT_REF=master

WORKDIR ${SLIPS_DIR}

# Clone Slips directly from GitHub instead of COPYing the host build
# context. avoid accedinatelly pushing tmp files to docker images, easier to checkout diff branches, and makes it the
# dockerfile's responsibility to install git-lfs instead of the builder.
RUN apt-get update -o Acquire::Retries=5 \
    && apt-get install -y --no-install-recommends git-lfs ca-certificates \
    && git init . \
    && git remote add origin https://github.com/stratosphereips/StratosphereLinuxIPS.git \
    && git fetch --depth 1 origin "${SLIPS_GIT_REF}" \
    && git checkout FETCH_HEAD \
    && git fetch --depth 1 origin master:refs/remotes/origin/master \
    && git fetch --depth 1 origin develop:refs/remotes/origin/develop \
    && git lfs install \
    && git lfs pull \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

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

RUN cd modules \
    && rm -rf \
        rnn_cc_detection/ \
        timeline/ \
        p2ptrust/ \
        cyst/ \
        cesnet/ \
        exporting_alerts/ \
        risk_iq/ \
        template/ \
        blocking/ \
        virustotal/ \
    && cd .. \
    && rm -rf dataset/ docs/  tests/ \
    && rm pytest.ini \
      CITATION.cff \
      CHANGELOG.md \
      conftest.py

RUN python3 docker/light/generate_requirements.py \
    && pip3 install --no-cache-dir --break-system-packages --ignore-installed --upgrade pip  \
    && pip install --ignore-installed --break-system-packages --no-cache-dir -r docker/light/requirements.txt \
    && chmod 774 slips.py

CMD /bin/bash
