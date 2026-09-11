FROM ubuntu:22.04
# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive
# Blocking module requirement to avoid using sudo
ENV IS_IN_A_DOCKER_CONTAINER=True
# destionation dir for slips inside the container
ENV SLIPS_DIR=/StratosphereLinuxIPS

# use bash instead of sh
SHELL ["/bin/bash", "-c"]

# Install wget and add Zeek and redis repositories to our sources.
# set -eux for safer builds (stop on error, show commands)
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates gnupg wget curl \
    && apt-get update && apt-get install -y --no-install-recommends \
        git lsb-release software-properties-common \
        build-essential file lsof iproute2 tshark whois yara net-tools less unzip \
        python3-certifi python3-dev python3-tzlocal python3-pip \
    && curl -O https://download.redis.io/redis-stable.tar.gz \
    && tar xzf redis-stable.tar.gz \
    && cd redis-stable/src \
    && make distclean && make MALLOC=libc \
    && cd ../.. && rm -rf redis-stable.tar.gz \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
        | tee /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
        | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
    && apt-get update && apt-get install -y --no-install-recommends --fix-missing zeek-8.0  \
    && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH="$PATH:/redis-stable/src"

COPY . ${SLIPS_DIR}

WORKDIR ${SLIPS_DIR}

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
    && pip3 install --no-cache-dir --upgrade pip  \
    && pip install --ignore-installed --no-cache-dir -r docker/light/requirements.txt \
    && chmod 774 slips.py \
    && git init \
    && git remote add origin https://github.com/stratosphereips/StratosphereLinuxIPS.git

CMD /bin/bash
