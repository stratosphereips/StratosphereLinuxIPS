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
    && cd redis-stable \
    && make distclean && make MALLOC=libc \
    && cd .. && rm -rf redis-stable.tar.gz \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
        | tee /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
        | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
    && apt-get update && apt-get install -y --no-install-recommends --fix-missing zeek \
    && ln -s /opt/zeek/bin/zeek /usr/local/bin/bro \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH="$PATH:/redis-stable/src"

COPY . ${SLIPS_DIR}

WORKDIR ${SLIPS_DIR}

RUN cd modules \
    && rm -rf \
        rnn_cc_detection/ \
        timeline/ \
        kalipso/ \
        p2ptrust/ \
        flowmldetection/ \
        cyst/ \
        cesnet/ \
        exporting_alerts/ \
        riskiq/ \
        template/ \
        blocking/ \
        virustotal/ \
    && cd .. \
    && rm -rf dataset/ docs/  tests/ \
    && rm kalipso.sh \
      package.json \
      pytest.ini \
      webinterface.sh \
      CITATION.cff \
      CHANGELOG.md \
      conftest.py

RUN pip3 install --no-cache-dir --upgrade pip  \
    && grep -v -f docker/light/excluded_libs.txt install/requirements.txt | xargs -n 1 pip install \
    && chmod 774 slips.py \
    && git init \
    && git remote add origin https://github.com/stratosphereips/StratosphereLinuxIPS.git

CMD /bin/bash
