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
    iproute2 \
    tshark \
    whois \
    yara \
    net-tools \
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
