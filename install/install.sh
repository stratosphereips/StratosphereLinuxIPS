#!/bin/sh


sudo apt-get update

echo "[+] Installing Slips dependencies ...\n"
sudo apt-get install  -y --no-install-recommends \
    cmake \
    make \
    gcc\
    g++ \
    flex \
    bison \
    libpcap-dev \
    libssl-dev \
    swig \
    zlib1g-dev \
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
    golang \
    notify-osd \
    libnotify-bin \
    net-tools \
    lsb_release

UBUNTU_VERSION=$(lsb_release -r | awk '{print $2}' | sed 's/\./_/')
ZEEK_REPO_URL="http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VERSION}/"

# Add the repository to the sources list
echo "deb ${ZEEK_REPO_URL} /" | sudo tee /etc/apt/sources.list.d/security:zeek.list

# Add the zeek repository key
curl -fsSL "${ZEEK_REPO_URL}/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# install redis
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list

sudo apt-get update

sudo apt install -y --no-install-recommends \
  python3 \
  redis \
  zeek

# create a symlink to zeek so that slips can find it
sudo ln -s /opt/zeek/bin/zeek /usr/local/bin/bro
export PATH=$PATH:/usr/local/zeek/bin
echo "export PATH=$PATH:/usr/local/zeek/bin" >> ~/.bashrc


echo "[+] Executing 'python3 -m pip install --upgrade pip'"
python3 -m pip install --upgrade pip
echo "[+] Executing 'pip3 install -r install/requirements.txt'"
pip3 install -r install/requirements.txt
echo "[+] Executing pip3 install --ignore-installed six"
pip3 install --ignore-installed six

# For Kalipso
echo "[+] Downloading nodejs v19 and npm dependencies"
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash - \
    && export NVM_DIR="$HOME/.nvm" \
    && [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" \
    && nvm install 22 \
    && cd modules/kalipso && npm install \
    && cd ../..


echo "[+] Installing p2p4slips\n"
# build the pigeon and Add pigeon to path
git submodule init && git submodule update && cd p2p4slips && go build && export PATH=$PATH:$(pwd) >> ~/.bashrc && cd ..


# running slips for the first time
echo "[+] Executing 'redis-server --daemonize yes'\n"
redis-server --daemonize yes
