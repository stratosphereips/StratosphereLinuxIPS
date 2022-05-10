#!/bin/sh
# Installing slips dependencies


echo "[+] Installing zeek ..."
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

echo "[+] Executing 'sudo apt-get update'"
sudo apt-get update
echo "[+] Executing 'sudo apt-get -y install tshark whois iproute2 python3-tzlocal net-tools python3-dev build-essential python3-certifi curl git gnupg ca-certificates redis wget python3-minimal python3-redis python3-pip python3-watchdog nodejs redis-server npm lsof file iptables nfdump zeek'"
sudo apt-get -y install tshark whois iproute2 python3-tzlocal net-tools python3-dev build-essential python3-certifi curl git gnupg ca-certificates redis wget python3-minimal python3-redis python3-pip python3-watchdog nodejs redis-server npm lsof file iptables nfdump zeek

# create a symlink to zeek so that slips can find it
echo "[+] Executing 'ln -s /opt/zeek/bin/zeek /usr/local/bin/bro'"
ln -s /opt/zeek/bin/zeek /usr/local/bin/bro
echo "[+] Executing 'export PATH=$PATH:/usr/local/zeek/bin'"
export PATH=$PATH:/usr/local/zeek/bin
echo "[+] Adding /usr/local/zeek/bin to ~/.bashrc"
echo "export PATH=$PATH:/usr/local/zeek/bin" >> ~/.bashrc


echo "[+] Executing 'python3 -m pip install --upgrade pip'"
python3 -m pip install --upgrade pip
echo "[+] Executing 'pip3 install -r requirements.txt'"
pip3 install -r requirements.txt
echo "[+] Executing pip3 install --ignore-installed six"
pip3 install --ignore-installed six

echo "[+] Executing 'sudo npm install blessed blessed-contrib redis async chalk strip-ansi@6.0.0 clipboardy fs sorted-array-async yargs pytest'"
sudo npm install blessed@0.1.81 blessed-contrib@4.10.0 redis@3.1.2 async@3.2.0 chalk@4.1.2 strip-ansi@6.0.0  clipboardy@2.3.0 fs@0.0.1-security sorted-array-async@0.0.7 yargs@17.0.1

echo "[+] Installing YARA ..."
sudo apt install -y automake libtool make gcc pkg-config
wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.1.3.tar.gz \
  && tar -zxf v4.1.3.tar.gz \
  && cd yara-4.1.3 \
  && ./bootstrap.sh \
  && ./configure \
  && make \
  && make install

git clone https://github.com/VirusTotal/yara-python yara-python && cd yara-python
python3 setup.py build && python3 setup.py install

echo "[+] Executing 'python3 -m pip install yara-python'"
python3 -m pip install yara-python && cd ..


echo "[+] Installing go'"
# download and install go:
sudo apt install go

echo "[+] Installing p2p4slips'"
# build the pigeon and Add pigeon to path
git submodule init && git submodule update && cd p2p4slips && go build && export PATH=$PATH:$(pwd) >> ~/.bashrc && cd ..


# running slips for the first time
echo "[+] Executing 'redis-server --daemonize yes'"
redis-server --daemonize yes

