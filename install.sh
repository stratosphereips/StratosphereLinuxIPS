#!/bin/sh
# Installing slips dependencies

echo "[+] Executing 'sudo apt-get update'"
sudo apt-get update
echo "[+] Executing 'sudo apt-get -y install curl git redis python3.7-minimal python3-redis python3-pip python3-watchdog nodejs npm file iptables nfdump'"
sudo apt-get -y install curl git redis python3.7-minimal python3-redis python3-pip python3-watchdog nodejs npm lsof file iptables nfdump
echo "[+] Executing 'python3 -m pip install --upgrade pip'"
python3 -m pip install --upgrade pip
echo "[+] Executing 'pip3 install maxminddb colorama validators urllib3 numpy sklearn pandas certifi keras redis==3.4.1 netaddr slackclient stix2 cabby ipwhois tzlocal psutil yara-python tshark'"
pip3 install maxminddb colorama validators urllib3 numpy sklearn requests pandas certifi keras redis==3.4.1 netaddr slackclient stix2 cabby ipwhois tzlocal psutil yara-python tshark
echo "[+] Executing pip3 install --ignore-installed six"
pip3 install --ignore-installed six
echo "[+] Executing 'sudo npm install blessed blessed-contrib redis async chalk strip-ansi@6.0.0 clipboardy fs sorted-array-async yargs pytest'"
sudo npm install blessed blessed-contrib redis@3.1.2 async chalk@4.1.2 strip-ansi@6.0.0 clipboardy fs sorted-array-async yargs

# Compile and install YARA
echo "[+] Installing YARA ..."
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
python3 -m pip install yara-python


# Installing zeek
echo "[+] Installing zeek ..."
echo "[+] Executing 'sudo apt-get -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev'"
sudo apt-get -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev
echo "[+] Executing 'git clone --recursive https://github.com/zeek/zeek'"
git clone --recursive https://github.com/zeek/zeek
echo "[+] Executing 'cd zeek/'"
cd zeek/
echo "[+] Executing '/configure'"
./configure
echo "[+] Executing 'sudo make'"
sudo make
echo "[+] Executing 'sudo make install'"
sudo make install
echo "[+] Executing 'sudo ln --symbolic /usr/local/zeek/bin/zeek /usr/bin/zeek'"
sudo ln --symbolic /usr/local/zeek/bin/zeek /usr/bin/zeek
echo "[+] Executing 'export PATH=$PATH:/usr/local/zeek/bin'"
export PATH=$PATH:/usr/local/zeek/bin
echo "[+] Adding /usr/local/zeek/bin to ~/.bashrc"
echo "export PATH=$PATH:/usr/local/zeek/bin" >> ~/.bashrc

# running slips for the first time
echo "[+] Executing 'redis-server --daemonize yes'"
redis-server --daemonize yes

