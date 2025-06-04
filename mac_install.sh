#!/bin/bash

brew update
echo "[+] Installing zeek ...\n"
brew install cmake make gcc flex bison libpcap openssl@1.1 python swig zlib go
brew install zeek

# create a symlink to zeek so that slips can find it
echo "[+] Executing 'ln -s /usr/local/Cellar/zeek/4.1.0/bin/zeek /usr/local/bin/bro'\n"
sudo ln -s /usr/local/Cellar/zeek/4.1.0/bin/zeek /usr/local/bin/bro
echo "[+] Executing 'export PATH=$PATH:/usr/local/Cellar/zeek/4.1.0/bin'\n"
export PATH=$PATH:/usr/local/Cellar/zeek/4.1.0/bin
echo "[+] Adding /usr/local/Cellar/zeek/4.1.0/bin to ~/.bash_profile\n"
echo "export PATH=$PATH:/usr/local/Cellar/zeek/4.1.0/bin" >> ~/.bash_profile

echo "[+] Installing Slips dependencies ...\n"
brew install python redis wireshark nfdump whois yara libnotify

echo "[+] Executing 'python3 -m pip install --upgrade pip'\n"
python3 -m pip install --upgrade pip
echo "[+] Executing 'pip3 install -r requirements.txt'\n"
pip3 install -r requirements.txt
echo "[+] Executing pip3 install --ignore-installed six\n"
pip3 install --ignore-installed six

# For Kalipso
echo "[+] Installing nodejs and npm dependencies"
brew install node
cd ./modules/kalipso && npm install
cd ../..

echo "[+] Installing p2p4slips\n"
# build the pigeon and Add pigeon to path
git submodule init && git submodule update && cd p2p4slips && go build && export PATH=$PATH:$(pwd) >> ~/.bash_profile && cd ..

# running slips for the first time
echo "[+] Executing 'redis-server --daemonize yes'\n"
redis-server --daemonize yes