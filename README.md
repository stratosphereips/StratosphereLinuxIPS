# Stratosphere Linux IPS (slips)
This is tha linux version of the Stratosphere IPS. It receives flows from a ra client (argus).

## Platform
slips (using argus) has been tested on Linux Debian 8 and Apple IOS 10.9.5


## Usage
- First you have to start an Argus program capturing the traffic and serving it in a given port

    argus -i wlan0 -S 5 -P 902

- Then you start the slips program receiving packets from a ra client. The ra client reads the flows from an Argus program

    ra -F ra.conf -n -Z b -S 127.0.0.1:902 | ./slips.py

## Features and restrictions
