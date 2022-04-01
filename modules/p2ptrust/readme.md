# Dovecot module for Slips

This module was developed as a [Master Thesis](https://dspace.cvut.cz/handle/10467/90252)
on CTU FEL. The goal was to enable Slips instances in a local network to share
detections and collectively improve blocking decisions. While the thesis succeeded in
creating a framework and a trust model, the project is far from stable.

This readme provides a shallow overview of the code structure, to
briefly document the code for future developers. The whole architecture was
thoroughly documented in the thesis itself, which can be downloaded from the
link above.

## Project sections

The project is built into Slips as a module and uses Redis for communication. Integration with Slips
is seamless, and it should be easy to adjust the module for use with other IPSs. The
following code is related to Dovecot:

 - Slips, the Intrusion Prevention System
 - Dovecot module, the module for Slips
 - Pigeon, a P2P wrapper written in golang
 - Dovecot experiments, a framework for evaluating trust models (optional)


##### Pigeon

Pigeon is written in golang and is developed in a repository independent of Slips.
https://github.com/stratosphereips/p2p4slips
It handles the P2P communication using the libp2p library, and provides a simple interface to the module. A compiled
Pigeon binary is included in the module for convenience.

Pigeon uses the JSON format to communicate with the module or with other Pigeons. For details on the communication
format, see the thesis.


To install:
1. download and install go: 
curl https://dl.google.com/go/go1.18.linux-amd64.tar.gz --output go.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz 
export PATH=$PATH:/usr/local/go/bin

2. build the pigeon
git clone https://github.com/stratosphereips/p2p4slips && cd p2p4slips && go build

3. Add pigeon to path, make sur ethe cwd where the p2p4slips binary is
export PATH=$PATH:$(pwd)

##### Dovecot experiments

Experiments are not essential to the module, and the whole project runs just fine without them. They are useful for
development of new trust models and modelling behavior of the P2P network. To use the experiments, clone
the https://github.com/stratosphereips/p2p4slips-experiments repository into
`modules/p2ptrust/testing/experiments`.

The experiments run independently (outside of Slips) and start all processes that are needed, including relevant parts
of Slips. The code needs to be placed inside the module, so that necessary dependencies are accessible. This is not the
best design choice, but it was the simplest quick solution.  


