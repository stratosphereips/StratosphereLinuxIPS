# P2P module for Slips

This module was developed as a [Master Thesis](https://dspace.cvut.cz/handle/10467/90252)
on CTU FEL. The goal was to enable Slips instances in a local network to share
detections and collectively improve blocking decisions. While the thesis succeeded in
creating a framework and a trust model, the project is far from stable.

This readme provides a shallow overview of the code structure, to
briefly document the code for future developers. The whole architecture was
thoroughly documented in the thesis itself, which can be downloaded from the
link above.

## Pigeon

Pigeon is written in golang and is developed in a repository independent of Slips, and also as a submodules of Slips repository.
https://github.com/stratosphereips/p2p4slips

It handles the P2P communication using the libp2p library, and provides a simple interface to the module. A compiled
Pigeon binary is included in the module for convenience.

Pigeon uses the JSON format to communicate with the module or with other Pigeons. For details on the communication
format, see the thesis.


## Installation:
1. download and install go: 

```
curl https://dl.google.com/go/go1.18.linux-amd64.tar.gz --output go.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz 
export PATH=$PATH:/usr/local/go/bin
```

2. build the pigeon:

- if you installed slips with the submodules using 
```git clone --recurse-submodules https://github.com/stratosphereips/StratosphereLinuxIPS ``` 
then you should only build the pigeon using:
```cd p2p4slips && go build```
- If you installed Slips without the submodules then you should download and build the pigeon using:

```
git clone https://github.com/stratosphereips/p2p4slips && cd p2p4slips && go build
```

3. Add pigeon to path:
```
cd p2p4slips 
export PATH=$PATH:$(pwd)
```

Remember that to permanently add the pigeon to path you should add it to ```.bashrc``` using the following commands:

```
echo "export PATH=$PATH:/path/to/StratosphereLinuxIPS/p2p4slips/" >> ~/.bashrc 
source ~/.bashrc
```


## Project sections

The project is built into Slips as a module and uses Redis for communication. Integration with Slips
is seamless, and it should be easy to adjust the module for use with other IPSs. The
following code is related to Dovecot:

 - Slips, the Intrusion Prevention System
 - Dovecot module, the module for Slips
 - Pigeon, a P2P wrapper written in golang
 - Dovecot experiments, a framework for evaluating trust models (optional)

## Dovecot experiments

Experiments are not essential to the module, and the whole project runs just fine without them. They are useful for
development of new trust models and modelling behavior of the P2P network. 

To use the experiments, clone
the https://github.com/stratosphereips/p2p4slips-experiments repository into
`modules/p2ptrust/testing/experiments`.

The experiments run independently (outside of Slips) and start all processes that are needed, including relevant parts
of Slips. 
The code needs to be placed inside the module, so that necessary dependencies are accessible. 
This is not the
best design choice, but it was the simplest quick solution.  


