# P2P

The P2P module makes Slips be a peer in a peer to peer network of computers in the local network. The peers are only in the local network and they communicate using multicast packets. The P2P module is a highly complex system of data sharing, reports on malicious computers, asking about IoC to the peers and a complex trust model that is designed to resiste adversarial peers in the network. Adversarial peers are malicious peers that lie about the data being shared (like saying that a computer is maliciuos when is not, or that an attacker is benign).

This module was designed and partially implemented in a [Master Thesis](https://dspace.cvut.cz/handle/10467/90252) on CTU FEL by [Dita Hollmannova](https://www.linkedin.com/in/dita-hollmannova/). The goal was to enable Slips instances in a local network to share detections and collectively improve blocking decisions. While the thesis succeeded in creating a framework and a trust model, the project is far from stable. The final implementation in Slips was finished by Alya Gomaa.

This readme provides a shallow overview of the code structure, to briefly document the code for future developers. The whole architecture was thoroughly documented in the thesis itself, which can be downloaded from the link above.

The basic structure of the P2P system is (i) an Slips P2P module in python (called Dovecot), and (ii) a P2P communication system done in Golang (called Pigeon).


## Pigeon

Pigeon is written in golang and is developed in an independent repository from Slips, but is included as a submodules of Slips repository. [https://github.com/stratosphereips/p2p4slips](https://github.com/stratosphereips/p2p4slips)

Pigeon handles the P2P communication in the network using the libp2p library, and provides a simple interface to the Slips module. A compiled
Pigeon binary is included in the module for convenience.

Pigeon uses the JSON format to communicate with the module or with other Pigeons. For details on the communication
format, see the thesis.

## Docker direct use
You can use Slips with P2P directly in a special docker image by doing:

```
docker pull stratosphereips/slips
docker run -it --rm --net=host --cap-add=NET_ADMIN stratosphereips/slips
```

For the p2p to be able to listen on the network interfaces
and receive packets you should use ```--cap-add=NET_ADMIN```

## Installation:

1. download and install go:

```
apt install golang
```

or by hand

```
curl https://dl.google.com/go/go1.18.linux-amd64.tar.gz --output go.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

2. build the pigeon:

- if you installed slips with the submodules using
```
git clone --recurse-submodules --remote-submodules https://github.com/stratosphereips/StratosphereLinuxIPS -j4
```

then you should only build the pigeon using:
```cd p2p4slips && go build```
- If you installed Slips without the submodules then you should download and build the pigeon using:

```
git submodule init && git submodule update && cd p2p4slips && go build
```

The p2p binary should now be in ```p2p4slips/``` dir and slips will be able to find it.

***NOTE***

If you installed the p2p4slips submodule anywhere other than slips main directory, remember to add it to PATH
by using the following commands:

```
echo "export PATH=$PATH:/path/to/StratosphereLinuxIPS/p2p4slips/" >> ~/.bashrc
source ~/.bashrc
```

## Usage in Slips

The P2P module is disabled by default in Slips.

To enable it, change ```use_p2p=no``` to ```use_p2p=yes``` in ```config/slips.yaml```

P2P is only available when running slips in you local network using an interface. (with -i <interface>)

You don't have to do anything in particular for the P2P module to work, just enable it and Slips will:
1- Automatically find other peers in the network (and remember them even if they go offline for days)

2- Ask the group of peers (the network) about what they think of some IoC

3- Group the answers and give Slips an aggregated, balanced, normalized view of the network opinion on each IoC

4- Send blame reports to the whole network about attackers

5- Receive blame reports on attackers from the network, balanced by the trust model

6- Keep a trust score on each peer, which varies in time based on the interactions and quality of data shared

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

## How it works:

Slips interacts with other slips peers for the following purposes:

### Blaming IPs

If slips finds that an IP is malicious given enough evidence, it blocks it and tells other peers that this IP is malicious and they need to block it. this is called sending a blame report.

### Receiving Blames

When slips receives a blame report from the network,
which means some other slips instance in th network set an evidence about
an IP and is letting other peers know about it.

Slips then generates an evidence about the reported IP and takes the report into consideration
when deciding to block the attacker's IP.



### Asking the network about an IP

Whenever slips sees a new IP, it asks other peers about it, and waits 3 seconds for them to reply.

The network then replies with a score and confidence for the IP. The higher the score the more malicious this IP is.

Once we get the score of the IP, we store it in the database,
and we alert if the score of this IP is more than 0 (threat level=info).


### Answering the network's request about an IP

When asked about an ip, slips shares the score of it and the confidence with the requesting peer. the scores are generated by slips and saved in the database.

## Logs

Slips contains a minimal log file for reports received by other peers and peer updates in
```output/p2p_reports.log```

For a more detailed p2p logs, for example (peer ping pongs, peer lists, errors, etc.)
you can enable p2p.log in slips.yaml by setting ```create_p2p_logfile``` to ```yes```
and a ```p2p.log``` will be available in the output dir

Slips rotates the p2p.log every 1 day by default, and keeps the logs of 1 past day only.


## Limitations

For now, slips only supports requests and blames about IPs.

Domains, URLs, or hashes are not supported, but can easily be added in the future.


## TLDR;

Slips only shares scores and confidence (numbers) generated by slips about IPs to the network,
no private information is shared.
