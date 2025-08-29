# Iris module

Traditional network defense systems depend on centralized threat intelligence, which has limitations like single points of failure, inflexibility, and reliance on trust in centralized authorities. Peer-to-peer networks offer an alternative for sharing threat intelligence but face challenges in verifying the trustworthiness of participants, including potential malicious actors.

The Iris Module is based on the [Master Thesis]([https://github.com/stratosphereips/iris](https://dspace.cvut.cz/handle/10467/101308)) of Martin Řepa. The goal of this module is to provide a methodology and a new P2P system that mediates the global connection of peers in the global P2P network. The Iris Module administers organizations as well as the evaluation of membership in the organizations. Addressing and reachability of peers are handled by Iris as well. The module also sends threat intelligence data, including files and alert distribution.

All those functionalities are implemented based on Kademlia DHT, which serves as the core of the whole application.

This readme provides an overview of the code structure to briefly document the code for future developers. The whole architecture was thoroughly documented in the thesis itself, which can be downloaded from the link above.

The Iris Module needs a trust-based mediator with Slips. This mediation and trust evaluation is provided by the Fides Module.


## Docker direct use
```
docker pull stratosphereips/slips
docker run -it --rm --net=host --interface=<select_interface_to_run_on> stratosphereips/slips
```

Both the Fides Module and the Iris Module can be enabled in Slips' configuration file by adding:

    global_p2p:
        use_global_p2p: True

## Condition

Slips needs to be running on an interface or a growing Zeek directory. The Iris Module is ignored when Slips is run on a file.

## Configuration
Identity, trusted organisations, peer discovery, and other configuration is located in [iris/config.yml](https://github.com/stratosphereips/iris/blob/main/config.yaml)

## Usage in Slips

Iris will be inactive by default because Fides is inactive by default in Slips.

Please run the Fides Module or another trust evaluation module when running Iris.

Iris Module and Fides Module have been designed to cooperate and therefore can be both enabled in the configuration file of Slips by adding:

    global_p2p:
        use_global_p2p: True

Once Iris is enabled, it will be using port 9010 by default.

## **Communication & Messages**

Please refer to the [original Iris documentation](https://github.com/stratosphereips/iris/tree/main/docs) since it is complete and comprehensive.

Iris uses the internet to communicate with other peers and Redis channels of Slips to communicate with a trust intelligence module.

## How it works:

Slips interacts with other Slips peers for the following purposes:

### Organisation membership

Iris uses a DHT to store organisation members. This is a key for the underlying trust evaluation.

### File sharing

Iris has a file-sharing protocol implemented, which can be used to share files containing TI data.

Iris also uses the DHT capabilities to store file providers. Metadata about files is shared by Epidemic Protocols, which serves as a notification of authorized peers.
It is also necessary to verify whether a peer requesting a file is authorized to do so.


### Providing messaging service for the trust module

Trust evaluation may require interaction with other peers. Iris Module provides such a service.

### Dispatching alerts

If a threat is so great that it may impact the whole network, one or more organisations, a threat alert is dispatched to peers, without regard to the trust level accumulated on them.

### Bootstrapping node
The Slips configuration file now has an option for starting as a bootstrapping node.
The bootstrapping functionality for the global P2P network under Iris is facilitated.
This mode triggers only if Slips is run on an interface or growing zeek log directory mode AND the bootstrapping is set to True in the Slips configurations file AND GlobalP2P mode is allowed.
When the bootstrapping mode is used, Slips runs with a subset of nodes that are selected by names (currently Fides and Iris).


## Testing

### Unit Tests
Unit tests for the Iris Module have been added to the own repository of Iris. This procedure was selected because
Slips is written in Python in its entirety, while Iris is based on Go. And following the best practices of
unit testing in Go leads to including the unit tests in the Iris repository itself.

Please take the following into account. At the time of unit test development,
Go is yet to support mocking as known in Python, Java and many other languages.
It has been decided by the development team of Slips that running the unit test of Iris
will be left upon the future developers.

#### Running the Tests
* The unit tests run best with ```go v1.17```.
* Go to the directory containing Iris code.
* ```cd pkg```
* ```go test ./...```

### Integration Testing
Integration tests are located in ```tests/integration_tests/test_iris.py```.

### Test Messaging
The scenario that was modeled in this test refers to a common use case.

The first node (called main) under a Slips instance is created and puts its connection string that contains its identity/public key and details of how to reach it
in the P2P network.

The user would then distribute the connection string to other users so they can connect to the main and start forming a network. The distribution is simulated by automatically extracting the connection string and adding it to a configuration file of the second peer.

The second peer is started shortly after the first one and forms a connection. First peer discovers an alert-worthy information and tries to inform its peers (the second node).

Peers receive the message, and the test is considered successful.

## Logs

Slips contains a log file for reports received by other peers and peer updates of the Iris Module in
```output/<path_to_a_Slips_output_folder>/iris/iris_logs.txt```

## Limitations

The main limitation of Iris is that it is the responsibility of the organisation themselves to disclose their identifiers to users.

## Implementation notes and credit
The Go code was written by Martin Řepa as part of his thesis and can be accessed [here](https://github.com/stratosphereips/iris/tree/main).
