# Iris module

Traditional network defense systems depend on centralized threat intelligence, 
which has limitations like single points of failure, inflexibility, and 
reliance on trust in centralized authorities. Peer-to-peer networks offer 
an alternative for sharing threat intelligence but face challenges in verifying 
the trustworthiness of participants, including potential malicious actors.

The Iris Module, based on [Master Theses](https://github.com/stratosphereips/iris)
on CTU FEL by Martin Řepa. The goal of this module is to provide a tool that 
mediates the global connection of peers in the global peer-to-peer network. Iris 
Module (i.e. Iris) administers organization-membership as well as 
organisation-membership evaluation. Addressing and reachability of peers is
handled by iris as well. Last but not least, sending threat intelligence data 
including files and alert distribution is handled by the module. 
All those functionalities are implemented based on Kademlia DHT which serves as
a core to the whole application.

This readme provides an overview of the code structure, to briefly 
document the code for future developers. The whole architecture was 
thoroughly documented in the thesis itself, which can be downloaded from the 
link above.

## Docker direct use
You cannot use Slips with Iris Module directly, please keep in mind that Iris 
Module needs a trust evaluation module as a mediator between Slips and itself. 
In the original design, this mediation and trust evaluation is 
provided by Fides Module.

```
docker pull stratosphereips/slips
docker run -it --rm --net=host --cap-add=NET_ADMIN stratosphereips/slips
```

For the Fides Module enabled on top of the Iris module you should use ```--cap-add=NET_ADMIN```

## Installation

```
docker pull stratosphereips/slips
docker run -it --rm --net=host --use_fides=True stratosphereips/slips
```
***NOTE***

If you plan on using the Iris Module, please be aware that it is used only
if Slips is running on an interface. The Iris Module is ignored when Slips is run on a file.

### Configuration
Identity, trusted organisations, peer discovery and other configuration is located in [iris/config.yml](https://github.com/stratosphereips/iris/blob/main/config.yaml) 

## Usage in Slips

Iris will be inactive be default, because Fides is inactive by default in Spips.

Please run Fides Module or other trust evaluation module when running Iris.


### **Communication & Messages**

Please refer to the [original Iris documentation](https://github.com/stratosphereips/iris/tree/main/docs) since it is complete and comprehensive.

Iris uses the internet to communicate with other peers and Redis channels of Slips to communicate with a trust intelligence module.

## Project sections

The project is built into Slips as a module and uses Redis for communication. Integration with Slips
is seamless, and it should be easy to adjust the module for use with other IPSs.

 - Slips, the Intrusion Prevention System
 - Iris Module the module for global p2p interaction


## How it works:

Slips interacts with other Slips peers for the following purposes:

### Organisation membership 

The Iris uses a DHT to store organisation members. This is a key for underlying 
trust evaluation.

### File sharing

Iris has a file sharing protocol implemented, this can be used to share files containing TI data.

Iris also uses the DHT capabilities to store file providers. Metadata about files are shared by Epidemic Protocols, this serves as a notification of authorized peers.
It is also necessary to verify whether a peer requesting a file is authorized to do so. 

### Providing messaging service for trust module

Trust evaluation may require interaction with other peers. Iris Module provides such a service.

### Dispatching alerts

If a threat so great it may impact whole network, one or more organisations, threat alert is
dispatched to peers, without regard to trust level accumulated on them.

<!--### Answering and receiving requests form global P2P network 
-->
## Testing

### Unit Tests
Unit tests for Iris Module have been added to the own repository of Iris. This procedure was selected because 
Slips is written in Python in its entirety, while Iris is based in Go. And following the best practices of
unit testing in Go leads to including the unit tests into the Iris repository itself.

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

#### Countdown Function

The countdown(seconds, message) function provides a countdown mechanism, displaying a message every second until it reaches zero. It is used to introduce delays before executing critical commands to ensure proper synchronization.

#### Message Sending

The message_send(port, channel, message) function connects to a Redis instance running on the specified port and publishes a given message to the specified channel.

#### Checking Strings in Log Files

The check_strings_in_file(string_list, file_path) function verifies whether a given list of strings is present within a specified file. It ensures that expected log entries appear in test output files.

#### Configuration Preparation

The prepare_configuration(cleanup=False) function is responsible for modifying the configuration file before running tests and restoring it afterward. It extracts the connection string from a log file, modifies it for testing, and updates the configuration file. It also ensures the proper placement of key files required for testing.

#### Test: test_messaging_1

The test_messaging_1 function is the primary integration test, verifying the message distribution functionality. The test workflow includes:

1. Creating required output directories.

2. Starting a Redis server instance.

3. Running the Iris key creator process.

4. Modifying configuration settings.

5. Running two instances of Slips:

   - One instance acting as a bootstrap node.

   - A second instance joining the network as a normal peer.

6. Sending an alert message via Redis.

7. Validating that expected log entries appear in the output logs.

8. Cleaning up by stopping processes and restoring configurations.

Throughout the test, countdown delays are used to ensure proper initialization and message processing times before terminating the test instances.

#### Error Handling & Assertions

- The test verifies that no errors appear in the output directories.

- It checks for the presence of expected log entries to confirm that the alert messages were successfully distributed.

- The test includes mechanisms to safely terminate and clean up running processes to prevent resource leaks.

## Logs

Slips contains a minimal log file for reports received by other peers and peer updates in
```output/irisModule.log```

## Limitations

The main limitation of Iris is that it is the responsibility of the organisation themselves to disclose their
identifiers to users.

## Implementation notes and credit
The go code was written by Martin Řepa as part of his thesis and can be accessed [here](https://github.com/stratosphereips/iris/tree/main).


## TLDR;

Slips (meaning Iris Module here) fully supports organisations, file sharing and messaging related to trust evaluation.
Each peer must ensure by itself that the recipient of a file is authorized to receive that file and that
organisation identifiers are correct and valid.

## Programmers notes

Slips and its modules are mainly written in Python, Iris is written in Go, which bring the need ot understand both languages and
ensure compilation of the Go code into an executable.
