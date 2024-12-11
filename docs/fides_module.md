# Fides module

Traditional network defense systems depend on centralized threat intelligence, which has limitations like single points of failure, inflexibility, and reliance on trust in centralized authorities. Peer-to-peer networks offer an alternative for sharing threat intelligence but face challenges in verifying the trustworthiness of participants, including potential malicious actors.

The Fides Module, based on [Master Theses](https://github.com/stratosphereips/fides/tree/bfac47728172d3a4bbb27a5bb53ceef424e45e4f) on CTU FEL by Lukáš Forst. The goal of this module is to address the challenge of trustworthyness of peers in peer-to-peer networks by providing several trust evaluation models. It evaluates peer behavior, considers membership in trusted organizations, and assesses incoming threat data to determine reliability. Fides aggregates and weights data to enhance intrusion prevention systems, even in adversarial scenarios. Experiments show that Fides can maintain accurate threat intelligence even when 75% of the network is controlled by malicious actors, assuming the remaining 25% are trusted.

This readme provides a shallow overview of the code structure, to briefly document the code for future developers. The whole architecture was thoroughly documented in the thesis itself, which can be downloaded from the link above.

## Docker direct use
You can use Slips with Fides Module by allowing it in the Slips config file or by using the following commands.

```
docker pull stratosphereips/slips
docker run -it --rm --net=host --cap-add=NET_ADMIN stratosphereips/slips
```

For the Fides Module enabled you should use ```--cap-add=NET_ADMIN```

## Installation:

```
docker pull stratosphereips/slips
docker run -it --rm --net=host --use_fides=True stratosphereips/slips
```
***NOTE***

If you plan on using the Fides Module, lease be aware that it is used only
if Slips is running on an interface. The `--use_fides=True` is ignored when Slips is run on a file.

### Configuration
Evaluation model, evaluation thrash-holds and other configuration is located in fides.conf.yml 

**Possible threat intelligence evaluation models**

| **Model Name**         | **Description**                                                  |
|:-----------------------|--------------------------------------------------------------|
| `average`              | Average Confidence Trust Intelligence Aggregation            |
| `weightedAverage`      | Weighted Average Confidence Trust Intelligence Aggregation   |
| `stdevFromScore`       | Standard Deviation From Score Trust Intelligence Aggregation |

## Usage in Slips

Fides is inactive by default in Spips.

To enable it, change ```use_fides=False``` to ```use_fides=True``` in ```config/slips.yaml```


### **Communication**
The module uses Slips' Redis to receive and send messages related to trust intelligence, evaluation of trust in peers and alert message dispatch.

**Used Channels**

| **Slips Channel Name** | **Purpose**                                                             |
|-----------------|-------------------------------------------------------------------------|
| `slips2fides`   | Provides communication channel from Slips to Fides                      |
| `fides2slips`   | Enables the Fides Module to answer requests from slips2fides            |
| `network2fides` | Facilitates communication from network (P2P) module to the Fides Module |
| `fides2network` | Lets the Fides Module request network opinions form network modules     |

For more details, the code [here](https://github.com/stratosphereips/fides/tree/bfac47728172d3a4bbb27a5bb53ceef424e45e4f/fides/messaging) may be read.


### **Messages**

| **Message type (data['type'])** | **Channel**     | **Call/Handle**                                                                                                       | **Description**                                                                                       |
|:-------------------------------:|-----------------|-----------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
|             `alert`             | `slips2fides`   | FidesModule as self.__alerts.dispatch_alert(target=data['target'], confidence=data['confidence'],score=data['score']) | Triggers sending an alert to the network, about given target, which SLips believes to be compromised. |
|     `intelligence_request`      | `slips2fides`   | FidesModule as self.__intelligence.request_data(target=data['target'])                                                | Triggers request of trust intelligence on given target.                                               |
|          `tl2nl_alert`          | `fides2network` | call dispatch_alert() of AlertProtocol class instance                                                                 | Broadcasts alert through the network about the target.                                                |
|  `tl2nl_intelligence_response`  | `fides2network` | NetworkBridge.send_intelligence_response(...)                                                                         | Shares Intelligence with peer that requested it.                                                      |
|  `tl2nl_intelligence_request`   | `fides2network` | NetworkBridge.send_intelligence_request(...)                                                                          | Requests network intelligence from the network regarding this target.                                 |
| `tl2nl_recommendation_response` | `fides2network` | NetworkBridge.send_recommendation_response(...)                                                                       | Responds to given request_id to recipient with recommendation on target.                              |
| `tl2nl_recommendation_request`  | `fides2network` | NetworkBridge.send_recommendation_request(...)                                                                        | Request recommendation from recipients on given peer.                                                 |
|    `tl2nl_peers_reliability`    | `fides2network` | NetworkBridge.send_peers_reliability(...)                                                                             | Sends peer reliability, this message is only for network layer and is not dispatched to the network.  |


Implementations of Fides_Module-network-communication can be found in modules/fidesModule/messaging/network_bridge.py.

## Project sections

The project is built into Slips as a module and uses Redis for communication. Integration with Slips
is seamless, and it should be easy to adjust the module for use with other IPSs.

 - Slips, the Intrusion Prevention System
 - Fides Module the trust evaluation module for global p2p interaction


## How it works:

Slips interacts with other slips peers for the following purposes:

### Sharing opinion on peers

If a peers A is asked for its opinion on peer B by peer C, peer A sends the aggregated opinion on peer B to peer C, if there is any.

### Asking for an opinion

Newly connected peer will create a base trust by asking ather peers for opinion.

### Dispatching alerts

If a threat so great it may impact whole network, one or more groups, threat alert is
dispatched to peers, without regard to trust level accumulated on them.

### Answering and receiving requests form global P2P module. 

## Logs

Slips contains a minimal log file for reports received by other peers and peer updates in
```output/fidesModule.log```

## Limitations

For now, slips supports the trust intelligence evaluation, global p2p is to be implemented.

## Implementation notes and credit
The mathematical models for trust evaluation were written by Lukáš Forst as part of his theses and can be accessed [here](https://github.com/LukasForst/fides/commits?author=LukasForst).


## TLDR;

Slips (meaning Fides Module here) only shares trust level and confidence (numbers) generated by slips about IPs to the network,
no private information is shared.
