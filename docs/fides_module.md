# Fides module

Traditional network defense systems depend on centralized threat intelligence, which has limitations like single points of failure, inflexibility, and reliance on trust in centralized authorities. Peer-to-peer networks offer an alternative for sharing threat intelligence but face challenges in verifying the trustworthiness of participants, including potential malicious actors.

The Fides Module, based on [research](https://github.com/stratosphereips/fides/tree/bfac47728172d3a4bbb27a5bb53ceef424e45e4f) by Lukáš Forst, addresses these challenges by providing a trust model for peer-to-peer networks. It evaluates peer behavior, considers membership in trusted organizations, and assesses incoming threat data to determine reliability. Fides aggregates and weights data to enhance intrusion prevention systems, even in adversarial scenarios. Experiments show that Fides can maintain accurate threat intelligence even when 75% of the network is controlled by malicious actors, assuming the remaining 25% are trusted.
## How to use
### **Communication**
The module uses Slips' Redis to receive and send messages related to trust and P2P connection and data evaluation.

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

### Configuration
Evaluation model, evaluation thrash-holds and other configuration is located in fides.conf.yml 

**Possible threat intelligence evaluation models**

| **Model Name**         | **Description**                                                  |
|:-----------------------|--------------------------------------------------------------|
| `average`              | Average Confidence Trust Intelligence Aggregation            |
| `weightedAverage`      | Weighted Average Confidence Trust Intelligence Aggregation   |
| `stdevFromScore`       | Standard Deviation From Score Trust Intelligence Aggregation |

## Implementation notes and credit
The mathematical models for trust evaluation were written by Lukáš Forst as part of his theses and can be accessed [here](https://github.com/LukasForst/fides/commits?author=LukasForst).