from dataclasses import dataclass
from typing import List, Optional, Any, Dict


# peerinfo class
@dataclass
class PeerInfo:
    """Identification data of a single peer in the network."""
    id: str  # unique identification of a peer in the network
    organisations: List[str]  # list of organizations that trust the peer
    ip: Optional[str] = None  # ip address of the peer, if known

    def to_dict(self):
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'organisations': [org for org in self.organisations],
            'ip': self.ip,
        }


# slips threat intelligence class
@dataclass
class SlipsThreatIntelligence:
    target: Dict[str, Any]  # target of the intelligence
    confidentiality: Optional[Dict[str, Any]] = None  # confidentiality level if known
    score: Optional[Dict[str, Any]] = None  # score of the threat
    confidence: Optional[Dict[str, Any]] = None  # confidence level

    def to_dict(self):
        return {
            "target": self.target,
            "confidentiality": self.confidentiality if self.confidentiality else None,
            "score": self.score,
            "confidence": self.confidence
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            target=data["target"],
            confidentiality=data.get("confidentiality"),
            score=data.get("score"),
            confidence=data.get("confidence")
        )


# network message class
@dataclass
class NetworkMessage:
    type: str  # message type
    version: int  # protocol version
    data: Any  # message payload


# handler to process messages
def __on_nl2tl_intelligence_response(data: Dict):
    print('Processing nl2tl_intelligence_response message...')
    responses = [
        {
            "sender": PeerInfo(
                id=single['sender']['id'],
                organisations=single['sender']['organisations'],
                ip=single['sender'].get('ip')
            ),
            "intelligence": SlipsThreatIntelligence.from_dict(single['payload']['intelligence'])
        }
        for single in data
    ]
    return responses


# function to simulate receiving a message
import json


def message_received(message: str):
    print(f"@@@@@@@@@@@@@@@@ msg received here {message}")
    try:
        print("New message received! Trying to parse.")
        parsed: dict = json.loads(message)
        network_message = NetworkMessage(
            type=parsed['type'],
            version=parsed['version'],
            data=parsed['data']
        )
        print("Message parsed. Executing handler.")
        if network_message.type == "nl2tl_intelligence_response":
            result = __on_nl2tl_intelligence_response(network_message.data)
            print("Handler executed successfully. Processed data:")
            print(result)
    except Exception as e:
        print(f"There was an error processing message, Exception: {e}.")


# test message
test_message = """
{
  "type": "nl2tl_intelligence_response",
  "version": 1,
  "data": [
    {
      "sender": {
        "id": "peer123",
        "organisations": ["org1", "org2"],
        "ip": "192.168.1.10"
      },
      "payload": {
        "intelligence": {
          "target": {
            "ip": "192.168.1.100",
            "port": 8080
          },
          "confidentiality": {
            "level": "high"
          },
          "score": {
            "value": 85
          },
          "confidence": {
            "percentage": 95
          }
        }
      }
    },
    {
      "sender": {
        "id": "peer789",
        "organisations": ["org3"],
        "ip": "10.0.0.200"
      },
      "payload": {
        "intelligence": {
          "target": {
            "ip": "10.0.0.150",
            "port": 443
          },
          "confidentiality": {
            "level": "medium"
          },
          "score": {
            "value": 60
          },
          "confidence": {
            "percentage": 80
          }
        }
      }
    }
  ]
}
"""

# test the function
message_received(test_message)




self.db.publish("network2fides", """ {   "type": "nl2tl_intelligence_response",   "version": 1,   "data": [     {       "sender": {         "id": "peer123",         "organisations": ["org1", "org2"],         "ip": "192.168.1.10"       },       "payload": {         "intelligence": {           "target": {             "ip": "192.168.1.100",             "port": 8080           },           "confidentiality": {             "level": "high"           },           "score": {             "value": 85           },           "confidence": {             "percentage": 95           }         }       }     },     {       "sender": {         "id": "peer789",         "organisations": ["org3"],         "ip": "10.0.0.200"       },       "payload": {         "intelligence": {           "target": {             "ip": "10.0.0.150",             "port": 443           },           "confidentiality": {             "level": "medium"           },           "score": {             "value": 60           },           "confidence": {             "percentage": 80           }         }       }     }   ] } """)
self.db.publish("network2fides", '''
{
    "type": "nl2tl_intelligence_response",
    "version": 1,
    "data": [
        {
            "sender": {
                "id": "peer_001",
                "organisations": ["org_123", "org_456"],
                "ip": "192.168.1.1"
            },
            "payload": {
                "intelligence": {
                    "target": {"type": "server", "value": "192.168.1.10"},
                    "confidentiality": {"level": 0.8},
                    "score": {"value": 90},
                    "confidence": {"value": 0.95}
                }
            }
        },
        {
            "sender": {
                "id": "peer_002",
                "organisations": ["org_789"],
                "ip": "192.168.1.2"
            },
            "payload": {
                "intelligence": {
                    "target": {"type": "workstation", "value": "192.168.1.20"},
                    "confidentiality": {"level": 0.7},
                    "score": {"value": 85},
                    "confidence": {"value": 0.92}
                }
            }
        }
    ]
}
''')

# should be called __on_nl2tl_intelligence_response
then on_intelligence_response()
then intelligence.handle_intelligence_response()
handle_intelligence_response() does the calculations and stpres in the db