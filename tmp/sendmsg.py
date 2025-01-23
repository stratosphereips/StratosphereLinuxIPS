import redis

# connect to redis database 0
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

message  = '''
{
    "type": "nl2tl_intelligence_response",
    "version": 1,
    "data": [
        {
            "sender": {
                "id": "peer1",
                "organisations": ["org_123", "org_456"],
                "ip": "192.168.1.1"
            },
            "payload": {
                "intelligence": {
                    "target": {"type": "server", "value": "192.168.1.10"},
                    "confidentiality": {"level": 0.8},
                    "score": 0.5,
                    "confidence": 0.95
                },
                "target": "stratosphere.org"
            }
        },
        {
            "sender": {
                "id": "peer2",
                "organisations": ["org_789"],
                "ip": "192.168.1.2"
            },
            "payload": {
                "intelligence": {
                    "target": {"type": "workstation", "value": "192.168.1.20"},
                    "confidentiality": {"level": 0.7},
                    "score": -0.85,
                    "confidence": 0.92
                },
                "target": "stratosphere.org"
            }
        }
    ]
}
'''

messagee  = '''
{
    "type": "nl2tl_intelligence_response",
    "version": 1,
    "data": [
        {
            "sender": {
                "id": "peer1",
                "organisations": ["org_123", "org_456"],
                "ip": "192.168.1.1"
            },
            "payload": {
                "intelligence": {
                    "target": {"type": "server", "value": "192.168.1.10"},
                    "confidentiality": {"level": 0.8},
                    "score": 0.5,
                    "confidence": 0.95
                },
                "target": "stratosphere.org"
            }
        },
        {
            "sender": {
                "id": "peer2",
                "organisations": ["org_789"],
                "ip": "192.168.1.2"
            },
            "payload": {
                "intelligence": {
                    "target": {"type": "workstation", "value": "192.168.1.20"},
                    "confidentiality": {"level": 0.7},
                    "score": -0.85,
                    "confidence": 0.92
                },
                "target": "stratosphere.org"
            }
        }
    ]
}
'''
message1  = '''
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
                    "score": 0.5,
                    "confidence": 0.95
                },
                "target": "128.169.5.1"
            }
        }
    ]
}
'''
message2 = '''
{
    "type": "nl2tl_intelligence_response",
    "version": 1,
    "data": [
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
                    "score": -0.85,
                    "confidence": 0.92
                },
                "target": "stratosphere.org"
            }
        }
    ]
}
'''

# publish the message to the "network2fides" channel
channel = "network2fides"
redis_client.publish(channel, message)

print(f"Message published to channel '{channel}'.")
