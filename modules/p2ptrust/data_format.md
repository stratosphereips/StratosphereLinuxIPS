# Data saved to Slips

Slips database expects a dictionary of data. The data from this module (for a given IP) has the following format: 

```json
{
  "p2p4slips": {
    "score": 0.9,
    "confidence": 0.6,
    "network_score": 0.9,
    "timestamp": 154900000
  }
}
```

The `p2p4slips` field in the database will the report from the network. The report will have the IP address that is
reported, the computed score and confidence, and an additional value with score of all the peers that gave the opinion. 

# Communication between python and go parts of the implementation

The core of each peer is implemented in python. The python code collects data, shares this data with other peers
(report), asks other peers for data (request) etc. Python code doesn't communicate with other peers directly - it relies
on the go part of the node to do that work. The two parts of the node exchange information and instructions using redis
channels. 

## The channel from Slips to Go `p2p_pygo`

Slips sends data to go in json. The Json object has two fields: `message` and `recipient`. 

```json
{"message": "ewogICAgImtleV90eXBlIjogImlwIiwKICAgICJrZXkiOiAiMS4yLjMuNDAiLAogICAgImV........jYKfQ==", "recipient": "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"}
```

The message is the base64 encoded string that the modules are exchanging, This is not unpacked in the transporting layer. The `recipient` field is the peerID of the peer the message is sent to. Use `*` to send the message to all peers.

## The channel from Go to Slips `p2p_pygo`

The go library sends several types of messages to the core. The messages in the channel always start with a command,
followed by a space and then data. The command is a string without spaces, and the data is json.

### Data forwarded from other peers: `go_data`

Go layer listens for data from other peers. However, it doesn't unpack the data, validate it or otherwise process it. It
expects a string and forwards it to the node core, with some additional information: the sender's peerid and the time
the report was received (system time, unix).

The internal structure of the messages sent between peers is discussed later. For now, it is only important to recognize
that the go messages are base64 encoded strings.

To simplify implementation, the message from go layer always wraps the data in a list - this allows for sending one or
more reports at the same time.

```json
{
  "message_type": "go_data",
  "message_contents": 
    {
      "reporter": "abcsakughroiauqrghaui",   // the peer that sent the data
      "report_time": 154900000,              // time of receiving the data
      "message": "ewogICAgImtleV90eXBlIjogImlwIiwKICAgICJrZXkiOiAiMS4yLjMuNDAiLAogICAgImV........jYKfQ=="
    }
}
```

### Peer data update `peer_update`

When the reliability of a peer changes, the go layer should notify the Python layer. The update must contain the peerID
of the peer in question. The update message can be used to update reliability as well as IP address of the peer. At
least one of the parameters `ip` and `reliability` should be provided.

Unlike go data, peer updates are expected to be sent separately, therefore a the dictionary type is required instead of
a list.

```json
{
  "message_type": "peer_update",
  "message_contents":
    {
      "peerid": "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
      "ip": "1.2.3.40",
      "reliability": "0.3"
    }
}
```


# Message format between peers

The message is a json object (encoded as base64), and it must contain the field `message_type`, which describes what
kind of message should be expected. The acceptable message types are `report`, `request` and `blame`.

The report always contains the key type (currently, on IP addresses are supported), and the key itself - this is the IP
address the node is reporting about. Then, the Evaluation object follows, this aims to allow for easier expansion later
on. Nodes advertise the Evaluation type with the type attribute in each message.

At the time of writing this, the only supported type is `score_confidence` and there are two values shared - score and
confidence.

The nodes always report the key type - currently, only IP addresses are supported, nodes should drop any unknown key
types. A valid report can look like this:

### Type request

```json
{
  "message_type": "request",
  "key_type": "ip",
  "key": "1.2.3.40",
  "evaluation_type": "score_confidence"
}
```

### Type report

```json
{
  "message_type": "report",
  "key_type": "ip",
  "key": "1.2.3.40",
  "evaluation_type": "score_confidence",
  "evaluation": {
    "score": 0.9,
    "confidence": 0.6
  }
}
```
