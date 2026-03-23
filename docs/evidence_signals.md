# Evidence Signals

Slips now adds an `evidence_signal` field to every evidence when the evidence reaches the shared evidence pipeline. Detection modules do not need to set this field themselves.

The `T Cell` module consumes this same central field and only activates its
state machine for antigen recognition from `PAMP` evidence. `DAMP` evidence is
still stored by the module as an observation and contributes to the danger
pressure used in T-cell co-stimulation and context calculations for the same
responsible IP, and each new `DAMP` also reevaluates cells that are already
waiting on that responsible IP. `DAMP` does not create cells or perform regex
matching by itself. See
[T Cell Module](t_cell_module.md) for the responder details.

The supported values are:

- `PAMP`
- `DAMP`

Unknown evidence types default to `PAMP`.

## Configuration

Configure the default signal and per-evidence overrides in `config/slips.yaml`:

```yaml
EvidenceSignals:
  default_signal: PAMP
  overrides:
    ANOMALOUS_FLOW: DAMP
    MALICIOUS_FLOW: DAMP
    UNSOLICITED_ARP: DAMP
    CONNECTION_TO_MULTIPLE_PORTS: DAMP
    CONNECTION_TO_PRIVATE_IP: DAMP
    CONNECTION_WITHOUT_DNS: DAMP
    DNS_WITHOUT_CONNECTION: DAMP
    HIGH_ENTROPY_DNS_ANSWER: DAMP
    LONG_CONNECTION: DAMP
    MULTIPLE_RECONNECTION_ATTEMPTS: DAMP
    MULTIPLE_SSH_VERSIONS: DAMP
    NON_SSL_PORT_443_CONNECTION: DAMP
    UNKNOWN_PORT: DAMP
    YOUNG_DOMAIN: DAMP
    HTTP_TRAFFIC: DAMP
    MULTIPLE_USER_AGENT: DAMP
    NON_HTTP_PORT_80_CONNECTION: DAMP
    SSH_SUCCESSFUL: DAMP
```

Rules:

- `default_signal` is applied to every evidence type that is not listed in `overrides`.
- `overrides` keys are evidence type names from `EvidenceType`.
- Invalid values fall back to `PAMP`.
- The default shipped mapping marks the following evidence types as `DAMP`:
  `ANOMALOUS_FLOW`, `MALICIOUS_FLOW`, `UNSOLICITED_ARP`,
  `CONNECTION_TO_MULTIPLE_PORTS`, `CONNECTION_TO_PRIVATE_IP`,
  `CONNECTION_WITHOUT_DNS`, `DNS_WITHOUT_CONNECTION`,
  `HIGH_ENTROPY_DNS_ANSWER`, `LONG_CONNECTION`,
  `MULTIPLE_RECONNECTION_ATTEMPTS`, `MULTIPLE_SSH_VERSIONS`,
  `NON_SSL_PORT_443_CONNECTION`, `UNKNOWN_PORT`, `YOUNG_DOMAIN`,
  `HTTP_TRAFFIC`, `MULTIPLE_USER_AGENT`, `NON_HTTP_PORT_80_CONNECTION`,
  and `SSH_SUCCESSFUL`.

## Propagation

The field is added centrally before the evidence is stored or published, so it is available consistently in:

- Redis-stored evidence
- `alerts.json`
- STIX/TAXII export
- SlipsWeb dashboard payloads

## Current Evidence Inventory

The table below lists the evidence types currently emitted by Slips modules and their default signal classification.

| Module | Evidence type | Default signal |
| --- | --- | --- |
| `anomaly_detection_https` | `ANOMALOUS_FLOW` | `DAMP` |
| `arp` | `ARP_SCAN` | `PAMP` |
| `arp` | `ARP_OUTSIDE_LOCALNET` | `PAMP` |
| `arp` | `UNSOLICITED_ARP` | `DAMP` |
| `arp` | `MITM_ARP_ATTACK` | `PAMP` |
| `flowalerts` | `BAD_SMTP_LOGIN` | `PAMP` |
| `flowalerts` | `CN_URL_MISMATCH` | `PAMP` |
| `flowalerts` | `CONNECTION_TO_MULTIPLE_PORTS` | `DAMP` |
| `flowalerts` | `CONNECTION_TO_PRIVATE_IP` | `DAMP` |
| `flowalerts` | `CONNECTION_WITHOUT_DNS` | `DAMP` |
| `flowalerts` | `DATA_UPLOAD` | `PAMP` |
| `flowalerts` | `DEVICE_CHANGING_IP` | `PAMP` |
| `flowalerts` | `DGA_NXDOMAINS` | `PAMP` |
| `flowalerts` | `DIFFERENT_LOCALNET` | `PAMP` |
| `flowalerts` | `DNS_ARPA_SCAN` | `PAMP` |
| `flowalerts` | `DNS_WITHOUT_CONNECTION` | `DAMP` |
| `flowalerts` | `GRE_SCAN` | `PAMP` |
| `flowalerts` | `GRE_TUNNEL` | `PAMP` |
| `flowalerts` | `HIGH_ENTROPY_DNS_ANSWER` | `DAMP` |
| `flowalerts` | `HORIZONTAL_PORT_SCAN` | `PAMP` |
| `flowalerts` | `INCOMPATIBLE_CN` | `PAMP` |
| `flowalerts` | `INVALID_DNS_RESOLUTION` | `PAMP` |
| `flowalerts` | `LONG_CONNECTION` | `DAMP` |
| `flowalerts` | `MALICIOUS_JA3` | `PAMP` |
| `flowalerts` | `MALICIOUS_JA3S` | `PAMP` |
| `flowalerts` | `MALICIOUS_SSL_CERT` | `PAMP` |
| `flowalerts` | `MULTIPLE_RECONNECTION_ATTEMPTS` | `DAMP` |
| `flowalerts` | `MULTIPLE_SSH_VERSIONS` | `DAMP` |
| `flowalerts` | `NON_SSL_PORT_443_CONNECTION` | `DAMP` |
| `flowalerts` | `PASSWORD_GUESSING` | `PAMP` |
| `flowalerts` | `PASTEBIN_DOWNLOAD` | `PAMP` |
| `flowalerts` | `PORT_0_CONNECTION` | `PAMP` |
| `flowalerts` | `SELF_SIGNED_CERTIFICATE` | `PAMP` |
| `flowalerts` | `SMTP_LOGIN_BRUTEFORCE` | `PAMP` |
| `flowalerts` | `SSH_SUCCESSFUL` | `DAMP` |
| `flowalerts` | `UNKNOWN_PORT` | `DAMP` |
| `flowalerts` | `VERTICAL_PORT_SCAN` | `PAMP` |
| `flowalerts` | `YOUNG_DOMAIN` | `DAMP` |
| `flowmldetection` | `MALICIOUS_FLOW` | `DAMP` |
| `http_analyzer` | `EMPTY_CONNECTIONS` | `PAMP` |
| `http_analyzer` | `EXECUTABLE_MIME_TYPE` | `PAMP` |
| `http_analyzer` | `HTTP_TRAFFIC` | `DAMP` |
| `http_analyzer` | `INCOMPATIBLE_USER_AGENT` | `PAMP` |
| `http_analyzer` | `MULTIPLE_USER_AGENT` | `DAMP` |
| `http_analyzer` | `NON_HTTP_PORT_80_CONNECTION` | `DAMP` |
| `http_analyzer` | `PASTEBIN_DOWNLOAD` | `PAMP` |
| `http_analyzer` | `SUSPICIOUS_USER_AGENT` | `PAMP` |
| `http_analyzer` | `WEIRD_HTTP_METHOD` | `PAMP` |
| `ip_info` | `MALICIOUS_JARM` | `PAMP` |
| `leak_detector` | `NETWORK_GPS_LOCATION_LEAKED` | `PAMP` |
| `network_discovery` | `DHCP_SCAN` | `PAMP` |
| `network_discovery` | `ICMP_ADDRESS_MASK_SCAN` | `PAMP` |
| `network_discovery` | `ICMP_ADDRESS_SCAN` | `PAMP` |
| `network_discovery` | `ICMP_TIMESTAMP_SCAN` | `PAMP` |
| `network_discovery.horizontal_portscan` | `HORIZONTAL_PORT_SCAN` | `PAMP` |
| `network_discovery.vertical_portscan` | `VERTICAL_PORT_SCAN` | `PAMP` |
| `p2ptrust` | `MALICIOUS_IP_FROM_P2P_NETWORK` | `PAMP` |
| `p2ptrust` | `P2P_REPORT` | `PAMP` |
| `p2ptrust.go_director` | `P2P_REPORT` | `PAMP` |
| `rnn_cc_detection` | `COMMAND_AND_CONTROL_CHANNEL` | `PAMP` |
| `threat_intelligence` | `MALICIOUS_DOWNLOADED_FILE` | `PAMP` |
| `threat_intelligence` | `THREAT_INTELLIGENCE_ANSWER_OF_BLACKLISTED_QUERY` | `PAMP` |
| `threat_intelligence` | `THREAT_INTELLIGENCE_BLACKLISTED_ASN` | `PAMP` |
| `threat_intelligence` | `THREAT_INTELLIGENCE_BLACKLISTED_DNS_ANSWER` | `PAMP` |
| `threat_intelligence` | `THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN` | `PAMP` |
| `threat_intelligence` | `THREAT_INTELLIGENCE_TO_BLACKLISTED_IP` | `PAMP` |
| `threat_intelligence.urlhaus` | `MALICIOUS_DOWNLOADED_FILE` | `PAMP` |
| `threat_intelligence.urlhaus` | `THREAT_INTELLIGENCE_MALICIOUS_URL` | `PAMP` |

`ANOMALOUS_FLOW` is emitted by `anomaly_detection_https`, while `MALICIOUS_FLOW`
is emitted by `flowmldetection`. Both are marked as `DAMP` by default in the
central signal configuration. The additional shipped DAMP overrides in
`config/slips.yaml` are `UNSOLICITED_ARP`,
`CONNECTION_TO_MULTIPLE_PORTS`, `CONNECTION_TO_PRIVATE_IP`,
`CONNECTION_WITHOUT_DNS`, `DNS_WITHOUT_CONNECTION`,
`HIGH_ENTROPY_DNS_ANSWER`, `LONG_CONNECTION`,
`MULTIPLE_RECONNECTION_ATTEMPTS`, `MULTIPLE_SSH_VERSIONS`,
`NON_SSL_PORT_443_CONNECTION`, `UNKNOWN_PORT`, `YOUNG_DOMAIN`,
`HTTP_TRAFFIC`, `MULTIPLE_USER_AGENT`, `NON_HTTP_PORT_80_CONNECTION`,
and `SSH_SUCCESSFUL`.
