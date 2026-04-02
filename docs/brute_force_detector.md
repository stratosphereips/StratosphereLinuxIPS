# Brute force detector Module

The `brute_force_detector` module detects SSH brute forcing by combining repeated SSH sessions, Zeek SSH metadata, client software banners, and Zeek notice confirmations.

This module is loaded automatically by Slips like the rest of the modules in `modules/`, unless it is explicitly disabled in `config/slips.yaml`.

## Inputs

The module subscribes to the following Slips channels:

- `new_ssh`
- `new_software`
- `new_notice`
- `tw_closed`

These channels are populated from Zeek logs:

- `ssh.log`
- `software.log`
- `notice.log`

## What It Detects

The module tracks repeated SSH activity from the same source IP to the same destination IP and destination port inside the same time window.

It uses the following inputs:

- `ssh.log` to count repeated SSH sessions and authentication attempts
- `software.log` to extract the `SSH::CLIENT` banner and identify likely automation libraries such as `libssh`, `libssh2`, `paramiko`, `hydra`, `medusa`, or `ncrack`
- `notice.log` to consume Zeek `SSH::Password_Guessing` confirmations

## Detection Logic

### Counting Attempts

For each SSH flow, the module first checks the Zeek SSH authentication outcome:

- If `auth_success` is `true` or `T`, the flow is ignored for `brute_force_detector`.
- If `auth_attempts` is greater than `0`, that value is added to the bruteforce campaign counter.
- If `auth_attempts` is `0` or missing, but the SSH session is not marked successful, the module counts the session as one suspected password attempt.

The last rule is important for datasets where Zeek records repeated SSH handshakes without recording explicit authentication attempts, such as the `malicious-ssh-bruteforce.pcap` sample.

### Threshold and Reporting

The default SSH brute force detector threshold is `9` attempts.

After the threshold is reached, the module does not alert on every new attempt. Instead, it uses sparse bucketed reporting so alerts become less frequent over time but never completely stop. With the default threshold, the alert points are:

- 9
- 10
- 12
- 16
- 24
- 40
- ...

### Confidence

The evidence threat level is `medium`.

Confidence grows with the number of attempted passwords:

- first brute force detector evidence starts at the configured threshold
- full confidence is reached at `30` attempts
- suspicious SSH client banners add a small confidence bonus
- a Zeek `SSH::Password_Guessing` notice acts as confirmation and promotes confidence using Zeek's confirmed connection count

## Evidence Produced

The module emits `PASSWORD_GUESSING` evidence with:

- source attacker IP
- destination victim IP when available
- TCP destination port
- time window
- accumulated UIDs
- threat level `medium`
- confidence based on the number of attempts and confirmation data

Example description:

```text
SSH brute force detector from 147.32.80.40 to 147.32.80.37 on SSH 902/tcp. Attempts observed: 24. Client banner: libssh libssh2_1.11.0 from software.log. Confidence: 0.89. by Slips
```

## Zeek Confirmation

If Zeek raises `SSH::Password_Guessing` in `notice.log`, the module:

- emits an evidence immediately based on the notice
- stores the notice as confirmation for later `brute_force_detector` evidence
- uses the confirmed connection count from the Zeek notice to increase confidence

If Zeek does not generate `notice.log` for SSH password guessing, the module still detects `brute_force_detector` events from `ssh.log` and `software.log`.

## Configuration

The module currently exposes:

```yaml
brute_force_detector:
  ssh_attempt_threshold: 9
```

This value is read from `config/slips.yaml`.

## Relationship With Flow Alerts

SSH brute force detector is now handled by the `brute_force_detector` module.

The `flow_alerts` module still handles:

- successful SSH detections
- Zeek port-scan notices
- certificate alerts
- DNS and connection heuristics
- SMTP bruteforce and the rest of the single-flow detections

It no longer owns SSH password guessing detection.
