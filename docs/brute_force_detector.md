# Brute force detector Module

The `brute_force_detector` module detects repeated failed SSH authentication using Zeek SSH metadata and password-guessing notices. Client software banners add context after failure evidence has been observed.

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

- `ssh.log` to count authentication attempts in explicitly failed SSH sessions
- `software.log` to extract the `SSH::CLIENT` banner and identify likely automation libraries such as `libssh`, `libssh2`, `paramiko`, `hydra`, `medusa`, or `ncrack`
- `notice.log` to consume Zeek `SSH::Password_Guessing` confirmations

## Detection Logic

### Counting Attempts

For each SSH flow, the module first checks the Zeek SSH authentication outcome:

- If `auth_success` is `true` or `T`, the flow is ignored. JSON boolean `true` is also supported.
- If `auth_success` is absent, empty or otherwise unknown, the flow is ignored even when `auth_attempts` is positive. Repeated unknown sessions do not establish password guessing.
- Only `auth_success=false` or `F`, including JSON boolean `false`, contributes to the counter. Positive `auth_attempts` values are added; an explicitly failed session without a usable count contributes one failed session.

[Zeek defines an unset authentication result as unknown](https://docs.zeek.org/en/v8.1.0/scripts/base/protocols/ssh/main.zeek.html#type-SSH::Info). Its observed attempts are not necessarily failures. Encrypted SSH sessions, including successful public-key administration, can have an unknown result and zero observed attempts. Neither session frequency nor an OpenSSH or automation-library banner turns those records into failed logins.

Unknown sessions remain available as SSH flows. Captures without failure outcomes require a separate Zeek `SSH::Password_Guessing` notice to produce this finding. Successful sessions do not erase earlier observed failures from a genuine guessing campaign.

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

Confidence grows with authentication attempts in failed sessions:

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
SSH password guessing from 147.32.80.40 to 147.32.80.37 on SSH 902/tcp. Authentication attempts in failed sessions: 24. Client banner: libssh libssh2_1.11.0 from software.log. Confidence: 0.89. by Slips
```

## Zeek Confirmation

If Zeek raises `SSH::Password_Guessing` in `notice.log`, the module:

- emits an evidence immediately based on the notice
- stores the notice as confirmation for later `brute_force_detector` evidence
- uses the confirmed connection count from the Zeek notice to increase confidence

Without a Zeek notice, the module still detects repeated explicitly failed logins in `ssh.log`. `software.log` alone cannot create a campaign.

## Configuration

The module currently exposes:

```yaml
brute_force_detector:
  ssh_attempt_threshold: 9
```

This value is read from `config/slips.yaml`.

Restart Slips to load changed detector code. Existing saved evidence is not recalculated automatically; an old finding based on unknown sessions can be reviewed as a false positive without whitelisting the hosts or disabling SSH attack detection.

## Relationship With Flow Alerts

SSH brute force detector is now handled by the `brute_force_detector` module.

The `flow_alerts` module still handles:

- successful SSH detections
- Zeek port-scan notices
- certificate alerts
- DNS and connection heuristics
- SMTP bruteforce and the rest of the single-flow detections

It no longer owns SSH password guessing detection.
