# Penetration Test Fixes

## Table of Contents
- [Overview](#overview)
- [Scope of the audit](#scope-of-the-audit)
- [TLDR; findings and their status](#tldr-findings-and-their-status)
- [Fixed findings](#fixed-findings)
  * [SLP-002: Docker compose missing privilege restrictions](#slp-002-docker-compose-missing-privilege-restrictions)
  * [SLP-003: Unsafe variable interpolation in GitHub Actions shell steps](#slp-003-unsafe-variable-interpolation-in-github-actions-shell-steps)
  * [SLP-004: TLS certificate verification is disabled](#slp-004-tls-certificate-verification-is-disabled)
  * [SLP-005: Multiple python dependency vulnerabilities](#slp-005-multiple-python-dependency-vulnerabilities)
  * [SLP-006: Redis instance lacks authentication](#slp-006-redis-instance-lacks-authentication)
  * [SLP-007: Pickle deserialization in the ML module](#slp-007-pickle-deserialization-in-the-ml-module)
  * [SLP-008: A p2p4slips private key is stored in a world-readable file](#slp-008-a-p2p4slips-private-key-is-stored-in-a-world-readable-file)
  * [SLP-011: FileShare path traversal via Redis announcement](#slp-011-fileshare-path-traversal-via-redis-announcement)
  * [SLP-012: Downloaded files in Iris are world readable](#slp-012-downloaded-files-in-iris-are-world-readable)
  * [SLP-013: Race condition in Iris Redis callback waitgroup](#slp-013-race-condition-in-iris-redis-callback-waitgroup)
  * [SLP-014: Threat intelligence in Iris unencrypted](#slp-014-threat-intelligence-in-iris-unencrypted)
  * [SLP-015: GitHub Actions use mutable version tags](#slp-015-github-actions-use-mutable-version-tags)
  * [SLP-016: Dated Go and libp2p versions in p2p4slips](#slp-016-dated-go-and-libp2p-versions-in-p2p4slips)
  * [Bonus: Iris authentication bypass on node id and public key mismatch](#bonus-iris-authentication-bypass-on-node-id-and-public-key-mismatch)
- [Unresolved findings and why](#unresolved-findings-and-why)
  * [SLP-001: Docker containers execute as superuser](#slp-001-docker-containers-execute-as-superuser)
  * [SLP-009: Blame P2P message manipulation can block arbitrary legitimate hosts](#slp-009-blame-p2p-message-manipulation-can-block-arbitrary-legitimate-hosts)
  * [SLP-010: Fides algorithm is prone to trust inflation](#slp-010-fides-algorithm-is-prone-to-trust-inflation)
- [How AI was used here](#how-ai-was-used-here)
- [PR and related issues](#pr-and-related-issues)

## Overview

[Radically Open Security](https://www.radicallyopensecurity.com/) did a crystal-box penetration test of Slips.
They had full access to the Python and Go code.
They found 4 High, 3 Moderate and 9 Low severity issues (16 in total, final report v0.2, September 9, 2026).
This report documents what we fixed, what we didn't fix, and why.

All the fixes live in one PR (see [PR and related issues](#pr-and-related-issues)) plus the `iris` and `p2p4slips` submodules.
This is the second security review of Slips Immune. The first one, done with Trivy and Bearer, is documented [here](https://stratospherelinuxips.readthedocs.io/en/develop/immune/security_audit.html).

## Scope of the audit

In scope:

- Slips core code, detection modules, and the web interface
- `p2p4slips`
- `Iris`
- Docker files and docker compose
- GitHub Actions workflows
- Python and Go dependencies

## TLDR; findings and their status

| ID | Severity | Finding | Status | Notes |
|----|----------|---------|--------|-------|
| SLP-001 | Low | Slips runs as root inside docker | Not fixed | [Slips needs root for blocking, ARP poisoning and packet capture](#slp-001-docker-containers-execute-as-superuser) |
| SLP-002 | Low | Docker compose lets the container gain extra privileges | Partially fixed | [No-new-privileges added, read-only filesystem skipped since it breaks self-update and the p2p rebuild](#slp-002-docker-compose-missing-privilege-restrictions) |
| SLP-003 | Low | CI scripts trusted their input values | Fixed |  |
| SLP-004 | Moderate | Slips didn't check HTTPS certificates when downloading feeds and calling RiskIQ | Fixed |  |
| SLP-005 | Moderate | Old python libraries with known vulnerabilities | Fixed |  |
| SLP-006 | High | Redis had no password | Fixed |  |
| SLP-007 | Low | A tampered ML model file could run code as Slips | Fixed |  |
| SLP-008 | High | The P2P private key was readable by every user on the host | Fixed |  |
| SLP-009 | High | One fake peer could get Slips to block any IP | Not applicable | [Nothing in Slips sends blame reports yet, the receiving side was hardened anyway](#slp-009-blame-p2p-message-manipulation-can-block-arbitrary-legitimate-hosts) |
| SLP-010 | Moderate | A peer can inflate its own trust in Fides | Not fixed | [Needs a redesign of the trust model](#slp-010-fides-algorithm-is-prone-to-trust-inflation) |
| SLP-011 | High | Iris could be tricked into sharing any file on the host | Fixed |  |
| SLP-012 | Low | Files downloaded by Iris were readable by every user on the host | Fixed |  |
| SLP-013 | Low | Iris could drop P2P messages during shutdown | Fixed |  |
| SLP-014 | Low | Iris sent threat intelligence in plaintext | Fixed |  |
| SLP-015 | Low | CI actions could be swapped out from under us | Fixed |  |
| SLP-016 | Low | The pigeon was built with 5-year-old Go and libp2p | Fixed |  |
| Bonus | - | A peer could pretend to be another peer in Iris | Fixed |  |

Summary: 13 of the 16 findings fixed, 1 partially fixed, 1 not applicable and 2 not fixed by design. Plus one bonus fix.

## Fixed findings

### SLP-002: Docker compose missing privilege restrictions

**Problem**

- Our docker compose file gives the container host networking (`network_mode: host`) and the network-admin capability (`cap_add: NET_ADMIN`), but doesn't stop a process inside it from gaining more privileges.

**Impact**

- In combination with SLP-001 (containers execute as superuser), a compromised process inside the container has a path to privilege escalation and host-level network manipulation.
- This finding does not constitute a standalone attack vector; exploitation presupposes an existing code-execution foothold in the container.

**What we did**

- Added the no-new-privileges option (`security_opt: no-new-privileges:true`). Slips already runs as root inside the container, so it loses nothing.

**What we did not do, by design**

- A read-only filesystem (`read_only: true`). Slips writes to its own directory at runtime: the [self-update](https://stratospherelinuxips.readthedocs.io/en/develop/immune/updating_slips.html) functionality pulls the new version into the repo and rebuilds the p2p binary, and the output dir, zeek logs and `permanent/` all live under the repo. Making it read-only breaks all of that.
- Dropping all capabilities (`cap_drop: ALL`). Blocking, packet capture and ARP poisoning each need some of them, and we haven't tested the minimal set yet.

### SLP-003: Unsafe variable interpolation in GitHub Actions shell steps

**Problem**

- Two GitHub Actions workflows pasted their input values straight into shell scripts. A crafted value could have become part of the script.

**Impact**

- Currently there is no confirmed path for external (fork PR) exploitation under the current workflow configuration.
- If a future change to a calling workflow derives `test_dir`, `output_prefix`, or `image_tag_prefix` from PR-controlled data (for example a branch name or PR title), this issue could become directly exploitable.

**Fix**

- The inputs are now handed to the scripts as environment variables, so a crafted value is just a string.

### SLP-004: TLS certificate verification is disabled

**Problem**

- The feeds update manager and the RiskIQ module skipped certificate checks on their HTTPS requests.

**Impact**

- An attacker can intercept RiskIQ credentials, and tamper with the contents of the threat intelligence feed.

**Fix**

- Certificate checks are back on in both.

### SLP-005: Multiple python dependency vulnerabilities

**Problem**

- GitPython, Keras and scapy were pinned to versions with public vulnerabilities.
- Many other libraries were not pinned at all, so Slips could pull in whatever version happened to be current, including vulnerable ones.

**Impact**

- Various paths to code execution, data exfiltration and file system manipulation are permitted via more than one of these issues.

**Fix**

- Upgraded the three libraries and pinned every library to an exact version.
- Added `pip-audit` as a pre-commit hook, so a new vulnerable version can't be committed unnoticed. Dependabot keeps opening PRs for new advisories as before.
- The new versions need a newer Python, so Slips moved to Python 3.12.3 and Ubuntu 24.04 in the docker image, `install.sh` and CI.

### SLP-006: Redis instance lacks authentication

**Problem**

- Every Redis database Slips starts accepted connections without a password.

**Impact**

- A rogue process on the host, or a dockerized process that manages to escape the container, will be able to tamper with a multitude of aspects related to Slips functionality. These can relate to the blocking of other hosts, the correctness of detected threats, and the reporting given to other nodes.
- The auditors call this the root cause of a whole cluster of findings (SLP-009 and SLP-011 both need Redis access).

**Fix**

- Slips now generates a random password the first time it runs and stores it in `permanent/redis_auth.conf`, readable only by the user running Slips. `install.sh` does the same during installation.
- Every Redis database Slips starts requires it, and every client (Slips, the web interface, the pigeon and Iris) reads it from that file.
- The password is kept across runs, because the shared cache database on port 6379 outlives any single run.
- Redis servers started before this change have no password. Slips retries without one, so existing setups keep working.
- Docker compose now mounts `permanent/` so the password survives recreating the container.
- The same password now protects the web interface, which had no login at all before.


### SLP-007: Pickle deserialization in the ML module

**Problem**

- The ML modules loaded their trained models with Python's pickle, which runs whatever the file tells it to.

**Impact**

- An attacker with write access to the model files can inject a malicious pickle payload that would execute commands on behalf of the Slips user when deserialized.

**Fix**

- Models are now loaded through a restricted loader that only allows the pieces the ML libraries need. Anything else is refused, and the module starts with a fresh model instead.
- We kept the pickle format with an allowlist instead of switching to another format, so the existing trained models keep loading unchanged.

### SLP-008: A p2p4slips private key is stored in a world-readable file

**Problem**

- The pigeon saved the private key that identifies this Slips node on the P2P network with permissions that let every user on the host read it.

**Impact**

- An attacker with read access to the filesystem will be able to read the saved private key file, enabling them to impersonate that node to other P2P Slips instances.

**Fix**

- The key is now readable by the Slips user only.

### SLP-011: FileShare path traversal via Redis announcement

**Problem**

- Iris shares files with the network based on announcements it receives over Redis, and it opened whatever path the announcement named.

**Impact**

- An attacker with Redis access can read any file the Iris process has permission to access, and exfiltrate sensitive files from the host system.
- In addition to Redis lacking authentication (SLP-006), an attacker can publish a file announcement with a path like `../../../../etc/passwd`, and Iris will open and read that file.

**Fix**

- Iris only shares files that live inside its download directory. Anything else is rejected.

### SLP-012: Downloaded files in Iris are world readable

**Problem**

- Files received from peers were saved to `/tmp` with permissions that let every user on the host read them.

**Impact**

- Any user on the system can read downloaded files, which may contain sensitive threat intelligence data.

**Fix**

- Downloads go to a private directory (`/tmp/iris-downloads`) and both the directory and the files are readable by the Slips user only.

### SLP-013: Race condition in Iris Redis callback waitgroup

**Problem**

- A timing bug in how Iris waited for its Redis message handlers meant it could stop listening while messages were still being processed.

**Impact**

- The subscriber goroutine may exit while callbacks are still processing messages, and threat intelligence or alert messages may not be fully processed before the connection closes.

**Fix**

- Fixed the ordering so Iris waits for every handler to finish.

### SLP-014: Threat intelligence in Iris unencrypted

**Problem**

- Answers to intelligence requests travelled through the P2P network unencrypted. The code had a TODO saying they should be encrypted for the requester.

**Impact**

- Intelligence responses containing threat scores, IP assessments, and detection data are visible to all peers.

**Fix**

- Answers are now encrypted with the requester's public key, so only the peer that asked can read them.

### SLP-015: GitHub Actions use mutable version tags

**Problem**

- Our GitHub Actions workflows referenced third-party actions by version tag, like `@v7`. A tag is a moving pointer: whoever controls the action can repoint it.

**Impact**

- If an action's owner account is compromised, or a maintainer maliciously repoints a tag, the altered action code executes in CI with access to workflow secrets (registry credentials, signing keys) and can inject backdoors into published images.
- The auditors have not observed this happening; this is a risk-reduction, defense-in-depth measure.

**Fix**

- Every action is pinned to an exact commit, with the version kept in a comment so upgrades stay readable.
- A new CI check fails if a moving tag sneaks back in.

### SLP-016: Dated Go and libp2p versions in p2p4slips

**Problem**

- The pigeon (`p2p4slips`) was stuck on Go 1.16 and a 2021 release of libp2p, plus a deprecated libp2p module.

**Impact**

- Security fixes and hardening shipped in go-libp2p and the Go toolchain since 2021 are not applied to p2p4slips.
- The auditors did not confirm any specific unpatched CVE in these exact versions; the risk is in the accumulated, untracked delta between v0.13.0 and current releases.

**Fix**

- Upgraded to a current Go and libp2p and dropped the deprecated module. Docker and `install.sh` install the new Go for you.
- A new CI workflow scans the pigeon for vulnerable Go dependencies and insecure code on every push and PR that touches it.

**Side effect**: the peer discovery protocol changed with the upgrade. Pigeons older than 1.1.24 can't discover the new ones. All peers in a network must be upgraded together. Documented in `docs/P2P.md`.

### Bonus: Iris authentication bypass on node id and public key mismatch

Not in the audit. We found it while working on the Iris fixes above.

**Problem**

- Iris accepted a message as authentic even when the sender id in it didn't match the key that signed it.

**Impact**

- A peer could sign a message with its own key while claiming to be a different, trusted node.

**Fix**

- Such messages are rejected now. Regression tests added and the Iris binary rebuilt.

## Unresolved findings and why

### SLP-001: Docker containers execute as superuser

**Problem**

- None of our Dockerfiles switch to a non-root user (no `USER` directive), so Slips runs as root in the container.

**Impact**

- An attacker managing to find an exploit that executes code in the context of the containerized process will gain superuser permissions.
- This is mitigated by the container's namespacing, but that foothold can enable further attacks.

**Why it's not fixed, by design**

- Slips needs root inside the container:
  - iptables for [blocking](https://stratospherelinuxips.readthedocs.io/en/develop/immune/blocking_in_slips.html)
  - raw sockets for [ARP poisoning](https://stratospherelinuxips.readthedocs.io/en/develop/immune/arp_poisoning.html) and for Zeek to capture on the interface
  - the self-update pulls into the repo and rebuilds the pigeon
- Dropping to a non-root user would break all of that unless every capability is handed out one by one, the same open question as in SLP-002.
- The auditors' first suggestion, user namespace remapping (`userns-remap`), is a setting of the docker daemon on the host, not something we can ship in a Dockerfile. Users who want it can enable it on their daemon.

### SLP-009: Blame P2P message manipulation can block arbitrary legitimate hosts

**Problem**

- A "blame" message from a local P2P peer (a peer asking us to block an IP) went straight to the blocking module. No trust check, no second opinion, no Fides.

**Impact**

- An attacker on the LAN can spawn a fake libp2p peer advertised over mDNS. The victim Slips discovers and connects to it (no whitelist), the hello handshake completes with trust 1.0, and the attacker sends a single blame message for an IP, say `10.0.0.1`. That leads to `10.0.0.1` being blocked via iptables.
- A proof of concept that automates the process is in the appendix of the audit report.
- The auditors' recommendation: unify the treatment of blame messages through the Fides module.

**Why this is not applicable right now**

- Nothing in Slips generates a blame report yet. The sending side of the blame feature is not implemented, see [#2113](https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2113).
- So there is no blame path to unify with Fides today. The recommendation only becomes applicable once Slips starts sending blames, and that's when we'll route them through Fides.

**What we did anyway, on the receiving side**

- A blame from a peer no longer goes straight to the blocking module. It's stored like any other report, so it counts towards the network's opinion of that IP.
- Slips then weighs its own opinion of the IP against the network's trust-weighted opinion and only blocks when the two together cross a threshold. Both the weight and the threshold are configurable in `modules/p2p_trust/p2p_trust.py`.
- One peer's say-so is not enough anymore. This follows the original Dovecot / Omega-Trust design from Hollmannova's 2020 thesis, where a single peer's report can never trigger a block on its own.
- A unit test covers exactly the auditors' proof of concept.

Related: [#1935](https://github.com/stratosphereips/StratosphereLinuxIPS/issues/1935) (the blame message should carry the timewindow to block in).

### SLP-010: Fides algorithm is prone to trust inflation

**Problem**

- In Fides, every interaction with a peer (an alert, a recommendation, an intelligence request) raises that peer's trust a little, with no limit on how often.

**Impact**

- An attacker able to inject mDNS messages (p2p4slips or Iris) sends 50 intelligence requests and their trust increases from 0.5 to about 0.7. They send 20 alerts and it increases to about 0.8, so their alerts now have a 0.8 confidence multiplier.
- Their malicious threat intelligence is weighted 80% in aggregation. With other compromised or attacker peers, they can dominate the aggregated opinion.

**Why it's not fixed**

- This is a design issue in the trust model, not a bug in one function. The auditors put the possible fixes under "Future Work", not under a recommendation, because each one is a redesign:
  - only let peers adjust our confidence on IPs we already have local evidence for
  - grade peers by how much they agree with our local evidence
  - a Sybil-proof way of combining opinions instead of the current additive one
  - an admin-seeded trust graph, where unconnected peers get rate-limited
  - or simply a shared secret / encrypted tunnel (wireguard) between collaborating peers
- Each option changes what the P2P feature can do and needs experiments and feedback from Slips users before we pick one. That is a separate task, not something to patch in a security fix PR.




## How AI was used here

- The following were written by AI, then reviewed and tested manually by a human:
  - upgrading and pinning the python dependencies
  - migrating `p2p4slips` to go-libp2p v0.49
  - encrypting the Iris intelligence responses
  - the Iris authentication bypass fix and its tests
  - the web login page design
- Helped with mapping the audit findings to the commits and to polish this report.
- Tests and tmp scripts used for testing.



## PR and related issues

- PR: https://github.com/stratosphereips/StratosphereLinuxIPS/pull/2117
- Nothing in Slips sends blame reports yet: https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2113
- Redis password file ownership in docker: https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2114
- Blame messages should carry the timewindow: https://github.com/stratosphereips/StratosphereLinuxIPS/issues/1935
- Previous security audit (Trivy and Bearer): https://stratospherelinuxips.readthedocs.io/en/develop/immune/security_audit.html
