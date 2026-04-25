# Updating Slips

## Table of Contents

- [Overview](#overview)
- [How Auto-Update Works](#how-auto-update-works)
  * [New version checks](#new-version-checks)
  * [Updating Logic](#updating-logic)
    + [Redis handling](#redis-handling)
    + [Zeek log handling](#zeek-log-handling)
  * [Draining and Shutdown of the old Slips](#draining-and-shutdown-of-the-old-slips)
- [How to use it](#how-to-use-it)
- [Manual update](#manual-update)
  * [Running Slips in Docker](#running-slips-in-docker)
  * [Running Slips natively](#running-slips-natively)
- [PR](#pr)

## Overview

Slips auto update functionality was designed to allow a running instance of
Slips to update itself with no downtime during the transition between versions.

Updates usually consist of:

A full application stop -> update -> restart sequence.
rather than simple restart.

That sequence would lead to downtime and temporarily missing of flows during the upgrade.

The implemented update mechanism was designed around "handover" instead of "restarts".
Where slips checks periodically for new compatible versions, pulls the update,
starts the new version, and orchestrates a controlled handover from the old
version to the new one.


## How Auto-Update Works

```text
Old Slips running
        ↓
Check for compatible update
        ↓
git pull origin master
        ↓
Start new Slips with -u
        ↓
New Slips restores state and starts processing
        ↓
Old Slips drains
        ↓
Old Slips graceful shutdown
        ↓
New Slips continues normally
```


### New version checks

Slips checks for updates once per day.

This is handled by the UpdateManager, which:

- checks whether auto-update is enabled in the config file
- checks whether a new version exists
- checks compatibility before attempting update.

Compatibility is determined using an `update.json` file hosted with the
deployed version.

This file includes metadata about the new version such as:

- latest version,
- backwards compatibility,
- whether new dependencies are needed.


The compatibility parser was added so we avoid updating to incompatible new releases.


**The update is aborted if:**

- `auto_update_slips` is disabled in slips config.
- Slips is running on offline input instead of interface
- no newer version exists
- update is incompatible according to `update.json`
- local uncommitted changes are detected during `git pull`
- startup of the new version fails


### Updating Logic


When designing this, our main goal was zero downtime and zero missed flows during the update. This has the cost of maybe reading a very few duplicate flows, and this was done by
Starting the new Slips before stopping the old one.

How this is done is:
- The old version starts the new one with the undocumented `-u` flag.
- The `-u` flag tells the new Slips instance that: 1. this is not a fresh run and 2. Slips should continue existing analysis and handle database migrations.
- do not overwrite: output dir, log files, and previous analysis artifacts/metrics.


#### Redis handling

The new Slips does not flush Redis on startup.

Instead, it appends to the existing Redis state as if the old process never
stopped.

Without this, ongoing detections, states, and evidence state would be lost.


Now what happen when in the very few seconds during handover, a msg from the old slips' pub/sub is published, and the new updated slips receives it?

To avoid this we added Pub/Sub message versioning, now each pub/sub message includes
the Slips version and consumers ignore messages that belong to the updated version and only read msgs intended
for them.


#### Zeek log handling

The new Slips starts a new zeek process that uses new zeek log files in ```output/zeek_files/slips_vx.y.z```.
This ensures that the old zeek logs are not modified, re-read or overwritten during the update

This was a major simplification because sharing Zeek logs between versions
introduced complexity and race conditions.


### Draining and Shutdown of the old Slips

Once the updated Slips is confirmed to be running:

the old Slips begins draining.

Draining means:

- stop ingesting new flows.
- finish processing pending flows.


PS: the new updated slips version starts reading flows before the old one starts draining to ensure 0 downtime.

## How to use it

enable ```auto_update_slips``` in ```config/slips.yaml``` and run slips on your interface.

now whenever a new version of Slips is available, it will update itself and the new slips will use the same CLI as the old one.

## Manual update

If you do not use `auto_update_slips`, update Slips manually using the method
that matches your installation.

### Running Slips in Docker

If you run Slips from the published Docker image, pull the new image and start a
new container from it:

```bash
docker pull stratosphereips/slips:latest
docker run -it --rm --net=host --cap-add=NET_ADMIN --name slips stratosphereips/slips:latest
```


If you build Slips locally from `docker/Dockerfile`, first update the
repository, then rebuild the image so the new code and dependencies are available
into the container:

```bash
git pull --recurse-submodules && git submodule update --init --recursive
docker build --target amd --no-cache -t slips -f docker/Dockerfile .
```

If Docker cannot access the network during the build, use:

```bash
docker build --target amd --network=host --no-cache -t slips -f docker/Dockerfile .
```

Then start a new container from the rebuilt image.

### Running Slips natively

For native installations, first update the repository and all submodules:

```bash
git pull --recurse-submodules && git submodule update --init --recursive
```

Then run the installer script:

```bash
sudo ./install/install.sh
```

Re-running `install.sh` is important because a new Slips version may require new
apt packages, pip packages or rebuilt components such as Redis and `p2p4slips`.

After the update finishes, start Slips again normally. As with a fresh install,
the first run may spend some time updating threat intelligence files in the
background.

## PR

https://github.com/stratosphereips/StratosphereLinuxIPS/pull/1915
