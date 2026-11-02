# Contributing

All contributions are welcomed, thank you for taking the time to contribute to this project!
These are a set of guidelines for contributing to the development of Slips [1].

## How can you contribute?

* Run Slips and report bugs and needed features, and suggest ideas
* Pull requests with a solved GitHub issue and new feature
* Pull request with a new detection module.

## Persistent Git Branches

The following git branches in the Slips repository are permanent:

- `master`: contains the stable version of Slips, with new versions at least once a month.
- `develop`: contains the latest unstable version of Slips and also its latest features. All new features should be based on this branch.

## Naming Git branches for Pull Requests

To keep the Git history clean and facilitate the revision of contributions we
ask all branches to follow concise namings. These are the branch-naming patterns
to follow when contributing to Slips:

- author-bugfix-:        pull request branch, contains one bugfix,
- author-docs-:          pull request branch, contains documentation work,
- author-enhance-:       pull request branch, contains one enhancement (not a new feature, but improvement nonetheless)
- author-feature-:       pull request branch, contains a new feature,
- author-refactor-:      pull request branch, contains code refactoring,

## What branch should you base your contribution to Slips?

As a general rule, base your contributions to the `develop` branch.

## Creating a pull request

Commits:
- Commits should follow the KISS principle: do one thing, and do it well (keep it simple, stupid).
- Commit messages should be easily readable, imperative style ("Fix memory leak in...", not "FixES mem...")

Pull Requests:
- If you have developed multiple features and/or bugfixes, create separate
    branches for each one of them, and request merges for each branch;
- Each PR to develop will trigger the develop Github checks, these checks will run Slips unit tests and integration tests locally in a ubuntu VM and in docker to make sure the branch is ready to merge.
- PRs won't be merged unless the checks pass.
- The cleaner you code/change/changeset is, the faster it will be merged.

## Beginner tips on how to create a PR in Slips

Here's a very simple beginner-level steps on how to create your PR in Slips

1. Fork the Slips repo
2. Clone the forked repo
3. In your clone, checkout origin/develop: ```git checkout origin develop```
4. Install slips pre-commit hooks ```pre-commit install```
5. Generate a baseline for detecting secrets before they're committed ```detect-secrets scan --exclude-files ".*dataset/.*|(?x)(^config/local_ti_files/own_malicious_JA3.csv$|.*test.*|slips.yaml|.*\.md$)" > .secrets.baseline```
6. Create your own branch off develop using your name and the feature name:  ```git checkout -b <yourname>_<feature_name> develop```
7. Change the code, add the feature or fix the bug, etc. then commit with a descriptive msg ```git commit -m "descriptive msg here" ```
8. Test your code: this is a very important step. you shouldn't open a PR with code that is not working: ```./tests/run_all_tests.sh```
9. If some tests didn't pass, it means you need to fix something in your branch.
10. Push to your own repo: ```git push -u origin <yourname>_<feature_name>```
11. Open a PR in Slips, remember to set the base branch as develop.
12. List your changes in the PR description

## How to test the auto update functionality

To test Slips auto update using the `testing` channel, follow these steps:

1. Create a new temporary branch from the branch you want to test, for example `origin/yourname-autoupdate-test`.
2. Edit [update.json] in your new branch and update the `testing` channel entry:
   - increase the `version` value so this branch appears newer than the version currently available
   - keep `"backwards_compatible": true`
   - keep `"has_new_dependencies": false`
   - set the testing branch entry to your new branch name e.g `origin/yourname-autoupdate-test`
3. Commit the `update.json` change in that temporary branch and push the branch to your remote.
4. Check out your original old branch again. Before continuing, make sure there are no merge conflicts and no modified Slips files in this branch.
5. Create a copy of [config/slips.yaml](config/slips.yaml) .
6. In your copied config file, enable auto update and configure the testing channel:

   ```yaml
   update:
     auto_update_slips: true
     channel_to_update_slips_from: testing
     testing_branch_to_update_slips_from: origin/<yourname-autoupdate-test>
   ```

7. Run Slips on an interface and point it to your copied config file using `-c`, for example:

   ```bash
   ./slips.py -i <interface_name> -c config/<your_test_config>.yaml
   ```

8. While Slips is running, it should detect the higher version in the `testing` channel and auto update to the branch you pushed in step 3.


## Rejected PRs

We will not review PRs that have the following:

* Code that's not tested. a screenshot of the passed tests is required for each PR.
* PRs without steps to reproduce your proposed changes.
* Asking for a step by step guide on how to solve the problem. It is ok to ask us clarifications after putting some effort into reading the code and the docs. but asking how exactly should i do X shows that you didn't look at the code


Some IDEs like [PyCharm](https://www.jetbrains.com/help/pycharm/work-with-github-pull-requests.html) and [vscode](https://levelup.gitconnected.com/how-to-create-a-pull-request-on-github-using-vs-code-f03db28308c4) have the option
to open a PR from within the IDE.

That's it, now you have a ready-to-merge PR!

***
[1] These contributions guidelines are inspired by the project [Snoopy](https://raw.githubusercontent.com/a2o/snoopy/master/.github/CONTRIBUTING.md)﻿

For frequently asked questions regarding development, architecture, database design, and testing, please see our [FAQ](FAQ.md).

## Global P2P - Fides contribution notes

Variables used in the trust evaluation and its accompanied processes, such as database-backup in persistent
SQLite storage and memory persistent
Redis database of Slips, are strings, integers and floats grouped into custom dataclasses. Aforementioned data classes can
be found in modules/fides/model. The reader may find that all of the floating variables are in the interval <-1; 1>
and some of them are between <0; 1>, please refer to the modules/fides/model directory.

The Fides Module is designed to cooperate with a global-peer-to-peer module. The communication is done using Slips' Redis
channel, for more information please refer to communication and messages sections above.

An example of a message answering Fides-Module's opinion request follows.
```
import redis

# connect to redis database 0
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

message = '''
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

# publish the message to the "network2fides" channel
channel = "network2fides"
redis_client.publish(channel, message)

print(f"Message published to channel '{channel}'.")
```

For more information about message handling, please also refer to modules/fides/messaging/message_handler.py
and to modules/fides/messaging/dacite/core.py for message parsing.


### **Communication**
The module uses Slips' Redis to receive and send messages related to trust intelligence,
evaluation of trust in peers and alert message dispatch.

**Used Channels**
modules/fides/messaging/message_handler.py
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


Implementations of Fides_Module-network-communication can be found in ```modules/fides/messaging/network_bridge.py```.
