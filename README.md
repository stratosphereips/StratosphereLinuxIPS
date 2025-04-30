<h1 align="center">
Slips v1.1.9
</h1>


[![License](https://img.shields.io/badge/license-GPLv2-blue)](./LICENSE)
[![GitHub version](https://img.shields.io/github/v/tag/stratosphereips/StratosphereLinuxIPS?label=version)](https://github.com/stratosphereips/StratosphereLinuxIPS)
![Python](https://img.shields.io/badge/python-3.8-blue)
![GitHub language count](https://img.shields.io/github/languages/count/stratosphereips/StratosphereLinuxIPS)
![GitHub repository size](https://img.shields.io/github/repo-size/stratosphereips/StratosphereLinuxIPS)
![Docker Image Size (tag)](https://img.shields.io/docker/image-size/stratosphereips/slips/latest?color=blue&label=docker%20image%20size)
![Docker Pulls](https://img.shields.io/docker/pulls/stratosphereips/slips)

[![GitHub issues](https://img.shields.io/github/issues/stratosphereips/StratosphereLinuxIPS.svg?color=green)](https://GitHub.com/stratosphereips/StratosphereLinuxIPS/issues/)
[![GitHub issues-closed](https://img.shields.io/github/issues-closed/stratosphereips/StratosphereLinuxIPS.svg?color=green)](https://GitHub.com/stratosphereips/StratosphereLinuxIPS/issues?q=is%3Aissue+is%3Aclosed)
[![GitHub open-pull-requests](https://img.shields.io/github/issues-pr-raw/stratosphereips/StratosphereLinuxIPS?color=green&label=open%20PRs)](https://github.com/stratosphereips/StratosphereLinuxIPS/pulls?q=is%3Aopen)
[![GitHub pull-requests closed](https://img.shields.io/github/issues-pr-closed-raw/stratosphereips/StratosphereLinuxIPS?color=green&label=closed%20PRs)](https://github.com/stratosphereips/StratosphereLinuxIPS/pulls?q=is%3Aclosed)
[![GitHub contributors](https://img.shields.io/github/contributors/stratosphereips/StratosphereLinuxIPS?color=orange)](https://GitHub.com/stratosphereips/StratosphereLinuxIPS/contributors/)
![GitHub forks](https://img.shields.io/github/forks/stratosphereips/StratosphereLinuxIPS?color=orange)
![GitHub Org's stars](https://img.shields.io/github/stars/stratosphereips/StratosphereLinuxIPS?color=orange)
[![GitHub watchers](https://img.shields.io/github/watchers/stratosphereips/StratosphereLinuxIPS?color=orange)](https://GitHub.com/stratosphereips/StratosphereLinuxIPS/watchers/)

[![License](https://img.shields.io/badge/Blog-Stratosphere-cyan)](https://www.stratosphereips.org/blog/tag/slips)
[![Discord](https://img.shields.io/discord/761894295376494603?label=&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/zu5HwMFy5C)
![Twitter Follow](https://img.shields.io/twitter/follow/StratosphereIPS?style=social)

<hr>


# Table of Contents

- [Introduction](#introduction)
- [Usage](#usage)
- [GUI](#graphical-user-interface)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Features](#features)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Credits](#credits)
- [Changelog](#changelog)
- [Roadmap](#roadmap)
- [Demos](#demos)
- [Funding](#funding)


# Slips: Behavioral Machine Learning-Based Intrusion Prevention System


Slips is a powerful endpoint behavioral intrusion prevention and detection system that uses machine learning to detect malicious behaviors in network traffic. Slips can work with network traffic in real-time, PCAP files, and network flows from popular tools like Suricata, Zeek/Bro, and Argus. Slips threat detection is based on a combination of machine learning models trained to detect malicious behaviors, 40+ threat intelligence feeds, and expert heuristics. Slips gathers evidence of malicious behavior and uses extensively trained thresholds to trigger alerts when enough evidence is accumulated.

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/slips.gif" width="850px" title="Slips in action.">

---


# Introduction
Slips is the first free software behavioral machine learning-based IDS/IPS for endpoints. It was created in 2012 by Sebastian Garcia at the Stratosphere Laboratory, AIC, FEE, Czech Technical University in Prague. The goal was to offer a local IDS/IPS that leverages machine learning to detect network attacks using behavioral analysis.


Slips is supported on Linux, MacOS, and windows dockers only. The blocking features of Slips are only supported on Linux

Slips is Python-based and relies on [Zeek network analysis framework](https://zeek.org/get-zeek/) for capturing live traffic and analyzing PCAPs. and relies on
Redis >= 7.0.4 for interprocess communication.

---

# Usage

The recommended way to use Slips is on Docker.

#### Linux and Windows hosts
```
docker run --rm -it -p 55000:55000  --cpu-shares "700" --memory="8g" --memory-swap="8g" --net=host --cap-add=NET_ADMIN --name slips stratosphereips/slips:latest
```

```
./slips.py -f dataset/test7-malicious.pcap -o output_dir
```

```
cat output_dir/alerts.log
```

#### Macos
In MacOS, do not use --net=host if you want to access the internal container's ports from the host.

```
docker run --rm -it -p 55000:55000 --platform linux/amd64 --cpu-shares "700" --memory="8g" --memory-swap="8g" --cap-add=NET_ADMIN --name slips stratosphereips/slips_macos_m1:latest
```

```
./slips.py -f dataset/test7-malicious.pcap -o output_dir
```

```
cat output_dir/alerts.log
```


[For more installation options](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installation)

[For a detailed explanation of Slips parameters](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#slips-parameters)

---


# Graphical User Interface

To check Slips output using a GUI you can use the web interface
or our command-line based interface Kalipso

##### Web interface

    ./webinterface.sh

Then navigate to ```http://localhost:55000/``` from your browser.

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/web_interface.png" width="850px">

For more info about the web interface, check the docs: https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#the-web-interface


##### Kalipso (CLI-Interface)

    ./kalipso.sh

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/kalipso.png" width="850px">


For more info about the Kalipso interface, check the docs: https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#kalipso

---


# Requirements

Slips requires Python 3.10.12 and at least 4 GBs of RAM to run smoothly.

---

# Installation


Slips can be run on different platforms, the easiest and most recommended way if you're a Linux user is to run Slips on Docker.

* [Docker](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#slips-in-docker)
  * Dockerhub (recommended)
    * [Linux and windows hosts](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#linux-and-windows-hosts)
    * [MacOS hosts](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#macos-hosts)
  * [Docker-compose](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#running-slips-using-docker-compose)
  * [Dockerfile](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#building-slips-from-the-dockerfile)
* Native
  * [Using install.sh](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#install-slips-using-shell-script)
  * [Manually](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-slips-manually)
* [on RPI (Beta)](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-slips-on-a-raspberry-pi)


---


# Configuration
Slips has a [config/slips.yaml](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/develop/config/slips.yaml) that contains user configurations for different modules and general execution.

* You can change the timewindow width by modifying the ```time_window_width``` parameter
* You can change the analysis direction to ```all```  if you want to see the attacks from and to your computer
* You can also specify whether to ```train``` or ```test``` the ML models

* You can enable [popup notifications](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#popup-notifications) of evidence, enable [blocking](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#slips-permissions), [plug in your own zeek script](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#plug-in-a-zeek-script) and more.


[More details about the config file options here]( https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#modifying-the-configuration-file)

---

# Features
Slips key features are:

* **Behavioral Intrusion Prevention**: Slips acts as a powerful system to prevent intrusions based on detecting malicious behaviors in network traffic using machine learning.
* **Modularity**: Slips is written in Python and is highly modular with different modules performing specific detections in the network traffic.
* **Targeted Attacks and Command & Control Detection**: It places a strong emphasis on identifying targeted attacks and command and control channels in network traffic.
* **Traffic Analysis Flexibility**: Slips can analyze network traffic in real-time, PCAP files, and network flows from popular tools like Suricata, Zeek/Bro, and Argus.
* **Threat Intelligence Updates**: Slips continuously updates threat intelligence files and databases, providing relevant detections as updates occur.
* **Integration with External Platforms**: Modules in Slips can look up IP addresses on external platforms such as VirusTotal and RiskIQ.
* **Graphical User Interface**: Slips provides a console graphical user interface (Kalipso) and a web interface for displaying detection with graphs and tables.
* **Peer-to-Peer (P2P) Module**: Slips includes a complex automatic system to find other peers in the network and share IoC data automatically in a balanced, trusted manner. The P2P module can be enabled as needed.
* **Docker Implementation**: Running Slips through Docker on Linux systems is simplified, allowing real-time traffic analysis.
* **Detailed Documentation**: Slips provides detailed documentation guiding users through usage instructions for efficient utilization of its features.
* **Federated learning** Using the feel_project submodule. for more information [check the docs](https://github.com/stratosphereips/feel_project/blob/main/docs/Federated_Learning.md)

---

# Contributing

We welcome contributions to improve the functionality and features of Slips.

Please read carefully the [contributing guidelines](https://stratospherelinuxips.readthedocs.io/en/develop/contributing.html) for contributing to the development of Slips

You can run Slips and report bugs, make feature requests, and suggest ideas, open a pull request with a solved GitHub issue and new feature, or open a pull request with a new detection module.

The instructions to create a new detection module along with a template [here](https://stratospherelinuxips.readthedocs.io/en/develop/create_new_module.html).

If you are a student, we encourage you to apply for the Google Summer of Code program that we participate in as a hosting organization.

Check [Slips in GSoC2023](https://github.com/stratosphereips/Google-Summer-of-Code-2023) for more information.


You can [join our conversations in Discord](https://discord.gg/zu5HwMFy5C) for questions and discussions.
We appreciate your contributions and thank you for helping to improve Slips!

---

# Documentation
[User documentation](https://stratospherelinuxips.readthedocs.io/en/develop/)

[Code docs](https://stratospherelinuxips.readthedocs.io/en/develop/code_documentation.html )

---

# Troubleshooting

If you can't listen to an interface without sudo, foe example when zeek is throwing the following error:
```bash
fatal error: problem with interface wlan0 (pcap_error: socket: Operation not permitted (pcap_activate))
```

you can adjust zeek capabilities using the following command

```
sudo setcap cap_net_raw,cap_net_admin=eip /<path-to-zeek-bin/zeek
```


---

You can [join our conversations in Discord](https://discord.gg/zu5HwMFy5C) for questions and discussions.

Or email us at
* sebastian.garcia@agents.fel.cvut.cz
* eldraco@gmail.com,
* alyaggomaa@gmail.com

---

# License

 [GNU General Public License](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/master/LICENCE)

---


# Credits

Founder: [Sebastian Garcia](https://github.com/eldraco), sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com.

Main authors: [Sebastian Garcia](https://github.com/eldraco), [Alya Gomaa](https://github.com/AlyaGomaa), [Kamila Babayeva](https://github.com/kamilababayeva)

Contributors:

* [Veronica Valeros](https://github.com/verovaleros)
* [Frantisek Strasak](https://github.com/frenky-strasak)
* [Dita Hollmannova](https://github.com/draliii)
* [Ondrej Lukas](https://github.com/ondrej-lukas)
* Elaheh Biglar Beigi
* [Martin Řepa](https://github.com/HappyStoic)
* [arkamar](https://github.com/arkamar)
* [Maria Rigaki](https://github.com/MariaRigaki)
* [Lukas Forst](https://github.com/LukasForst)
* [Daniel Yang](https://github.com/danieltherealyang)

---


# Changelog

https://github.com/stratosphereips/StratosphereLinuxIPS/blob/develop/CHANGELOG.md


---

# Demos
The following videos contain demos of Slips in action in various events:

- 2022 BlackHat Europe Arsenal, Slips: A Machine-Learning Based, Free-Software, Network Intrusion Prevention System [[web](https://www.blackhat.com/eu-22/arsenal/schedule/index.html#slips-free-software-machine-learning-tool-for-network-intrusion-prevention-system-29599)]
- 2022 BlackHat USA Arsenal, Slips: A Machine-Learning Based, Free-Software, Network Intrusion Prevention System [[web](https://www.blackhat.com/us-22/arsenal/schedule/index.html#slips-free-software-machine-learning-tool-for-network-intrusion-prevention-system-26687)]
- 2021 BlackHat Europe Arsenal, Slips: A Machine-Learning Based, Free-Software, Network Intrusion Prevention System [[slides](https://mega.nz/file/EAIjWA5D#DoYhJknH1hpbqfS2ayVLwA7ewNT50jFQb7S3dVAKPko)] [[web](https://www.blackhat.com/eu-21/arsenal/schedule/#slips-a-machine-learning-based-free-software-network-intrusion-prevention-system-25116)]
- 2021 BlackHat USA Arsenal, Slips: A Machine-Learning Based, Free-Software, Network Intrusion Prevention System [[web](https://www.blackhat.com/us-21/arsenal/schedule/#slips-a-machine-learning-based-free-software-network-intrusion-prevention-system-24105)]
- 2021 BlackHat Asia Arsenal, Slips: A Machine-Learning Based, Free-Software, Network Intrusion Prevention System [[web](https://www.blackhat.com/asia-21/arsenal/schedule/#slips-a-machine-learning-based-free-software-network-intrusion-prevention-system-22576)]
- 2020 Hack In The Box CyberWeek, Android RATs Detection With A Machine Learning-Based Python IDS [[video](https://www.youtube.com/watch?v=wx0V3qWdmyk)]
- 2019 OpenAlt, Fantastic Attacks and How Kalipso can Find Them [[video](https://www.youtube.com/watch?v=p2FL2sECpS0&t=1s)]
- 2016 Ekoparty, Stratosphere IPS. The free machine learning malware detection [[video](https://www.youtube.com/watch?v=IazEdK8R4YI)]

---

# Funding
We are grateful for the generous support and funding provided by the following organizations:


- NlNet Foundation, https://nlnet.nl/

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/Iris-P2P).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)


- Artificial Intelligence Centre at the Czech Technical University in Prague, https://www.aic.fel.cvut.cz/
- Avast, https://www.avast.com/
- CESNET, https://www.cesnet.cz/
- Google Summer of Code (2023, 2024), https://summerofcode.withgoogle.com/

Their funding has played a crucial role in the development and success of this project.
We sincerely appreciate their commitment to advancing technology and their recognition of
the value Slips brings to the community.
