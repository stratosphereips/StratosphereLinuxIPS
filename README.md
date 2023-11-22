<h1 align="center"> 
Slips v1.0.8
</h1>

[Documentation](https://stratospherelinuxips.readthedocs.io/en/develop/) — [Features](https://stratospherelinuxips.readthedocs.io/en/develop/features.html) — [Installation](#installation) — [Authors](#people-involved) — [Contributions](#contribute-to-slips)



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
- [Contributing](#contributing)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Features](#features)
- [Documentation](#documentation)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Credits](#credits)
- [Changelog](#changelog)
- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
- [Roadmap](#roadmap)
- [References](#references)
- [Demos](#demos)
- [Funding](#funding)


# Slips: Behavioral Machine Learning-Based Intrusion Prevention System


Slips is a powerful endpoint behavioral intrusion prevention and detection system that uses machine learning to detect malicious behaviors in network traffic. Slips can work with network traffic in real-time, pcap files, and network flows from popular tools like Suricata, Zeek/Bro, and Argus. Slips threat detection is based on a combination of machine learning models trained to detect malicious behaviors, 40+ threat intelligence feeds and expert heuristics. Slips gathers evidence of malicious behavior and uses extensively trained thresholds to trigger alerts when enough evidence is accumulated.

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/slips.gif" width="850px"
title="Slips in action.">



# Introduction
Slips is the first free software behavioral machine learning-based IDS/IPS for endpoints. It was created in 2012 by Sebastian Garcia at the Stratosphere Laboratory, AIC, FEE, Czech Technical University in Prague. The goal was to offer a local IDS/IPS that leverages machine learning to detect network attacks using behavioral analysis. 


Slips is supported on Linux and MacOS only. The blocking features of Slips are only supported on Linux

Slips is python-based and relies on [Zeek network analysis framework](https://zeek.org/get-zeek/) for capturing live traffic and analyzing PCAPs.

Slips needs Redis >= 7.0.4 for interprocess communication. Redis can be installed directly in the host computer or in Docker.

# Contributing
Explain how users can contribute to the tool's development. Provide guidelines for submitting bug reports, feature requests, or pull requests.


We welcome contributions to improve the functionality and features of this tool. 
Please read carefully the [contributing guidelines](https://stratospherelinuxips.readthedocs.io/en/develop/contributing.html) for contributing to the development of Slips

If you are a student, we encourage you to apply for the Google Summer of Code program that we participate in as a hosting organization. 

Check [Slips in GSoC2023](https://github.com/stratosphereips/Google-Summer-of-Code-2023) for more information.


You can [join our conversations in Discord](https://discord.gg/zu5HwMFy5C) for questions and discussions.
We appreciate your contributions and thank you for helping to improve Slips!

# Installation
Provide step-by-step instructions on how to install and set up the tool. 
Include any necessary commands or configurations. 
If applicable, specify any prerequisites or dependencies required for installation.

Slips can be run on different platforms, the easiest and most recommended way if you're a linux user is to run Slips on docker.

```
docker run -it --rm --net=host -v ~/dataset:/StratosphereLinuxIPS/dataset stratosphereips/slips:latest
```

Check the installation guide for more Installation options:

* [Docker](#slips-in-docker)
  * Dockerhub (recommended)
    * On a linux host
      * [Without P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-linux-and-macos-non-m1-processors)
      * [With P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-p2p-support-on-linux-or-macos-non-m1-architecture)

    * On MacOS M1 host
      * [Without P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-macos-m1)
    
    * On MacOS (non-M1 processor)
      * [Without P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-linux-and-macos-non-m1-processors) 
      * [With P2P support](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#for-p2p-support-on-linux-or-macos-non-m1-architecture)
  * [Docker-compose](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#running-slips-using-docker-compose)
  * [Dockerfile](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#building-slips-from-the-dockerfile)
* Native
  * [Using install.sh](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#install-slips-using-shell-script)
  * [Manually](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-slips-manually)
* [on RPI (Beta)](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-slips-on-a-raspberry-pi)



# Features

Slips key features are:

* **Behavioral Intrusion Prevention**: Slips acts as a powerful system to prevent intrusions based on detecting malicious behaviors in network traffic using machine learning.
* **Modularity**: Slips is written in Python and is highly modular with different modules performing specific detections in the network traffic.
* **Targeted Attacks and Command & Control Detection**: It places a strong emphasis on identifying targeted attacks and command and control channels in network traffic.
* **Traffic Analysis Flexibility**: Slips can analyze network traffic in real-time, pcap files, and network flows from popular tools like Suricata, Zeek/Bro, and Argus.
* **Threat Intelligence Updates**: Slips continuously updates threat intelligence files and databases, providing relevant detections as updates occur.
* **Integration with External Platforms**: Modules in Slips can look up IP addresses on external platforms such as VirusTotal and RiskIQ.
* **Graphical User Interface**: Slips provides a console graphical user interface (Kalipso) and a web interface for displaying detection with graphs and tables.
* **Peer-to-Peer (P2P) Module**: Slips includes a complex automatic system to find other peers in the network and share IoC data automatically in a balanced, trusted manner. The P2P module can be enabled as needed.
* **Docker Implementation**: Running Slips through Docker on Linux systems is simplified, allowing real-time traffic analysis.
* **Detailed Documentation**: Slips provides detailed documentation guiding users through usage instructions for efficient utilization of its features.


