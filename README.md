<h1 align="center"> 

Slips v0.9.0

Behavioral Machine Learning Based Intrusion Prevention System
</h1>

Slips is a behavioral intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. Slips is designed to focus on targeted attacks, detection of command and control channels, and to provide a good visualisation for the analyst. It can analyze network traffic in real time, network captures such as pcap files, and network flows produced by Suricata, Zeek/Bro and Argus. Slips processes the input, analyzes it, and highlights suspicious behaviour that need the analyst attention. 

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/slips.gif" title="Slips in action.">

<h3 align="center"> 
    
[Documentation](https://stratospherelinuxips.readthedocs.io/en/develop/) — [Features](#features) — [Installation](#installation) — [Authors](#people-involved) — [Contributions](#contribute-to-slips)
</h3>

# Features

Slips is written in Python and is highly modular. Each module is designed to perform a specific detection in the network traffic. The complete documentation of Slips internal architecture and instructions how to implement a new module are available [here](https://stratospherelinuxips.readthedocs.io/en/develop/).

The following table summarizes all active modules in Slips, its status and purpose:

|   Module            | Status | Description | 
| --------------------|   :-:  |------------ |  
| https               |   ⏳   | training and testing of the Random Forest algorithm to detect malicious HTTPS flows |
| port scan detector  |   ✅   | detects horizontal and vertical port scans |
| rnn-cc-detection    |   ✅   | detects command and control channels using recurrent neural network and the Stratosphere behavioral letters |
| flowalerts          |   ✅   | detects a malicious behaviour in each flow. Current measures are: long duration of the connection, successful ssh |
| flowmldetection     |   ✅   | detects malicious flows using ML pretrained models |
| leak_detector       |   ✅   | detects leaks of data in the traffic using YARA rules |
| threat Intelligence |   ✅   | checks IPs against known threat intelligence lists |
| ARP                 |   ✅   | checks for ARP attacks in ARP traffic  |
| timeline            |   ✅   | creates a timeline of what happened in the network based on all the flows and type of data available  |
| VirusTotal          |   ✅   | lookups IP addresses on VirusTotal |
| RiskIQ              |   ✅   | lookups IP addresses on RiskIQ  |
| IP_Info             |   ✅   | lookups Geolocation, ASN, RDNS information from IPs and MAC vendors |
| CESNET              |   ✅   | sends and receives alerts from CESNET Warden servers |
| ExportingAlerts     |   ✅   | exports alerts to Slack, STIX or Suricata-like JSON format |
| http_analyzer       |   ✅   | analyzes HTTP traffic |
| blocking            |   ✅   | blocks malicious IPs connecting to the device |
| P2P                 |   ✅   | shares network detections with other Slips peers in the local network |
| Kalipso             |   ✅   | Slips console graphical user interface to show detection with graphs and tables |

# Installation

The easiest way to run Slips is inside a docker. Current version of Slips docker can analyze network captures (pcap, Zeek flows, Argus flows, etc.), but it is not able to analyze real live traffic from inside the docker. If you need to analyze the traffic from your computer, use the native version.

## How to use Slips docker from DockerHub and share files between the host and the docker:

        mkdir ~/dataset
        cp <some-place>/myfile.pcap ~/dataset
        docker run -it --rm --net=host -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset stratosphereips/slips:latest
        ./slips.py -c slips.conf -f dataset/myfile.pcap

## How to build Slips docker from Dockerfile:

        docker build --no-cache -t slips -f docker/ubuntu-image/Dockerfile .
        docker run -it --rm --net=host slips
        ./slips.py -c slips.conf -f dataset/test3.binetflow

## If you want to allow Slips inside the docker to analyze and block the traffic in your Linux host, run docker with --cap-add=NET_ADMIN. And run with -p

        docker run -it --rm --net=host --cap-add=NET_ADMIN stratosphereips/slips:latest
        ./slips.py -c slips.conf -i eno1 -p


## If you want to run Slips locally on bare metal
The easiest way is to use [conda](https://docs.conda.io/en/latest/) for Python environment management. 
Note that if you want to analyze PCAPs, you need to have either `zeek` or `bro` installed. Check [slips.py](slips.py) and usage of `check_zeek_or_bro` function.
Slips also needs Redis for interprocess communication, you can either install Redis on bare metal and run `redis-server --daemonize yes` or you can use docker version
and execute `docker run --rm -d --name slips_redis -p 6379:6379 redis:alpine`.
```bash
# clone repository
git@github.com:stratosphereips/StratosphereLinuxIPS.git && cd StratosphereLinuxIPS
# create conda environment and download all python dependencies
conda env create -f conda-environment.yaml
# activate conda environment
conda activate slips 
# and finally run slips
./slips.py -c slips.conf -f dataset/myfile.pcap
```

You can now put pcap files or other flow files in the ./dataset/ folder and analyze them

## P2P Module
The peer to peer system os Slips is a highly complex automatic system to find other peers in the network and share data on IoC automatically in a balanced, trusted way. You just have to enable the P2P system. Please check the documentation [here](../docs/P2P.md)

You can use Slips with P2P directly in a special docker image by doing:

```
docker pull stratosphereips/slips_p2p
docker run --name slipsp2p -d -it --rm --net=host --cap-add=NET_ADMIN stratosphereips/slips_p2p
```


# Train the machine learning models with your data

Slips can also be used in _training_ mode with traffic from the user, so that the machine learning model can be **extended** with the users' traffic to improve detection.
To use this feature you need to modify the configuration file ```slips.conf``` to add in the ```[flowmldetection]``` section:

    mode = train

And also you need to specify the label of the traffic you are adding with:

    label = normal

After this, just run slips normally in your data (interface or any input file) and the machine learning model will be updated automatically.
To use the new model, just reconfigure slips in test mode

    mode = train

# Slips in the Media

- 2021 BlackHat Europe Arsenal, Slips: A Machine-Learning Based, Free-Software, Network Intrusion Prevention System [[slides](https://mega.nz/file/EAIjWA5D#DoYhJknH1hpbqfS2ayVLwA7ewNT50jFQb7S3dVAKPko)] [[web](https://www.blackhat.com/eu-21/arsenal/schedule/#slips-a-machine-learning-based-free-software-network-intrusion-prevention-system-25116)]
- 2021 BlackHat USA Arsenal, Slips: A Machine-Learning Based, Free-Software, Network Intrusion Prevention System [[web](https://www.blackhat.com/us-21/arsenal/schedule/#slips-a-machine-learning-based-free-software-network-intrusion-prevention-system-24105)]
- 2021 BlackHat Asia Arsenal, Slips: A Machine-Learning Based, Free-Software, Network Intrusion Prevention System [[web](https://www.blackhat.com/asia-21/arsenal/schedule/#slips-a-machine-learning-based-free-software-network-intrusion-prevention-system-22576)]
- 2020 Hack In The Box CyberWeek, Android RATs Detection With A Machine Learning-Based Python IDS [[video](https://www.youtube.com/watch?v=wx0V3qWdmyk)]
- 2019 OpenAlt, Fantastic Attacks and How Kalipso can Find Them [[video](https://www.youtube.com/watch?v=p2FL2sECpS0&t=1s)]
- 2016 Ekoparty, Stratosphere IPS. The free machine learning malware detection [[video](https://www.youtube.com/watch?v=IazEdK8R4YI)]

# People Involved

**Founder:** Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com. 

**Main authors:** Sebastian Garcia, Alya Gomaa, Kamila Babayeva

**Contributors:**
- Veronica Valeros
- Frantisek Strasak
- Dita Hollmannova
- Ondrej Lukas
- Elaheh Biglar Beigi
- Maria Rigaki 
- kartik88363
- arkamar

# Contribute to Slips
All contributors are welcomed! How you can help?

- Run Slips and report bugs and needed features, and suggest ideas
- Pull requests with a solved GitHub issue and new feature
- Pull request with a new detection module. The instructions and a template for new detection module [here](https://stratospherelinuxips.readthedocs.io/en/develop/).

## Get in touch

Feel free to join our [Discord server](https://discord.gg/zu5HwMFy5C) and ask questions, suggest new features or give us feedback.


# Acknowledgments

Slips was funded by the following organizations.

- NlNet Foundation, https://nlnet.nl/
- AIC Group, Czech Technical University in Prague, https://www.aic.fel.cvut.cz/
- Avast Software, https://www.avast.com/
- CESNET, https://www.cesnet.cz/
