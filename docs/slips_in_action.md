
# Slips in action

To demonstrate the capabilities of Slips, we will give it real life malware traffic and checking how Slips analyses it.


<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/slips.gif" title="Slips in action.">


## Saefko RAT

We provide the analysis of the network traffic of the RAT06-Saefko [download here](https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT06_Saefko/) using Slips.

The capture contains different actions done by the RAT controller (e.g. upload a file, get GPS location, monitor files, etc.). For detailed analysis, check Kamila Babayeva's blog [Dissecting a RAT. Analysis of the Saefko RAT](https://www.stratosphereips.org/blog/2021/6/2/dissecting-a-rat-analysis-of-the-saefko-rat).

First we run slips using the following command:

    ./slips.py -e 1 -f RAT06_Saefko.pcap


First, Slips will start by updating all the remote TI feeds added in slips.conf

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/updating_remote_feeds.png" title="Slips updating remote TI feeds">

To make sure Slips is up to date with the most recent IoCs in all feeds,
all feeds are loaded, parsed and updated periodically and automatically by
Slips every 24 hours by our [Update Manager](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#update-manager-module), which requires no user interaction.


Afetr updating, slips modules start and print the PID of every successfully started module.

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/modules_starting.png" title="Slips modules starting">

Then, we see the get alert

saefko_first_alert.png

Alerts are printed by the evidence module, Slips detected IP `2001:718:2:903:b877:48ae:9531:fbfc`  as infected due to the above evidence See the difference between alerts and evidence [here](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html)

Slips splits does detections in timewindows, each time window is 1 hour long by default and contains dozens of features computed for all connections that start in that time window.
So if an IP behaves maliciously at 4 PM, it will be marked as infected only during that hour, the next hour if no malicious behaviour occurs, slips will treat the traffic as normal.
This explains the start and stop timestamps in the alert `start 2021-04-10T16:44:43.285478+02:00, stop 2021-04-10T17:44:43.285478+0200`. This is the period (timewindow) in which this IP was behaving maliciously.

The difference between infected and normal timewindows is shown better in [kalispo](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#reading-the-output),  our user interface.

You can start it in another terminal using `./kalipso.sh`

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/kalispo_infected_tw.png" title="Kalipso infected timewindow">
<p> Figure 3 </p>

We can see that IP 2001:718:2:903:b877:48ae:9531:fbfc is infected only in timewindow1 as it's marked in red and is behaving normally in timewindow0 as it's colored in green.

We can see all the flows done by this IP in the infected timewindow in kalipso by pressing enter on timewindow1.


<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/expanding_infected_timewindow.png" title="Kalipso expanding infected timewindow">


At the bottom box in kalipso we can scroll though the evidence and se what slips detected, this is the same evidence printed in Figure 3.

We can see the following detections in the evidence:

`Detected Malicious JA3: 807fca46d9d0cf63adf4e5e80e414bbe from source address 2001:718:2:903:b877:48ae:9531:fbfc AS: CESNET z.s.p.o. description: Tofsee ['malicious']`

JA3 fingerprint the client part of the SSL certificate. This indicates that the source IP 2001:718:2:903:b877:48ae:9531:fbfc was infected with one of the Tofsee malware family

Slips also detected

    SSL certificate validation failed with (certificate has expired) Destination IP: 2a02:4780:dead:d8f::1. SNI: experimentsas.000webhostapp.com

From the RAT analysis, we know that `000webhostapp.com`  is the web hosting service used by the C&C server.

Slips also detected

    Connection to unknown destination port 6669/TCP destination IP 2001:67c:2564:a191::fff:1. (['open.ircnet.net'])
    Connection to unknown destination port 8000/TCP destination IP 192.168.131.1.

From the APK list of IRC servers shown in the RAT analysis, we know that the phone connects on port 6669/TCP  and 8000/TCP to different IRC servers to receive the malicious commands. The rDNS of the server is also printed in the alert `open.ircnet.net`

Our machine learning module rnn-cc-detection detected the C&C server using recurrent neural network

	Detected C&C channel, destination IP: 192.168.131.1 port: 8000/tcp score: 0.9871

Slips also detected

    Possible DGA or domain scanning. 192.168.131.2 failed to resolve 15 domains

The above detections are evidence that when accumulated, resulted in an alert.

To view all evidence that slips detected including those that weren't enough to generate an alert, you can

	cat output/alerts.log

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/alerts_log.png" title="Slips updating remote TI feeds">

Slips also has another log file in JSON format so they can be easily parsed and exported. See [the exporting section](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html%29) of the documentation.

The generated alerts in this file follow [CESNET's IDEA0 format](https://idea.cesnet.cz/en/index).

    cat output/alerts.json


















