
# Slips in action

To demonstrate the capabilities of Slips, we will give it real life malware traffic and checking how Slips analyses it.


<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/slips.gif" title="Slips in action.">


## Saefko RAT

We demonstarte Slips capabilities by running Slips on Saefko-RAT [download here](https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT06_Saefko/) network traffic.

The capture contains different actions done by the RAT controller
(e.g. upload a file, get GPS location, monitor files, etc.).
For detailed analysis, check Kamila Babayeva's blog [Dissecting a RAT. Analysis of the Saefko RAT](https://www.stratosphereips.org/blog/2021/6/2/dissecting-a-rat-analysis-of-the-saefko-rat).

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


---


## DroidJack v4.4 RAT

Running Slips on DroidJack v4.4 RAT [download here](https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v1/DroidJack.zip). password: `infected`.

The capture contains different actions done by the RAT controller(e.g. upload a file, get GPS location, monitor files, etc.). For detailed analysis, check Kamila Babayeva's blog [Analysis of DroidJack v4.4 RAT network traffic](https://www.stratosphereips.org/blog/2021/1/22/analysis-of-droidjack-v44-rat-network-traffic).

From the analysis we know that:
-  The controller IP address: 147.32.83.253
-  The victim's IP address: 10.8.0.57

When running slips on the PCAP, we get the following alerts

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/droidjack_alert.png" title="Slips generated DroidJack alerts">

Slips detected the connection to the C&C server using an unknown port

	Detected Connection to unknown destination port 1334/TCP destination IP 147.32.83.253.

Slips also detected the reconnection attemps made from the victim to the C&C server

	Multiple reconnection attempts to Destination IP: 147.32.83.253 from IP: 10.8.0.57

Slips also detects connections without resolutions due to their wide usages among malware to either check internet connectivity or get commands fro the C&C servers.


		Detected a connection without DNS resolution to IP: 147.32.83.253. AS: CESNET z.s.p.o., rDNS: dhcp-83-253.felk.cvut.cz


The indentification (AS, SNI, rDNS) of each IP, if available, is printed in every evidence generated by Slips.

Our Threat intelligence feed [Abuse.ch](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv) detected a malicious JA3 indicating that the victim 10.8.0.57 is infected

	Detected Malicious JA3: 7a29c223fb122ec64d10f0a159e07996 from source address 10.8.0.57 description: ['malicious']

And our machine learning models detected the C&C server

	Detected C&C channel, destination IP: 147.32.83.253 port: 1334/tcp score: 0.9755

Slips creates a profile per each IP that appeared in the traffic.
Each profile contains flows sent from this IP.
Each flow is described with a specific letter which description can be found [here](https://www.stratosphereips.org/stratosphere-testing-framework).

 Considering that, Slips detects the C&C channel over 1334/TCP.
 Slips’ machine learning module called LSTM detecting C&C channel is shown below

<img src="https://images.squarespace-cdn.com/content/v1/5a01100f692ebe0459a1859f/1611308467564-L34N8ANZOO8WUIO9OT7O/image2.png" title="Behavioral model of the connection between the phone and C&C over 1334/TCP.">

Slips did not detect periodic connection over 1337/UDP because the LSTM module focuses on TCP. But from the behavioral model of the connections over 1337/UDP shown below, we can conclude that the model is periodic and most of connections are of a small size.

<img src="https://images.squarespace-cdn.com/content/v1/5a01100f692ebe0459a1859f/1611308530585-BKXFXAQXGFIPXPRLSSVF/image5.png" title="Behavioral model created by Slips for the connection between phone and server using 1337/UDP.">





















