# Datasets

Slips comes with some datasets for you to try on the folder `dataset`. They are a mix of real malware, real normal, both malicious and bening, in Argus format, Zeek, pcap, etc. 





## 2017-3-8_win5.pcap

## conn.log

## CTU-Malware-Capture-Botnet-1

## malicious-cc.conn.log

## port-scans

## test10-mixed-zeek-dir

## test11-portscan.binetflow

## test12-icmp-portscan.pcap

## test13-malicious-dhcpscan-zeek-dir

## test14-malicious-zeek-dir

## test15-malicious-zeek-dir

## test16-malicious-zeek-dir

## test1-normal.nfdump

## test2-malicious.binetflow

## test3-mixed.binetflow

## test4-malicious.binetflow

## test5-mixed.binetflow

## test6-malicious.suricata.json

## test7-malicious.pcap

## test8-malicious.pcap

## test9-mixed-zeek-dir

## test-cc
This is a test for detecting command and control channels. It is a synthetic dataset created by capturing very periodic and semi-periodic connections.

### test-cc-capture-1.pcap
Very periodic every 2 seconds.

Capture
- sudo tcpdump -n -s0 -i eno1 host 147.32.80.37 and host testing.com -v -w test-cc-capture-1.pcap

Connection
- while [ 1 ]; do curl https://testing.com; sleep 2; done

### test-cc-capture-2.pcap
Semi-periodic, from 2 to 3 second]s

Capture
- sudo tcpdump -n -s0 -i eno1 port 53 or \(host 147.32.80.37 and host testing.com\) -v -w test-cc-capture-2.pcap

Connection
- while [ 1 ]; do curl https://testing.com; sleep $(echo "scale=2; 2+$RANDOM / 20000" | bc); done

### test18-malicious-ctu-sme-11-win
This capture is a short part of the Dataset [CTU-SME-11](https://zenodo.org/records/7958259), capture Experiment-VM-Microsoft-Windows7full-3, day 2023-02-22. It consist of only the first 5000 packets.

#### Labels
The labels were assigned by an expert by hand. The configuration file is `labels.config` and it was labeled using the tool [netflowlabeler](https://github.com/stratosphereips/netflowlabeler).

