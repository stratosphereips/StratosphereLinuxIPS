# Usage


Slips supports many different network files as well as reading from interface. Supported types are: PCAPs, Argus binetflow, zeek files, NFDUMP files. 

## To read own files
### PCAP

``` ./slips.py -c slips.conf -r test.pcap ```

### Argus binetflow

``` ./slips.py -c slips.conf -f test.binetflow ```

### Zeek folder

``` ./slips.py -c slips.conf -f zeek_files ```

### NFDUMP - netflow dump

``` ./slips.py -c slips.conf -b test.nfdump ```

## To read form the network

In Linux, to get your network interface:

```lshw -C network ```

If your interface is, for example: ```wlp3s0``` you can run slips using:

``` ./slips.py -c slips.conf -i wlp3s0 ```

## Kalipso GUI interface

You can run slips and run kalipso as a shell script in another terminal using:

```./kalipso.sh```

Or use the ```-G``` flag when running slips.

``` ./slips.py -c slips.conf -i wlp3s0 -G ```

# Config file

Slips has a ```slips.conf``` the contains user configurations for different modules.

Below are some of slips features and the available configurations for each of them.

## Generic configurations


Each IP that appears in the traffic is represented as a profile in slips,
each profile. Each profile is divided into time windows. 

Each time window is 1 hour long by default. You can change that in slips.conf using

```time_window_width```

Log files are stored in ```slips.log``` file by default, you can change this file using the ```logfile``` variable. 

You can also change how often slips creates log files using the ```log_report_time``` variable.

You can also disable logging by setting ```create_log_files``` to ```no``` or running slips with the ```-l``` flag

## Modules configurations

You can disable modules easily by appending to the ```disable``` list.

### MLdetection1

The ```mode=train``` should be used to tell the MLdetection1 module that the flows received are all for training.

The ```mode=test``` should be used after training the models, to test unknown data. 

You should have trained at least once with 'Normal' data and once with 'Malicious' data in order for the test to work.

### virustotal

In order for this module to work you need to add your virustotal API key to 
```modules/virustotal/api_key_secret```

If you have your key elsewhere you can specify the path in the ```api_key_file``` variable.

The file should contain the key at the start of the first line, and nothing more.

If no key is found, virustotal module will not be started.

### threatintelligence

This module reads IoCs from local and remote files. We update the remote ones regularly.

You can change the paths of both using these two variable. 

```download_path_for_local_threat_intelligence``` and ```download_path_for_remote_threat_intelligence```

All the files in these folders are read and the IPs are considered malicious.

You can add your own remote threat intelligence files in the ```ti_files``` variable. 

Supported extensions are: .txt, .csv, .netset, ipsum feeds, or .intel

You can also hardcode your own malicious IPs in ```modules/ThreatIntelligence1/local_data_files/own_malicious_ips.csv```

### flowalerts

Slips needs a threshold to determine a long connection. by default it is 1500 seconds. you can change that in ```long_connection_threshold```

### ExportingAlerts

Slips supports exporting alerts to slack and STIX.

You can specify where to export, You can append to the ```export_to``` list. 

To export to slack:

You need to add your slack bot token to ```modules/ExportingAlerts/slack_bot_token_secret```

The file should contain the token at the start of the first line, and nothing more.

If you don't have a slack bot follow steps 1 to 3 [here](https://api.slack.com/bot-users#creating-bot-user) to get one.

You can specify the channel name to send alerts to in the ```slack_channel_name``` variables and the sensor name to be sent with the alert in the ```sensor_name``` variable.

To export to STIX:

If you have stix to the ```export_to``` variable slips will automatically generate a 
```STIX_data.json``` containing all alerts it detects.

You can add your TAXII server details in the following variables:
```TAXII_server```: link to your TAXII server
```port``` , ```use_https```.

```discovery_path``` and ```inbox_path``` should contain URIs not full urls.

for example:

```python
discovery_path = /services/discovery-a
inbox_path = /services/inbox-a
```

```collection_name``` is the collection on the server you want to push your STIX data to.

```push_delay``` is the time to wait before pushing STIX data to server (in seconds). It is used when slips is running non-stop (e.g with -i )

If running on a file not an interface, slips will export to server after analysis is done. 

Add your TAXII server credentials to ```taxii_username ``` and ```taxii_password``` 

If you're using JWT based authentication, add the auth url to ```jwt_auth_url```.

