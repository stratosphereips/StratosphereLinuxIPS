# Exporting

Slips supports exporting alerts to other systems using different modules (ExportingAlerts, CESNET sharing etc.) 

For now the supported systems are:

- Slack
- TAXII Servers (STIX format)
- Warden servers
- suricata-like JSON format
- Logstash

## Slack
Slips uses the WebHook method to send data to Slack, more info [here](https://api.slack.com/messaging/webhooks).

To export into a slack channel you need to:

1. Create a new application in your slack, see `https://api.slack.com/apps/`
Remember that applications are seen per user, so other users in your Slack will not see this application probably.
2. Activate Incoming Webhooks while creating your app.
3. Create an Incoming Webhook for the channel you want to send the messages too.
4. Go to Slack and copy the channel ID for this channel.
You can do this by going to the channel, then clicking on the channel's name. The ID is in the bottom of the pop-up window.
5. You need to give your app the correct scope. Slips only needs write access to one channel. Do:
5.1 Go to your app in Slack `https://api.slack.com/apps`
5.2 In the navigation menu, choose the OAuth & Permissions feature.
5.3 Scroll down to the Scopes section, and pick channels:read and chat:write from the drop down menu.
5.4 Scroll back to the top of this page and look for the button that says Install App to Workspace (or Reinstall App if you've done this before). Click it.
6. You need to add the new app to the channel in Slack. You do this by clicking on the bot's name (is in the messae when you add an integration in the channel), and click 'Add this app to a channel'.
7. Edit the slips.conf file, put `slack` in the export\_to variable, and add the channel's name to which you want to send.

    [ExportingAlerts]
    export_to = [slack]
    slack_channel_name = SlipsAlertsChannel


## STIX

If you want to export alerts to your TAXII server using STIX format, change ```export_to``` variable to export to STIX, and Slips will automatically generate a 
```STIX_data.json``` containing all alerts it detects.


    [ExportingAlerts]
    export_to = [stix]


You can add your TAXII server details in the following variables:

```TAXII_server```: link to your TAXII server

```port```: port to be used

```use_https```: use https or not.

```discovery_path``` and ```inbox_path``` should contain URIs not full urls. For example:

```python
discovery_path = /services/discovery-a
inbox_path = /services/inbox-a
```

```collection_name```: the collection on the server you want to push your STIX data to.

```push_delay```: the time to wait before pushing STIX data to server (in seconds). It is used when slips is running non-stop (e.g with -i )

```taxii_username```: TAXII server user credentials

```taxii_password```: TAXII server user password

```jwt_auth_url```: auth url if JWT based authentication is used.

If running on a file not an interface, Slips will export to server after analysis is done. 

More details on how to [export to slack or TAXII server here](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html)

## JSON format


By default Slips logs all alerts to ```output/alerts.json``` in [CESNET's IDEA0 format](https://idea.cesnet.cz/en/index) which is also a JSON format.

 
If you want to export Slips alerts in a simpler JSON format instead of IDEA0 format,
change ```export_to``` variable to export to JSON, and Slips will automatically generate a 
```exported_alerts.json``` containing all alerts it detects.


    [ExportingAlerts]
    export_to = [json]


## CESNET Sharing  
  
Slips supports exporting alerts to warden servers, as well as importing alerts.  
  
To enable the exporting, set ```receive_alerts``` to ```yes``` in slips.conf  
  
The default configuration file path in specified in the ```configuration_file``` variable in ```slips.conf```  
  
The default path is ```modules/CESNET/warden.conf```  
  
The format of ```warden.conf``` should be the following:  

  ```
 { "url": "https://example.com/warden3", 
   "certfile": "cert.pem", 
   "keyfile": "key.pem", 
   "cafile": "/etc/ssl/certs/DigiCert_Assured_ID_Root_CA.pem", 
   "timeout": 600, 
   "errlog": {"file": "/var/log/warden.err", "level": "debug"}, 
   "filelog": {"file": "/var/log/warden.log", "level": "warning"}, 
   "name": "com.example.warden.test" }  
```
To get your key and the certificate, you need to run ```warden_apply.sh``` with you registered client_name and password. [Full instructions here](https://warden.cesnet.cz/en/index)
  
The ```name``` key is your registered warden node name.   
  
All evidence causing an alert are exported to warden server once an alert is generated. See the [difference between alerts and evidence](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html)) in Slips architecture section.
  
You can change how often you get alerts (import) from warden server  
  
By default Slips imports alerts every 1 day, you can change this by changing the ```receive_delay``` value in ```slips.conf```

Slips logs all alerts to ```output/alerts.json``` in [CESNET's IDEA0 format](https://idea.cesnet.cz/en/index) by default.

Refer to the [Detection modules section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#cesnet-sharing-module) for detailed instructions on how CESNET importing.


## Logstash

Slips has logstash.conf file that exports our alerts.json to a given output file,
you can change the output to your preference (for example: elastic search, stdout, etc.)

## Text logs

By default, the output of Slips is stored in the ```output/``` directory in two files: 


1. alert.json in IDEA0 format
2. alerts.log human readable text format