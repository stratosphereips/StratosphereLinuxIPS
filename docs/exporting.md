# Exporting

The exporting module allows Slips to export alerts and evidence to other systems. For now the supported systems are:

- Slack
- STIX Servers
- Warden servers
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



## CESNET Sharing

Slips supports exporting alerts to warden servers, as well as importing alerts.

To enable the module, set ```send_alerts``` and/or ```receive_alerts``` to ```yes``` in slips.conf

The default configuration file path in specified in the ```configuration_file``` variable in ```slips.conf```

The default path is ```modules/CESNET/warden.conf```

The format of ```warden.conf``` should be the following:

    {
       "url": "https://example.com/warden3",
       "certfile": "cert.pem",
       "keyfile": "key.pem",
       "cafile": "/etc/ssl/certs/DigiCert_Assured_ID_Root_CA.pem",
       "timeout": 600,
       "errlog": {"file": "/var/log/warden.err", "level": "debug"},
       "filelog": {"file": "/var/log/warden.log", "level": "warning"},
       "name": "com.example.warden.test"
    }

To get the key and the certificate, you need to run ```warden_apply.sh``` with you registered client_name and password.

The ```name``` key is your registered warden node name. 

You can change how much time to wait be before pushing alerts to warden server (in seconds). this is used when slips is running non-stop (e.g with -i )

If running on a file (a PCAP, binetflow, suricata ..etc.) not an interface, slips will export alerts to server after the analysis is done slips will push as soon as it finished the analysis.

By default slips will push every 1 day, you can change this by changing the ```push_delay``` value in ```slips.conf```
    

You can change how often we get alerts from warden server

By default Slips receives alerts every 1 day, you can change this by changing the ```receive_delay``` value in ```slips.conf```


## Logstash

Slips has logstash.conf file that exports our alerts.json to a given output file, you can change the output to your preference (e.g elastic search, stdout, etc..)
