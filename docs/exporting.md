# Exporting Slips Alerts

Slips supports exporting alerts to other systems using different modules (`exporting_alerts`, `cesnet`, etc.)

For now the supported systems are:

- Slack
- TAXII Servers (STIX format)
- IDMEFv2 Managers (over HTTPS)
- Warden servers
- IDEA JSON format
- Logstash
- TSV and json of labeled flows

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
6. In this same 'OAuth & Permissions' page, copy the 'Bot User OAuth Token'. It should look something like 'xoxb-nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn' with a lot of letters.
7. Put the bot OAuth token to the file: ```config/slack_bot_token_secret```
8. You need to add the new app to the channel in Slack. You do this by clicking on the bot's name (is in the messae when you add an integration in the channel), and click 'Add this app to a channel'.
9. Alternatively you can add the bot to the channel by going to the channel and doing ```/invite @bots_name```.
9. Edit the config/slips.yaml file, put `slack` in the export\_to variable, and add the channel's name to which you want to send.

    [exporting_alerts]
    export_to = [slack]
    slack_channel_name = SlipsAlertsChannel


## STIX

If you want to export alerts to your TAXII 2 server using STIX 2.1 format,
set ```export_to``` to ```stix``` and Slips will automatically generate a
```STIX_data.json``` bundle containing the indicators it detects and push it to
your collection.


    [ExportingAlerts]
    export_to = [stix]


Configure the TAXII client by editing the following variables:

```TAXII_server```: host name or IP address of the TAXII server.

```port```: TCP port (optional, defaults to 80/443).

```use_https```: set to true to connect over HTTPS (be careful that the default TAXII server in SlipsWeb, Medallion, do not support HTTPS yet)

```discovery_path```: TAXII discovery endpoint path or full URL
 (for example ```/taxii2/```).

```taxii_version```: set to ```2``` for TAXII 2.1 (Medallion) or ```1``` for
TAXII 1.x (OpenTAXII). TAXII 1 export uses the inbox service and is sent via
direct export.

```collection_name```: ID or title of the TAXII collection that should receive your indicators. Be default `Alerts`.

```push_delay```: time between automatic pushes (in seconds) when Slips is
running continuously.

```taxii_username``` / ```taxii_password```: credentials used for HTTP Basic authentication.

**Change the default config password of the TAXII servers you are going to export to in ```config/medallion_config.yaml```**


Slips stores the generated bundle for each run in the output directory of that
execution (for example `output/<run_id>/STIX_data.json`), so you can inspect the
exact STIX objects that were pushed.

If running on a file, Slips will export once before shutdown.
If running on an interface, Slips will export to the server every
```push_delay``` seconds (default 1 hour).

## IDMEFv2 Manager

Slips can export alerts to an IDMEFv2 Manager over HTTPS,
In this setup Slips acts as an IDMEFv2 **Analyzer** (the HTTP client) and the
Manager is the HTTP server. Each alert is converted to a single IDMEFv2 JSON
message and sent as its own `POST` request (normally to `/`). A `2xx` response
means the Manager safely stored or handed off the alert.

To enable it, add ```idmef_manager```  to the ```export_to``` list. and fill the cert paths in the idmef_manager block

```yaml
exporting_alerts:
  export_to: [idmef_manager]

  idmef_manager:
    url: https://localhost:8443/
    client_certificate: "/path/to/idmef/analyzer.crt"
    client_private_key: "/path/to/idmef/analyzer.key"
    trusted_ca: "/path/to/idmef/ca.crt"
    timeout: 10
```

The settings under `idmef_manager` are:

```url```: URL of the IDMEFv2 Manager (default `https://localhost:8443/`).

```client_certificate```: path to the analyzer client certificate that
Slips presents to the Manager. **Required.**

```client_private_key```: path to the private key for the client certificate.
**Required.**

```trusted_ca```: path to the CA certificate used to validate the Manager's
certificate. **Required.**

```timeout```: per-request timeout in seconds (default `10`).

The transport requires **mutual TLS 1.3**: Slips validates the Manager against
`trusted_ca` and presents its own `client_certificate` / `client_private_key`,
and the Manager authenticates Slips in return. Certificates must use DNS
`subjectAltName` entries (wildcards are prohibited by the draft), and the
Manager URL hostname is validated against the Manager certificate's SAN.

There are no default certificate paths: the three certificate/key paths are
required, and must point to existing files. If any of them is unset or missing,
IDMEFv2 export is disabled and a message is logged.

For details on the transport, the mutual-TLS requirements, and how to set up
the certificates, see the specification:
[draft-lehmann-idmefv2-https-transport](https://datatracker.ietf.org/doc/draft-lehmann-idmefv2-https-transport/).

Because the export happens per evidence as alerts are generated, this exporting
works both when Slips runs on a file and on an interface.

## JSON format


By default Slips logs all alerts to ```output/alerts.json``` in [CESNET's IDEA0 format](https://idea.cesnet.cz/en/index) which is also a JSON format.

## CESNET Sharing

Slips supports exporting alerts to warden servers, as well as importing alerts.

To enable the exporting, set ```receive_alerts``` to ```yes``` in config/slips.yaml

The default configuration file path is specified in the ```configuration_file``` variable in ```config/slips.yaml```

The default path is ```config/warden.conf```

The format of ```warden.conf``` should be the following:

  ```
 { "url": "https://example.com/warden3",
   "certfile": "cert.pem",
   "keyfile": "key.pem",
   "cafile": "/etc/ssl/certs/DigiCert_Assured_ID_Root_CA.pem",
   "timeout": 600,
   "errlog": {"file": "output/warden_logs/warden.err", "level": "debug"},
   "filelog": {"file": "output/warden_logs/warden.log", "level": "warning"},
   "name": "com.example.warden.test" }
```
To get your key and the certificate, you need to run ```warden_apply.sh``` with you registered client_name and password. [Full instructions here](https://warden.cesnet.cz/en/index)

The ```name``` key is your registered warden node name.

All evidence causing an alert are exported to warden server once an alert is generated.
See the [difference between alerts and evidence](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html)) in Slips architecture section.

You can change how often you get alerts (import) from warden server

By default Slips imports alerts every 1 day, you can change this by changing the ```receive_delay``` value in ```config/slips.yaml```

Slips logs all alerts to ```output/alerts.json``` in
[CESNET's IDEA0 format](https://idea.cesnet.cz/en/index) by default.

Make sure that the DigiCert_Assured_ID_Root_CA is somewhere accessible by slips. or run slips with
root if you want to leave it in ```/etc/ssl/certs/```

Refer to the [Detection modules section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#cesnet-sharing-module)
for detailed instructions on how CESNET importing.


## Logstash

Slips has logstash.conf file that exports our alerts.json to a given output file,
you can change the output to your preference (for example: elastic search, stdout, etc.)

## Text logs

By default, the output of Slips is stored in the ```output/``` directory in two files:


1. alert.json in IDEA0 format
2. alerts.log human readable text format

## TSV and json of labeled flows

Slips supports exporting all the labeled flows and altflows stored in the sqlite database
the sqlite database can be exported to json or tsv format.

Each labeled flow has an [AID fingerprint](https://pypi.org/project/aid-hash/), which is used to identify the flow based on the ts,
source and destination address, source and destination port and protocol.


this can be done by setting the ```export_labeled_flows``` parameter to ```yes``` in slips.yaml and changing
the ```export_format``` parameter to your desired format.
for now, the ```export_format``` parameter supports tsv or json formats only.

the exported flows are stored in a file called ```labeled_flows.json``` or ```labeled_flows.tsv``` in the output directory.
