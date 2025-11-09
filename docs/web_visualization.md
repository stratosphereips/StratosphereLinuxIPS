# Stratosphere Web Visualization

To see the alerts of Slips in a visual way, the methodology is the following

1. Slips must be configured to export the alerts in STIX format to a TAXII server, as explained in [exporting](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html).
2. You need to install a TAXII server (available in the StratosphereWeb submodule folder)
3. Use the program `slips_dashboard` that is availbale in the StratosphereWeb submodule that reads from the TAXII server.

All the setup does not consume many resources, so you can run this visualization even in small servers like a Raspberry Pi. However, by having many Slips exporting to the same server you can centralize the visualization of many sensors in a unique location, probably with more hardware if needed.