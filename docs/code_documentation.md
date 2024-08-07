# Code documentation

## How Slips Works

<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/slips_workflow.png" title="Slips Workflow">


slips.py serves as the entry point for the slips framework, responsible for orchestrating its various components and ensuring smooth analysis processes.

### Input Process Management

- slips.py initiates the input process, responsible for ingesting flow data from specified files using the `-f` option. It intelligently detects the file type, reads it, and forwards the flows to the profiler process. Additionally, when handling PCAP files or interfacing directly with network interfaces, slips.py spawns a Zeek thread, leveraging slips' customized Zeek configuration to analyze the data and relay the processed flows to the profiler process.

### Update Manager Operation

- Furthermore, slips.py manages the update manager, tasked with keeping slips' local threat intelligence (TI) files up to date. This includes files stored in directories like `slips_files/organizations_info` and `slips_files/ports_info`. During startup, slips.py triggers the update manager to refresh remote TI files as well, ensuring comprehensive threat intelligence coverage.

### Profiler Process Workflow

- Upon receiving flows from the input process, the profiler process transforms them into a format compatible with slips' analysis capabilities. It establishes profiles and time windows for each encountered IP address, facilitating efficient data processing and analysis.

### Module Integration and Database Utilization

- The profiler process then routes flows to relevant modules based on their characteristics. For instance, flows from `http.log` are directed to `http_analyzer.py` for in-depth analysis. Data, profiles, and other relevant information are stored in slips' databases, leveraging both SQLite for persistent storage of labeled flows and Redis for real-time operations, enhancing overall performance.

### Human-Readable Output and User Interface Integration

- Utilizing the stored data and leveraging the timeline module, slips generates human-readable representations of flows, pivotal for the functionality of the web UI and kalipso UI, enhancing user experience and comprehension.

### Evidence Handling and Sharing

- Detected evidence undergoes scrutiny by the whitelist to ensure it's not whitelisted per the configuration in `config/whitelist.conf`. Non-whitelisted evidence proceeds to the evidence process, logging and distributing it to relevant modules responsible for exporting evidence. Enabling modules like CEST, Exporting modules, or CYST facilitates seamless evidence sharing and collaboration.

### Blocking and P2P Functionality

- With the blocking module enabled, slips can share detected alerts with the blocking module for immediate action, including blocking attacker IPs through the Linux firewall (supported on Linux platforms). Furthermore, if P2P functionality is enabled, slips' P2P module disseminates attacker information and blocking requests across the network, enhancing collective security measures.

### Output Process Handling

- Finally, slips' output process acts as a robust logging framework, formatting and printing all alerts, warnings, and informational messages for clear understanding and operational visibility.

This summary provides new contributors with an overview of slips' core functionalities. For detailed information on individual modules and processes, refer to the comprehensive documentation available.



## Code Docs

[Slips auto-generated code documentation here](https://stratosphereips.github.io/StratosphereLinuxIPS/files.html)
