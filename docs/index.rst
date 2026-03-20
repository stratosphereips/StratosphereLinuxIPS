.. image:: /images/slips_logo.png
    :align: center

Slips
============================

The tool is available on GitHub `here <https://github.com/stratosphereips/StratosphereLinuxIPS/tree/master>`_.

**Slips** is a Python-based intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. Slips was designed to focus on targeted attacks, to detect of command and control channelsi, and to provide good visualisation for the analyst. Slips is able to analyze real live traffic from the device and the large network captures in the type of a pcap files, Suricata, Zeek/Bro and Argus flows. As a result, Slips highlights suspicious behaviour and connections that needs to be deeper analyzed.

This documentation gives an overview how Slips works, how to use it and how to help. To be specific, that table of contents goes as follows:


- **Installation**. Instructions to install Slips in a Docker and in a computer. See :doc:`Installation <installation>`.

- **Usage**. Instructions and examples how to run Slips with different type of files and analyze the traffic using Slips and its web interface or the optional Kalipso submodule. See :doc:`Usage <usage>`.

- **Detection modules**. Explanation of detection modules in Slips, types of input and output. See :doc:`Detection modules <detection_modules>`.

- **brute_force_detector**. Dedicated documentation for the SSH brute force detector module. See :doc:`brute_force_detector <brute_force_detector>`.
- **LLM module**. Shared access to configured LLM backends from other Slips modules. See :doc:`LLM module <llm_module>`.

- **Regex Generator module**. Shared service that generates and validates pseudo-random regexes for later Zeek-side use. See :doc:`Regex Generator module <regex_generator_module>`.

- **T Cell module**. Immune-style responder that consumes PAMP evidence, regex matches, and context to decide blocking or memory. See :doc:`T Cell module <t_cell_module>`.

- **HTTPS anomaly detection**. Detailed design and behavior of the HTTPS anomaly detector. See :doc:`HTTPS anomaly detection <https_anomaly_detection>`.

- **Architecture**. Internal architecture of Slips (profiles, timewindows), the use of Zeek and connection to Redis. See :doc:`Architecture <architecture>`.

- **Training with your own data**. Explanation on how to re-train the machine learning system of Slips with your own traffic (normal or malicious).See :doc:`Training <training>`.

- **Detections per Flow**. Explanation on how Slips works to make detections on each flow with different techniques. See :doc:`flow_alerts <flow_alerts>`.

- **Exporting**. The exporting module allows Slips to export to Slack and STIX servers. See :doc:`Exporting <exporting>`.

- **Evidence signals**. Central PAMP/DAMP classification for evidence, configuration overrides, and the current evidence inventory. See :doc:`Evidence signals <evidence_signals>`.

- **Slips in Action**. Example of using slips to analyze different PCAPs See :doc:`Slips in action <slips_in_action>`.

- **Contributing**. Explanation how to contribute to Slips, and instructions how to implement new detection module in Slips. See :doc:`Contributing <contributing>`.

- **Create a new module**. Step by step guide on how to create a new Slips module See :doc:`Create a new module <create_new_module>`.

- **Code documentation**. Auto generated slips code documentation See :doc:`Code docs <code_documentation>`.

- **Datasets**. The folder `dataset` contains some testing datasets for you to try. See :doc:`Datasets <datasets>`.




.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Slips
   :glob:

   self
   installation
   usage
   architecture
   detection_modules
   brute_force_detector
   llm_module
   regex_generator_module
   t_cell_module
   https_anomaly_detection
   flow_alerts
   features
   training
   exporting
   evidence_signals
   P2P
   fides
   create_new_module
   datasets
   immune/Immune
   slips_in_action
   FAQ
   contributing
   code_documentation
   related_repos
   visualisation
