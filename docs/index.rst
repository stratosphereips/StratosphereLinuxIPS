.. image:: /images/slips_logo.png
    :align: center

Slips
============================

The tool is available on GitHub `here <https://github.com/stratosphereips/StratosphereLinuxIPS/tree/master>`_.

**Slips** is a Python-based intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. Slips was designed to focus on targeted attacks, to detect of command and control channelsi, and to provide good visualisation for the analyst. Slips is able to analyze real live traffic from the device and the large network captures in the type of a pcap files, Suricata, Zeek/Bro and Argus flows. As a result, Slips highlights suspicious behaviour and connections that needs to be deeper analyzed.

This documentation gives an overview how Slips works, how to use it and how to help. To be specific, that table of contents goes as follows:


- **Installation**. Instructions to install Slips in a Docker and in a computer. See :doc:`Installation <installation>`.

- **Usage**. Instructions and examples how to run Slips with different type of files and analyze the traffic using Slips and its GUI Kalipso. See :doc:`Usage <usage>`.

- **Detection modules**. Explanation of detection modules in Slips, types of input and output. See :doc:`Detection modules <detection_modules>`.

- **Architecture**. Internal architecture of Slips (profiles, timewindows), the use of Zeek and connection to Redis. See :doc:`Architecture <architecture>`.

- **Training with your own data**. Explanation on how to re-train the machine learning system of Slips with your own traffic (normal or malicious).See :doc:`Training <training>`.

- **Detections per Flow**. Explanation on how Slips works to make detections on each flow with different techniques. See :doc:`Flow Alerts <flowalerts>`.

- **Exporting**. The exporting module allows Slips to export to Slack and STIX servers. See :doc:`Exporting <exporting>`.

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
   flowalerts
   features
   training
   exporting
   P2P
   fides_module
   create_new_module
   datasets
   immune/Immune
   slips_in_action
   FAQ
   contributing
   code_documentation
