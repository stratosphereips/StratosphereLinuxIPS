.. image:: /images/slips_logo.png
    :align: center

Slips v0.7.3
============================

The tool is available on GitHub `here <https://github.com/stratosphereips/StratosphereLinuxIPS/tree/master>`_.

**Stratosphere Linux IPS**, shortly **Slips**, is a Python-based intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. Slips was designed to focus on targeted attacks, to detect of command and control channelsi, and to provide good visualisation for the analyst. Slips is able to analyze real live traffic from the device and the large network captures in the type of a pcap files, Suricata, Zeek/Bro and Argus flows. As a result, Slips highlights suspicious behaviour and connections that needs to be deeper analyzed.

This documentation gives an overview how Slips works, how to use it and how to help. To be specific, that table of contents goes as follows:


- **Installation**. Instructions to install Slips in a Docker and in a computer. See :doc:`Installation <installation>`.

- **Usage**. Instructions and examples how to run Slips with different type of files and analyze the traffic using Slips and its GUI Kalipso. See :doc:`Usage <usage>`.

- **Detection modules**. Explanation of detection modules in Slips, types of input and output. See :doc:`Detection modules <detection_modules>`.

- **Architecture**. Internal architecture of Slips (profiles, timewindows), the use of Zeek and connection to Redis. See :doc:`Architecture <architecture>`.
  



.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Slips 
   
   self 
   installation
   usage
   detection_modules
   architecture
