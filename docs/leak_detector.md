# Leak detector

This module work only when slips is given a PCAP

The leak detector module uses YARA rules to detect leaks in PCAPs

### Module requirements

In order for this module to run you need:
<ul>
  <li>to have YARA installed and compiled on your machine</li>
  <li>yara-python</li>
  <li>tshark</li>
</ul>

You can compile YARA by running

`wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.1.3.tar.gz 
  && tar -zxf v4.1.3.tar.gz 
  && cd yara-4.1.3 
  && ./bootstrap.sh 
  && ./configure 
  && make 
  && make install`

You can install yara-python by running

`git clone https://github.com/VirusTotal/yara-python yara-python && cd yara-python
python3 setup.py build && python3 setup.py install`

You can install tshark by running

`apt install wireshark`


### How it works

This module works by

  1. Compiling the YARA rules in the ```modules/leak_detector/yara_rules/rules/``` directory
  2. Saving the compiled rules in ```modules/leak_detector/yara_rules/compiled/```
  3. Running the compiled rules on the given PCAP
  4. Once we find a match, we get the packet containing this match and set evidence.


### Extending 

You can extend the module be adding more YARA rules in ```modules/leak_detector/yara_rules/rules/```. 

The rules will be automatically detected, compiled and run on the given PCAP.

If you want to contribute, improve existing Slips detection modules or implement your own detection modules, see section :doc:`Contributing <contributing>`.
