# How to Create a New Slips Module



## What is SLIPS and why are modules useful
Slips is a machine learning-based intrusion prevention system for Linux and MacOS, developed at the Stratosphere Laboratories from the Czech Technical University in Prague. Slips reads network traffic flows from several sources, applies multiple detections (including machine learning detections) and detects infected computers and attackers in the network. It is easy to extend the functionality of Slips by writing a new module. This blog shows how to create a new module for Slips from scratch.

## Goal of this Blog
This blog creates an example module to detect when any private IP address communicates with another private IP address. What we want is to know if, for example, the IP 192.168.4.2, is communicating with the IP 192.168.4.87. This simple idea, but still useful, is going to be the purpose of our module. Also, it will generate an alert for Slips to consider this situation. Our module will be called 'local_connection_detector'.

### High-level View of how a Module Works

The Module consists of the __init__() function for initializations, for example starting the database, 
setting up the outputqueue for printing and logging, subscribing to channels, etc.

The main function of each module is the ```run()```, this function should contain a while True that keeps looping as long as
Slips is running so that the module doesn't terminate.

Each module has it's own print() function that handles text printing and logging by passing everything to the 
```OutputProcess.py``` for processing

Each Module also has it's own shutdown_gracefully() function that handles cleaning up after the module is done processing.
It handles for example:
- Saving a model before Slips stops
- Saving alerts in a .txt file if the module's job is to export alerts
- Telling the main module (slips.py) that the module is done processing so slips.py can kill it
etc.


## Developing a Module
When Slips runs, it automatically loads all the modules inside the ```modules/``` directory. Therefore, 
our new module should be placed there.

Slips has a template module directory that we are going to copy and then modify for our purposes.

```bash
cp -a modules/template modules/local_connection_detector
```    

### Changing the Name of the Module

Each module in Slips should have a name, author and description.

We should change the name inside the py file by finding the lines with the name and description in the class 'Module'
and changing them:

```python
name = 'local_connection_detector'
description = (
    'detects connections to other devices in your local network'
    )
authors = ['Your name']
```

At the end you should have a structure like this:
```
modules/
├─ local_connection_detector/
│  ├─ __init__.py
│  ├─ local_connection_detector.py
```

The __init__.py is to make sure the module is treated as a python package, don't delete it.

Remember to delete the __pycache__ dir if it's copied to the new module using:

```rm -r modules/local_connection_detector/__pycache__```


### Redis Pub/Sub

First, we need to subscribe to the channel ```new_flow``` 

```python
self.c1 = __database__.subscribe('new_flow')
```

So now everytime slips sees a new flow, you can access it from your module using the following line

```python
message = __database__.get_message(self.c1)
```

The above line checks if a message was recieved on the channel you subscribed to.

```python
if utils.is_msg_intended_for(message, 'new_flow'):
```

The above line checks if the message we have now is meant for the ```new_flow``` channel, and isn't a subscribe msg, 
and isn't a stop_process msg.

Now, you can access the content of the flow using 

```python
message = message['data']
```

Thus far, we have the following code that gets a msg everytime slips reads a new flow

```python
def __init__(self, outputqueue, config, redis_port):
        self.c1 = __database__.subscribe('new_flow')
```


```python
def run(self):
        utils.drop_root_privs()
        while True:
            try:
                message = __database__.get_message(self.c1)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'new_flow'):
                    #TODO
                    pass

            except KeyboardInterrupt:
                self.shutdown_gracefully()
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(str(inst), 0, 1)

```


### Detecting connections to local devices

Now that we have the flow, we need to:

- Extract the source IP
- Extract the destination IP
- Check if both of them are private
- Generate an evidence


Extracting IPs is done by the following:

```python
message = message['data']
message = json.loads(message)
flow = json.loads(message['flow'])
uid = next(iter(flow))
flow = json.loads(flow[uid])
saddr = flow['saddr']
daddr = flow['daddr']
```

Now we need to check if both of them are private.


```python
import ipaddress
srcip_obj = ipaddress.ip_address(saddr)
dstip_obj = ipaddress.ip_address(daddr)
if srcip_obj.is_private and dstip_obj.is_private:
    #TODO
    pass
```

Now that we're sure both ips are private, we need to generate an alert.

Slips requires certain info about the evidence to be able to sort them and properly display them using Kalipso.

Each parameter is described below

```python
# on a scale of 0 to 1, how confident you are of this evidence
confidence = 0.8
# how dangerous is this evidence? info, low, medium, high, critical?
threat_level = 'high'

# the name of your evidence, you can put any descriptive string here
evidence_type = 'ConnectionToLocalDevice'
# what is this evidence category according to IDEA categories 
category = 'Anomaly.Connection'
# which ip is the attacker here? the src or the dst?
attacker_direction = 'srcip'
# what is the ip of the attacker?
attacker = saddr
# describe the evidence
description = f'Detected a connection to a local device {daddr}'
timestamp = datetime.datetime.now().strftime('%Y/%m/%d-%H:%M:%S')
# the crrent profile is the source ip, this comes in 
# the msg received in the channel
profileid = message['profileid']
# Profiles are split into timewindows, each timewindow is 1h, 
# this comes in the msg received in the channel
twid = message['twid']

__database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                         timestamp, category, profileid=profileid, twid=twid)
```



### Testing the Module
The module is now ready to be used. 
You can copy/paste the complete code that is 
[here](https://stratospherelinuxips.readthedocs.io/en/develop/create_new_module.html#complete-code)


First we start Slips by using the following command:

```bash
./slips.py -i wlp3s0 -o local_conn_detector
```

-o is to store the output in the ```local_conn_detector/``` dir.

Then we make a connnection to a local ip

```
ping 192.168.1.18
```


And you should see your alerts in ./local_conn_detector/alerts.log by using

```
cat local_conn_detector/alerts.log 
```

```
Using develop - 9f5f9412a3c941b3146d92c8cb2f1f12aab3699e - 2022-06-02 16:51:43.989778

2022/06/02-16:51:57: Src IP 192.168.1.18              . Detected Detected a connection to a local device 192.168.1.12
2022/06/02-16:51:57: Src IP 192.168.1.12              . Detected Detected a connection to a local device 192.168.1.18
```


<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/module.gif" 
title="Testing The Module">



### Conclusion

Due to the high modularity of slips, adding a new slips module is as easy as modifying a few lines in our
template module, and slips handles running 
your module and integrating it for you.

This is the [list of the modules](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#detection-modules)
Slips currently have. You can enhance them, add detections, suggest new ideas using
[our Discord](https://discord.com/invite/zu5HwMFy5C) or by opening
a PR.

For more info about the threat levels, [check the docs](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html#threat-levels)

Detailed explanation of [IDEA categories here](https://idea.cesnet.cz/en/classifications)

Detailed explanation of [Slips profiles and timewindows here](https://idea.cesnet.cz/en/classifications)

[Contributing guidelines](https://stratospherelinuxips.readthedocs.io/en/develop/contributing.html)


## Complete Code
Here is the whole local_connection_detector.py code for copy/paste.

```python
# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
import platform
import sys

# Your imports
import datetime
import ipaddress
import json


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'local_connection_detector'
    description = 'detects connections to other devices in your local network'
    authors = ['Template Author']

    def __init__(self, outputqueue, config, redis_port):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the config/slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(redis_port)
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        # Remember to subscribe to this channel in database.py
        self.c1 = __database__.subscribe('new_flow')

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)

    def run(self):
        utils.drop_root_privs()
        # Main loop function
        while True:
            try:
                message = __database__.get_message(self.c1)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'new_flow'):
                    message = message['data']
                    message = json.loads(message)
                    flow = json.loads(message['flow'])
                    uid = next(iter(flow))
                    flow = json.loads(flow[uid])
                    saddr = flow['saddr']
                    daddr = flow['daddr']
                    srcip_obj = ipaddress.ip_address(saddr)
                    dstip_obj = ipaddress.ip_address(daddr)
                    if srcip_obj.is_private and dstip_obj.is_private:
                        # on a scale of 0 to 1, how confident you are of this evidence
                        confidence = 0.8
                        # how dangerous is this evidence? info, low, medium, high, critical?
                        threat_level = 'high'
                        # the name of your evidence, you can put any descriptive string here
                        evidence_type = 'ConnectionToLocalDevice'
                        # what is this evidence category according to IDEA categories
                        category = 'Anomaly.Connection'
                        # which ip is the attacker here? the src or the dst?
                        attacker_direction = 'srcip'
                        # what is the ip of the attacker?
                        attacker = saddr
                        # describe the evidence
                        description = f'Detected a connection to a local device {daddr}'
                        timestamp = datetime.datetime.now().strftime('%Y/%m/%d-%H:%M:%S')
                        # the crrent profile is the source ip, this comes in the msg received in the channel
                        profileid = message['profileid']
                        # Profiles are split into timewindows, each timewindow is 1h, this comes in the msg received in the channel
                        twid = message['twid']

                        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level,
                                                 confidence, description, timestamp, category, profileid=profileid,
                                                 twid=twid)

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True


```


## Line by Line Explanation of the Module


This section is for more detailed explaination of what each line of the module does.

```python
self.outputqueue = outputqueue
```

the outputqueue is used whenever the module wants to print something,
each module has it's own print() function that uses this queue.

So in order to print you simply write

    self.print("some text", 1, 0)

and the text will be sent to the outputqueue to process, log, and print to the terminal.

---

```python
self.config = config
```

This line is necessary if you need to read the ```config/slips.conf ``` configuration file for your own configurations

```python
__database__.start(redis_port)
```

This line starts the redis database, Slips mainly depends on redis Pub/Sub system for modules communications, 
so if you need to listen on a specific channel after starting the db you can add the following line to __init__()


Now here's the run() function, this is the main function of each module, it's the one that gets executed when the module starts.

All the code in this function should be run in a loop or else the module will finish execution and terminate.


```python
utils.drop_root_privs()
 ```


the above line is responsible for dropping root priveledges, so if slips starts with sudo and the module doesn't need the sudo permissions, we drop them.

```python
message = __database__.get_message(self.c1)
```

The above line listen on the c1 channel ('new ip') that we subscribed to earlier.

The messages recieved in the channel can either be stop_process or a message with data

```python
if message and message['data'] == 'stop_process':
```

The ```stop_message ``` is sent from the main slips.py to tell the module
that slips is stopping and the module should finish all the processing it's doing and shutdown.

So, for example if you're training a ML model in your module, and you want to save it before the module stops, 

You should place the save_model() function right above the following line, or inside the function
```python
self.shutdown_gracefully()
```

inside shutdown_gracefully() we have the following line

```python

__database__.publish('finished_modules', self.name)

```

This is the module, responding to the stop_message, telling slips.py that it successfully finished processing and
is terminating.

### Troubleshooting
Most errors occur when running the module inside SLIPS. These errors are hard to resolve, because warnings and debug messages may be hidden under extensive outputs from other modules.

If the module does not start at all, make sure it is not disabled in the config/slips.conf file. If that is not the case, check that the \_\_init\_\_.py file is present in module directory, and read the outputs - if there were any errors (eg. import errors), they would prevent the module from starting. 


In case that the module is started, but does not receive any messages from the channel, make sure that:

	-The channel is properly subscribed to the module

	-Messages are being sent trought the channels

	-Other modules subscribed to the channel get the message

	-Module is started in time (this should not be an issue in new SLIPS releases)

### Testing


Slips has 2 kinds of tests, unit tests and integration tests.

integration tests are done by testing all files in our ```dataset/``` dir and 
are done in ```tests/test_dataset.py```

Before pushing, run the unit tests and integration tests by:


1- Make sure you're in slips main dir (the one with kalipso.sh)


2- Run all tests ```./tests/run_all_tests.sh``` 

Slips supports the -P flag to run redis on your port of choice. this flag is
used so that slips can keep track of the ports it opened while testing and close them later.

### Adding your own unit tests

Slips uses ```pytest``` as the main testing framework, You can add your own unit tests by:

1- create a file called ```test_module_name.py``` in the ```tests/``` dir


2- every function should start with ```test_```


3- go to the main slips dir and run ```./tests/run_all_tests.sh``` and every test file in the ```tests/``` dir will run

### Getting in touch

Feel free to join our [Discord server](https://discord.gg/zu5HwMFy5C) and ask questions, suggest new features or give us feedback.

PRs and Issues are welcomed in our repo.

### Conclusion

Adding a new feature to SLIPS is an easy task. The template is ready for everyone to use and there is not much to learn about Slips to be able to write a module.

If you wish to add a new module to the Slips repository, issue a pull request and wait for a review. 
