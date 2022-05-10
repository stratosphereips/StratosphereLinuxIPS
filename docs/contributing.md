# Contributing
To help Slips grow, you can:
	- use Slips, open GitHub issues/push requests with new features and bugs.
	- implement new Slips detection module, and do Github push request to Slips repo.

Below we will describe base steps to implement new detection module in Slips.

## Implement new module
Slips is a modular software. It uses modules that process the data further, perform additional checks and store more data for other modules to use. It is easy to write a new module for SLIPS to extend its functionality, as modules are python files mostly independent of the complex SLIPS structure.

### Getting started

To start writing the module, create a fork of the Slips repository and a new branch with a descriptive name. The recent development branch is **develop**, so be sure to use it. For easy module creation, a template is present in the repository. Create a new folder for the new module in *modules* folder of the repo. For example, for virustotal module it would be:

```modules/virustotal/```

Once created, copy the contents of ./modules/template on this new folder. There is an empty \_\_init\_\_.py file, without which the module would not be found, and a template.py file, which should be renamed to match the folder name: virustotal.py. In the template, change the class name and fill in the fields with basic information: name of the module, brief description and authors.

There are three functions in the template:

	-__init__(self, outputqueue, config):
	Starts a separate process, and subscribes to database channels

	- print(self, text, verbose=1, debug=0): 
	Sends print statements to output-process. This function must be used instead of printing directly

	- run(self):
	Main loop, the function waits for a message to arrive and processes it

The run function in the template has a sample code that prints number of profiles in the database:

```
# Main loop function
while True:
    message = self.c1.get_message(timeout=-1)
    if message['channel'] == 'new_ip':
        # Example of printing the number of profiles in the Database every second
        data = len(__database__.getProfiles())
        self.print('Amount of profiles: {}'.format(data))
```

This loop reads the new messages in the channel with new IPs and process them. Notice that there is a try catch clause around the loop, and any errors that are not caught and handled will jump out of the loop, crashing the module. Slips will not restart crashed modules, so taking care of all errors is important.

### Redis database

The data used in each of the modules is recevied from other processes directly or retrieved from the Redis database, where Slips stores all the information. Python file **StratosphereLinuxIPS/slips/common/database.py** contains get/set functions from/in the Redis database. To use this file in the module, we have import it in each of the modules:

```from slips.core.database import __database__```

An example of using the functions from the database.py after it was imported:

```__database__.set_virustotal_score(ip,ip_score)```


### Redis channels in Slips

As was already mentioned before, Slips uses channels to send updates from one process to another. Processes may create new channels and publish to them, and similarly, they can subscribe to channels and listen for new messages - which is what the VT module is doing. To go more into detail of Redis channels, see the overview on Redis website: https://redis.io/topics/pubsub.

After subscribing to the channel, the module is waiting for a message to come, and then starts processing the data. This may take some time - for example, if the VT API rejects a request because of API limits, the module must wait one minute (more in rare cases) until the request can be run again. The module will return to waiting for new messages on the channel only after processing of the previous message is finished. Fortunately, no messages will be dropped - they are queued and Redis will eventually deliver them in FIFO order (more on that in this StackOverflow thread: https://stackoverflow.com/questions/27745842/redis-pubsub-and-message-queueing). While the capacity of the queue is limited in theory, no messages were lost during the development and testing of the VT module.

As an example, currently, Slips has following channels, the modules can subscribe to:

```
def subscribe(self, channel):
    """ Subscribe to channel """
    # For when a TW is modified
    pubsub = self.r.pubsub()
    supported_channels = ['tw_modified' , 'evidence_added' , 'new_ip' ,  'new_flow' , 'new_dns', 'new_dns_flow','new_http', 'new_ssl' , 'new_profile',\
                    'give_threat_intelligence', 'new_letters', 'ip_info_change', 'dns_info_change', 'dns_info_change', 'tw_closed', 'core_messages',\
                    'new_blocking', 'new_ssh','new_notice']
    for supported_channel in supported_channels:
        if supported_channel in channel:
            pubsub.subscribe(channel)
            break
    return pubsub
```

To subscribe a module to a channel, change the value of **self.c1** variable in \_\_init\_\_ function as in the template:

```
def __init__(self, outputqueue, config):
    multiprocessing.Process.__init__(self)
    # All the printing output should be sent to the outputqueue.
    # The outputqueue is connected to another process called OutputProcess
    self.outputqueue = outputqueue
    # In case you need to read the slips.conf configuration file for
    # your own configurations
    self.config = config
    # Start the DB
    __database__.start(self.config)
    # To which channels do you wnat to subscribe? When a message
    # arrives on the channel the module will wakeup
    # The options change, so the last list is on the
    # slips/core/database.py file. However common options are:
    # - new_ip
    # - tw_modified
    # - evidence_added
    # Remember to subscribe to this channel in database.py
    self.c1 = __database__.subscribe('new_ip')
```

### Reading values from the configuration file

The config file used by SLIPS is in the .conf format, and is parsed by the https://docs.python.org/3/library/configparser.html library. It contains comments (#), sections ([mysection]) and value declarations (key = value). This config file is used to set user parameters to run Slips, as timewindow width, ignore necessary modules, choose mode home/not home network, paths to API keys, etc. 

The path to Slips configuration file is specified in the *self.config* variable of \_\_init\_\_ function in the template:

`self.config = config`

An example of retrieving parameters from the configuration file:
```
try:
    self.key_file = self.config.get("virustotal", "api_key_file")
except (configparser.NoOptionError, configparser.NoSectionError, NameError):
    # There is a conf, but there is no option, or no section or no configuration file specified
    self.key_file = None
``` 
In this example, the path to the virustotal API key was retrieved from the *virustotal* section and *api_key_file* key.


## Plug in a zeek script

Slips supports automatically running a custom zeek script by adding it to ```zeek-scripts``` dir and adding the file name in ```zeek-scripts/__load__.zeek```.

For example, if you want to add a zeek script called ```arp.zeek``` you should add it to ```__load__.zeek``` like this:

	@load ./arp.zeek

Zeek output is suppressed by default, so if your script has errors, Slips will fail silently.


### Troubleshooting
Most errors occur when running the module inside SLIPS. These errors are hard to resolve, because warnings and debug messages may be hidden under extensive outputs from other modules.

If the module does not start at all, make sure it is not disabled in the slips.conf file. If that is not the case, check that the \_\_init\_\_.py file is present in module directory, and read the outputs - if there were any errors (eg. import errors), they would prevent the module from starting. 


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


2- Run all tests ```python3 tests/run_all_tests.py``` 


### Adding your own unit tests

Slips uses ```pytest``` as the main testing framework, You can add your own unit tests by:

1- create a file called ```test_module_name.py``` in the ```tests``` dir


2- every function should start with ```test_```


3- go to the main slips dir and run ```python3 tests/run_all_tests.py``` and every test file in the ```tests/``` dir will run

### Getting in touch

Feel free to join our [Discord server](https://discord.gg/zu5HwMFy5C) and ask questions, suggest new features or give us feedback.

PRs and Issues are welcomed in our repo.

### Conclusion
Adding a new feature to SLIPS is an easy task. The template is ready for everyone to use and there is not much to learn about Slips to be able to write a module.

If you wish to add a new module to the Slips repository, issue a pull request and wait for a review. 
