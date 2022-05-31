# How to Create a New Slips Module



## What is SLIPS and why are modules useful
Slips is a machine learning-based intrusion prevention system for Linux and MacOS, developed at the Stratosphere Laboratories from the Czech Technical University in Prague. Slips reads network traffic flows from several sources, applies multiple detections (including machine learning detections) and detects infected computers and attackers in the network. It is easy to extend the functionality of Slips by writing a new module. This blog shows how to create a new module for Slips from scratch.

## Goal of this Blog
This blog creates an example module to detect when any private IP address communicates with another private IP address. What we want is to know if, for example, the IP 192.168.4.2, is communicating with the IP 192.168.4.87. This simple idea, but still useful, is going to be the purpose of our module. Also, it will generate an alert for Slips to consider this situation. Our module will be called 'local_connection_detector'.

### High-level View of how a Module Works
Structure of the module.. run(), the idea of while True...


## Developing a Module
When Slips runs, it automatically loads all the modules inside the ```modules/``` directory. Therefore, our new module should be placed there. Slips has a template module directory that we are going to copy and then modify for our purposes.

```bash
cp -a modules/template modules/local_connection_detector
```    

### Changing the Name of the Module
Change the python file name

```bash
asdf
```

Change the name inside the py. Find the lines with the name and description in the class 'Module' and change them:

```python
name = 'flowmldetection'
description = (
    'Train or test a Machine Learning model to detect malicious flows'
    )
authors = ['Your name']
```

At the end you should have a structure like this:
```
modules/
├─ scan_detector/
│  ├─ __init__.py
│  ├─ scan_detector
```

The __init__.py is to make sure the module is treated as a python package, don't delete it


### Explain the channel you have to register and what it does
You don't have to modify the code here, but see that...
```python
self.c1 = __database__.subscribe('new_flow')
```

```python
message = self.c1.get_message(timeout=self.timeout)
```

The line xxxxx checks that the channel you subscribe received the data correctly so you can access it.
```python
if message and message['channel'] == 'new_flow':
```

- extract the src ip
- extract the dst ip
- check if any are private, import ipaddress, and do ip = ipaddress.ipv4..., is_local()
- If it is true, generate evidence for slips


### Testing of the Module
The module is now ready to be uses. You can copy/paste the complete code that is on /ref{complete-core}

```python
./slips.py -c sdfasfasfdasfd -f dataset/test3.binetflow -o output....
```
And you should see in ./output/slips.log something and in ./output/alerts.log your alert

```bash
example output of alert.log
```


### Conclusion
-  links
- The names and descriptions of the modules are printed when slips is starting along with the module's PID.
- what is the self.print function

## Complete Code
have the whole asdfasf.py code for copy/paste.

```python

asf
asf
asf
as
fsa
dfas
df
asfa
sf
asf
asd
fas

```


## Line by Line Explanation of the Module

Let's look at what each line does:

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

This line is necessary if you need to read the ```slips.conf ``` configuration file for your own configurations

        __database__.start(self.config, redis_port)

This line starts the redis database, Slips mainly depends on redis Pub/Sub system for modules communications, 
so if you need to listen on a specific channel after starting the db you can add the following line to __init__()




        self.timeout = 0.0000001

Is used for listening on the redis channel, if your module will be using 1 channel, timeout=0 will work fine, but in order to 
listen on more than 1 channel, you need to set a timeout so that the module won't be stck listening on the same channel forever.


Now here's the run() function, this is the main function of each module, it's the one that gets executed when the module starts.

All the code in this function should be run in a loop or else the module will finish execution and terminate.



utils.drop_root_privs()

the above line is responsible for dropping root priveledges, so if slips starts with sudo and the module doesn't need the sudo permissions, we drop them.




    message = self.c1.get_message(timeout=self.timeout)

The above line listen on the c1 channel ('new ip') that we subscribed to earlier.

The messages recieved in the channel can either be stop_process or a message with data

        if message and message['data'] == 'stop_process':

The ```stop_message ``` is sent from the main slips.py to tell the module
that slips is stopping and the module should finish all the processing it's doing and shutdown.

So, for example if you're training a ML model in your module, and you want to save it before the module stops, 

You should place the save_model() function right above the following line, or inside the function

    self.shutdown_gracefully()

inside shutdown_gracefully() we have the following line

    __database__.publish('finished_modules', self.name)

This is the module, responding to the stop_message, telling slips.py that it successfully finished processing and
is terminating.
