# Training

Slips has one machine learning module that can be retrained by users. This is done by puttin slips in training mode so you can re-train the machine learning models with your own traffic. By default Slips includes an already trained model with our data, but it is sometimes necessary to adapt it to your own circumstances.

Until Slips 0.7.3, there is only one module for now that can do this, the one called 'flowmldetection'. This module analyzes flows one by one, as formatted similarly as in a conn.log Zeek file. This module is enabled by default in testing mode. This module uses by default the SGDClassifier with a linear support vector machine (SVM). The decision to use SVM was done because is one of the few algorithms that can be used for online learning and that can extend a current model with new data.

To re-train this machine learning algorithm, you need to do the following:

1- Edit the config/slips.yaml file to put Slips in train mode. Search the word __train__ in the section __[flowmldetection]__ and uncomment the __mode = train__ and comment __mode = test__. It should look like

    [flowmldetection]
    # The mode 'train' should be used to tell the flowmldetection module that the flows received are all for training.
    # A label should be provided in the [Parameters] section
    mode = train

    # The mode 'test' should be used after training the models, to test in unknown data.
    # You should have trained at least once with 'Normal' data and once with 'Malicious' data in order for the test to work.
    #mode = test

2- Establish the general label for all the traffic that you want to re-train with. For now we only support 1 label per file. Search in the [parameters] section and choose the type of traffic you will send to Slips.

    # Set the label for all the flows that are being read. For now only normal and malware directly. No option for setting labels with a filter
    label = normal
    #label = malicious
    #label = unknown

After this edits, just run Slips as usual with any type of input, for example with a Zeek folder.

    ./slips.py -c config/slips.yaml -f ~/my-computer-normal/

Or with a pcap file.

    ./slips.py -c config/slips.yaml -f ~/my-computer-normal2.pcap

3- If you have also malicious traffic, first change the label to malicious in config/slips.yaml

    # Set the label for all the flows that are being read. For now only normal and malware directly. No option for setting labels with a filter
    #label = normal
    label = malicious
    #label = unknown

    ./slips.py -c config/slips.yaml -f ~/my-computer-normal2.pcap

After this edits, just run Slips as usual with any type of input, for example another pcap

    ./slips.py -c config/slips.yaml -f ~/malware1.pcap

You can also run slips in an interface and train it directly with your data

    ./slips.py -c config/slips.yaml -i eth0

4- Finally to use the model, put back the __test__ mode in the configuration config/slips.yaml

    [flowmldetection]
    # The mode 'train' should be used to tell the flowmldetection module that the flows received are all for training.
    # A label should be provided in the [Parameters] section
    #mode = train

    # The mode 'test' should be used after training the models, to test in unknown data.
    # You should have trained at least once with 'Normal' data and once with 'Malicious' data in order for the test to work.
    mode = test

5- Use slips normally in files or interfaces

    ./slips.py -c config/slips.yaml -i eth0
