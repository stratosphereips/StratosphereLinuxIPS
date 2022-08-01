Kalipso is a graphical user interface based on Nodejs. To create a colorful interface 
in the command-line, Kalipso uses two javascript libraries: blessed and blessed-contrib. 

#Kalipso architecture
There is so-called 'screen' is created every time Kalipso is run. Kalipso fills the screen with
widgets (box, table, bar, tree, etc.) where all necessary information is displayed. 

For each type of the widget, there is a file in the folder 'kalipso_widgets'. Each widget has 4 basic functionalities:
(i) show - display the widget on the screen, 
(ii) hide - hide the widget on the screen, 
(iii) focus - focus on the widget on the screen, 
(iv) setData - put data inside the widget. 

Other functions shown in the files of 'kalipos_widgets' are mostly responsible for retrieving data from the
Redis database and formatting the data to be put in the widget. 

All widgets needed in Kalipso are initialized in *kalipso_screen.js*, and all the keypresses are captured there as well.
The main execution file is *kalipso.js*: libraries are imported and main screen is initialized.
Kalipso consists of a main page and hotkeys. 
 
## Kalipso main page
Kalipso main page consists of:

- tree widget (*kalipso_tree.js*) -  a widget that displays all profiles and
 their timewindows.
- timeline info box (*kalipso_table.js*) - a table that displays information about selected IP in the timeline.
- evidence box (*kalipso_box.js*) - a box that diplays all the evidences presented in the timewindow.
- listbar with shortcuts (*kalipso_listbar.js*)- a listbar with all the shortcuts for the hotkeys.

## Kalipso hotkeys
Kalipso has a lot of hotkeys:
- h (*kalipso_listtable.js*) - help for hotkeys
- e (*kalipso_connect_listtable_gauge.js*)  - src ports when the IP of the profile acts as client.
 Total flows, packets and bytes going IN a specific source port.
- d (*kalipso_connect_listtable_gauge.js*) - dst IPs when the IP of the profile acts as client. 
Total flows, packets and bytes going TO a specific dst IP.
- r (*kalipso_connect_listtable_gauge.js*) - dst ports when the IP of the profile as server. 
Total flows, packets and bytes going TO a specific dst IP.
- f (*kalipso_connect_listtable_gauge.js*) - dst ports when the IP of the profile acted as client.
 Total flows, packets and bytes going TO a specific dst port.
- t  (*kalipso_connect_listtable_gauge.js*) - dst ports when the IP of the profile acted  as client. 
The amount of connections to a dst IP on a specific port 
- i (*kalipso_listtable.js*) - outTuples ‘IP-port-protocol’combined together with outTuples
 Behavioral letters, DNS resolution  of the IP, ASN, geo country and 
 Virus Total summary.
- y (*kalipso_listtable.js*) - inTuples ‘IP-port-protocol’combined together with inTuples 
Behavioral letters, DNS resolution  of the IP, ASN, 
geo country and Virus Total summary.
- z (*kalipso_table.js*) - evidences from all timewindows in the selected profile.
- o (*kalipso_screen.js*) - manually update the tree with profiles and timewindows. Default is 2 minutes. 
- q (*kalipso_screen.js*) - exit the hotkey
- ESC (*kalipso_screen.js*) - exit Kalipso
  
## Setup
Install required NPM packages `npm install` and then start it up `npm run start`.