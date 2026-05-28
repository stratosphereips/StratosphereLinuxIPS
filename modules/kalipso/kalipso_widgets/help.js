// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib } = require("./libraries.js");
const listTable = require("../lib_widgets/listtable.js")
var async = require('async')
var color = require('chalk')
var stripAnsi = require('strip-ansi')

class Help extends listTable.ListTableClass{

    constructor(grid, redis_database, characteristics){
        super(grid, redis_database, characteristics)
    }


      /*Set data for the help*/
    setHelp(){
        var data = [['hotkey', 'description'],
                    ['-h','help for hotkeys.'],
                    ['-e','src ports when the IP of the profile acts as clien. Total flows, packets and bytes going IN a specific source port.'],
                    ['-d','dst IPs when the IP of the profile acts as client. Total flows, packets and bytes going TO a specific dst IP.'],
                    ['-r','dst ports when the IP of the profile as server. Total flows, packets and bytes going TO a specific dst IP.'],
                    ['-f','dst ports when the IP of the profile acted as client. Total flows, packets and bytes going TO a specific dst port.'],
                    ['-t','dst ports when the IP of the profile acted  as client. The amount of connections to a dst IP on a specific port .'],
                    ['-i','outTuples "IP-port-protocol" combined together with outTuples Behavioral letters, DNS resolution  of the IP, ASN, geo country and Virus Total summary.'],
                    ['-y','inTuples "IP-port-protocol" combined together with inTuples Behavioral letters, DNS resolution  of the IP, ASN, geo country and Virus Total summary.'],
                    ['-z', 'evidences from all timewindows in the selected profile.' ],
                    ['-o','manually update the tree with profiles and timewindows. Default is 2 minutes. '],
                    ['-q','exit the hotkey'],
                    ['-ESC','exit Kalipso']]
        this.setData(data)
    }
}

module.exports = {HelpClass:Help}
