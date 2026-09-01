// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib } = require("./libraries.js");
const listTable = require("../lib_widgets/listtable.js")
var async = require('async')
var color = require('chalk')
var stripAnsi = require('strip-ansi')

class IpInfo extends listTable.ListTableClass{

    constructor(grid, redis_database,screen, characteristics){
        super(grid, redis_database, characteristics)
                this.screen = screen

    }

}

module.exports = {IpInfoClass:IpInfo}
