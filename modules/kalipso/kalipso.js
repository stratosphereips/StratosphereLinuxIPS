// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only

const { redis } = require("./kalipso_widgets/libraries.js");

/*Import all the widgets.*/
var screen_class = require('./kalipso_widgets/screen')
var redis_database_class = require('./kalipso_widgets/database')

var {argv} = require('yargs').option('l',{

            alias:     'limit_letter_outtuple',
            default:   200,
            describe:  'Include something',
            type:      'number',
            nargs: 1

    }).option('p',{

            alias: 'redis_port',
            describe:  'port to use for redis database',
            type:     'number',
            nargs: 1

    });

const {limit_letter_outtuple, redis_port } = argv


// Initialize all channels in Redis database.
const redis_database = new redis_database_class(redis, redis_port)
redis_database.createClient()

// Initialize screen with all necessary widgets.
const screen = new screen_class(redis_database,limit_letter_outtuple)

// Register all keypresses in the screen.
screen.registerEvents()
screen.update_interface()
