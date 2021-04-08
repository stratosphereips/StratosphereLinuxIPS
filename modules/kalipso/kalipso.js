/*Import all the widgets.*/
var screen_class = require('./kalipso_widgets/kalipso_screen')
var blessed = require('blessed')
var contrib = require('blessed-contrib')
var redis = require('redis')
var redis_database_class = require('./kalipso_widgets/kalipso_redis')
var tree = require('./kalipso_widgets/kalipso_tree')
var table = require('./kalipso_widgets/kalipso_table')
var box = require('./kalipso_widgets/kalipso_box')
var listtable = require('./kalipso_widgets/kalipso_listtable')
var gauge = require('./kalipso_widgets/kalipso_gauge')
var combine_listtable_gauge = require('./kalipso_widgets/kalipso_connect_listtable_gauge')
var listbar = require("./kalipso_widgets/kalipso_listbar")

var {argv} = require('yargs').option('l',{

            alias:     'limit_letter_outtuple',
            default:   200,
            describe:  'Include something',
            type:      'number',
            nargs: 1

    });

const {limit_letter_outtuple} = argv

// Initialize all channels in Redis database.
const redis_database = new redis_database_class(redis)
redis_database.createClient()

// Initialize screen with all necessary widgets.
const screen = new screen_class(blessed, contrib, redis_database,tree, table, box,listtable, gauge, combine_listtable_gauge, listbar,limit_letter_outtuple)
screen.init()
screen.render()

// Register all keypresses in the screen.
screen.registerEvents()
screen.update_interface()

