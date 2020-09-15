//import all widgets classes
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


const redis_database = new redis_database_class(redis)
//Initialize all channels in redis
redis_database.createClient()

//initialize screen with all necessary widget classes
const screen = new screen_class(blessed, contrib, redis_database,tree, table, box,listtable, gauge, combine_listtable_gauge, listbar)
screen.init()
screen.render()
//Register all keypresses in the screen
screen.registerEvents()
screen.update_interface()

