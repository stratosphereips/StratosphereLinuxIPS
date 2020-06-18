var screen_class = require('./kalipso_screen')
var blessed = require('blessed')
var contrib = require('blessed-contrib')
var redis = require('redis')
var redis_database_class = require('./kalipso_redis')
var tree = require('./kalipso_tree')
var table = require('./kalipso_table')
var box = require('./kalipso_box')


const redis_database = new redis_database_class(redis)
redis_database.createClient()

const screen = new screen_class(blessed, contrib, redis_database,tree, table, box)

screen.init()
screen.render()
screen.registerEvents()

