const blessed = require('blessed')
const blessed_contrib = require('blessed-contrib')
const redis = require('redis')
const async = require('async')
const color = require('chalk')
const stripAnsi = require('strip-ansi')
const sortedArray = require('sorted-array-async');


module.exports = {
    blessed,
    blessed_contrib,
    redis,
    async,
    color,
    stripAnsi,
    sortedArray
};