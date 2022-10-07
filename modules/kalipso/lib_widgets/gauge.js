const { redis, blessed, blessed_contrib } = require("./libraries.js");

var async = require('async')

class Gauge{
    constructor(grid, characteristics){
        this.grid = grid
        this.widget = this.initGauge(characteristics);
    }

    /*Initialize the widget gauge and its parameters*/
    initGauge(characteristics){
        return this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], blessed_contrib.gaugeList,
            {style:{
                    border:{ fg:'blue'},
                    focus: {border:{ fg:'magenta'}}},
            keys:true,
            gaugeSpacing: 1,
            gaugeHeight: 1,
            gauges:[]
            })
        }

    /*Hide the widget on the screen*/
    hide(){
        this.widget.hide()
    }

    /*Show the widget on the screen*/
    show(){
        this.widget.show()
    }

    /*Focus on the widget on the screen*/
    focus(){
        this.widget.focus()
    }

    /*Set data in the widget*/
    setData(data){
        this.widget.setGauges(data)
    } 
}

module.exports = {GaugeClass:Gauge}
