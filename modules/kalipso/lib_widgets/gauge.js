// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib, async, color, stripAnsi } = require("../kalipso_widgets/libraries.js");


class Gauge{
    constructor(grid, gridParameters ){
        this.grid = grid
        const widgetParameters =                {style:{
                    border:{ fg:'blue'},
                    focus: {border:{ fg:'magenta'}}},
            keys:true,
            gaugeSpacing: 1,
            gaugeHeight: 1,
            gauges:[]
            }
        this.widget = this.grid.set(gridParameters[0],gridParameters[1],gridParameters[2], gridParameters[3],
                    blessed_contrib.gaugeList,
                    widgetParameters);
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
