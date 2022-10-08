const { redis, blessed, blessed_contrib, async, color, stripAnsi } = require("../kalipso_widgets/libraries.js");


class Gauge{
    constructor(grid, gridParameters, widgetParameters){
        this.grid = grid
        this.widget = this.initGauge(gridParameters, widgetParameters);
    }

    /*Initialize the widget gauge and its parameters*/
    initGauge(gridParameters, widgetParameters){
        return this.grid.set(gridParameters[0],gridParameters[1],gridParameters[2], gridParameters[3],
                    blessed_contrib.gaugeList,
                    widgetParameters)
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
