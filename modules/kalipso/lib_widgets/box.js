// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib } = require("../kalipso_widgets/libraries.js");

class Box{
    constructor(grid, gridParameters, widgetParameters){
      this.grid = grid
      this.widget = this.initBox(gridParameters, widgetParameters);
    }

    /*Initialize the parameters for the widgets 'Box'.*/
    initBox(gridParameters, widgetParameters){
        return this.grid.set(gridParameters[0], gridParameters[1], gridParameters[2], gridParameters[3],
                            blessed.box,
                            widgetParameters)
    }

    /*Set data in the widget*/
    setData(data){
        this.widget.setContent(data)
    }

    /*Hide the widget from the screen*/
    hide(){
        this.widget.hide()
    }

    /*Show the widget on the screen*/
    show(){
        this.widget.show()
    }

    /*Focus on the widget in the screen*/
    focus(){
        this.widget.focus()
    }
}

module.exports  = { BoxClass: Box }
