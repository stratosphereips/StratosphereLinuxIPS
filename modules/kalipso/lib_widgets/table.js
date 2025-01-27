// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib } = require("../kalipso_widgets/libraries.js");

class Table{

    constructor(grid, gridParameters, widgetParameters){
        this.widget = grid.set(gridParameters[0],gridParameters[1],gridParameters[2],gridParameters[3],
        blessed_contrib.table,
        widgetParameters
        )
    }

    /*Set data in the widget 'Table'*/
    setData(widget_headers, widget_data){
        this.widget.setData({headers:widget_headers, data:widget_data})
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
}

module.exports = {TableClass: Table};
