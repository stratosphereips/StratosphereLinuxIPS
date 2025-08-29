// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib, async, color, stripAnsi } = require("../kalipso_widgets/libraries.js");

class ListBar{

    constructor(grid){
        this.grid = grid
        this.widget = this.initWidget()
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

    /*Initialize widget on the screen with its parameters*/
    initWidget(){
    return this.grid.set(5.7,0,0.4,6, blessed.listbar,{
          keys: false,
          style:
                {
            prefix: {fg: 'yellow'},
            item: {},
            selected:{fg:'red'}
                },
          autoCommandKeys: true,
          commands:
           {
                'main':{ keys : ' '},

                'srcPortClient': { keys: ['e'] },

                'dstIPsClient': { keys: ['d'] },

                'dstPortServer': { keys: ['r'] },

                'dstPortsClient': { keys: ['p'] },

                'dstPortsClientIPs': { keys: ['t'] },

                'OutTuples': { keys: ['i'] },

                'InTuples': { keys: ['y'] },

                'ProfileEvidences':{ keys : ['z'] },

                'reload':{ keys : ['o'] },

                'quit hotkey':{ keys : ['ESC'] },

                'quit kalipso':{ keys : ['q'] },

                 'help':{ keys: ['h'] }
           }
        })
    }

    /*Select key in the widget 'Listbar'*/
    selectTab(key){
        this.widget.selectTab(key)
    }
}

module.exports = {ListBarClass:ListBar}
