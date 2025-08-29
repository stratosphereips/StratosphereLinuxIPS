// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib, async, color, stripAnsi } = require("../kalipso_widgets/libraries.js");

class Tree{
    constructor(grid){
		  this.grid = grid
		  this.widget =this.grid.set(0,0,5.7,1, blessed_contrib.tree,
			  { vi:true
			  , style: {fg:'green',border: {fg:'blue'}}
			  , template: { lines: true }
			  , label: 'IPs'})
    }

    /*Focus on the widget in the screen*/
    focus(){
        this.widget.focus()
    }

    /*Hide widget in the screen.*/
    hide(){
        this.widget.hide()
  	}

  	/*Show widget in the screen*/
    show(){
	    this.widget.show()
    }

    /*Set data in the widget*/
    setData(data){
      	this.widget.setData({extended:true, children:data})
    }
}

module.exports = {TreeClass:Tree}
