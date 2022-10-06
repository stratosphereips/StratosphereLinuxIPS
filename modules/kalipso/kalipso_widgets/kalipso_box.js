var async = require('async')
var color = require('chalk')
const { redis, blessed, blessed_contrib } = require("./libraries.js");

class Box{
    constructor(grid, redis_database,screen, characteristics){
      this.screen = screen
      this.grid = grid
      this.redis_database = redis_database
      this.widget = this.initBox(characteristics);
    }

    /*Initialize the parameters for the widgets 'Box'.*/
    initBox(characteristics){
        return this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], blessed.box,{
            top: 'center',
            left: 'center',
            width: '50%',
            height: '50%',
            label:characteristics[4],
            tags: true,
            keys: true,
            style:{
              border:{ fg:'blue',type: 'line'},
              focus: {border:{ fg:'magenta'}}
            },
            vi:true,
            scrollable: true,
            alwaysScroll: true,
            scrollbar: {
              ch: ' ',
              inverse: true
            }
        })
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