const { redis, blessed, blessed_contrib } = require("../kalipso_widgets/libraries.js");

class Table{

    constructor(grid, characteristics){
        this.grid = grid
        this.widget = this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], blessed_contrib.table,
        {
          keys: true
        , vi:true
        , style:{border:{ fg:'blue'}}
        , interactive:characteristics[6]
        , scrollbar: true
        , label: characteristics[4]
        , columnWidth: characteristics[5]
        }
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
