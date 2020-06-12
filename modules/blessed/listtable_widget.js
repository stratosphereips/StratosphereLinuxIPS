 class Widget_listtable {
  constructor(grid,blessed) {
      this.blessed = blessed
      this.grid = grid
      this.widget =this.grid.set(3.1, 2, 1, 4, this.blessed.listtable,{
          keys: true,
          mouse: true,
          tags: true,
          border: 'line',
          style: {bg: 'blue'},
          style: {header: {fg: 'blue',bold: true},
                  cell: {fg: 'magenta',selected: {bg: 'blue'}}},
          align: 'left'})
  }
    setContent(data){
        this.widget.setData(data);}

    focus(){
      this.widget.focus()
      }
      
    hide(){
        this.widget.hide()
      }

}


module.exports = Widget_listtable