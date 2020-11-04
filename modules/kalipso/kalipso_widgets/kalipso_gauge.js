var async = require('async')
/*
Widget contrib.gaugeList to display received data (usually totalflows, totalbytes and totalpackets) in stacked bars
*/
class Gauge{
  constructor(grid, blessed, contrib, redis_database,screen, characteristics){
      this.contrib = contrib
      this.screen = screen
      this.blessed = blessed
      this.grid = grid
      this.redis_database = redis_database
      this.widget = this.initGauge(characteristics);
}

initGauge(characteristics){
  /*
  Widget initialisation and its papameters
  */
  return this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], this.contrib.gaugeList,
      { style:{
          border:{ fg:'blue'},
          focus: {border:{ fg:'magenta'}}},
        keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      })
      }
  
hide(){
  /*
  To hide the widget
  */
  this.widget.hide()
    }
show(){
  /*
  To show the widget
  */
  this.widget.show()
    }
focus(){
  /*
  To focus on the widget
  */
  this.widget.focus()
    }
setData(data){
  /*
  To set data in the widget
  */
  this.widget.setGauges(data)
    } 
}

module.exports = Gauge
