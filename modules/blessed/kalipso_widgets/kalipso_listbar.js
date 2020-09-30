/*
This is the widget to display hotkeys and their letters in the bottom
*/
class ListBar{

  constructor(grid, blessed, contrib, redis_database,screen ){
        this.contrib = contrib
        this.screen = screen
        this.blessed = blessed
        this.grid = grid
        this.redis_database = redis_database
        this.widget = this.initWidget()
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

  initWidget(){
    /*
    Widget initialisation on the screen abd its parameters
    */
    return this.grid.set(5.7,0,0.4,6,this.blessed.listbar,{
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
                'main':{
                  keys : ' '},
                
                'srcPortClient': {
                  keys: ['e']
                            },

                'dstIPsClient': {
                  keys: ['c']
                            },

                'dstPortServer': {
                  keys: ['b']
                            },

                'dstPortsClient': {
                  keys: ['p']
                            },

                'dstPortsClientIPs': {
                  keys: ['f']
                            },
                
                'OutTuples': {
                  keys: ['h']
                            },

                'InTuples': {
                  keys: ['i']
                            },
           
                'reload':{
                  keys : ['o']
                         },    

                'quit hotkey':{
                  keys : ['q']
                         },  

                'quit kalipso':{
                  keys : ['ESC']
                         },                 
            }
    })
  }
selectTab(key){
  this.widget.selectTab(key)
}
}

module.exports = ListBar