class ListBar{

    constructor(grid, blessed, contrib, redis_database,screen ){
        this.contrib = contrib
        this.screen = screen
        this.blessed = blessed
        this.grid = grid
        this.redis_database = redis_database
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

module.exports = ListBar