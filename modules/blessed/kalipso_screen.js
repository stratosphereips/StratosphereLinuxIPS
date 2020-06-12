class screen {
  constructor(blessed, contrib, redis_database,tree_class, timeline_class) {
      this.blessed = blessed
      this.contrib = contrib
      this.tree_class = tree_class
      this.redis_database = redis_database
      this.timeline_class= timeline_class
      this.screen = undefined
      this.grid = undefined
      this.tree_widget = undefined
      this.timeline_widget = undefined
      }

    init(){
    	this.initScreen()
    	this.initGrid()
      this.initTimeline()
    	this.initTree()
    	this.render()
    }

    initScreen(){
    	this.screen =this.blessed.screen()
    }

    initGrid(){
    	this.grid =  new this.contrib.grid({
		  rows: 6,
		  cols: 6,
		  screen: this.screen
		});
		
    }
    initTimeline(){
      this.timeline_widget = new this.timeline_class(this.grid, this.blessed, this.contrib, this.redis_database, this.screen)
      this.append(this.timeline_widget.widget)
      this.render()
    }
    initTree(){
    	this.tree_widget = new this.tree_class(this.grid, this.blessed, this.contrib, this.redis_database, this.timeline_widget, this.screen)
      this.append(this.tree_widget.widget)
    	this.tree_widget.getTreeDataFromDatabase() 
      this.tree_widget.focus()
      this.tree_widget.on()
    	this.render()

    }

    append(widget){
    	this.screen.append(widget)
    }

    registerEvents(){
        this.screen.on('keypress', (ch, key)=>{
        	if(key.name == 'tab'){
        		this.timeline_widget.focus()
        		this.render()
        	}	
        	else if(key.name == 'f'){
        		this.tree_widget.show()
        		this.render()
        	}	
        	else if(key.name == 'q'){
        		return process.exit(0);
        	}
        })}

    render(){
    	this.screen.render()
    }

}

module.exports = screen;