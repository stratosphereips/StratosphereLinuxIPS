class screen {
  constructor(blessed, contrib, redis_database,tree_class, timeline_class, box_class, listtable_class) {
      this.blessed = blessed
      this.contrib = contrib
      this.tree_class = tree_class
      this.redis_database = redis_database
      this.timeline_class= timeline_class
      this.box_class = box_class
      this.listtable_class = listtable_class
      this.screen = undefined
      this.grid = undefined
      this.tree_widget = undefined
      this.timeline_widget = undefined
      this.evidence_box_widget = undefined
      this.ipinfo_widget = undefined
      this.focus_widget = undefined
      this.outTuple_widget = undefined
      }

    init(){
    	this.initScreen()
    	this.initGrid()
      this.initBoxEvidence()
      this.initTimeline()
      this.initIPInfo()
    	this.initTree()
      this.initMain()

      this.initOutTuple()
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
    initOutTuple(){
      this.outTuple_widget = new this.listtable_class(this.grid, this.blessed, this.contrib, this.redis_database, this.screen, [0,0,5.7,6])
      this.outTuple_widget.hide()
    }
    initBoxEvidence(){
      this.evidence_box_widget = new this.box_class(this.grid, this.blessed, this.contrib, this.redis_database, this.screen, [4.8,1, 0.9, 5,'Evidence'])
    }
    initTimeline(){
      this.timeline_widget = new this.timeline_class(this.grid, this.blessed, this.contrib, this.redis_database, this.screen, [0.6, 1, 4.3, 5,'Timeline',[200], true])
    }
    initIPInfo(){
      this.ipinfo_widget = new this.timeline_class(this.grid, this.blessed, this.contrib, this.redis_database, this.screen, [0, 1, 0.6, 5,'IPInfo',[30,30,10,10,10,10], false])

    }
    initTree(){
    	this.tree_widget = new this.tree_class(this.grid, this.blessed, this.contrib, this.redis_database, this.timeline_widget, this.screen, this.evidence_box_widget, this.ipinfo_widget)
    	this.tree_widget.getTreeDataFromDatabase() 
      this.tree_widget.focus()
      this.tree_widget.on()
      this.tree_widget.widget.style.border.fg = 'magenta'
      this.focus_widget = this.tree_widget.widget

    }
    initMain(){
      this.mainPage = [this.tree_widget.widget, this.ipinfo_widget.widget, this.evidence_box_widget.widget, this.timeline_widget.widget]
    }

    append(widget){
    	this.screen.append(widget)
    }

    registerEvents(){
        this.screen.on('keypress', (ch, key)=>{
        if(key.name == 'tab'){
          if(this.focus_widget == this.tree_widget.widget){
            this.focus_widget = this.timeline_widget.widget
            this.tree_widget.widget.style.border.fg = 'blue'
            this.timeline_widget.widget.focus();}
          else if(this.focus_widget == this.timeline_widget.widget){
            this.timeline_widget.widget.style.border.fg='magenta'
            this.focus_widget = this.evidence_box_widget.widget
            this.evidence_box_widget.widget.focus()}
          else{
            this.focus_widget = this.tree_widget.widget
            this.tree_widget.widget.style.border.fg = 'magenta'
            this.tree_widget.focus();}
        		this.render()
        	}	
        	else if(key.name == 'q'){
        		return process.exit(0);
        	}
          else if(key.name == 'h'){ 
          console.log(this.tree_widget.current_ip, this.tree_widget.current_tw) 
            for(var widget = 0; widget<this.mainPage.length; widget++){
                this.mainPage[widget].hide()
              }
            this.outTuple_widget.setOutTuples(this.tree_widget.current_ip, this.tree_widget.current_tw)
            this.outTuple_widget.show()
            this.outTuple_widget.focus()
            this.render()
          }
        })}

    render(){
    	this.screen.render()
    }

}

module.exports = screen;