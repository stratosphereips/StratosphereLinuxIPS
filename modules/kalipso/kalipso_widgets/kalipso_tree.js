var async = import('async')
var stripAnsi = import('strip-ansi')
var color = import('chalk')

class Tree{
    constructor(grid, blessed, contrib, redis_database, timeline_widget, screen, evidence_widget,ipinfo_widget){
		  this.contrib = contrib
		  this.screen = screen
		  this.blessed = blessed
		  this.grid = grid
		  this.redis_database = redis_database
		  this.timeline = timeline_widget
		  this.evidence = evidence_widget
		  this.ipinfo = ipinfo_widget
		  this.widget =this.grid.set(0,0,5.7,1,this.contrib.tree,
			  { vi:true
			  , style: {fg:'green',border: {fg:'blue'}}
			  , template: { lines: true }
			  , label: 'IPs'})
		  this.tree_data = {}
		  this.current_ip = ''
		  this.current_tw = ''
    }

    /*Focus on the widget in the screen*/
    focus(){
        this.widget.focus()
    }

    /*Function to manipulate tree, timeline, evidence*/
    on(){
    	// node is the widgest name

        this.widget.on('select',node=>{
        	// comes here when you press enter on an IP in the leftmost widget(the one that has iPs and tws)
		  	if(!node.name.includes('timewindow')){
		  		// get the ip of the host
	    	  	var ip = node.name.replace(' (me)','')
	    	    ip = ip.replace(' (old me)','')
	    	  	ip = stripAnsi(ip)
		      	this.current_ip = ip
				// fill the widget at the top right of the screen with this IP info
		      	this.ipinfo.setIPInfo(ip)
	        	}
	      	else{
	      		// comes here when you press enter on a tw in the leftmost widget(the one that has iPs and tws)
		      	var ip  = stripAnsi(node.parent.name);
		      	ip = ip.replace(' (me)','')
		        ip = ip.replace(' (old me)','')
		    	var timewindow = stripAnsi(node.name);
		    	this.current_ip = ip
		    	this.current_tw = timewindow
				// prepare what to show when pressing z
		    	this.evidence.setEvidence(ip, timewindow)
				// prepare timeline for this ip,tw
		    	this.timeline.setTimeline(ip, timewindow)
		    	this.screen.render()
		    	}
			});
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

    /*Fill tree with Profile IPs and their timewindows, highlight blocked timewindows and the host*/
    setTree(values, blockedIPsTWs,hostIP){
      	return new Promise(resolve=>{
      		var ips_tws = this.tree_data
      	    var result = {};
      		var ips_with_profiles = Object.keys(ips_tws)
      		for(var i=0; i<ips_with_profiles.length; i++){
          		var tw = ips_tws[ips_with_profiles[i]];
          		var child = ips_with_profiles[i];
                var sorted_tws = this.sortTWs(blockedIPsTWs,tw[0], child)
                var new_child = child
                var length_hostIP = hostIP.length
                async.forEachOf(hostIP,(ip,ind, callback)=>{
	            if(child.includes(ip) && ind == length_hostIP - 1 )
	            	{
	            	new_child = child + ' (me)'
	             	}
	             else if(child.includes(ip)){
                    new_child = child+ ' (old me)'
	                }

	            callback();
	            }, (err)=>{
	            if(err)console.log('Check setTree in kalipso_tree.js. Error: ',err)
		        if(Object.keys(blockedIPsTWs).includes(child))
		        	{
		        	if(this.current_ip.includes(child)){
		          	    result[child] = { name:color.red(new_child), extended:true, children: sorted_tws};}
		          	else{
		          	result[child] = { name:color.red(new_child), extended:false, children: sorted_tws}}
		        	}	
		        else
		        	{
		        	if(this.current_ip.includes(child)){
		          	    result[child] = { name:new_child, extended:true, children: tw[0]};}
		          	else{
		          	    result[child] = { name:new_child, extended:false, children: tw[0]};
		          	}
		        	}
		        resolve (result)})
		    }
     	})
	}

    /*Function to sort timewindows in ascending order*/
	sortTWs(blocked,tws_dict, ip){

		var blocked_tws = blocked[ip];
	    var keys = Object.keys(tws_dict);
	    keys.sort(function(a,b){return(Number(a.match(/(\d+)/g)[0]) - Number((b.match(/(\d+)/g)[0])))}); 
	    var temp_tws_dict = {};
	    for (var i=0; i<keys.length; i++){ 
		    var key = keys[i];
		    if(blocked_tws != undefined && blocked_tws.includes(key)){
		    temp_tws_dict[color.red(key)] = {}
			}
		    else{
		    temp_tws_dict[key] = {}
			}
	    } 
	    return temp_tws_dict;
	}

    /*Reprocess the necessary data for the tree*/
	fillTreeData(redis_keys){
		return Promise.all([redis_keys[0].map(key_redis =>this.getTreeData(key_redis)),this.getBlockedIPsTWs(redis_keys[1]), redis_keys[2]]).then(values=>{this.setTree(values[0],values[1],values[2]).then(values=>{this.setData(values); this.screen.render()})}) 
    }

    /*Prepare needed data from Redis to fill the tree and call the next function to format data*/
	getTreeDataFromDatabase(){
		return Promise.all([this.redis_database.getAllKeys(),this.redis_database.getBlockedIPsTWs(), this.redis_database.getHostIP()]).then(values=>{this.fillTreeData(values)})
	}

    /*Get profiles and timewindows that are blocked*/
	getBlockedIPsTWs(reply_blockedIPsTWs){
		return new Promise((resolve, reject)=>{
			var blockedIPsTWs = {};
			async.each(reply_blockedIPsTWs,(blockedIPTW_line,callback)=>{
				var blockedIPTW_list = blockedIPTW_line.split('_');
				if(!Object.keys(blockedIPsTWs).includes(blockedIPTW_list[1]))
				{
					blockedIPsTWs[blockedIPTW_list[1]] = [];
					blockedIPsTWs[blockedIPTW_list[1]].push(blockedIPTW_list[2])
				}
				else{blockedIPsTWs[blockedIPTW_list[1]].push(blockedIPTW_list[2])}
				callback()
			},(err)=>{
			if(err){console.log('Check getBlockedIPsTWs in kalipso_tree.js. Error: ', err); reject(err);}
			else{ resolve(blockedIPsTWs)}
			})
		})
	}

    /*Get tree nodes. Node is an IP of profile*/
	getTreeData(redis_key){
		if(redis_key.includes('timeline')){
	        var redis_key_list = redis_key.split('_')
	        if(!Object.keys(this.tree_data).includes(redis_key_list[1]))
	        {
	          this.tree_data[redis_key_list[1]]  = [];
	          this.tree_data[redis_key_list[1]][0] = {};
	          this.tree_data[redis_key_list[1]][0][redis_key_list[2]]={}
	      	}
	        else
	        {
	          this.tree_data[redis_key_list[1]][0][redis_key_list[2]]={};
	    	}
  		  	
		}
	}
}

module.exports = Tree
