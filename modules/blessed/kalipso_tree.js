var async = require('async')
var stripAnsi = require('strip-ansi')

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
    }

    focus(){
      this.widget.focus()
      }

    on(){
     	this.widget.on('select',node=>{
	  if(!node.name.includes('timewindow')){
      	var ip = node.name.replace('(host)','')
      	this.ipinfo.setIPInfo(stripAnsi(ip))
      }
      else{

      	var ip  = stripAnsi(node.parent.name);
      	ip = ip.replace('(host)','')
    	var timewindow = stripAnsi(node.name);
    	this.evidence.setEvidence(ip, timewindow)
    	this.timeline.setTimeline(ip, timewindow)
    	this.screen.render()}
		});
    }
    hide(){
        this.widget.hide()
  	}
    show(){
	    this.widget.show()
    }

    setData(data){
      	this.widget.setData({extended:true, children:data})
    }

    setTree(values){
      	return new Promise(resolve=>{
      		var ips_tws = this.tree_data
      	    var result = {};
      		var ips_with_profiles = Object.keys(ips_tws)//this.tree_data);
      		for( var i=0; i<ips_with_profiles.length; i++){
          		var tw = ips_tws[ips_with_profiles[i]];
          		var child = ips_with_profiles[i];
          // var sorted_tws = this.sortTWs(blockedIPsTWs,tw[0], child)
        //   if(child.includes(hostIP)){var new_child = child+ '(host)'}
        //   else{var new_child = child}
        // if(Object.keys(blockedIPsTWs).includes(child)){
        //   result[child] = { name:color.red(new_child), extended:false, children: sorted_tws};
        // }
        // else{
          // console.log(result['10.0.2.2'])
          		result[child] = { name:child, extended:false, children: tw[0]};
        }
        resolve (result)	     
      	})
	}

	sortTWs(blocked,tws_dict, ip){
	  // var new_keys = []
	  var blocked_tws = blocked[ip];
	  var keys = Object.keys(tws_dict); // or loop over the object to get the array
	// keys will be in any order
	   keys.sort(); // maybe use custom sort, to change direction use .reverse()
	// keys now will be in wanted order
	  var temp_tws_dict = {};
	  for (var i=0; i<keys.length; i++) { // now lets iterate in sort order
	      var key = keys[i];
	      if(blocked_tws != undefined && blocked_tws.includes(key)){
	        temp_tws_dict[color.red(key)] = {};}
	      else{
	        temp_tws_dict[key] = {};}
	  } 
	  return temp_tws_dict;
	}


	fillTreeData(redis_keys){
		return Promise.all([redis_keys[0].map(key_redis =>this.getTreeData(key_redis)),this.getBlockedIPsTWs(redis_keys[1]), redis_keys[2]]).then(values=>{this.setTree(values).then(values=>{this.setData(values); this.screen.render()})}) 
		}

	getTreeDataFromDatabase(){
		return Promise.all([this.redis_database.getAllKeys(),this.redis_database.getBlockedIPsTWs(), this.redis_database.getHostIP()]).then(values=>{this.fillTreeData(values)})
		
	}

	getBlockedIPsTWs(reply_blockedIPsTWs){ 
		return new Promise((resolve, reject)=>{
			var blockedIPsTWs = {};
			async.each(reply_blockedIPsTWs,(blockedIPTW_line,callback)=>{
				var blockedIPTW_list = blockedIPTW_line.split('_');
				if(!Object.keys(blockedIPsTWs).includes(blockedIPTW_list[1])){
					blockedIPsTWs[blockedIPTW_list[1]] = [];
					blockedIPsTWs[blockedIPTW_list[1]].push(blockedIPTW_list[2])
				}
				else{blockedIPsTWs[blockedIPTW_list[1]].push(blockedIPTW_list[2])}
				callback()
		},function(err){
		if(err){reject(err);}
		else{ resolve(blockedIPsTWs)}
		})

		})
	}

	getTreeData(redis_key){
		
		if(redis_key.includes('timeline')){
        var redis_key_list = redis_key.split('_')
        if(!Object.keys(this.tree_data).includes(redis_key_list[1])){
          this.tree_data[redis_key_list[1]]  = [];
          this.tree_data[redis_key_list[1]][0] = {};
          this.tree_data[redis_key_list[1]][0][redis_key_list[2]]={};}
        else{
          this.tree_data[redis_key_list[1]][0][redis_key_list[2]]={};
        	}
    	
	}
}

}
module.exports = Tree