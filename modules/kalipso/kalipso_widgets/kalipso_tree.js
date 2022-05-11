var async = require('async')
var stripAnsi = require('strip-ansi')
var color = require('chalk')

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
        // node is the widget name

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
                // remove '(me)', '(old me)' and host name from the profile
                ip = ip.split(' ')[0]
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
            async.forEachOf(ips_with_profiles, (ip, ind, callback)=>{
                // get the twids of each ip
                var tw = ips_tws[ip];
                var sorted_tws = this.sortTWs(blockedIPsTWs, tw[0], ip)
                var decorated_ip = ip
                // get the length of the hostIP list
                var length_hostIP = hostIP.length

                this.redis_database.getHostnameOfIP("profile_" + ip).then(res => {
                    if(res){decorated_ip += " " +res;}

                    // check if the current ip aka child aka new_child is the same as any of the Host IPs
                    async.forEachOf(hostIP,(host_ip, ind, callback)=>{
                        // the last ip in hostIP list is the current host ip, this is the one we'll be adding (me) to
                        if(ip.includes(host_ip) && ind == length_hostIP - 1 )
                        {
                            // found a child that is also a host ip, add (me) next to the ip
                            decorated_ip += ' (me)'
                        }
                        else if(ip.includes(host_ip)){
                            decorated_ip += ' (old me)'
                        }
                        callback();
                    }, (err)=>{
                        if(err) {console.log('Check setTree in kalipso_tree.js. Error: ',err)}
                        // no errors, color the malicious ips in red
                        if(Object.keys(blockedIPsTWs).includes(ip))
                        {
                            result[ip] = { name:color.red(decorated_ip), extended:false, children: sorted_tws}
                        }
                        else
                        {
                            result[ip] = { name:decorated_ip, extended:false, children: sorted_tws}
                        }
                        resolve (result)})
                })
                callback();
            },
                 (err)=>{
                    if(err) {console.log('Check setTree in kalipso_tree.js. Error: ',err)}
            })
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
