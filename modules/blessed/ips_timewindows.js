var redis = require('redis')
  , redis_ips_with_profiles = redis.createClient()
  , redis_tree = redis.createClient()
  , redis_tws_for_ip = redis.createClient()
  , redis_ip_info = redis.createClient()
  , redis_get_timeline = redis.createClient()
  , redis_outtuples_timewindow = redis.createClient()
  , redis_detections_timewindow = redis.createClient()
  , redis_timeline_ip = redis.createClient()
  , async = require('async')
  ,	blessed = require('blessed')
  , contrib = require('blessed-contrib')
  ,  fs = require('fs')
  , screen = blessed.screen()
  var colors = require('colors');

//read countries  location
let country_loc = {};
fs.readFile('country.txt', 'utf8', function(err,data) {
    if(err) throw err;
    
    let splitted = data.toString().split(";");
    for (let i = 0; i<splitted.length; i++) {
        let splitLine = splitted[i].split(":");
        try{
        country_loc[splitLine[0]] = splitLine[1].split(",");}
        catch(err){
        }
    }
});


// set up elements of the interface.

var grid = new contrib.grid({
  rows: 6,
  cols: 6,
  screen: screen
});
var table_timeline =  grid.set(0, 1, 2.5, 5, contrib.table, 
  {keys: true
  , vi:true
  , scrollbar: true
  , fg: 'green'
  , label: "Timeline"
  , columnWidth:[200]})

  ,table_outTuples =  grid.set(2.5,1,1.8,2.5, contrib.table, 
  { keys: true
  , vi:true
  , fg: 'green'
  , label: "OutTuples"
  
   , columnWidth:[25,30]})

  , tree =  grid.set(0,0,5,1,contrib.tree,
  {  vi:true 
  ,style: {border: {fg:'magenta'}}
  , template: { lines: true }
  , label: 'Ips from slips'})

  , box_ip = grid.set(5, 0, 0.5, 3.5, blessed.box,
      {top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      content: "SELECT IP TO SEE IPS INFO!",
      tags: true,
      border: {
      type: 'line'
    }})

 , box_detections = grid.set(2.5, 3.5, 0.9, 2.5,blessed.box,{
  		top: 'center',
  		left: 'center',
  		width: '50%',
  		height: '50%',
  		label:'Detections',
  		tags: true,
 		vi:true,
 		border: {
   		type: 'line'
 		}
	})
 , box_evidence = grid.set(3.4, 3.5, 0.9, 2.5,blessed.box,{
  		top: 'center',
  		left: 'center',
  		width: '50%',
  		height: '50%',
  		label:'Evidence',
  		tags: true,
  		keys: true,
  		vi:true,
  scrollable: true,
  alwaysScroll: true,
  scrollbar: {
    ch: ' ',
    inverse: true
  },
 		border: {
   		type: 'line'
 		},
	})
, box_hotkeys = grid.set(4.3, 1, 0.8, 1, blessed.box,
      {top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      content: "{bold}-e{/bold} -> dstPortClient\n{bold}-b{/bold} -> dstPortServer\n{bold}-c{/bold} -> SrcPortsClient\n{bold}-m{/bold} -> map",
      tags: true,
      border: {
      type: 'line'
    },
    })
, map = grid.set(0, 0, 6, 6,contrib.map,{label: 'World Map'})
map.hide()

 function round(value, decimals) {
  return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
};


function ip_tcp_bars(key, key2,reply,bar){
	if(reply[key]==null){
 		ip_udp_bars(key2,reply,[],[],bar);
 		return;
 	}

 	var bar_category_ips = [];
 	var data_stacked_bar = [];
 	try{
	    	var obj_ip = JSON.parse(reply[key]);
			var keys_ip = Object.keys(obj_ip);
		}
	catch(err){
	    	var obj_ip = reply[key];	
	    	var keys_ip = Object.keys(obj_ip);
	    }
	async.each(keys_ip, function(ip, callback) {
		bar_category_ips.push('TCP/'+ip);
		var ip_info = obj_ip[ip];
		var row = [];
		row.push(ip_info['totalflows'],ip_info['totalpkt']);
		data_stacked_bar.push(row);
		callback();
	}, function(err){
		if(err){
			console.log('sasdfsaa')
		}
		else{
			ip_udp_bars(key2,reply, bar_category_ips, data_stacked_bar,bar)

		}
	});

}

function ip_udp_bars(key,reply, bar_category_ips, data_stacked_bar,bar){
	if(reply[key]==null){
 		set_stacked_bar_ip(data_stacked_bar,bar_category_ips,bar);
 		return;
 	}

 	try{
	    	var obj_ip = JSON.parse(reply[key]);
			var keys_ip = Object.keys(obj_ip);
		}
	catch(err){
	    	var obj_ip = reply[key];	
	    	var keys_ip = Object.keys(obj_ip);
	    }
	async.each(keys_ip, function(ip, callback) {
		bar_category_ips.push('TCP/'+ip);
		var ip_info = obj_ip[ip];
		var row = [];
		row.push(ip_info['totalflows'],ip_info['totalpkt']);
		data_stacked_bar.push(row);
		callback();
	}, function(err){
		if(err){
			console.log('sasdfsaa')
		}
		else{
			set_stacked_bar_ip(data_stacked_bar, bar_category_ips, bar)

		}
	});
function set_stacked_bar_ip(data,bars,bar){
			if(data.length==0){
				bar.setData(
        	{ barCategory: bars
        	, stackedCategory: ['EMPTY']
        	, data: data})
			screen.render();

			}
			else{
			bar.setData(
        	{ barCategory: bars
        	, stackedCategory: ['totalflows', 'totalpkt']
        	, data: data})
			screen.render();}
		}

}

function setMap(ips){
	
	redis_ip_info.hgetall('IPsInfo', (err,reply)=>{
		async.each(ips, function(ip,callback){
			try{
			var inf = JSON.parse(reply[ip])
			}
			catch(err){
				return;
			}
			var country = inf["geocountry"]
			
			geoloc = country_loc[" "+country]
			
			if(geoloc!=undefined && geoloc !='Private'){
			
			var loc =country_loc[" "+country]
		 	map.addMarker({"lon" : loc[1], "lat" : loc[0], color: "red", char: "X" })}			
			callback();


	}, function(err){
		if(err){
			console.log(err)
		};
	
	})

	})
	
}
 function tcp_connections(key, key2,reply,bar){
 	if(reply[key]==null){
 		udp_connections(key2,[],[],reply,bar);
 		return;
 	}
		var bar_categories_protocol_port = [];
		var data_stacked_bar = []
  		
  		try{
	    	var obj_tcp = JSON.parse(reply[key]);
			var keys_tcp = Object.keys(obj_tcp);
		}
	    catch(err){
	    	var obj_tcp = reply[key];	
	    	var keys_tcp = Object.keys(obj_tcp);

	    }

  		async.each(keys_tcp, function(key_TCP_est, callback) {
  			bar_categories_protocol_port.push('TCP/'+key_TCP_est);
	    	var service_info = obj_tcp[key_TCP_est];
	    	var row = [];
	    	row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0));
	    	data_stacked_bar.push(row);
	    	
	    	callback();
	    	}, function(err) {

 		if( err ) {
 			console.log('unable to create user');
 		} else {
 			
 			udp_connections(key2,data_stacked_bar,bar_categories_protocol_port,reply,bar);
		}
		});}

function udp_connections(key,data_stacked_bar,bar_categories_protocol_port,reply,bar){
	if(reply[key]==null){
		set_stacked_bar(data_stacked_bar,bar_categories_protocol_port,bar)
	return;
	};
	
	try{
		var obj_udp = JSON.parse(reply[key]);
		var keys_udp = Object.keys(obj_udp);
	}
	catch(err){
		var obj_udp = reply[key];
		var keys_udp = Object.keys(obj_udp);
	}

	async.each(keys_udp, function(key_UDP_est, callback) {
		bar_categories_protocol_port.push('UDP/'+key_UDP_est);
	var service_info = obj_udp[key_UDP_est];
	var row = [];
	row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0));
	data_stacked_bar.push(row);
	callback()
	}, function(err) {

		if( err ) {
			console.log('unable to create user');
		} else {
			set_stacked_bar(data_stacked_bar,bar_categories_protocol_port,bar)
		}
	});

}		

function set_stacked_bar(data,bars,bar){
	if(data.length==0){
		bar.setData(
    	{ barCategory: bars
    	, stackedCategory: ['EMPTY']
    	, data: data})
		screen.render();
	}
	else{
		bar.setData(
    	{ barCategory: bars
    	, stackedCategory: ['totalflows', 'totalpkt', 'totalbytes']
    	, data: data})
		screen.render();}
	};

 function timewindows_list_per_ip(tw){

 	/*
 	create a list of dictionaries with tws(to set the tree). [{'tw1':{},'tw2':{}"}]
 	*/
	var temp_list = []
	var dict = {};
	for(i=0; i<tw.length; i++){
		dict[tw[i]] = {}};
		temp_list.push(dict);
	return temp_list;
 };



function getIpInfo_box_ip(ip){
	/*
	retrieves IPsInfo from redis.
	*/
	redis_timeline_ip.hgetall("IPsInfo",(err,reply)=>{
		try{
		var obj = JSON.parse(reply[ip]);
  		var l =  Object.values(obj)
  		box_ip.setContent(l.join(', '));
      	screen.render();}
      	catch (err){
      		box_ip.setContent(reply[ip]);

      	    screen.render();
      	}
    });
};

function getEvidence(reply){
	/*
	retrieves IPsInfo from redis.
	*/var ev = ''

		try{
		var obj = JSON.parse(reply);
  		var keys = Object.keys(obj);
  		async.each(keys, (key,callback)=>{
  			ev = ev+'{bold}'+key.green+'{/bold}'+" "+obj[key]+'\n'
  			callback();
  		}, function(err){
  			if(err);
  			box_evidence.setContent(ev);
  		})
      	screen.render();}
      	catch (err){
      		return;
      	}
};


function set_tree_data(timewindows_list){
	/*
	sets ips and their tws for the tree.
	*/
  var ips_with_profiles = Object.keys(timewindows_list);
  var explorer = { extended: true
  , children: function(self){
      var result = {};
      try {
        if (!self.childrenContent) {
          for(i=0;i<ips_with_profiles.length;i++){
          	var tw = timewindows_list[ips_with_profiles[i]]
            child = ips_with_profiles[i];
            result[child] = { name: child, extended:false, children: tw[0]};
            }
        }else
        result = self.childrenContent;
      } catch (e){}
      return result;
    }
}
return explorer;};


async.waterfall([
	/*async_waterfall to fill the data for the tree*/
	function get_IPs_with_profiles(callback){
		/*
		retrieve ips with profile from redis key 'Profiles'
		*/
		var ips_with_profiles = [];
		redis_tree.keys('*', (err,reply)=>{
			if(err){callback(err)}
			async.each(reply, function(key,callback){
				if(key.includes('timewindow')){
					ips_with_profiles.push(key.split('_')[1]);
				}
				callback(null)
			},function(err) {

		 if( err ) {
		 	console.log('unable to create user');
		 }else {
		 	callback(null, ips_with_profiles);
		 };
		})


})},

	function get_tws_for_ips(ips_with_profiles, callback){
		var tree_dict = {};
		function createUser(ip_profile, reply, callback)
		{
			tree_dict[ip_profile]=timewindows_list_per_ip(reply);	
		 	callback(null);
		}
		async.each(ips_with_profiles, function(ip_profile, callback) {
		redis_tws_for_ip.zrangebyscore("twsprofile_"+ip_profile,
		   			Number.NEGATIVE_INFINITY,Number.POSITIVE_INFINITY, (err,reply)=>{
		    			if(err){
		      				callback(err);
		   				}else{
		   					createUser(ip_profile,reply, callback);
		        	}})
		}, function(err,res) {
		 if( err ) {
		 console.log('unable to create user');
		 } else {		 
		 callback(null,  tree_dict);

		 }
		})}, 

  	function setTree(timewindows_list,callback){
  		tree.setData(set_tree_data(timewindows_list));
  		screen.render();
  		callback(null)
  	}
], function(err){if(err){console.log(err)}});

tree.on('select',function(node){

    if(!node.name.includes('timewindow')){
    	getIpInfo_box_ip(node.name)}
  		
    else{
    
    redis_outtuples_timewindow.hgetall("profile_"+node.parent.name+"_"+node.name, (err,reply)=>{
        if(reply == null){
        	table_outTuples.setData({headers: [''], data: []})
        	box_detections.setContent('');
        	return;}
	    box_detections.setContent(reply['Detections']);
	    getEvidence(reply['Evidence'])
	    

	    var obj_outTuples = JSON.parse(reply["OutTuples"])
	    var keys = Object.keys(obj_outTuples);
	    var data = [];

	    async.each(keys, function(key,callback){
	      var row = [];
	      var tuple_info = obj_outTuples[key]
	      row.push(key,tuple_info[0].trim());
	      data.push(row);
	      callback(null);

  		},function(err) {
 		if( err ) {
			console.log('unable to create user');
 		} else {
 			table_outTuples.setData({headers: [''], data: data});
		screen.render();	
 		}
		});


	var conn_state = true;
	var conn_state2 = true;
	var bar = grid.set(0,0,3,6,contrib.stackedBar,
       	{ 
         barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "50%"
       , border : 'green'
       ,scrollbar: true
       , width: "50%"
       , barBgColor: [ 'red', 'blue', 'green' ]})
	var bar2 = grid.set(3,0,3,6,contrib.stackedBar,
       { 
         barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "100%"
       , border : 'green'
       ,scrollbar: true
       , width: "100%"
       , barBgColor: [ 'red', 'blue', 'green' ]})
	bar.hide()		
	bar2.hide()		
	screen.key('e', function(ch, key) {
		if(conn_state2){
			bar.show()
			bar.focus()
			bar2.show()
		tcp_connections("DstPortsClientTCPEstablished","DstPortsClientUDPEstablished",reply,bar);
		tcp_connections("DstPortsClientTCPNotEstablished","DstPortsClientUDPNotEstablished",reply,bar2);
		bar.setLabel({text:'DstPortsClientEstablished',side:'left'})
		bar2.setLabel({text:'DstPortsClientNotEstablished',side:'left'})
		}
		else{
  			bar.hide();
  			bar2.hide();
  		}
  		conn_state2 = !conn_state2;
  		screen.render()
	
});

	screen.key('b', function(ch, key) {
		if(conn_state){
			bar.show()
			bar.focus()
			bar2.show()
		
		tcp_connections("DstPortsServerTCPEstablished","DstPortsServerUDPEstablished",reply,bar);
		tcp_connections("DstPortsServerTCPNotEstablished","DstPortsServerUDPNotEstablished",reply,bar2);
		bar.setLabel({text:'DstPortsServerEstablished',side:'left'})
		bar2.setLabel({text:'DstPortsServerTNotEstablished',side:'left'})
		}
		else{
  			bar.hide()	
  			bar2.hide()	
  			

  		}
  		conn_state = !conn_state;
  		screen.render()
	
});
	var conn_state3 = true
	screen.key('c', function(ch, key) {
		if(conn_state3){
			bar.show()
			bar2.show()
		
		tcp_connections("SrcPortsClientTCPEstablished","SrcPortsClientUDPEstablished",reply,bar);
		tcp_connections("SrcPortsClientTCPNotEstablished","SrcPortsClientUDPNotEstablished",reply,bar2);
		bar.setLabel({text:'SrcPortsClientEstablished',side:'left'})
		bar2.setLabel({text:'SrcPortsClientTNotEstablished',side:'left'})
		}
		else{

  			bar.hide()	
  			bar2.hide()	
  			

  		}
  		conn_state3 = !conn_state3;
  		screen.render()
	
});

	var conn_state4 = true
	screen.key('o', function(ch, key) {
		if(conn_state4){
			bar.show()
			bar2.show()
		
		ip_tcp_bars("DstIPsClientTCPEstablished","DstIPsClientUDPEstablished",reply,bar);
		ip_tcp_bars("DstIPsClientTCPNotEstablished","DstIPsClientUDPNotEstablished",reply,bar2);
		bar.setLabel({text:'SrcPortsClientEstablished',side:'left'})
		bar2.setLabel({text:'SrcPortsClientTNotEstablished',side:'left'})
		}
		else{

  			bar.hide()	
  			bar2.hide()	
  			

  		}
  		conn_state4 = !conn_state4;
  		screen.render()
	
});
	

    }) 

    
    redis_get_timeline.lrange("profile_"+node.parent.name+"_"+node.name+'_timeline',0,-1, (err,reply)=>{
    	var data = [];
    	var ips = []	
    	map.innerMap.draw(null)

    	async.each(reply, function(line, callback){
    		var row = [];
    		var line_arr = line.split(" ")
	      	if(line_arr[6].includes('.')){
	      	ips.push(line_arr[6])
	      	line_arr[6]= "{bold}"+line_arr[6].blue+"{/bold}"}
	      	line_arr[1]= line_arr[1].substring(0, line_arr[1].lastIndexOf('.'));
			row.push(line_arr.join(" "));
			data.push(row);
			callback();
    	},function(err) {

 		if( err ) {
 			console.log('unable to create user');
 		} else {
 			table_timeline.setData({headers:[node.parent.name+" "+node.name], data: data});
 			setMap(ips)
			screen.render();}
		});
    	})
    var conn_state5 = true
	screen.key('m', function(ch, key) {
		if(conn_state5){
			map.show()
			
		}
		else{
  			map.hide()	
  		}
  		conn_state5 = !conn_state5;
  		screen.render()
	
});
   
    }
});

table_timeline.rows.on('select', (item, index) => {
	var timeline_line = item.content.split(" ");
	var timeline_ip = timeline_line[6].slice(6,-7)
	getIpInfo_box_ip(timeline_ip)
});

table_outTuples.rows.on('select', (item, index) => {
	var outTuple_ip = item.content.trim().split(":")[0]
	getIpInfo_box_ip(outTuple_ip)

});
screen.key(['escape', 'q', 'C-c'], function(ch, key) {
  return process.exit(0);
});



screen.key(['tab'], function(ch, key) {
  if(screen.focused == tree.rows){
	tree.style.border.fg = 'blue'
  	table_timeline.style.border.fg='magenta'
    table_timeline.focus();}
  else if(screen.focused == table_timeline.rows){
  	table_timeline.style.border.fg='blue'
  	table_outTuples.style.border.fg='magenta'
  	table_outTuples.focus();}
  else if(screen.focused == table_outTuples.rows){
  	table_outTuples.style.border.fg='blue'
  	box_detections.style.border.fg = 'magenta'
  	box_detections.focus()}
  else if(screen.focused == box_detections){
  	box_detections.style.border.fg='blue'
  	box_evidence.style.border.fg = 'magenta'
  	box_evidence.focus()}

  else{
  	box_evidence.style.border.fg = 'blue'
  	tree.style.border.fg = 'magenta'
    tree.focus();}
screen.render();
});
tree.focus();
screen.render();
