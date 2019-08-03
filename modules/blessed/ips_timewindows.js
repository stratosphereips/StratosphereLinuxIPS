const redis = require('redis')
  , redis_ips_with_profiles = redis.createClient()
  , redis_tws_for_ip = redis.createClient()
  , redis_ip_info = redis.createClient()
  , redis_get_timeline = redis.createClient()
  , redis_outtuples_timewindow = redis.createClient()
  , redis_detections_timewindow = redis.createClient()
  , redis_timeline_ip = redis.createClient()
  , async = require('async')
  ,	blessed = require('blessed')
  , contrib = require('blessed-contrib')
  , screen = blessed.screen()


// set up elements of the interface.

const grid = new contrib.grid({
  rows: 6,
  cols: 6,
  screen: screen
});
const table_timeline =  grid.set(0, 1, 2.5, 5, contrib.table, 
  { keys: true
  , fg: 'green'
  , label: "Timeline"
  , columnWidth:[200]})

  ,table_outTuples =  grid.set(2.5,1,1.7,2.5, contrib.table, 
  { keys: true
  , fg: 'green'
  , label: "OutTuples"
  , columnWidth:[25,30]})

  , tree =  grid.set(0,0,5.1,1,contrib.tree,
  { style: { text: "red" }
  , template: { lines: true }
  , label: 'Ips from slips'})

  , box_ip = grid.set(5.1, 0, 0.5, 3, blessed.box,
      {top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      content: "SELECT IP TO SEE IPS INFO!",
      tags: true,
      border: {
      type: 'line'
    },
    style: {
      fg: 'white',
      border: {
        fg: '#f0f0f0'
      },
    }})

 , box_detections = grid.set(4.2, 1, 0.9, 2.5,blessed.box,{
  		top: 'center',
  		left: 'center',
  		width: '50%',
  		height: '50%',
  		label:'Detections',
  		// content:'',
  		tags: true,
 		border: {
   		type: 'line'
 		},
 		style: {
    	fg: 'white',
    	// bg: 'magenta',
    	border: {
      	fg: '#f0f0f0'
    	},
    	hover: {
      	bg: 'green'
    	}
  		}
	})
 , bar = grid.set(2.5,3.5,2.6,2.5,contrib.stackedBar,
       { label: 'Connection Port Established'
       , barWidth: 3
       , barSpacing: 5
       , xOffset: 2
       , height: "90%"
       , width: "100%"
       , barBgColor: [ 'red', 'blue', 'green' ]})



function interface_element(state){
  this.state = state;
  };

var stacked_bar = new interface_element(0)

 function round(value, decimals) {
  return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
}

// var pic = grid.set(5.1, 2, 1, 0.5,contrib.picture,
//    { file: 'greece.png'
//    , cols: 20
//    , onReady: ready})
// function ready() { screen.render() }



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
 }



function getIpInfo(ip){
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
      	    screen.render();}
    });
}

    



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

		redis_ips_with_profiles.smembers("profiles", (err,reply)=>{
		if(err){callback(err)}
		async.each(reply, function(ip_profile, callback) {
			ips_with_profiles.push(ip_profile.split('_')[1]);

			callback(null)
		}, function(err) {

		 if( err ) {
		 	console.log('unable to create user');
		 }else {
		 	callback(null, ips_with_profiles);
		 }
		});

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
    	getIpInfo(node.name)}
  		
    else{
    redis_detections_timewindow.hget("profile_"+node.parent.name+"_"+node.name,'Detections',(err,reply)=>{
    	box_detections.setContent(reply)
    })
    redis_outtuples_timewindow.hgetall("profile_"+node.parent.name+"_"+node.name, (err,reply)=>{
        if(reply == null){
        	table_outTuples.setData({headers: [''], data: []})
        	return;}
	    
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
  		
  		

		function stackedbar(first, second){
		const mapTCPEstablished = async () => {
		var bar_categories_protocol_port = []
		try{
	    var obj_dstPorts_tcp_established = JSON.parse(reply[first])
		var keys_dstPorts_tcp_established = Object.keys(obj_dstPorts_tcp_established)
		var data_tcp_est = [];
}
	    catch(err){
	     var obj_dstPorts_tcp_established = reply[first]	
	     var keys_dstPorts_tcp_established = Object.keys(obj_dstPorts_tcp_established)
		var data_tcp_est = [];

	    }
		
	    const promises_TCP_est = keys_dstPorts_tcp_established.map(async key_TCP_est => {
	    	bar_categories_protocol_port.push('TCP/'+key_TCP_est)
	    	var service_info = obj_dstPorts_tcp_established[key_TCP_est]
	    	var row = []

	    	row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0))
	    	
	    	data_tcp_est.push(row)
  		})

  		try{
  		var obj_dstPorts_udp_established = JSON.parse(reply[second])
  		var keys_dstPorts_udp_established = Object.keys(obj_dstPorts_udp_established)
  	    var data_udp_est = [];}
  		catch(err){
  			var obj_dstPorts_udp_established = reply[second]
  			var keys_dstPorts_udp_established = Object.keys(obj_dstPorts_udp_established)
  	    var data_udp_est = []

  		}
		

	    const promises_UDP_est = keys_dstPorts_udp_established.map(async key_UDP_est => {
	    	bar_categories_protocol_port.push('UDP/'+key_UDP_est)
	    	var service_info_udp = obj_dstPorts_udp_established[key_UDP_est]
	    	var row_udp = []
	    	row_udp.push(round(Math.log(service_info_udp['totalflows']),0), round(Math.log(service_info_udp['totalpkt']),0), round(Math.log(service_info_udp['totalbytes']),0))
	    	data_udp_est.push(row_udp)
	    	
  		})
  		await Promise.all(promises_TCP_est)
  		await Promise.all(promises_UDP_est)
  		data_tcp_est.push(...data_udp_est)
  		 bar.setData(
        { barCategory: bar_categories_protocol_port
        , stackedCategory: ['totalflows', 'totalpkt', 'totalbytes']
        , data: data_tcp_est
        })
		screen.render();}
		mapTCPEstablished()};
// 		  screen.key(['e'], function(ch, key) {
// 			if(stacked_bar.state == 0){
// 				stackedbar("DstPortsClientTCPEstablished","DstPortsClientUDPEstablished");
// 				stacked_bar.state=1;}
// 			else{
// 				stackedbar("DstIPsClientTCPEstablished","DstIPsClientUDPEstablished");
// 				stacked_bar.state = 0;

// 			}

  
// });
    	stackedbar("DstIPsClientTCPEstablished","DstIPsClientUDPEstablished");
    }) 

    
    redis_get_timeline.lrange("profile_"+node.parent.name+"_"+node.name+'_timeline',0,-1, (err,reply)=>{
    	const mapTimeline = async _ => {
	    var data = [];
	    const promises = reply.map(async line => {
	      	var row = [];
	      	var line_arr = line.split(" ")
	      	if(line_arr[6].includes('.')){
	      	line_arr[6]= "{bold}"+line_arr[6]+"{/bold}"}
	      	line_arr[1]= line_arr[1].substring(0, line_arr[1].lastIndexOf('.'));
			row.push(line_arr.join(" "));
			data.push(row);
  		})
  		await Promise.all(promises)
  		table_timeline.setData({headers:[node.parent.name+" "+node.name], data: data});
		screen.render();}
		mapTimeline();
    	})
    }
});

table_timeline.rows.on('select', (item, index) => {
	var timeline_line = item.content.split(" ");
	var timeline_ip = timeline_line[6].slice(6,-7)
	getIpInfo(timeline_ip)
});

table_outTuples.rows.on('select', (item, index) => {
	var outTuple_ip = item.content.trim().split(":")[0]
	getIpInfo(outTuple_ip)

});



screen.key(['escape', 'q', 'C-c'], function(ch, key) {
  return process.exit(0);
});

screen.key(['tab'], function(ch, key) {
  if(screen.focused == tree.rows)
    table_timeline.focus();
  else if(screen.focused == table_timeline.rows)
  	table_outTuples.focus();

  else
    tree.focus();
});
tree.focus();
screen.render();
