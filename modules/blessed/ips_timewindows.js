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

  ,table_outTuples =  grid.set(2.5,1,1.8,2.5, contrib.table, 
  { keys: true
  , fg: 'green'
  , label: "OutTuples"
  , columnWidth:[25,30]})

  , tree =  grid.set(0,0,5.1,1,contrib.tree,
  { style: { text: "red" }
  , template: { lines: true }
  , label: 'Ips from slips'})

  , box_ip = grid.set(5.1, 0, 0.5, 6, blessed.box,
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
 //  , box = grid.set(5.5, 0, 0.5, 6,blessed.box,{
 //  		top: 'center',
 //  		left: 'center',
 //  		width: '50%',
 //  		height: '50%',
 //  		content:'what to do',
 //  		tags: true,
 // 		border: {
 //   		type: 'line'
 // 		},
 // 		style: {
 //    	fg: 'white',
 //    	bg: 'magenta',
 //    	border: {
 //      	fg: '#f0f0f0'
 //    	},
 //    	hover: {
 //      	bg: 'green'
 //    	}
 //  		}
	// })
 , box_detections = grid.set(4.2, 1, 1, 2.5,blessed.box,{
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
 , bar = grid.set(2.5,3.5,2.7,2.5,contrib.stackedBar,
       { label: 'Connection Port Established'
       , barWidth: 3
       , barSpacing: 10
       , xOffset: 2
       , height: "90%"
       , width: "100%"
       , barBgColor: [ 'red', 'blue', 'green' ]})





 function round(value, decimals) {
  return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
}



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
      	catch (e){
      		box_ip.setContent(reply[ip]);
      	    screen.render();}
    });
}

    



function set_tree_data(ips_with_profiles, timewindows_list){
	/*
	sets ips and their tws for the tree.
	*/
  var explorer = { extended: true
  , children: function(self){
      var result = {};
      try {
        if (!self.childrenContent) {
          for(i=0;i<ips_with_profiles.length;i++){
            child = ips_with_profiles[i];
            result[child] = { name: child, extended:false, children: timewindows_list[i]};
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
		for(i=0; i<reply.length; i++){
 			ips_with_profiles.push(reply[i].split('_')[1]);}
 			callback(null, ips_with_profiles);
})},

	function get_tws_for_ips(ips_with_profiles, callback){

		var timewindows_list = [];
		for(i=0; i<ips_with_profiles.length;i++){

    		redis_tws_for_ip.zrangebyscore("twsprofile_"+ips_with_profiles[i],
   			Number.NEGATIVE_INFINITY,Number.POSITIVE_INFINITY, (err,reply)=>{
    		if(err){
      			callback(err);
   			}else{
   				timewindows_list.push(...timewindows_list_per_ip(reply));
        		
        	}});}
    callback(null, ips_with_profiles, timewindows_list);
  }, 

  	function setTree(ips_with_profiles,timewindows_list,callback){
  		tree.setData(set_tree_data(ips_with_profiles,timewindows_list));
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
        if(reply == null){return;}
	    const mapOutTuples = async _ => {
	    var obj_outTuples = JSON.parse(reply["OutTuples"])
	    var keys = Object.keys(obj_outTuples);
	    var data = [];
	    const promises_outTuples = keys.map(async key => {
	      var row = [];
	      var tuple_info = obj_outTuples[key]
	      row.push(key,tuple_info[0].trim());
	      data.push(row);
  		})
  		await Promise.all(promises_outTuples)
  		table_outTuples.setData({headers: [''], data: data});
		screen.render();}

		mapOutTuples()

		// const mapTCPEstablished
		const mapTCPEstablished = async _ => {
		var bar_categories_protocol_port = []
	    var obj_dstPorts_tcp_established = JSON.parse(reply["DstPortsClientTCPEstablished"])
		var keys_dstPorts_tcp_established = Object.keys(obj_dstPorts_tcp_established)
		var data_tcp_est = [];

	    const promises_TCP_est = keys_dstPorts_tcp_established.map(async key_TCP_est => {
	    	bar_categories_protocol_port.push('TCP/'+key_TCP_est)
	    	var service_info = obj_dstPorts_tcp_established[key_TCP_est]
	    	var row = []
	    	row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0))
	    	
	    	data_tcp_est.push(row)
  		})

  		var obj_dstPorts_udp_established = JSON.parse(reply["DstPortsClientUDPEstablished"])
		var keys_dstPorts_udp_established = Object.keys(obj_dstPorts_udp_established)
		var data_udp_est = [];

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
		mapTCPEstablished()
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

// table_outTuples.on('focus',(item,index) => {
// 	// console.log(item.var focus_line = item.ritems[item.selected];
// 	// console.log(item.items[0])
// 	var outTuple_ip = focus_line.trim().split(":")[0]
// 	getIpInfo(outTuple_ip);
// })
// table_timeline.rows.on('focus', (item)=>{
// 	console.log(item.data)
// 	console.log(item.content)
	
// 	// var focus_line = item.ritems[item.selected];
// 	// // console.log(item.items[0])
// 	// var outTuple_ip = focus_line.split(" ")
// 	// var ip_st = outTuple_ip[6]
// 	// var ip = ip_st.slice(6,-7)
// 	// getIpInfo(ip);
// })
table_timeline.rows.on('select', (item, index) => {
	var timeline_line = item.content.split(" ");
	var timeline_ip = timeline_line[6].slice(6,-7)
	getIpInfo(timeline_ip)
});

table_outTuples.rows.on('select', (item, index) => {
	var outTuple_ip = item.content.trim().split(":")[0]
	getIpInfo(outTuple_ip)

});


// screen.key(['e'],function(ch,key){
// 	redis_outtuples_timewindow.hgetall("profile_"+node.parent.name+"_"+node.name, (err,reply)=>{
//         if(reply == null){return;}
// 	const mapTCPNotEstablished = async _ => {
// 		var bar_categories_protocol_port = []
// 	    var obj_dstPorts_tcp_notestablished = JSON.parse(reply["DstPortsClientTCPNotEstablished"])
// 		var keys_dstPorts_tcp_notestablished = Object.keys(obj_dstPorts_tcp_notestablished)
// 		var data_tcp_notest = [];

// 	    const promises_TCP_notest = keys_dstPorts_tcp_notestablished.map(async key_TCP_notest => {
// 	    	bar_categories_protocol_port.push('TCP/'+key_TCP_notest)
// 	    	var service_info = obj_dstPorts_tcp_notestablished[key_TCP_notest]
// 	    	var row = []
// 	    	row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0))
	    	
// 	    	data_tcp_notest.push(row)
//   		})

//   		var obj_dstPorts_udp_notestablished = JSON.parse(reply["DstPortsClientUDPNotEstablished"])
// 		var keys_dstPorts_udp_notestablished = Object.keys(obj_dstPorts_udp_notestablished)
// 		var data_udp_notest = [];

// 	    const promises_UDP_notest = keys_dstPorts_udp_notestablished.map(async key_UDP_notest => {
// 	    	bar_categories_protocol_port.push('UDP/'+key_UDP_notest)
// 	    	var service_info_udp = obj_dstPorts_udp_notestablished[key_UDP_notest]
// 	    	var row_udp = []
// 	    	row_udp.push(round(Math.log(service_info_udp['totalflows']),0), round(Math.log(service_info_udp['totalpkt']),0), round(Math.log(service_info_udp['totalbytes']),0))
// 	    	data_udp_notest.push(row_udp)
//   		})
//   		await Promise.all(promises_TCP_notest)
//   		await Promise.all(promises_UDP_notest)
//   		data_tcp_notest.push(...data_udp_notest)
//   		 bar.setData(
//         { barCategory: bar_categories_protocol_port
//         , stackedCategory: ['totalflows', 'totalpkt', 'totalbytes']
//         , data: data_tcp_notest
//         })
// 		screen.render();}

// 		mapTCPNotEstablished()
// });
// });
// screen.key(['escape', 'q', 'C-c'], function(ch, key) {
//   return process.exit(0);
// });

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

