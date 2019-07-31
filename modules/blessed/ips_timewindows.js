const redis = require('redis')
  , redis_ips_with_profiles = redis.createClient()
  , redis_tws_for_ip = redis.createClient()
  , redis_ip_info = redis.createClient()
  , redis_get_timewindow = redis.createClient()
  , redis_outtuples_timewindow = redis.createClient()
  , async = require('async')
  ,	blessed = require('blessed')
  , contrib = require('blessed-contrib')
  , screen = blessed.screen()




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
  , columnWidth:[200]})

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
  , box = grid.set(5.5, 0, 0.5, 6,blessed.box,{
  		top: 'center',
  		left: 'center',
  		width: '50%',
  		height: '50%',
  		content:'what to do',
  		tags: true,
 		border: {
   		type: 'line'
 		},
 		style: {
    	fg: 'white',
    	bg: 'magenta',
    	border: {
      	fg: '#f0f0f0'
    	},
    	hover: {
      	bg: 'green'
    	}
  		}
	})

 , bar = grid.set(2.5,3.5,2.7,2.5,contrib.stackedBar,
       { label: 'Server Utilization (%)'
       , barWidth: 4
       , barSpacing: 6
       , xOffset: 0
       //, maxValue: 15
       , height: "40%"
       , width: "50%"
       , barBgColor: [ 'red', 'blue', 'green' ]})


 bar.setData(
        { barCategory: ['Q1', 'Q2', 'Q3', 'Q4']
        , stackedCategory: ['US', 'EU', 'AP']
        , data:
           [ [ 7, 7, 5]
           , [8, 2, 0]
           , [0, 0, 0]
           , [2, 3, 2] ]
        })

 function timewindows_list_per_ip(tw){
	var temp_list = []
	var dict = {};
	for(i=0; i<tw.length; i++){
		dict[tw[i]] = {}};
		temp_list.push(dict);
	return temp_list;
 }



function set_tree_data(ips_with_profiles, timewindows_list){
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
	
	function get_IPs_with_profiles(callback){
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
  		redis_ip_info.hgetall("IPsInfo",(err,reply)=>{
  	  	box_ip.setContent(reply[node.name]);
      	screen.render();
    });}

    else{

    redis_outtuples_timewindow.hgetall("profile_"+node.parent.name+"_"+node.name, (err,reply)=>{
        if(reply == null){return;}
      
	    var obj_outTuples = JSON.parse(reply["OutTuples"])
	    var keys = Object.keys(obj_outTuples);
	    var data = [];
	    for(i=0; i<keys.length;i++){
	      var row = [];
	      row.push(keys[i]+"      "+obj_outTuples[keys[i]]);
	      data.push(row);
	    }     
	    table_outTuples.setData({headers: ['OutTuples'], data: data});
		screen.render();

		var obj_dstPorts_tcp_established = JSON.parse(reply["DstPortsClientTCPEstablished"])
		var keys_dstPorts_tcp_established = Object.keys(obj_dstPorts_tcp_established)
    }) 

    redis_get_timewindow.lrange("profile_"+node.parent.name+"_"+node.name+'_timeline',0,-1, (err,reply)=>{
		var data = [];
		for(i=0; i<reply.length; i++){
			var row = [];
			row.push(reply[i]);
			data.push(row);
		}
		table_timeline.setData({headers: ['Info'], data: data})
		screen.render();	
    	})
    }
});

    

screen.key(['escape', 'q', 'C-c'], function(ch, key) {
  return process.exit(0);
});

screen.key(['tab'], function(ch, key) {
  if(screen.focused == tree.rows)
    table_timeline.focus();
  else
    tree.focus();
});
tree.focus();
screen.render();

