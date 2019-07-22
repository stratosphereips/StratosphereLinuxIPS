const redis = require('redis')
  , redis_new_profile = redis.createClient()
  , redis_get_profile = redis.createClient()
  , redis_get_timewindow = redis.createClient()
  , async = require('async')
  ,	blessed = require('blessed')
  , contrib = require('blessed-contrib')
  , screen = blessed.screen()


redis_new_profile.on('connect',function() {
 console.log("Redis is connected");
});

redis_new_profile.on('error',function() {
 console.log("Error in Redis");
});
redis_get_profile.on('connect',function() {
 console.log("Redis is connected");
});

redis_get_profile.on('error',function() {
 console.log("Error in Redis");
});

const grid = new contrib.grid({
  rows: 6,
  cols: 6,
  screen: screen
});
const table =  grid.set(0, 3, 4, 3, contrib.table, 
  { keys: true
  , fg: 'green'
  , label: "Channel 'tws'"
  , columnWidth:[60]})

  , tree =  grid.set(0,0,4,3,contrib.tree,
  { style: { text: "red" }
  , template: { lines: true }
  , label: 'Ips from slips'})

  , table_ipsinfo = grid.set(4, 0, 1, 6, contrib.table,
  { keys: true
  , fg: 'green'
  , label: "IPs Info"
  , columnWidth:[60]})


  ,	log = grid.set(5, 0, 1, 6, contrib.log, {
  label: 'Server Log'
});


 function updatearrays(tw){
  var temp_list = []
  var dict = {};
  for(i=0; i<tw.length; i++){
    dict[tw[i]] = {}};
  temp_list.push(dict);
  return temp_list;
}


var ips_with_profiles = []; 
var timewindows_list = [];



function updatetree(){
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
	function getIPs(callback){
		redis_new_profile.smembers("profiles", (err,reply)=>{
		if(err){callback(err)}
		for(i=0; i<reply.length; i++){
 			ips_with_profiles.push(reply[i].split('_')[1]);}
 			callback(null, ips_with_profiles);
})},
	function getTWs(ips_with_profiles, callback){
		for(i=0; i<ips_with_profiles.length;i++){
    		redis_get_profile.zrangebyscore("twsprofile_"+ips_with_profiles[i],
   			Number.NEGATIVE_INFINITY,Number.POSITIVE_INFINITY, (err,reply)=>{
    		if(err){
      			callback(err);
   			}else{
   				timewindows_list.push(...updatearrays(reply));
        		
        	}});}
    callback(null);
  }, 
  	function setTree(callback){
  		tree.setData(updatetree());
  		callback(null)
  	}
	], function(err){if(err){console.log(err)}});


tree.on('select',function(node){
  var data = [];
  var data2 = [];
  if(!node.name.includes('timewindow')){
  	redis_get_profile.hgetall("IPsInfo",(err,reply)=>{
    	var row = [];
    	row.push(reply[node.name]);
    	data.push(row);
    	table_ipsinfo.setData({headers: ['Info'], data: data});
    });}
    else{
    	redis_get_timewindow.hgetall("profile_"+node.parent.name+"_"+node.name, (err,reply)=>{
    		if(reply == null){
    			var row2 = [];
    		row2.push("No information");
    		data2.push(row2);
    		table.setData({headers: ['Info'], data: data2})

    		}
    		else{var row2 = [];
    		row2.push(reply["DstIPs"]);
    		data2.push(row2);
    		table.setData({headers: ['Info'], data: data2})}
    	})
    }
  screen.render();
});

    

screen.key(['escape', 'q', 'C-c'], function(ch, key) {
  return process.exit(0);
});
screen.key(['tab'], function(ch, key) {
  if(screen.focused == tree.rows)
    table.focus();
  else
    tree.focus();
});
tree.focus();
screen.render();
