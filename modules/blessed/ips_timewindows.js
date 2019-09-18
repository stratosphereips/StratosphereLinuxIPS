var redis = require('redis')
  , redis_ips_with_profiles = redis.createClient()
  , redis_tree = redis.createClient()
  , redis_tws_for_ip = redis.createClient()
  , redis_ip_info = redis.createClient()
  , redis_get_timeline = redis.createClient()
  , redis_outtuples_timewindow = redis.createClient()
  , redis_detections_timewindow = redis.createClient()
  , redis_timeline_ip = redis.createClient()
  ,redis_blocked_tws = redis.createClient()
  , async = require('async')
  , blessed = require('blessed')
  , contrib = require('blessed-contrib')
  , fs = require('fs')
  , screen = blessed.screen()
  , color = require('ansi-colors');


const clipboardy = require('clipboardy');
screen.dockBorders=true;
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


function blockedTW(){ 
  return new Promise(function(resolve,reject){
    var blockedTWs = {};
    redis_blocked_tws.smembers("BlockedProfTW",(err,reply)=>{
    async.each(reply,function(blocked_line,callback){
      var blocked_list = blocked_line.split('_');
      if(!Object.keys(blockedTWs).includes(blocked_list[1])){
        blockedTWs[blocked_list[1]] = [];
        blockedTWs[blocked_list[1]].push(blocked_list[2])
      }
      else{
        blockedTWs[blocked_list[1]].push(blocked_list[2])
      }
      callback(null)
    },function(err){
      if(err){
        console.log(err);
      }
     else{resolve(blockedTWs)}
    })
  })
})}

// set up elements of the interface.

var grid = new contrib.grid({
  rows: 6,
  cols: 6,
  screen: screen
});

var table_timeline =  grid.set(0.5, 1, 3.7, 5, contrib.table, 
  {keys: true
  , vi:true
  , scrollbar: true
  , label: "Timeline"
  , columnWidth:[200]})

  ,table_outTuples_listtable = grid.set(0,0,6,6, blessed.listtable, {
      keys: true,
      mouse: true,
  
      tags: true,
      // interactive: false,
      border: 'line',
      style: {
        bg: 'blue'
      },
      style: {
        header: {
          fg: 'blue',
          bold: true
        },
        cell: {
          fg: 'magenta',
          selected: {
            bg: 'blue'
          }
        }
      },
      align: 'left'
    })

,listtable_est_srcPort = grid.set(0,0,3,2, blessed.listtable, {
      border: 'line'
    })
,listtable_notEst_srcPort = grid.set(3,0,3,2, blessed.listtable, {
      border: 'line'
    })
,listtable_est_dstIPs = grid.set(0,0,3,2, blessed.listtable, {
      border: 'line'
    })
,listtable_notEst_dstIPs = grid.set(3,0,3,2, blessed.listtable, {
      border: 'line'
    })

  , tree =  grid.set(0,0,5,1,contrib.tree,
  { vi:true 
  , style: {fg:'green',border: {fg:'magenta'}}
  , template: { lines: true }
  , label: 'Ips from slips'})

  , box_ip = grid.set(0, 1, 0.5, 5, blessed.box,
      {top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      content: "SELECT IP TO SEE IPS INFO!",
      tags: true,
       style:{
         focus: {
      border:{ fg:'magenta'}
    }},
      border: {
      type: 'line'
    }})

 , box_evidence = grid.set(4.2, 3.5, 0.9, 2.5,blessed.box,{
      top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      label:'Evidence',
      tags: true,
      keys: true,
      style:{
         focus: {
      border:{ fg:'magenta'}
    }},
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


, map = grid.set(0, 0, 6, 6,contrib.map,{label: 'World Map'})
, bar_one_dstPortsServer = grid.set(0.5,0,3,6,contrib.stackedBar,
        { 
         barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "50%"
       , width: "50%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , barBgColor: [ 'red', 'blue', 'green' ]})
, bar_two_dstPortsServer = grid.set(3.5,0,2.7,6,contrib.stackedBar,
       { 
         barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "100%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , width: "100%"
       , barBgColor: [ 'red', 'blue', 'green' ]})
, box_bar_state = grid.set(0, 0, 0.5, 6, blessed.box,
      {top: 'center',
      left: 'center',
      width: '50%',
      style:{
         focus: {
      border:{ fg:'magenta'}
    }},
      height: '50%',
      tags: true,
      border: {
      type: 'line'
    },
    })
, bar_one_dstPortClient = grid.set(0.5,0,3,6,contrib.stackedBar,
        { //parent:bar_list
         barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "100%"
       , width: "100%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , barBgColor: [ 'green' ]})
, bar_two_dstPortClient = grid.set(3.5,0,2.6,6,contrib.stackedBar,
       { //parent:bar_list
         barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "100%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , width: "100%"
       , barBgColor: [ 'green' ]})
, help_list_bar = grid.set(5.7,0,0.4,6,blessed.listbar,{

      keys: false,
      mouse: true,
      style: {
        // border:'red',
        prefix: {
          fg: 'yellow'
          // bg:'white'
        },
        item: {
        },
      },
      autoCommandKeys: false,
      commands:
       {
            'srcPortClient': {
              keys: ['e']
                        },
            'dstIPsClient': {
              keys: ['c']
                        },
              'dstPortServer': {
              keys: ['b']
                        },
              'map': {
              keys: ['m']
                        },
            'dstPortsNotEstablished': {
              keys: ['v']
                        },
              'OutTuples and ipInfo': {
              keys: ['h']}
                        

          }
}),
gaugeList_est_srcPort = grid.set(0.3, 2, 2.8, 4, contrib.gaugeList,
      {
      style:{
         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_notEst_srcPort = grid.set(3.3, 2, 2.8, 4, contrib.gaugeList,
      {

        style:{
         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_est_dstIPs = grid.set(0.3, 2, 2.8, 4, contrib.gaugeList,
      {

      style:{
         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_notEst_dstIPs = grid.set(3.3, 2, 2.8, 4, contrib.gaugeList,
      {
        style:{
         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    )

gaugeList_notEst_srcPort.hide()
listtable_notEst_srcPort.hide()
gaugeList_notEst_dstIPs.hide()
listtable_notEst_dstIPs.hide()
gaugeList_est_dstIPs.hide()
listtable_est_dstIPs.hide()
table_outTuples_listtable.hide()
gaugeList_est_srcPort.hide()
listtable_est_srcPort.hide()
box_bar_state.hide()
bar_two_dstPortClient.hide()
bar_one_dstPortClient.hide()
bar_one_dstPortsServer.hide()
bar_two_dstPortsServer.hide()
map.hide()

var focus_widget = tree;
var bar_state_one = true;
var bar_state_two = true; 
var bar_state_three = true;
var bar_state_four = true;
var box_hotkeys_state = true;
var map_state = true;
var box_hotkeys_state = true;

function clean_widgets(){
  box_evidence.setContent('');
  table_timeline.setContent('');
  table_outTuples_listtable.setItems('')
  box_ip.setContent('')
}

function hide_widgets(){
  listtable_est_srcPort.hide()
  gaugeList_notEst_srcPort.hide()
  listtable_notEst_srcPort.hide()
  gaugeList_est_srcPort.hide()
  listtable_est_dstIPs.hide()
  gaugeList_notEst_dstIPs.hide()
  listtable_notEst_dstIPs.hide()
  gaugeList_est_dstIPs.hide()
  help_list_bar.hide()
  tree.hide()
  box_evidence.hide()
  table_timeline.hide()
  box_ip.hide()
  table_outTuples_listtable.hide()  
  box_bar_state.hide()
  bar_two_dstPortClient.hide()
  bar_one_dstPortClient.hide()
  bar_one_dstPortsServer.hide()
  bar_two_dstPortsServer.hide()
  map.hide()
}

function show_widgets(){
  help_list_bar.show()
  tree.show()
  box_evidence.show()
  table_timeline.show()
  box_ip.show()
  focus_widget  .focus()


}

// var number_bars = Math.floor((2*bar_two_srcPortClient.width-2*bar_two_srcPortClient.options.xOffset)/(bar_two_srcPortClient.options.barSpacing+2*bar_two_srcPortClient.options.barWidth));

screen.render() 

function chunkString (str, len) {
  const size = Math.ceil(str.length/len)
  const r = Array(size)
  let offset = 0
  
  for (let i = 0; i < size; i++) {
    r[i] = str.substr(offset, len)
    offset += len
  }
  
  return r
}


String.prototype.repeat = function(length) {
 return Array(length + 1).join(this);
};

function round(value, decimals) {
  return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
};
 
//function to fill in data for a stacked bars
function bar_setdata(bar, counter, data, number){
  bar.clear()
  bar.setData(
      { barCategory: data[1].slice(counter,counter+number)
      , stackedCategory: ['totalflows', 'totalpkt','totalbytes']
      , data: data[0].slice(counter,counter+number)})
};
function port_ip_setdata(bar, counter, data, number){
  var d = data[1]
  var values_bars = []
  bar.clear()
  async.each(d, function(value, callback){
    var row = []
    row.push(value)
    values_bars.push(row)
    callback()
  }, function(err){
    if(err){
      console.log('sds')
    }
    else{
      // bar.setLabel({text:Object..green,side:'left'})
      bar.setData(
      { barCategory:data[0].slice(counter,counter+number)
      , stackedCategory: ['Number of connections']
      , data: values_bars.slice(counter,counter+number)})

    }
  })

};

//function to fill in data for a box (box displays the state of the bar)
function set_box_bar_dstPortClient_state(bar_data, bar_data_two,bar_one,bar_two){
  if(bar_data[0].length > number_bars && bar_data_two[0].length > number_bars){
    box_bar_state.setContent('Bars are scrollable. -Tab to change bars. -Left and -Right to  scroll.');
    bar_one.focus();}
  else if(bar_data[0].length > number_bars){
    box_bar_state.setContent('Upper bar is scrollable. -Left and -Right to  scroll.');
    bar_one.focus();}
  else if(bar_data_two[0].length > number_bars){
    box_bar_state.setContent('Lower bar is scrollable. -Left and -Right to  scroll.');
    bar_two.focus();}
  else{box_bar_state.setContent('Bars are not scrollable.')
  bar_one.focus()};
  
}

//function to fill in data for a box (box displays the state of the bar)
function set_box_bar_state(bar_data, bar_data_two,bar_one,bar_two,number_bars){
  if(bar_data[0].length > number_bars && bar_data_two[0].length > number_bars){
    box_bar_state.setContent('Bars are scrollable. -Tab to change bars. -Left and -Right to  scroll. {bold}Logarithmic scale.{/bold}');
    bar_one.focus();}
  else if(bar_data[0].length > number_bars){
    box_bar_state.setContent('Upper bar is scrollable. -Left and -Right to  scroll. {bold}Logarithmic scale.{/bold}');
    bar_one.focus();}
  else if(bar_data_two[0].length > number_bars){
    box_bar_state.setContent('Lower bar is scrollable. -Left and -Right to  scroll. {bold}Logarithmic scale.{/bold}');
    bar_two.focus();}
  else{box_bar_state.setContent('Bars are not scrollable. {bold}Logarithmic scale.{/bold}')
  bar_one.focus()};
  bar_one.show();
  bar_two.show();
  box_bar_state.show();
}

//function to fill data about destIpsCLient
function port_ips_bars(key, key2,reply){
  
  var data_dict = {};
  try{
        var obj_port = JSON.parse(reply[key]);
      var keys_port = Object.keys(obj_port);
    }
  catch(err){
        var obj_port = [];
        var keys_port = [];
      }
  async.each(keys_port, function(port, callback) {  
    var port_info = obj_port[port];
    var row = [];
    data_dict['TCP'+port] = [Object.keys(port_info['dstips']), Object.values(port_info['dstips'])]
    callback();
  }, function(err){
    if(err){
      console.log('sasdfsaa')
    }
    else{
      try{
        var obj_port = JSON.parse(reply[key2]);
        var keys_port = Object.keys(obj_port);
        }
      catch(err){
        var obj_port = [];  
        var keys_port = [];
          }
      async.each(keys_port, function(port, callback) {
        var port_info = obj_port[port];
        var row = [];
        data_dict['UDP'+port] = [Object.keys(port_info['dstips']),Object.values(port_info['dstips'])];
        callback();
      }, function(err){
        if(err){
          console.log('sasdfsaa')
        }
      });

    }
  });
return data_dict;
};


//function to fill in the information about the map(loc and lot of a countries)
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
  
};


//function to fill the info about bars (srcPortsServer, dstPortsClient)
function tcp_udp_connections(key, key2,reply){
      
      var bar_categories_protocol_port  = [];
      var data_stacked_bar = [];
      var data_listtable = [];
      var data_gaugeList = [];
  try{
      var obj_tcp = JSON.parse(reply[key]);
    var keys_tcp = Object.keys(obj_tcp);
  }
    catch(err){
   
      var obj_tcp =[]
      var keys_tcp = []

    }

  async.each(keys_tcp, function(key_TCP_est, callback) {
    bar_categories_protocol_port.push('TCP/'+key_TCP_est);
    var service_info = obj_tcp[key_TCP_est];
    var row = [];
    var listtable_est_srcPort = [];
    listtable_est_srcPort.push('TCP/'+key_TCP_est,String(service_info['totalflows']), String(service_info['totalpkt']), String(service_info['totalbytes']))
    data_listtable.push(listtable_est_srcPort)
    data_listtable.push([])
    row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0));
    data_stacked_bar.push(row);
    // data_gaugeList.push({stack:[0,0,0]})
    data_gaugeList.push({stack:row})
    callback();
  }, function(err) {

  if( err ) {
    console.log('unable to create user');
  } else {

  try{
    var obj_udp = JSON.parse(reply[key2]);
    var keys_udp = Object.keys(obj_udp);
  }
  catch(err){
    var obj_udp = []
    var keys_udp = []
  }

  async.each(keys_udp, function(key_UDP_est, callback) {
    var listtable_est_srcPort = [];
    bar_categories_protocol_port.push('UDP/'+key_UDP_est);
    var service_info = obj_udp[key_UDP_est];
    var row = [];
    listtable_est_srcPort.push('UDP/'+key_UDP_est,String(service_info['totalflows']), String(service_info['totalpkt']), String(service_info['totalbytes']))
    data_listtable.push(listtable_est_srcPort)
    data_listtable.push([])
    row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0));
    data_stacked_bar.push(row);
    data_gaugeList.push({stack:row})
    callback()
    }, function(err) {
      if( err ) {
        console.log('unable to create user');
      }
    });
  }

});
  // console.log(data_gaugeList_est_srcPort.length)
return [data_stacked_bar,bar_categories_protocol_port, data_listtable, data_gaugeList]}

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


function getIpInfo_box_ip(ip,mode){
  /*
  retrieves IPsInfo from redis.
  */

  return new Promise(function(resolve, reject) {
 
    redis_timeline_ip.hget("IPsInfo",ip,(err,reply)=>{
      var ip_info_str = "";
      var ip_info_dict = {'asn':'', 'geocountry':'', 'VirusTotal':''}
      var ip_info_dict_outtuple = {'asn':'', 'geocountry':'', 'VirusTotal':''}

     try{
      var obj = JSON.parse(reply);
      var ip_values =  Object.values(obj);
      var ip_keys = Object.keys(obj);

      if(ip_keys.includes('VirusTotal')){
          var vt = obj['VirusTotal'];
          var vt_string ='VirusTotal : URL : ' + round(vt['URL'],5)+', down_file : ' + round(vt['down_file'],5)  + ', ref_file : '+ round(vt['ref_file'],5) + ', com_file : ' + round(vt['com_file'],5); 
         ip_info_dict['VirusTotal'] = vt_string;
         ip_info_dict_outtuple['VirusTotal'] = obj['VirusTotal']
      }

      if(ip_keys.includes('asn')){
        ip_info_dict_outtuple['asn']=obj['asn'];
        var len_asn =  obj['asn'].length
        if(len_asn>33){
        ip_info_dict['asn'] = obj['asn'].slice(0,33);}
        else{
         var rep = 33- len_asn;
         ip_info_dict['asn'] = obj['asn']+" ".repeat(rep) 
        }
      }
      else{ip_info_dict['asn'] = ' '.repeat(33);}

      if(ip_keys.includes('geocountry')){
        ip_info_dict_outtuple['geocountry']=obj['geocountry'];
        var len_geocountry = obj['geocountry'].length;
        if(len_geocountry > 33){
        ip_info_dict['geocountry'] = obj['geocountry'].slice(0,33);}
        else{
          var rep = 33 - len_geocountry;
          ip_info_dict['geocountry'] = obj['geocountry']+" ".repeat(rep);
        }
      }
      else{ip_info_dict['geocountry'] = ' '.repeat(33);}
      ip_info_str = Object.values(ip_info_dict).join("|");
      if(mode == 1)box_ip.setContent(ip_info_str);
      screen.render();
        resolve(ip_info_dict_outtuple);
      }
    catch (err){
        ip_info_str = " ".repeat(33) + "|"+" ".repeat(33) + "|"+" ".repeat(33)
        box_ip.setContent(ip_info_str);
        screen.render();
        resolve(ip_info_dict)}
    })
})
};

function getEvidence(reply){
  /*
  retrieves IPsInfo from redis.
  */
  var ev = ''
  try{
    var obj = JSON.parse(reply);
    var keys = Object.keys(obj);
    async.each(keys, (key,callback)=>{
      ev = ev+'{bold}'+color.green(key)+'{/bold}'+" "+obj[key]+'\n'
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
var ips_with_timewindows = {}

function set_tree_data(timewindows_list, blockedTW){
  /*
  sets ips and their tws for the tree.

  */
  // console.log(timewindows_list)
  var ips_with_profiles = Object.keys(timewindows_list);
  var explorer = { extended: true
  , children: function(self){
      var result = {};
             try {
            if (!self.childrenContent) {
          // var blockedTW = {};
            // blockedTW = Object.assign({}, blockedTWs);
            for(i=0;i<ips_with_profiles.length;i++){
              var tw = timewindows_list[ips_with_profiles[i]];
              child = ips_with_profiles[i];
            if(Object.keys(blockedTW).includes(child)){
              result[child] = { name:color.red(child), extended:false, children: tw[0]};
            }
            else{
              result[child] = { name:child, extended:false, children: tw[0]};
            }
           
            }
            }else
        result = self.childrenContent;
        } catch (e){}
        return result;
    }
}
return explorer;};

function getTreeData(key){
    if(key.includes('timeline')){
        var key_list = key.split('_');
        if(!Object.keys(ips_with_timewindows).includes(key_list[1])){
        ips_with_timewindows[key_list[1]]  = [];
        ips_with_timewindows[key_list[1]][0] = {};
        ips_with_timewindows[key_list[1]][0][key_list[2]]={};}
        else{
           ips_with_timewindows[key_list[1]][0][key_list[2]]={};
        }
    }
}
function timewindows_promises(reply) {
    return Promise.all(reply.map( key_redis => getTreeData(key_redis)))
      .then(blockedTW()
      .then(function(blocked_dict){tree.setData(set_tree_data(ips_with_timewindows,blocked_dict)); screen.render();return;}))
}

redis_tree.keys('*', (err,reply)=>{
    timewindows_promises(reply);
})        
var timeline_reply_global  = {};

tree.on('select',function(node){
  try{
  // console.log((tree.data.childrenContent.name))
  }
  catch(err){}
  screen.key('w',function(ch,key){
  clipboardy.writeSync(node.name);

clipboardy.readSync();

})
    clean_widgets()

    if(!node.name.includes('timewindow')){
      getIpInfo_box_ip(color.unstyle(node.name), 1)}
      
    else{
      var ip  = color.unstyle(node.parent.name)
      var timewindow = color.unstyle(node.name)

      redis_outtuples_timewindow.hgetall("profile_"+ip+"_"+node.name, (err,reply)=>{
        var ips = [];
        timeline_reply_global = reply;
        map.innerMap.draw(null);
        if(reply == null){
          table_outTuples_listtable.setItems('');
          box_detections.setContent('');
          return;}
        //box_detections.setContent(reply['Detections']);
        getEvidence(reply['Evidence']);
        
        var obj_outTuples = JSON.parse(reply["OutTuples"]);
        var keys = Object.keys(obj_outTuples);
        var data = [];
        async.each(keys, function(key,callback){
          var ip_dict = {'asn':'', 'geocountry':'', 'URL':'','down':'','ref':'', 'com':''}
          var row = [];
          var tuple_info = obj_outTuples[key];
          var outTuple_ip = key.split(':')[0];
          ips.push(outTuple_ip); 

          getIpInfo_box_ip(outTuple_ip,0).then(function(result_dict){
            var ipInfo_dict_keys = Object.keys(result_dict)
            if(ipInfo_dict_keys.includes('asn')){
              ip_dict['asn'] = result_dict['asn']
            }
            if(ipInfo_dict_keys.includes('geocountry')){
              // console.log((result_dict))
              ip_dict['geocountry'] = result_dict['geocountry']
            }
            if(ipInfo_dict_keys.includes('VirusTotal')){
              ip_dict['URL'] = String(round(result_dict['VirusTotal']['URL'],3))
              ip_dict['down'] = String(round(result_dict['VirusTotal']['down_file'],3))
              ip_dict['ref'] = String(round(result_dict['VirusTotal']['ref_file'],3))
              ip_dict['com'] = String(round(result_dict['VirusTotal']['com_file'],3))

            }
          if(tuple_info[0].trim().length>40){
            var k = chunkString(tuple_info[0].trim(),40)
          
            async.forEachOf(k, function(ctr,ind, callback){
              var row2 = []
              if(ind == 0){
                row2.push(key,ctr,Object.values(ip_dict)[0].slice(0,20), Object.values(ip_dict)[1], Object.values(ip_dict)[2], Object.values(ip_dict)[3],Object.values(ip_dict)[4], Object.values(ip_dict)[5]);
              }
              else{row2.push('',ctr, '', '' , '');}
              data.push(row2)
              callback(null)
            }, function(err){
              if(err){
                console.log('kamila',err)
              }
            })

          }  
          else{     
          row.push(key,tuple_info[0], Object.values(ip_dict)[0].slice(0,20), Object.values(ip_dict)[1], Object.values(ip_dict)[2], Object.values(ip_dict)[3],Object.values(ip_dict)[4], Object.values(ip_dict)[5]);
          data.push(row)}
          callback(null);
          })  
          
          

        },function(err) {
      if( err ) {
        console.log('unable to create user');
      } else {
        data.unshift(['key','string','asn','geocountry','url','down','ref','com'])
        table_outTuples_listtable.setData(data);
        setMap(ips)
      screen.render();  
      }
      });
    })}
      //get the timeline of a selected ip
    redis_get_timeline.lrange("profile_"+ip+"_"+node.name+'_timeline',0,-1, (err,reply)=>{
      var data = [];
      async.each(reply, function(line, callback){
        var row = [];
        var line_arr = line.split(" ")
        var index_to = line_arr.indexOf('to')
        var index_asked = line_arr.indexOf('asked');
        var index_careful = line_arr.indexOf('careful!');
        var index_recognized = line_arr.indexOf('recognized');
        var index_ip = index_to +1;
        if(index_to>= 0 && line_arr[index_ip].length>6)line_arr[index_ip]= "{bold}"+line_arr[index_ip]+"{/bold}"
        if(index_recognized >= 0){
          for(var i =index_recognized - 1; i < index_recognized+3;i++){
          line_arr[i] = color.red(line_arr[i]);}
          }
        if(index_careful > 0){
          line_arr[index_careful] = color.red(line_arr[index_careful]);
          line_arr[index_careful - 1] = color.red(line_arr[index_careful - 1])
        }
        for(var i =3; i < index_asked;i++){
          line_arr[i] = color.bold.cyan(line_arr[i]) }     
        if(line_arr[index_to+2].includes('/'))line_arr[index_to+2]=color.bold.yellow(line_arr[index_to+2].slice(0,-1))+','
        line_arr[1]= line_arr[1].substring(0, line_arr[1].lastIndexOf('.'));
        timeline_line = line_arr.join(" ");
        row.push(timeline_line.replace(/\|.*/,''));
        data.push(row);
        callback();
      },function(err) {
        if( err ) {
          console.log('unable to create user');
        } else {
          table_timeline.setData({headers:[node.parent.name+" "+node.name], data: data});
          screen.render();}
    });
  })
    })

//display two bars of dstPortsServer established and non established connections

  screen.key('b', function(ch, key) {
    hide_widgets()
    bar_state_one = true;
    var number_bars = 9
    // bar_state_two = true;  
    bar_state_three = true;
    bar_state_four = true;
    box_hotkeys_state = true;
    map_state = true;
    var first_bar_counter = 0;
    var second_bar_counter = 0;
    bar_two_dstPortsServer.options.barSpacing = 10;
    bar_one_dstPortsServer.options.barSpacing = 10;
    if(bar_state_two){
      var est_connections_dstPortsServer = tcp_udp_connections("DstPortsServerTCPEstablished","DstPortsServerUDPEstablished",timeline_reply_global);
      var notEst_connections_dstPortsServer = tcp_udp_connections("DstPortsServerTCPNotEstablished","DstPortsServerUDPNotEstablished",timeline_reply_global);
      var est_bar_number_dstPortsServer = Math.ceil(est_connections_dstPortsServer[0].length / number_bars);
      var notEst_bar_number_dstPortsServer = Math.ceil(notEst_connections_dstPortsServer[0].length /number_bars);
      set_box_bar_state(est_connections_dstPortsServer,notEst_connections_dstPortsServer,bar_one_dstPortsServer,bar_two_dstPortsServer)
      bar_setdata(bar_one_dstPortsServer, first_bar_counter,est_connections_dstPortsServer, number_bars);
      bar_setdata(bar_two_dstPortsServer, second_bar_counter, notEst_connections_dstPortsServer, number_bars);
      bar_one_dstPortsServer.setLabel({text:color.green('DstPortsServerEstablished'),side:'left'});
      bar_two_dstPortsServer.setLabel({text:color.green('DstPortsServerNotEstablished'),side:'left'});
      screen.render();
      screen.key('right', function(ch, key) {
        if(bar_one_dstPortsServer.focused == true){

            if(first_bar_counter >= (est_bar_number_dstPortsServer-1)*number_bars);
            else{
            first_bar_counter += number_bars;             
              bar_setdata(bar_one_dstPortsServer, first_bar_counter, est_connections_dstPortsServer,number_bars);}}
          else{
            if(second_bar_counter >= (notEst_bar_number_dstPortsServer-1)*number_bars); 
            else {
              second_bar_counter += number_bars;
              bar_setdata(bar_two_dstPortsServer, second_bar_counter, notEst_connections_dstPortsServer, number_bars);}
          }
        screen.render()
    });
      screen.key('left', function(ch, key) {
        if(bar_one_dstPortsServer.focused == true){
            first_bar_counter -=number_bars;
            if(first_bar_counter<0)first_bar_counter=0;
            bar_setdata(bar_one_dstPortsServer, first_bar_counter, est_connections_dstPortsServer,number_bars);}
          else{
            second_bar_counter -= number_bars;
            if(second_bar_counter<0)second_bar_counter=0;
            bar_setdata(bar_two_dstPortsServer, second_bar_counter, notEst_connections_dstPortsServer,number_bars);
          }
        screen.render()
      });

    }
    else{
    

        bar_one_dstPortsServer.hide();
        bar_two_dstPortsServer.hide();
        box_bar_state.hide();
        show_widgets()
      }
      bar_state_two= !bar_state_two;
      screen.render()
  
});

screen.key('v', function(ch, key) {
    hide_widgets()
    bar_state_one = true;
    bar_state_two = true; 
    bar_state_three = true;
    
    box_hotkeys_state = true;
    map_state = true;
    var first_bar_counter = 0;
    var second_bar_counter = 0;
    var vertical_counter = 0;
    bar_one_dstPortClient.options.barSpacing = 25;
    bar_two_dstPortClient.options.barSpacing = 25;
    if(bar_state_four){
      try{
      number_bars = 5
      var est_connections_dstPortsClient = port_ips_bars("DstPortsClientTCPNotEstablished","DstPortsClientUDPNotEstablished",timeline_reply_global);
      var dstPortsClient_keys = Object.keys(est_connections_dstPortsClient);
      var dstPortsClient_values = Object.values(est_connections_dstPortsClient);
      var est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
      var est_bar_two_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter+1][0].length / number_bars);
      var vertical = Math.ceil(dstPortsClient_keys.length / 2);
      port_ip_setdata(bar_one_dstPortClient, first_bar_counter, dstPortsClient_values[vertical_counter], number_bars);
      port_ip_setdata(bar_two_dstPortClient, second_bar_counter, dstPortsClient_values[vertical_counter+1], number_bars);
      bar_one_dstPortClient.setLabel({text:color.green(dstPortsClient_keys[0]),side:'left'});
      bar_two_dstPortClient.setLabel({text:color.green(dstPortsClient_keys[1]),side:'left'});
      bar_one_dstPortClient.show();
      
      bar_two_dstPortClient.show();
      box_bar_state.show();
      bar_one_dstPortClient.focus();
      screen.render();


      screen.key('right', function(ch, key) {
        
        if(bar_one_dstPortClient.focused == true){
            if(first_bar_counter >= (est_bar_one_number_dstPortsClient-1)*number_bars);
            else{
            first_bar_counter += number_bars;             
              port_ip_setdata(bar_one_dstPortClient, first_bar_counter, dstPortsClient_values[vertical_counter], number_bars);}}
          else{
            if(second_bar_counter >= (est_bar_two_number_dstPortsClient-1)*number_bars); 
            else {
              second_bar_counter += 5;
              port_ip_setdata(bar_two_dstPortClient, second_bar_counter, dstPortsClient_values[vertical_counter+1], number_bars);}
          }
        screen.render()
    });
      screen.key('left', function(ch, key) {
        if(bar_one_dstPortClient.focused == true){
            first_bar_counter -=number_bars;
            if(first_bar_counter<0)first_bar_counter=0;
            port_ip_setdata(bar_one_dstPortClient, first_bar_counter, dstPortsClient_values[vertical_counter], number_bars);}
          else{
            second_bar_counter -= number_bars;
            if(second_bar_counter<0)second_bar_counter=0;
            port_ip_setdata(bar_two_dstPortClient, second_bar_counter,dstPortsClient_values[vertical_counter+1], number_bars);
          }
        screen.render()
      });
      screen.key('down', function(ch, key) {
          vertical_counter +=2;
          if(vertical_counter > (vertical-1)*2){vertical_counter -=2;}
          else{
            if(dstPortsClient_keys[vertical_counter]===undefined){
              bar_one_dstPortClient.clear();
              bar_one_dstPortClient.setLabel({text:color.green('empty'),side:'left'})
              bar_two_dstPortClient.clear();
              bar_two_dstPortClient.setLabel({text:color.green('empty'),side:'left'})
            }
            else if(dstPortsClient_keys[vertical_counter+1]===undefined){
              est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
              bar_one_dstPortClient.setLabel({text:color.green(dstPortsClient_keys[vertical_counter]),side:'left'});
              port_ip_setdata(bar_one_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter], number_bars);
              bar_two_dstPortClient.clear();
              bar_two_dstPortClient.setLabel({text:color.green('empty'),side:'left'})
            }
            else{
              est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
              est_bar_two_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter+1][0].length / number_bars);
              bar_one_dstPortClient.setLabel({text:color.green(dstPortsClient_keys[vertical_counter]),side:'left'});
              bar_two_dstPortClient.setLabel({text:color.green(dstPortsClient_keys[vertical_counter+1]),side:'left'});
              port_ip_setdata(bar_one_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter], number_bars);
              port_ip_setdata(bar_two_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter+1], number_bars);
            }}
          
        screen.render()
      });
      screen.key('up', function(ch, key) {
          vertical_counter -=2;
          if(vertical_counter <0){vertical_counter =0;}
          else{
            if(dstPortsClient_keys[vertical_counter]===undefined){
              bar_one_dstPortClient.clear();
              bar_one_dstPortClient.setLabel({text:color.green('empty'),side:'left'})
              bar_two_dstPortClient.clear();
              bar_two_dstPortClient.setLabel({text:color.green('empty'),side:'left'})
            }
            else if(dstPortsClient_keys[vertical_counter+1]===undefined){
              est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
              bar_one_dstPortClient.setLabel({text:color.green(dstPortsClient_keys[vertical_counter]),side:'left'});
              port_ip_setdata(bar_one_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter], number_bars);
              bar_two_dstPortClient.clear();
              bar_two_dstPortClient.setLabel({text:color.green('empty'),side:'left'})
            }
            else{
              est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
              est_bar_two_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter+1][0].length / number_bars);
              bar_one_dstPortClient.setLabel({text:color.green(dstPortsClient_keys[vertical_counter]),side:'left'});
              bar_two_dstPortClient.setLabel({text:color.green(dstPortsClient_keys[vertical_counter+1]),side:'left'});
              port_ip_setdata(bar_one_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter], number_bars);
              port_ip_setdata(bar_two_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter+1], number_bars);
          }}
          
        screen.render()
      });

    }catch(err){
      box_bar_state.setContent('no information')
      bar_one_dstPortClient.show()
      bar_two_dstPortClient.show()
      box_bar_state.show();
      }}
    else{
      show_widgets()

      bar_one_dstPortClient.hide()
      bar_two_dstPortClient.hide()
      box_bar_state.hide();
      }
      bar_state_four = !bar_state_four;
      screen.render()
  
});

//display to bars of SrcPortsClient established and non established connections    
 screen.key('e', function(ch, key) {

    hide_widgets()
    // bar_state_one = true;
    bar_state_two = true; 
    bar_state_three = true;
    box_hotkeys_state = true;
    map_state = true;
    var gauge_counter1 = 0;
    var gauge_counter2 = 0;
    var listtable_counter1 = 0;
    var listtable_counter2 = 0;
    if(bar_state_one){
      var est_connections_srcPortsClient = tcp_udp_connections("SrcPortsClientTCPEstablished","SrcPortsClientUDPEstablished",timeline_reply_global);
      var notEst_connections_srcPortsClient = tcp_udp_connections("SrcPortsClientTCPNotEstablished","SrcPortsClientUDPNotEstablished",timeline_reply_global);
      var est_bar_one_number_srcPortsClient = Math.ceil(est_connections_srcPortsClient[3].length / 10);
      var notEst_bar_one_number_srcPortsClient = Math.ceil(notEst_connections_srcPortsClient[3].length / 10);

      gaugeList_notEst_srcPort.setGauges(notEst_connections_srcPortsClient[3].slice(0,10))
      gaugeList_est_srcPort.setGauges(est_connections_srcPortsClient[3].slice(0,10))
      var data_est =  [['estSrcPortClient', 'totalpkts','totalflows', 'totalbyes'],[]]
      data_est.push(...est_connections_srcPortsClient[2].slice(0,20))
      listtable_est_srcPort.setData(data_est)

      var data_notest =  [['notEstSrcPortClient', 'totalpkts','totalflows', 'totalbyes'],[]]
      data_notest.push(...notEst_connections_srcPortsClient[2].slice(0,20))
      listtable_notEst_srcPort.setData(data_notest) 

      gaugeList_est_srcPort.show()
      gaugeList_notEst_srcPort.show()
      listtable_notEst_srcPort.show()
      listtable_est_srcPort.show()
      gaugeList_est_srcPort.focus()
      screen.render();

    screen.key('down', function(ch, key){
      if(gaugeList_est_srcPort.focused == true || gaugeList_est_dstIPs.focused == true){
        if(gauge_counter1 >= (est_bar_one_number_srcPortsClient-1)*10);
        else{
          var data_est_srcPortClient =[['estSrcPortClient', 'totalpkts','totalflows', 'totalbyes'],[]];
          listtable_counter1 += 20;
          gauge_counter1 += 10;
          data_est_srcPortClient.push(...est_connections_srcPortsClient[2].slice(listtable_counter1,listtable_counter1 + 20));
          listtable_est_srcPort.setData(data_est_srcPortClient);
          gaugeList_est_srcPort.setGauges(est_connections_srcPortsClient[3].slice(gauge_counter1,gauge_counter1 + 10));
          screen.render();}
      }
      else{
        if(gauge_counter2 >= (notEst_bar_one_number_srcPortsClient-1)*10);
        else{
          var data_notEst_srcPortClient =[['notEstSrcPortClient', 'totalpkts','totalflows', 'totalbyes'],[]];
          listtable_counter2 += 20;
          gauge_counter2 += 10;
          data_notEst_srcPortClient.push(...notEst_connections_srcPortsClient[2].slice(listtable_counter2,listtable_counter2 + 20));
          listtable_notEst_srcPort.setData(data_notEst_srcPortClient);
          gaugeList_notEst_srcPort.setGauges(notEst_connections_srcPortsClient[3].slice(gauge_counter2,gauge_counter2 + 10));
          screen.render();}
      }
      })

    screen.key('up', function(ch, key){
      if(gaugeList_est_srcPort.focused == true ||gaugeList_est_dstIPs.focused == true){
        listtable_counter1 -= 20;
        gauge_counter1 -= 10;
        if(listtable_counter1 <=0){listtable_counter1 = 0; gauge_counter1 = 0}
        var data_est_srcPortClient =[['estSrcPortClient', 'totalpkts','totalflows', 'totalbyes'],[]];
        data_est_srcPortClient.push(...est_connections_srcPortsClient[2].slice(listtable_counter1,listtable_counter1 + 20));
        listtable_est_srcPort.setData(data_est_srcPortClient);
        gaugeList_est_srcPort.setGauges(est_connections_srcPortsClient[3].slice(gauge_counter1,gauge_counter1+10));
        screen.render();

      }
      else{
        listtable_counter2 -=20;
        gauge_counter2 -= 10;
        if(listtable_counter2 <=0){listtable_counter2 = 0; gauge_counter2 = 0}
        var data_notEst_srcPortClient = [['notEstSrcPortClient', 'totalpkts','totalflows', 'totalbyes'],[]];
        data_notEst_srcPortClient.push(...notEst_connections_srcPortsClient[2].slice(listtable_counter2,listtable_counter2 + 20));
        listtable_notEst_srcPort.setData(data_notEst_srcPortClient);
        gaugeList_notEst_srcPort.setGauges(notEst_connections_srcPortsClient[3].slice(gauge_counter2,gauge_counter2+10));
        screen.render();  }
    })

    }
    else{
        listtable_est_srcPort.hide()
        listtable_notEst_srcPort.hide()
        gaugeList_notEst_srcPort.hide()
        gaugeList_est_srcPort.hide()
        show_widgets();
      }
    bar_state_one = !bar_state_one;
    screen.render()
  
});
     
//display to bars of dstIPsClient established and non established connections
screen.key('c', function(ch, key) {
    hide_widgets()
    bar_state_one = true;
    bar_state_two = true; 
    // bar_state_three = true;
    box_hotkeys_state = true;
    map_state = true;
    var gauge_counter1 = 0;
    var gauge_counter2 = 0;
    var listtable_counter1 = 0;
    var listtable_counter2 = 0;
    if(bar_state_three){
      var est_connections_dstIPsClient = tcp_udp_connections("DstIPsClientTCPEstablished","DstIPsClientUDPEstablished",timeline_reply_global);
      var notEst_connections_dstIPsClient = tcp_udp_connections("DstIPsClientTCPNotEstablished","DstIPsClientUDPNotEstablished",timeline_reply_global);
      var est_bar_one_number_dstIPsClient= Math.ceil(est_connections_dstIPsClient[3].length / 10);
      var notEst_bar_one_number_dstIPsClient = Math.ceil(notEst_connections_dstIPsClient[3].length / 10);

      gaugeList_notEst_dstIPs.setGauges(notEst_connections_dstIPsClient[3].slice(0,10))
      gaugeList_est_dstIPs.setGauges(est_connections_dstIPsClient[3].slice(0,10))
      var data_est =  [['estDstIPsClient', 'totalpkts','totalflows', 'totalbyes'],[]]
      data_est.push(...est_connections_dstIPsClient[2].slice(0,20))
      listtable_est_dstIPs.setData(data_est)

      var data_notest =  [['notEstDstIPsClient', 'totalpkts','totalflows', 'totalbyes'],[]]
      data_notest.push(...notEst_connections_dstIPsClient[2].slice(0,20))
      listtable_notEst_dstIPs.setData(data_notest) 

      gaugeList_est_dstIPs.show()
      gaugeList_notEst_dstIPs.show()
      listtable_notEst_dstIPs.show()
      listtable_est_dstIPs.show()
      gaugeList_est_dstIPs.focus()
      screen.render();

    screen.key('down', function(ch, key){
      if(gaugeList_est_dstIPs.focused == true || gaugeList_est_srcPort.focused == true){
        if(gauge_counter1 >= (est_bar_one_number_dstIPsClient-1)*10);
        else{
          var data_est_dstIPsClient =[['estDstIPsClient', 'totalpkts','totalflows', 'totalbyes'],[]];
          listtable_counter1 += 20;
          gauge_counter1 += 10;
          data_est_dstIPsClient.push(...est_connections_dstIPsClient[2].slice(listtable_counter1,listtable_counter1 + 20));
          listtable_est_dstIPs.setData(data_est_dstIPsClient);
          gaugeList_est_dstIPs.setGauges(est_connections_dstIPsClient[3].slice(gauge_counter1,gauge_counter1 + 10));
          screen.render();}
      }
      else{
        if(gauge_counter2 >= (notEst_bar_one_number_dstIPsClient-1)*10);
        else{
          var data_notEst_dstIPsClient =[['notEstDstIPsClient', 'totalpkts','totalflows', 'totalbyes'],[]];
          listtable_counter2 += 20;
          gauge_counter2 += 10;
          data_notEst_dstIPsClient.push(...notEst_connections_dstIPsClient[2].slice(listtable_counter2,listtable_counter2 + 20));
          listtable_notEst_dstIPs.setData(data_notEst_dstIPsClient);
          gaugeList_notEst_dstIPs.setGauges(notEst_connections_dstIPsClient[3].slice(gauge_counter2,gauge_counter2 + 10));
          screen.render();}
      }
      })

    screen.key('up', function(ch, key){
      if(gaugeList_est_dstIPs.focused == true || gaugeList_est_srcPort.focused == true){
        listtable_counter1 -= 20;
        gauge_counter1 -= 10;
        if(listtable_counter1 <=0){listtable_counter1 = 0; gauge_counter1 = 0}
        var data_est_dstIPsClient =[['estDstIPsClient', 'totalpkts','totalflows', 'totalbyes'],[]];
        data_est_dstIPsClient.push(...est_connections_dstIPsClient[2].slice(listtable_counter1,listtable_counter1 + 20));
        listtable_est_dstIPs.setData(data_est_dstIPsClient);
        gaugeList_est_dstIPs.setGauges(est_connections_dstIPsClient[3].slice(gauge_counter1,gauge_counter1+10));
        screen.render();

      }
      else{
        listtable_counter2 -=20; 
        gauge_counter2 -= 10;
        if(listtable_counter2 <=0){listtable_counter2 = 0; gauge_counter2 = 0}
        var data_notEst_dstIPsClient = [['notEstDstIPsClient', 'totalpkts','totalflows', 'totalbyes'],[]];
        data_notEst_dstIPsClient.push(...notEst_connections_dstIPsClient[2].slice(listtable_counter2,listtable_counter2 + 20));
        listtable_notEst_dstIPs.setData(data_notEst_dstIPsClient);
        gaugeList_notEst_dstIPs.setGauges(notEst_connections_dstIPsClient[3].slice(gauge_counter2,gauge_counter2+10));
        screen.render();  }
    })

    }
    else{
        listtable_est_dstIPs.hide()
        listtable_notEst_dstIPs.hide()
        gaugeList_notEst_dstIPs.hide()
        gaugeList_est_dstIPs.hide()
        show_widgets();
      }
    bar_state_three = !bar_state_three;
    screen.render()
  
});





screen.key('m', function(ch, key) {
  hide_widgets()
  bar_state_one = true;
  bar_state_two = true; 
  bar_state_three = true;
  bar_state_four = true;
  box_hotkeys_state = true;
  // map_state = true;

  if(map_state){
    map.show()
  }
  else{
     show_widgets()
      map.hide()  
    }
    map_state = !map_state;
    screen.render()

});
 


table_timeline.rows.on('select', (item, index) => {
  var timeline_line = item.content.split(" ");
  var index_to = timeline_line.indexOf('to')
  var timeline_ip = timeline_line[index_to +1].slice(6,-7)
  getIpInfo_box_ip(timeline_ip,1)
});

// var l = true;
screen.key('h', function(ch, key) {
  hide_widgets()
  if(box_hotkeys_state){
    table_outTuples_listtable.show()
    table_outTuples_listtable.focus()
  }
  else{table_outTuples_listtable.hide()
    
    
  show_widgets()}
    box_hotkeys_state =! box_hotkeys_state
    screen.render();
});

screen.key(['tab'], function(ch, key) {
  if(gaugeList_est_srcPort.focused == true){
    gaugeList_notEst_srcPort.focus()
    // console.log('sdsds')
  }
  else if(gaugeList_notEst_srcPort.focused == true){
    gaugeList_est_srcPort.focus()
    // console.log('ss')
  }
  else if(gaugeList_notEst_dstIPs.focused == true){
    gaugeList_est_dstIPs.focus()
  }
  else if(gaugeList_est_dstIPs.focused == true){
    gaugeList_notEst_dstIPs.focus()
  }
  else if(bar_one_srcPortClient.focused == true){
      bar_two_srcPortClient.focus();}
  else if(bar_two_srcPortClient.focused == true){
    bar_one_srcPortClient.focus();}
  else if(bar_one_dstIPsClient.focused == true){
    bar_two_dstIPsClient.focus();}
  else if(bar_two_dstIPsClient.focused == true){
    bar_one_dstIPsClient.focus();}
  else if(bar_one_dstIPsClient.focused == true){
    bar_two_dstPortsServer.focus();}
  else if(bar_two_dstIPsClient.focused == true){
    bar_one_dstIPsClient.focus();}
  else if(bar_one_dstPortClient.focused == true){
    bar_two_dstPortClient.focus();}
  else if(bar_two_dstPortClient.focused == true){
    bar_one_dstPortClient.focus();}
  else if(screen.focused == tree.rows){
    focus_widget =table_timeline
    tree.style.border.fg = 'blue'
    table_timeline.style.border.fg='magenta'
    table_timeline.focus();}
  else if(screen.focused == table_timeline.rows){
    focus_widget = box_detections
    table_timeline.style.border.fg='blue'
    box_detections.focus()}
  else if(screen.focused == box_detections){
    focus_widget = box_evidence
    box_evidence.focus()}
  else{
    focus_widget = tree
    tree.style.border.fg = 'magenta'
    tree.focus();}
    screen.render()})


screen.key(['S-tab'], function(ch, key) {
  if(screen.focused == table_timeline.rows){
    focus_widget =tree;
    table_timeline.style.border.fg = 'blue'
    tree.style.border.fg='magenta'
    tree.focus();}

  else if(screen.focused == box_detections){
    focus_widget = table_timeline;
    table_timeline.style.border.fg='magenta'
    table_timeline.focus();}
  else if(screen.focused == box_evidence){
    focus_widget = box_detections;
    box_detections.focus()}
  else{
    focus_widget = box_evidence;
    tree.style.border.fg = 'blue'
    box_evidence.focus();}   
  screen.render();
});
tree.focus();

// screen.on('resize', function() {
//   tree.emit('attach');
//   table_timeline.emit('attach');
//   table_outTuples.emit('attach');
//   box_detections.emit('attach');
//   box_evidence.emit('attach');
//   box_ip.emit('attach');
//   table_outTuples_listtable.emit('attach');
//   map.emit('attach');
//   bar_two.emit('attach');
//   bar_one.emit('attach');0
// });
screen.key(["escape", "q", "C-c"], function(ch, key) {
    return process.exit(0);
});
screen.render();

